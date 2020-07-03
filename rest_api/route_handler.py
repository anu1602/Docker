import datetime
from json.decoder import JSONDecodeError
import logging
import time
import json
import base64
import re
from aiohttp import web

from aiohttp.web import json_response
import bcrypt
from Crypto.Cipher import AES
from itsdangerous import BadSignature
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from addressing import addresser

from errors import ApiBadRequest
from errors import ApiNotFound
from errors import ApiUnauthorized

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError

from sawtooth_rest_api.protobuf.validator_pb2 import Message

import sawtooth_rest_api.exceptions as errors
import sawtooth_rest_api.error_handlers as error_handlers
from sawtooth_rest_api.messaging import DisconnectError
#from sawtooth_rest_api.messaging import SendBackoffTimeoutError
from sawtooth_rest_api.protobuf import client_transaction_pb2
from sawtooth_rest_api.protobuf import client_list_control_pb2
from sawtooth_rest_api.protobuf import client_batch_submit_pb2
from sawtooth_rest_api.protobuf import client_state_pb2
from sawtooth_rest_api.protobuf import client_block_pb2
from sawtooth_rest_api.protobuf import client_batch_pb2
from sawtooth_rest_api.protobuf import client_receipt_pb2
from sawtooth_rest_api.protobuf import client_peers_pb2
#from sawtooth_rest_api.protobuf import client_status_pb2
from sawtooth_rest_api.protobuf.block_pb2 import BlockHeader
from sawtooth_rest_api.protobuf.batch_pb2 import BatchList
from sawtooth_rest_api.protobuf.batch_pb2 import BatchHeader
from sawtooth_rest_api.protobuf.transaction_pb2 import TransactionHeader



LOGGER = logging.getLogger(__name__)

limit_per_page = 10


class RouteHandler(object):
    def __init__(self, loop, messenger, database):
        self._loop = loop
        self._messenger = messenger
        self._database = database

    
    async def get_public_key(self, request):
        body = await decode_request(request)
        name = body.get('name')
        response = await self.create_agent(request)
        LOGGER.debug(response)
        try:
            auth_info = await self._database.fetch_auth_resource_by_name(name)
        except:
            pass
        return json_response({'public_key': auth_info.get('public_key')})

    async def authenticate(self, request):
        body = await decode_request(request)
        required_fields = ['name', 'password']
        validate_fields(required_fields, body)

        password = bytes(body.get('password'), 'utf-8')

        auth_info = await self._database.fetch_auth_resource_by_name(
            body.get('name'))
        if auth_info is None:
            raise ApiUnauthorized('No agent with that name exists')

        hashed_password = auth_info.get('hashed_password')
        if not bcrypt.checkpw(password, bytes.fromhex(hashed_password)):
            raise ApiUnauthorized('Incorrect public key or password')

        role = auth_info.get('role')
        token = generate_auth_token(
            request.app['secret_key'], auth_info.get('public_key'),role)

        return json_response({'authorization': token})


    async def create_agent(self, request):
        body = await decode_request(request)
        required_fields = ['name', 'password']
        validate_fields(required_fields, body)

        public_key, private_key = self._messenger.get_new_key_pair()

        await self._messenger.send_create_agent_transaction(
            private_key=private_key,
            name=body.get('name'),
            timestamp=get_time(),
            role=body.get('role'))

        encrypted_private_key = encrypt_private_key(
            request.app['aes_key'], public_key, private_key)
        hashed_password = hash_password(body.get('password'))
        name = body.get('name')
        role = body.get('role')

        await self._database.create_auth_entry(
            name, hashed_password, public_key, encrypted_private_key,role)

        #await self.create_fields(role)

        return json_response(
            {'data': 'agent created successfully'})

    
    async def fetch_fields(self, request):
        private_key = await self._authorize(request)

        fields = ['description', 'quantity', 'parent_id']

        role = request.match_info.get('role', '')
        if role == 'tool':
            add_fields = ['type', 'Haematite level', 'Ore qualifications', 
                'Certifying authority', 'Key results']
        
        elif role == 'raw_material':
            add_fields = ['type', 'Haematite level', 'Ore qualifications', 
                'Certifying authority', 'Key results']
        
        elif role == 'liquids':
            add_fields = ['type', 'Alloy Composition', 'Tests employed',
                'Key Test Results', 'Test conducted by']
        
        elif role == 'safety':
            add_fields = ['type', 'Process plan steps', 'Finishing',
            'Dimension #1', 'Tolerance #1', 'Dimension #2', 'Tolerance #2',
            'Dimension #3', 'Tolerance #3', 'Dimension #4', 'Tolerance #4',
            'qualification tests', 'Standard used', 'Agency',
            'Key Results', 'NDE tests employed']
        
        elif role == 'measurement':
            add_fields = ['type', 'Feature #1', 'Count #1', 'Standard #1', 'Result #1',
            'Feature #2', 'Count #2', 'Standard used #2', 'Result #2',
            'Feature #3', 'Count #3', 'Standard used #3', 'Result #3',
            'Feature #4', 'Count #4', 'Standard used #4', 'Result #4', 'Agency']
        
        elif role == 'cleaning':
            add_fields = ['type', 'Feature #1', 'Count #1', 'Standard #1', 'Result #1',
            'Feature #2', 'Count #2', 'Standard used #2', 'Result #2',
            'Feature #3', 'Count #3', 'Standard used #3', 'Result #3',
            'Feature #4', 'Count #4', 'Standard used #4', 'Result #4', 'Agency']

        elif role == 'infrastructure':
            add_fields = ['type', 'Feature #1', 'Count #1', 'Standard #1', 'Result #1',
            'Feature #2', 'Count #2', 'Standard used #2', 'Result #2',
            'Feature #3', 'Count #3', 'Standard used #3', 'Result #3',
            'Feature #4', 'Count #4', 'Standard used #4', 'Result #4', 'Agency']

        elif role == 'wastage':
            add_fields = ['type', 'Feature #1', 'Count #1', 'Standard #1', 'Result #1',
            'Feature #2', 'Count #2', 'Standard used #2', 'Result #2',
            'Feature #3', 'Count #3', 'Standard used #3', 'Result #3',
            'Feature #4', 'Count #4', 'Standard used #4', 'Result #4', 'Agency']
        
        elif role == 'toolstaff':
            add_fields = ['Name', 'Date of return committed', 'Shop', 'Details']

        elif role == 'toolstudents':
            add_fields = ['Name', 'Roll No.', 'Date of return committed', 
                'Department', 'Phone', 'Details', 'Guide-HOD approval']
        
        elif role == 'toolbreakage':
            add_fields = ['Work order No.', 'Location', 'Reason', 
                'Details', 'Guide-HOD approval']

        elif role == 'materialreq':
            add_fields = ['Purpose', 'Shop', 'Year',
                'Semester', 'Details']

        elif role == 'inspection':
            add_fields = ['Purchase order No.', 'Supplier', 'Details', 
                'Certifications', 'Key results']

        elif role == 'project':
            add_fields = ['Student', 'Supervisor', 'Details']

        else:
            raise ApiBadRequest('Invalid role specified')

        fields.extend(add_fields)
    
        #await self._database.edit_fields_entry(role, add_fields=add_fields)

        return json_response(
            {'other_fields': fields})



    async def list_agents(self, request):
        address_prefix = addresser.NAMESPACE + addresser.AGENT_PREFIX
        await self.list_state(request, address_prefix)


    async def create_record(self, request):
        private_key = await self._authorize(request)

        body = await decode_request(request)
        token = request.headers["Authorization"]
        required_fields = ['record_id', 'other_fields']
        validate_fields(required_fields, body)

        tokendes = deserialize_auth_token(request.app['secret_key'],token)
        
        if tokendes["role"]=="professor" or "shop" or "store" :    
            await self._messenger.send_create_record_transaction(
                private_key=private_key,
                record_id=body.get('record_id'),
                description=body.get('description'),
                price=body.get('price'),
                quantity=body.get('quantity'),
                units=body.get('units'),
                parent_id=body.get('parent_id'),
                other_fields=body.get('other_fields'),
                remarks=body.get('remarks'),
                new=body.get('new'),
                timestamp=get_time())
            return json_response({'data': 'Create record transaction submitted'})
            
        else:
            return json_response({'error':'You do not have the access privelage for this operation'})
        


    async def list_records(self, request):
        address_prefix = addresser.NAMESPACE + addresser.RECORD_PREFIX
        await self.list_state(request, address_prefix)


    async def transfer_record(self, request):
        private_key = await self._authorize(request)

        body = await decode_request(request)
        required_fields = ['receiving_agent']
        validate_fields(required_fields, body)

        receiver_db_details = await self._database.fetch_auth_resource_by_name(
            body.get('receiving_agent'))
        LOGGER.debug(receiver_db_details)
        receiving_public_key = receiver_db_details['public_key']

        record_id = request.match_info.get('record_id', '')

        await self._messenger.send_transfer_record_transaction(
            private_key=private_key,
            receiving_agent=receiving_public_key,
            record_id=record_id,
            timestamp=get_time())

        return json_response(
            {'data': 'Transfer record transaction submitted'})

    
    async def update_record(self, request):
        private_key = await self._authorize(request)

        body = await decode_request(request)
        #required_fields = ['description', 'price', 'quantity', 'units', 'parent_id']
        #validate_fields(required_fields, body)

        record_id = request.match_info.get('record_id', '')

        await self._messenger.send_update_record_transaction(
            private_key=private_key,
            record_id=record_id,
            description=body.get('description'),
            price=body.get('price'),
            quantity=body.get('quantity'),
            units=body.get('units'),
            parent_id=body.get('parent_id'),
            other_fields=body.get('other_fields'),
            timestamp=get_time())

        return json_response(
            {'data': 'Update record transaction submitted'})

    async def finalize_record(self, request):
        private_key = await self._authorize(request)

        body = await decode_request(request)
        required_fields = ['status', 'remarks']
        validate_fields(required_fields, body)

        record_id = request.match_info.get('record_id', '')

        await self._messenger.send_finalize_record_transaction(
            private_key=private_key,
            record_id=record_id,
            status=body.get('status'),
            remarks=body.get('remarks'),
            timestamp=get_time())

        return json_response(
            {'data': 'Finalize record transaction submitted'})


    async def _authorize(self, request):
        token = request.headers.get('authorization')
        if token is None:
            raise ApiUnauthorized('No auth token provided')
        token_prefixes = ('Bearer', 'Token')
        for prefix in token_prefixes:
            if prefix in token:
                token = token.partition(prefix)[2].strip()
        try:
            token_dict = deserialize_auth_token(request.app['secret_key'],
                                                token)
        except BadSignature:
            raise ApiUnauthorized('Invalid auth token')
        public_key = token_dict.get('public_key')

        auth_resource = await self._database.fetch_auth_resource_by_public_key(public_key)
        if auth_resource is None:
            raise ApiUnauthorized('Token is not associated with an agent')
        return decrypt_private_key(request.app['aes_key'],
                                   public_key,
                                   auth_resource['encrypted_private_key'])



    async def fetch_fields_resource_by_name(self, request):
        """ query from database"""
        private_key = await self._authorize(request)

        name = request.match_info.get('name', '')
        rows = await self._database.fetch_fields_resource_by_name(name)
        current_fields_dict = {}
        for row in rows:
            current_fields_dict[row['required_fields']] = ""
        
        return json_response(current_fields_dict)



    async def list_transactions(self, request):
        """Fetches list of txns from validator, optionally filtered by id.

        Request:
            query:
                - head: The id of the block to use as the head of the chain
                - id: Comma separated list of txn ids to include in results

        Response:
            data: JSON array of Transaction objects with expanded headers
            head: The head used for this query (most recent if unspecified)
            link: The link to this exact query, including head block
            paging: Paging info and nav, like total resources and a next link
        """
        #private_key = await self._authorize(request)

        paging_controls = self._get_paging_controls(request)
        validator_query = client_transaction_pb2.ClientTransactionListRequest(
            head_id=self._get_head_id(request),
            transaction_ids=self._get_filter_ids(request),
            sorting=self._get_sorting_message(request, "default"),
            paging=self._make_paging_message(paging_controls))

        response = await self._messenger._query_validator(
            Message.CLIENT_TRANSACTION_LIST_REQUEST,
            client_transaction_pb2.ClientTransactionListResponse,
            validator_query)

        data = [self._expand_transaction(t) for t in response['transactions']]

        return self._wrap_paginated_response(
            request=request,
            response=response,
            controls=paging_controls,
            data=data)


    async def list_state(self, request):
        """Fetches list of data entries, optionally filtered by address prefix.

        Request:
            query:
                - head: The id of the block to use as the head of the chain
                - address: Return entries whose addresses begin with this
                prefix

        Response:
            data: An array of leaf objects with address and data keys
            head: The head used for this query (most recent if unspecified)
            link: The link to this exact query, including head block
            paging: Paging info and nav, like total resources and a next link
        """
        #private_key = await self._authorize(request)

        paging_controls = self._get_paging_controls(request)

        head, root = await self._head_to_root(request.url.query.get(
            'head', None))
        validator_query = client_state_pb2.ClientStateListRequest(
            state_root=root,
            address=request.url.query.get('address', None),
            sorting=self._get_sorting_message(request, "default"),
            paging=self._make_paging_message(paging_controls))

        response = await self._messenger._query_validator(
            Message.CLIENT_STATE_LIST_REQUEST,
            client_state_pb2.ClientStateListResponse,
            validator_query)

        return self._wrap_paginated_response(
            request=request,
            response=response,
            controls=paging_controls,
            data=response.get('entries', []),
            head=head)

    @staticmethod
    def _get_paging_controls(request):
        """Parses start and/or limit queries into a paging controls dict.
        """
        start = request.url.query.get('start', None)
        limit = request.url.query.get('limit', limit_per_page)
        controls = {}

        if limit is not None:
            try:
                controls['limit'] = int(limit)
            except ValueError:
                LOGGER.debug('Request query had an invalid limit: %s', limit)
                raise errors.CountInvalid()

            if controls['limit'] <= 0:
                LOGGER.debug('Request query had an invalid limit: %s', limit)
                raise errors.CountInvalid()

        if start is not None:
            controls['start'] = start

        return controls

    @staticmethod
    def _get_sorting_message(request, key):
        """Parses the reverse query into a list of ClientSortControls protobuf
        messages.
        """
        control_list = []
        reverse = request.url.query.get('reverse', None)
        if reverse is None:
            return control_list

        if reverse.lower() == "":
            control_list.append(client_list_control_pb2.ClientSortControls(
                reverse=True,
                keys=key.split(",")
            ))
        elif reverse.lower() != 'false':
            control_list.append(client_list_control_pb2.ClientSortControls(
                reverse=True,
                keys=reverse.split(",")
            ))

        return control_list

    async def _head_to_root(self, block_id):
        error_traps = [error_handlers.BlockNotFoundTrap]
        if block_id:
            response = await self._messenger._query_validator(
                Message.CLIENT_BLOCK_GET_BY_ID_REQUEST,
                client_block_pb2.ClientBlockGetResponse,
                client_block_pb2.ClientBlockGetByIdRequest(block_id=block_id),
                error_traps)
            block = self._expand_block(response['block'])
        else:
            response = await self._messenger._query_validator(
                Message.CLIENT_BLOCK_LIST_REQUEST,
                client_block_pb2.ClientBlockListResponse,
                client_block_pb2.ClientBlockListRequest(
                    paging=client_list_control_pb2.ClientPagingControls(
                        limit=1)),
                error_traps)
            block = self._expand_block(response['blocks'][0])
        return (
            block['header_signature'],
            block['header']['state_root_hash'],
        )


    @staticmethod
    def _make_paging_message(controls):
        """Turns a raw paging controls dict into Protobuf ClientPagingControls.
        """

        return client_list_control_pb2.ClientPagingControls(
            start=controls.get('start', None),
            limit=controls.get('limit', None))


    @classmethod
    def _get_head_id(cls, request):
        """Fetches the request's head query, and validates if present.
        """
        head_id = request.url.query.get('head', None)

        if head_id is not None:
            cls._validate_id(head_id)

        return head_id

    @classmethod
    def _get_filter_ids(cls, request):
        """Parses the `id` filter paramter from the url query.
        """
        id_query = request.url.query.get('id', None)

        if id_query is None:
            return None

        filter_ids = id_query.split(',')
        for filter_id in filter_ids:
            cls._validate_id(filter_id)

        return filter_ids

    @staticmethod
    def _validate_id(resource_id):
        """Confirms a header_signature is 128 hex characters, raising an
        ApiError if not.
        """
        if not re.fullmatch('[0-9a-f]{128}', resource_id):
            raise errors.InvalidResourceId(resource_id)

    @classmethod
    def _expand_transaction(cls, transaction):
        """Deserializes a Transaction's header.
        """
        return cls._parse_header(TransactionHeader, transaction)

    @classmethod
    def _expand_batch(cls, batch):
        """Deserializes a Batch's header, and the header of its Transactions.
        """
        cls._parse_header(BatchHeader, batch)
        if 'transactions' in batch:
            batch['transactions'] = [
                cls._expand_transaction(t) for t in batch['transactions']]
        return batch

    @classmethod
    def _expand_block(cls, block):
        """Deserializes a Block's header, and the header of its Batches.
        """
        cls._parse_header(BlockHeader, block)
        if 'batches' in block:
            block['batches'] = [cls._expand_batch(b) for b in block['batches']]
        return block

    @classmethod
    def _parse_header(cls, header_proto, resource):
        """Deserializes a resource's base64 encoded Protobuf header.
        """
        header = header_proto()
        try:
            header_bytes = base64.b64decode(resource['header'])
            header.ParseFromString(header_bytes)
        except (KeyError, TypeError, ValueError, DecodeError):
            header = resource.get('header', None)
            LOGGER.error(
                'The validator sent a resource with %s %s',
                'a missing header' if header is None else 'an invalid header:',
                header or '')
            raise errors.ResourceHeaderInvalid()

        resource['header'] = cls._message_to_dict(header)
        return resource

    @staticmethod
    def _message_to_dict(message):
        """Converts a Protobuf object to a python dict with desired settings.
        """
        return MessageToDict(
            message,
            including_default_value_fields=True,
            preserving_proto_field_name=True)

    @classmethod
    def _wrap_paginated_response(cls, request, response, controls, data,
                                 head=None):
        """Builds the metadata for a pagingated response and wraps everying in
        a JSON encoded web.Response
        """
        paging_response = response['paging']
        if head is None:
            head = response['head_id']
        link = cls._build_url(
            request,
            head=head,
            start=paging_response['start'],
            limit=paging_response['limit'])

        paging = {}
        limit = controls.get('limit')
        start = controls.get("start")
        paging["limit"] = limit
        paging["start"] = start
        # If there are no resources, there should be nothing else in paging
        if paging_response.get("next") == "":
            return cls._wrap_response(
                request,
                data=data,
                metadata={
                    'head': head,
                    'link': link,
                    'paging': paging
                })

    @classmethod
    def _build_url(cls, request, path=None, **changes):
        """Builds a response URL by overriding the original queries with
        specified change queries. Change queries set to None will not be used.
        Setting a change query to False will remove it even if there is an
        original query with a value.
        """
        changes = {k: v for k, v in changes.items() if v is not None}
        queries = {**request.url.query, **changes}
        queries = {k: v for k, v in queries.items() if v is not False}
        query_strings = []

        def add_query(key):
            query_strings.append('{}={}'.format(key, queries[key])
                                 if queries[key] != '' else key)

        def del_query(key):
            queries.pop(key, None)

        if 'head' in queries:
            add_query('head')
            del_query('head')

        if 'start' in changes:
            add_query('start')
        elif 'start' in queries:
            add_query('start')

        del_query('start')

        if 'limit' in queries:
            add_query('limit')
            del_query('limit')

        for key in sorted(queries):
            add_query(key)

        scheme = cls._get_forwarded(request, 'proto') or request.url.scheme
        host = cls._get_forwarded(request, 'host') or request.host
        forwarded_path = cls._get_forwarded(request, 'path')
        path = path if path is not None else request.path
        query = '?' + '&'.join(query_strings) if query_strings else ''

        url = '{}://{}{}{}{}'.format(scheme, host, forwarded_path, path, query)
        return url

    @staticmethod
    def _get_forwarded(request, key):
        """Gets a forwarded value from the `Forwarded` header if present, or
        the equivalent `X-Forwarded-` header if not. If neither is present,
        returns an empty string.
        """
        forwarded = request.headers.get('Forwarded', '')
        match = re.search(
            r'(?<={}=).+?(?=[\s,;]|$)'.format(key),
            forwarded,
            re.IGNORECASE)

        if match is not None:
            header = match.group(0)

            if header[0] == '"' and header[-1] == '"':
                return header[1:-1]

            return header

        return request.headers.get('X-Forwarded-{}'.format(key.title()), '')

    @staticmethod
    def _wrap_response(request, data=None, metadata=None, status=200):
        """Creates the JSON response envelope to be sent back to the client.
        """
        envelope = metadata or {}

        if data is not None:
            envelope['data'] = data

        return web.Response(
            status=status,
            content_type='application/json',
            text=json.dumps(
                envelope,
                indent=2,
                separators=(',', ': '),
                sort_keys=True))


async def decode_request(request):
    try:
        return await request.json()
    except JSONDecodeError:
        raise ApiBadRequest('Improper JSON format')


def validate_fields(required_fields, body):
    for field in required_fields:
        if body.get(field) is None:
            raise ApiBadRequest(
                "'{}' parameter is required".format(field))


def encrypt_private_key(aes_key, public_key, private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    return cipher.encrypt(private_key)


def decrypt_private_key(aes_key, public_key, encrypted_private_key):
    init_vector = bytes.fromhex(public_key[:32])
    cipher = AES.new(bytes.fromhex(aes_key), AES.MODE_CBC, init_vector)
    private_key = cipher.decrypt(bytes.fromhex(encrypted_private_key))
    return private_key


def hash_password(password):
    return bcrypt.hashpw(bytes(password, 'utf-8'), bcrypt.gensalt())


def get_time():
    dts = datetime.datetime.utcnow()
    return round(time.mktime(dts.timetuple()) + dts.microsecond/1e6)


def generate_auth_token(secret_key, public_key, role):
    serializer = Serializer(secret_key)
    token = serializer.dumps({'public_key': public_key, 'role': role})
    return token.decode('ascii')


def deserialize_auth_token(secret_key, token):
    serializer = Serializer(secret_key)
    return serializer.loads(token)
