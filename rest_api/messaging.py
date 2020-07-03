import logging
import re

from sawtooth_rest_api.messaging import Connection
from sawtooth_rest_api.protobuf import client_batch_submit_pb2
from sawtooth_rest_api.protobuf import validator_pb2

from sawtooth_signing import create_context
from sawtooth_signing import CryptoFactory
from sawtooth_signing import secp256k1

from errors import ApiBadRequest
from errors import ApiInternalError
from transaction_create import \
    make_create_agent_transaction
from transaction_create import \
    make_create_record_transaction
from transaction_create import \
    make_transfer_record_transaction
from transaction_create import \
    make_update_record_transaction
from transaction_create import \
    make_finalize_record_transaction

from sawtooth_rest_api.protobuf.validator_pb2 import Message

from google.protobuf.json_format import MessageToDict
from google.protobuf.message import DecodeError

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

class Messenger(object):
    TIMEOUT = 300

    def __init__(self, validator_url):
        self._connection = Connection(validator_url)
        self._context = create_context('secp256k1')
        self._crypto_factory = CryptoFactory(self._context)
        self._batch_signer = self._crypto_factory.new_signer(
            self._context.new_random_private_key())

    def open_validator_connection(self):
        self._connection.open()

    def close_validator_connection(self):
        self._connection.close()

    def get_new_key_pair(self):
        private_key = self._context.new_random_private_key()
        public_key = self._context.get_public_key(private_key)
        return public_key.as_hex(), private_key.as_hex()


    async def send_create_agent_transaction(self,
                                            private_key,
                                            name,
                                            timestamp,
                                            role):
        transaction_signer = self._crypto_factory.new_signer(
            secp256k1.Secp256k1PrivateKey.from_hex(private_key))

        batch = make_create_agent_transaction(
            transaction_signer=transaction_signer,
            batch_signer=self._batch_signer,
            name=name,
            timestamp=timestamp,
            role=role)
        await self._send_and_wait_for_commit(batch)

    async def send_create_record_transaction(self,
                                             private_key,
                                             record_id,
                                             description,
                                             price,
                                             quantity,
                                             units,
                                             parent_id,
                                             other_fields,
                                             remarks,
                                             new,
                                             timestamp):
        transaction_signer = self._crypto_factory.new_signer(
            secp256k1.Secp256k1PrivateKey.from_hex(private_key))

        batch = make_create_record_transaction(
            transaction_signer=transaction_signer,
            batch_signer=self._batch_signer,
            record_id=record_id,
            description=description,
            price=price,
            quantity=quantity,
            units=units,
            parent_id=parent_id,
            other_fields=other_fields,
            remarks=remarks,
            new=new,
            timestamp=timestamp)
        await self._send_and_wait_for_commit(batch)

    async def send_transfer_record_transaction(self,
                                               private_key,
                                               receiving_agent,
                                               record_id,
                                               timestamp):
        transaction_signer = self._crypto_factory.new_signer(
            secp256k1.Secp256k1PrivateKey.from_hex(private_key))

        batch = make_transfer_record_transaction(
            transaction_signer=transaction_signer,
            batch_signer=self._batch_signer,
            receiving_agent=receiving_agent,
            record_id=record_id,
            timestamp=timestamp)
        await self._send_and_wait_for_commit(batch)

    async def send_update_record_transaction(self,
                                             private_key,
                                             record_id,
                                             description,
                                             price,
                                             quantity,
                                             units,
                                             parent_id,
                                             other_fields,
                                             timestamp):
        transaction_signer = self._crypto_factory.new_signer(
            secp256k1.Secp256k1PrivateKey.from_hex(private_key))
        batch = make_update_record_transaction(
            transaction_signer=transaction_signer,
            batch_signer=self._batch_signer,
            record_id=record_id,
            description=description,
            price=price,
            quantity=quantity,
            units=units,
            parent_id=parent_id,
            other_fields=other_fields,
            timestamp=timestamp)
        await self._send_and_wait_for_commit(batch)


    async def send_finalize_record_transaction(self,
                                             private_key,
                                             record_id,
                                             status,
                                             remarks,
                                             timestamp):
        transaction_signer = self._crypto_factory.new_signer(
            secp256k1.Secp256k1PrivateKey.from_hex(private_key))
        batch = make_finalize_record_transaction(
            transaction_signer=transaction_signer,
            batch_signer=self._batch_signer,
            record_id=record_id,
            status=status,
            remarks=remarks,
            timestamp=timestamp)
        await self._send_and_wait_for_commit(batch)


    async def _send_and_wait_for_commit(self, batch):
        # Send transaction to validator
        submit_request = client_batch_submit_pb2.ClientBatchSubmitRequest(
            batches=[batch])
        await self._connection.send(
            validator_pb2.Message.CLIENT_BATCH_SUBMIT_REQUEST,
            submit_request.SerializeToString())

        # Send status request to validator
        batch_id = batch.header_signature
        status_request = client_batch_submit_pb2.ClientBatchStatusRequest(
            batch_ids=[batch_id], wait=True)
        validator_response = await self._connection.send(
            validator_pb2.Message.CLIENT_BATCH_STATUS_REQUEST,
            status_request.SerializeToString())

        # Parse response
        status_response = client_batch_submit_pb2.ClientBatchStatusResponse()
        status_response.ParseFromString(validator_response.content)
        status = status_response.batch_statuses[0].status
        if status == client_batch_submit_pb2.ClientBatchStatus.INVALID:
            error = status_response.batch_statuses[0].invalid_transactions[0]
            raise ApiBadRequest(error.message)
        elif status == client_batch_submit_pb2.ClientBatchStatus.PENDING:
            raise ApiInternalError('Transaction submitted but timed out')
        elif status == client_batch_submit_pb2.ClientBatchStatus.UNKNOWN:
            raise ApiInternalError('Something went wrong. Try again later')




    

    async def _query_validator(self, request_type, response_proto,
                               payload, error_traps=None):
        """Sends a request to the validator and parses the response.
        """
        LOGGER.debug(
            'Sending %s request to validator',
            self._get_type_name(request_type))

        payload_bytes = payload.SerializeToString()
        response = await self._send_request(request_type, payload_bytes)
        content = self._parse_response(response_proto, response)

        LOGGER.debug(
            'Received %s response from validator with status %s',
            self._get_type_name(response.message_type),
            self._get_status_name(response_proto, content.status))

        self._check_status_errors(response_proto, content, error_traps)
        return self._message_to_dict(content)

    async def _send_request(self, request_type, payload):
        """Uses an executor to send an asynchronous ZMQ request to the
        validator with the handler's Connection
        """
        try:
            return await self._connection.send(
                message_type=request_type,
                message_content=payload,
                timeout=self.TIMEOUT)
        except DisconnectError:
            LOGGER.warning('Validator disconnected while waiting for response')
            raise errors.ValidatorDisconnected()
        except asyncio.TimeoutError:
            LOGGER.warning('Timed out while waiting for validator response')
            raise errors.ValidatorTimedOut()


    @staticmethod
    def _parse_response(proto, response):
        """Parses the content from a validator response Message.
        """
        try:
            content = proto()
            content.ParseFromString(response.content)
            return content
        except (DecodeError, AttributeError):
            LOGGER.error('Validator response was not parsable: %s', response)
            raise errors.ValidatorResponseInvalid()

    @staticmethod
    def _get_type_name(type_enum):
        return Message.MessageType.Name(type_enum)

    @staticmethod
    def _get_status_name(proto, status_enum):
        try:
            return proto.Status.Name(status_enum)
        except ValueError:
            return 'Unknown ({})'.format(status_enum)

    @staticmethod
    def _check_status_errors(proto, content, error_traps=None):
        """Raises HTTPErrors based on error statuses sent from validator.
        Checks for common statuses and runs route specific error traps.
        """
        if content.status == proto.OK:
            return

        try:
            if content.status == proto.INTERNAL_ERROR:
                raise errors.UnknownValidatorError()
        except AttributeError:
            # Not every protobuf has every status enum, so pass AttributeErrors
            pass

        try:
            if content.status == proto.NOT_READY:
                raise errors.ValidatorNotReady()
        except AttributeError:
            pass

        try:
            if content.status == proto.NO_ROOT:
                raise errors.HeadNotFound()
        except AttributeError:
            pass

        try:
            if content.status == proto.INVALID_PAGING:
                raise errors.PagingInvalid()
        except AttributeError:
            pass

        try:
            if content.status == proto.INVALID_SORT:
                raise errors.SortInvalid()
        except AttributeError:
            pass

        # Check custom error traps from the particular route message
        if error_traps is not None:
            for trap in error_traps:
                trap.check(content.status)

    @staticmethod
    def _message_to_dict(message):
        """Converts a Protobuf object to a python dict with desired settings.
        """
        return MessageToDict(
            message,
            including_default_value_fields=True,
            preserving_proto_field_name=True)