import hashlib

from sawtooth_rest_api.protobuf import batch_pb2
from sawtooth_rest_api.protobuf import transaction_pb2

from addressing import addresser
from protogen import payload_pb2


def make_create_agent_transaction(transaction_signer,
                                  batch_signer,
                                  name,
                                  timestamp,
                                  role):

    agent_address = addresser.get_agent_address(
        transaction_signer.get_public_key().as_hex())

    inputs = [agent_address]

    outputs = [agent_address]

    action = payload_pb2.CreateAgentAction(name=name, role=role)

    payload = payload_pb2.ScPayload(
        action=payload_pb2.ScPayload.CREATE_AGENT,
        create_agent=action,
        timestamp=timestamp)
    payload_bytes = payload.SerializeToString()

    return _make_batch(
        payload_bytes=payload_bytes,
        inputs=inputs,
        outputs=outputs,
        transaction_signer=transaction_signer,
        batch_signer=batch_signer)


def make_create_record_transaction(transaction_signer,
                                   batch_signer,
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


    inputs = [
        addresser.get_agent_address(
            transaction_signer.get_public_key().as_hex()),
        addresser.get_record_address(record_id)
    ]

    outputs = [addresser.get_record_address(record_id)]

    action = payload_pb2.CreateRecordAction(
        record_id=record_id,
        description=description,
        price=price,
        quantity=quantity,
        units=units,
        parent_id=parent_id,
        other_fields=other_fields,
        remarks=remarks,
        new=new
        )

    payload = payload_pb2.ScPayload(
        action=payload_pb2.ScPayload.CREATE_RECORD,
        create_record=action,
        timestamp=timestamp)
    payload_bytes = payload.SerializeToString()

    return _make_batch(
        payload_bytes=payload_bytes,
        inputs=inputs,
        outputs=outputs,
        transaction_signer=transaction_signer,
        batch_signer=batch_signer)


def make_transfer_record_transaction(transaction_signer,
                                     batch_signer,
                                     receiving_agent,
                                     record_id,
                                     timestamp):
    
    sending_agent_address = addresser.get_agent_address(
        transaction_signer.get_public_key().as_hex())
    receiving_agent_address = addresser.get_agent_address(receiving_agent)
    record_address = addresser.get_record_address(record_id)

    inputs = [sending_agent_address, receiving_agent_address, record_address]

    outputs = [record_address]

    action = payload_pb2.TransferRecordAction(
        record_id=record_id,
        receiving_agent=receiving_agent)

    payload = payload_pb2.ScPayload(
        action=payload_pb2.ScPayload.TRANSFER_RECORD,
        transfer_record=action,
        timestamp=timestamp)
    payload_bytes = payload.SerializeToString()

    return _make_batch(
        payload_bytes=payload_bytes,
        inputs=inputs,
        outputs=outputs,
        transaction_signer=transaction_signer,
        batch_signer=batch_signer)


def make_update_record_transaction(transaction_signer,
                                   batch_signer,
                                   record_id,
                                   description,
                                   price,
                                   quantity,
                                   units,
                                   parent_id,
                                   other_fields,
                                   timestamp):
    
    agent_address = addresser.get_agent_address(
        transaction_signer.get_public_key().as_hex())
    record_address = addresser.get_record_address(record_id)

    inputs = [agent_address, record_address]

    outputs = [record_address]

    action = payload_pb2.UpdateRecordAction(
        record_id=record_id,
        description=description,
        price=price,
        quantity=quantity,
        units=units,
        parent_id=parent_id,
        other_fields=other_fields)

    payload = payload_pb2.ScPayload(
        action=payload_pb2.ScPayload.UPDATE_RECORD,
        update_record=action,
        timestamp=timestamp)
    payload_bytes = payload.SerializeToString()

    return _make_batch(
        payload_bytes=payload_bytes,
        inputs=inputs,
        outputs=outputs,
        transaction_signer=transaction_signer,
        batch_signer=batch_signer)


def make_finalize_record_transaction(transaction_signer,
                                   batch_signer,
                                   record_id,
                                   status,
                                   remarks,
                                   timestamp):
    
    agent_address = addresser.get_agent_address(
        transaction_signer.get_public_key().as_hex())
    record_address = addresser.get_record_address(record_id)

    inputs = [agent_address, record_address]

    outputs = [record_address]

    action = payload_pb2.FinalizeRecordAction(
        record_id=record_id,
        status=status,
        remarks=remarks)

    payload = payload_pb2.ScPayload(
        action=payload_pb2.ScPayload.FINALIZE_RECORD,
        finalize_record=action,
        timestamp=timestamp)
    payload_bytes = payload.SerializeToString()

    return _make_batch(
        payload_bytes=payload_bytes,
        inputs=inputs,
        outputs=outputs,
        transaction_signer=transaction_signer,
        batch_signer=batch_signer)


def _make_batch(payload_bytes,
                inputs,
                outputs,
                transaction_signer,
                batch_signer):

    transaction_header = transaction_pb2.TransactionHeader(
        family_name=addresser.FAMILY_NAME,
        family_version=addresser.FAMILY_VERSION,
        inputs=inputs,
        outputs=outputs,
        signer_public_key=transaction_signer.get_public_key().as_hex(),
        batcher_public_key=batch_signer.get_public_key().as_hex(),
        dependencies=[],
        payload_sha512=hashlib.sha512(payload_bytes).hexdigest())
    transaction_header_bytes = transaction_header.SerializeToString()

    transaction = transaction_pb2.Transaction(
        header=transaction_header_bytes,
        header_signature=transaction_signer.sign(transaction_header_bytes),
        payload=payload_bytes)

    batch_header = batch_pb2.BatchHeader(
        signer_public_key=batch_signer.get_public_key().as_hex(),
        transaction_ids=[transaction.header_signature])
    batch_header_bytes = batch_header.SerializeToString()

    batch = batch_pb2.Batch(
        header=batch_header_bytes,
        header_signature=batch_signer.sign(batch_header_bytes),
        transactions=[transaction])

    return batch