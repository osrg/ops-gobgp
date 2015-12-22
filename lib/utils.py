import uuid
import os
import time
from ovs.db import idl
from ovs import jsonrpc, poller, stream


class ExceptionResult(object):
    def __init__(self, ex, tb):
        self.ex = ex
        self.tb = tb


def receive_signal(signum, stack):
    print('signal received:%d' % signum)
    print('exit')
    os._exit(0)


def wait_for_change(_idl, timeout, seqno=None):
    if seqno is None:
        seqno = _idl.change_seqno
    stop = time.time() + timeout
    while _idl.change_seqno == seqno and not _idl.run():
        ovs_poller = poller.Poller()
        _idl.wait(ovs_poller)
        ovs_poller.timer_wait(timeout * 1000)
        ovs_poller.block()
        if time.time() > stop:
            raise Exception("Timeout")


def get_schema_helper(connection, schema_name):
    err, strm = stream.Stream.open_block(
        stream.Stream.open(connection))
    if err:
        raise Exception("Could not connect to %s" % (
            connection,))
    rpc = jsonrpc.Connection(strm)
    req = jsonrpc.Message.create_request('get_schema', [schema_name])
    err, resp = rpc.transact_block(req)
    rpc.close()
    if err:
        raise Exception("Could not retrieve schema from %s: %s" % (
            connection, os.strerror(err)))
    elif resp.error:
        raise Exception(resp.error)
    return idl.SchemaHelper(None, resp.result)


def row_by_value(idl_, table, column, match):
    tab = idl_.tables[table]
    if tab.rows is not None:
        for r in tab.rows.values():
            if getattr(r, column) == match:
                return r
    return None


def get_column_value(row, col):
    if col == '_uuid':
        val = row.uuid
    else:
        val = getattr(row, col)

    # Idl returns lists of Rows where ovs-vsctl returns lists of UUIDs
    if isinstance(val, list) and len(val):
        if isinstance(val[0], idl.Row):
            val = [v.uuid for v in val]
        # ovs-vsctl treats lists of 1 as single results
        if len(val) == 1:
            val = val[0]
    return val
