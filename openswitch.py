# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import os
import sys
import threading
import traceback
import gobgp_pb2
import logging

from ovs import jsonrpc, poller, stream
from ovs.unixctl.client import *
from ovs.db import idl

from six.moves import queue as Queue
from optparse import OptionParser
from grpc.beta import implementations

log = logging.Logger("")


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


def row_not_found(**kwargs):
    rows = kwargs['rows']
    col = kwargs['col']
    message = 'Cannot find {0} in {1}'.format(col, rows)
    return message


def row_by_value(rows, c_name):
    if len(rows) > 0:
        try:
            r = rows[0]
            return getattr(r, c_name)
        except Exception:
            raise Exception(row_not_found(rows=rows, col=c_name))
    return []


def row_by_values(rows, c_name):
    res = []
    for r in rows:
        try:
            res.append(getattr(r, c_name))
        except Exception:
            raise Exception(row_not_found(rows=rows, col=c_name))
    return res


class ExceptionResult(object):
    def __init__(self, ex, tb):
        self.ex = ex
        self.tb = tb


class TransactionQueue(Queue.Queue, object):
    def __init__(self, *args, **kwargs):
        super(TransactionQueue, self).__init__(*args, **kwargs)
        alertpipe = os.pipe()
        self.alertin = os.fdopen(alertpipe[0], 'r', 0)
        self.alertout = os.fdopen(alertpipe[1], 'w', 0)

    def get_nowait(self, *args, **kwargs):
        try:
            result = super(TransactionQueue, self).get_nowait(*args, **kwargs)
        except Queue.Empty:
            return None
        self.alertin.read(1)
        return result

    def put(self, *args, **kwargs):
        super(TransactionQueue, self).put(*args, **kwargs)
        self.alertout.write('X')
        self.alertout.flush()

    @property
    def alert_fileno(self):
        return self.alertin.fileno()


class Connection(object):
    def __init__(self, connection, schema_name):
        self.idl = None
        self.connection = connection
        self.timeout = 5
        self.txns = TransactionQueue(1)
        self.lock = threading.Lock()
        self.schema_name = schema_name

    def start(self, gobgpd_addr, gobgpd_port):
        with self.lock:
            if self.idl is not None:
                return
            log.info('Connecting...')
            try:
                helper = get_schema_helper(self.connection, self.schema_name)
            except Exception:
                def do_get_schema_helper():
                    return get_schema_helper(self.connection, self.schema_name)
                helper = do_get_schema_helper()
            log.info('Connected...')
            helper.register_all()
            self.idl = idl.Idl(self.connection, helper)
            wait_for_change(self.idl, self.timeout)
            self.poller = poller.Poller()
            self.ops_handler = OpenSwitchHandler(gobgpd_addr, gobgpd_port)
            self.thread = threading.Thread(target=self.run)
            self.thread.setDaemon(True)
            self.thread.start()

    def run(self):
        while True:
            self.idl.wait(self.poller)
            self.poller.fd_wait(self.txns.alert_fileno, poller.POLLIN)
            self.poller.block()
            self.idl.run()

            self.ops_handler.new_table(self.idl.tables)
            self.ops_handler.handle_update()

            txn = self.txns.get_nowait()
            if txn is not None:
                try:
                    txn.results.put(txn.do_commit())
                except Exception as ex:
                    er = ExceptionResult(ex=ex, tb=traceback.format_exc())
                    txn.results.put(er)
                self.txns.task_done()

    def queue_txn(self, txn):
        self.txns.put(txn)


class OpenSwitchHandler():
    def __init__(self, gobgpd_addr, gobgpd_port):
        self.g_handler = GrpcHandler(gobgpd_addr, gobgpd_port)
        self.tables = None
        self.router_id = None
        self.neighbors = []

    def new_table(self, tables):
        self.tables = tables

    def handle_update(self):

        self.handle_vrf_update()

        self.handle_bgp_router_update()

        self.handle_bgp_neighbor_update()

    def handle_vrf_update(self):
        try:
            asn, uuid = self.get_bgp_router_uuid()
            log.debug('Catch vrf update: as={0}, uuid={1}'.format(asn, uuid))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))

            del_global_config_arguments = {'operation': gobgp_pb2.DEL}
            self.g_handler.mod_global_config(del_global_config_arguments)

            log.info('Delete the global config has been completed')
            self.router_id = None
            self.neighbors = []
        return

    def handle_bgp_router_update(self):
        rows = self.tables['BGP_Router'].rows.values()
        if len(rows) < 1:
            return
        try:
            asn, uuid = self.get_bgp_router_uuid()
            log.debug('Catch bgp router update: as={0}, uuid={1}'.format(asn, uuid))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))
            return

        # Register the router id
        router_id = row_by_value(rows, 'router_id')
        if len(router_id) > 0:
            router_id = router_id[0]
            if self.router_id is None:
                # grpc request: add global config
                bgp_conf = {'as': asn, 'router_id': router_id}
                add_global_config_arguments = {
                    'operation': gobgp_pb2.ADD,
                    'global': gobgp_pb2.Global(**bgp_conf)
                }
                self.g_handler.mod_global_config(add_global_config_arguments)
                log.info('Add the global config has been completed: router_id={0}'.format(router_id))
                self.router_id = router_id
            else:
                if router_id == '0.0.0.0':
                    # grpc request: remove global config
                    del_global_config_arguments = {'operation': gobgp_pb2.DEL}
                    self.g_handler.mod_global_config(del_global_config_arguments)

                    log.info('Delete the global config has been completed: router_id={0}'.format(router_id))
                    self.router_id = None
                elif router_id != self.router_id:
                    # grpc request: change global config
                    bgp_conf = {'as': asn, 'router_id': router_id}
                    mod_global_config_arguments = {
                        'operation': gobgp_pb2.ADD,
                        'global': gobgp_pb2.Global(**bgp_conf)
                    }
                    self.g_handler.mod_global_config(mod_global_config_arguments)

                    log.info('Change the global config has been completed: router_id={0}'.format(router_id))
                    self.router_id = router_id
                else:
                    log.info('Router id not change')
        else:
            log.info('Router id is not configured yet')

        if len(self.neighbors) > 0:
            new_neighbors = row_by_value(rows, 'bgp_neighbors')
            for n in self.neighbors:
                if n not in new_neighbors:
                    # grpc request: remove neighbor
                    peer_conf = {'conf': gobgp_pb2.PeerConf(neighbor_address=n)}
                    del_neighbor_config_arguments = {
                        'operation': gobgp_pb2.DEL,
                        'peer': gobgp_pb2.Peer(**peer_conf)
                    }
                    self.g_handler.mod_neighbor_config(del_neighbor_config_arguments)
                    log.info('Delete the Neighbor has been completed: addrs={0}'.format(n))
            self.neighbors = new_neighbors.keys()

    def handle_bgp_neighbor_update(self):
        rows = self.tables['BGP_Neighbor'].rows.values()
        if len(rows) < 1:
            return

        try:
            addrs, uuids = self.get_bgp_neighbor_uuids()
            log.debug('Catch bgp neighbor update: addrs={0}, uuids={1}'.format(addrs, uuids))
        except Exception as e:
            log.warn('Exception: {0}'.format(e))
            return

        # Register the neighbor
        remote_ass = row_by_values(rows, 'remote_as')
        remote_uuids = row_by_values(rows, 'uuid')
        if (len(remote_ass) > 0 and len(remote_uuids) > 0) and len(remote_ass) == len(remote_uuids):
            for idx, id in enumerate(uuids):
                for ridx, rid in enumerate(remote_uuids):
                    if rid != id:
                        continue
                    # grpc request: remove neighbor
                    peer_conf = {'conf': gobgp_pb2.PeerConf(neighbor_address=addrs[idx], peer_as=remote_ass[ridx][0])}
                    add_neighbor_config_arguments = {
                        'operation': gobgp_pb2.ADD,
                        'peer': gobgp_pb2.Peer(**peer_conf)
                    }
                    self.g_handler.mod_neighbor_config(add_neighbor_config_arguments)

                    log.info('Add the Neighbor has been completed: addr={0}, remote_as={1}'.format(addrs[idx], remote_ass[ridx]))
            self.neighbors = addrs

    def get_bgp_router_uuid(self):
        rows = self.tables['VRF'].rows.values()
        if len(rows) < 1:
            raise Exception('VRF table not found')

        name = row_by_value(rows, 'name')
        if name == 'vrf_default':
            routers = row_by_value(rows, 'bgp_routers')
            if len(routers) < 1:
                raise Exception('no bgp router configured')
            if len(routers) > 1:
                raise Exception('default vrf has multiple bgp router setting')
            for k in routers.keys():
                asn = k
                uuid = getattr(routers[asn], 'uuid')
                return asn, uuid

    def get_bgp_neighbor_uuids(self):
        rows = self.tables['BGP_Router'].rows.values()
        if len(rows) < 1:
            raise Exception('BGP_Router table not found')
        neighbors = row_by_values(rows, 'bgp_neighbors')
        addrs = []
        uuids = []
        if len(neighbors) < 1:
            raise Exception('no bgp neighbor configured')
        for n in neighbors:
            for k in n.keys():
                addrs.append(k)
                uuids.append(getattr(n[k], 'uuid'))
        return addrs, uuids


def grpc_request(f):
    def wrapper(*args):
        try:
            f(*args)
        except Exception as e:
            log.warn('faild grpc request: {0}'.format(e.details))
    return wrapper


class GrpcHandler():
    def __init__(self, addr, port):
        self.gobgpd_addr = addr
        self.gobgpd_port = port
        self.timeout_seconds = 3
        self.channel = implementations.insecure_channel(self.gobgpd_addr, self.gobgpd_port)


    @grpc_request
    def mod_global_config(self, arguments):
        with gobgp_pb2.beta_create_GobgpApi_stub(self.channel) as stub:
            response = stub.ModGlobalConfig(
                gobgp_pb2.ModGlobalConfigArguments(**arguments),
                self.timeout_seconds)
        log.debug('grpc response: {0}'.format(response))


    @grpc_request
    def mod_neighbor_config(self, arguments):
        with gobgp_pb2.beta_create_GobgpApi_stub(self.channel) as stub:
            response = stub.ModNeighbor(
                gobgp_pb2.ModNeighborArguments(**arguments),
                self.timeout_seconds)
        log.debug('grpc response: {0}'.format(response))


def logger(option):
    LEVELS = {'NOTSET': logging.NOTSET,
              'DEBUG': logging.DEBUG,
              'INFO': logging.INFO,
              'WARNING': logging.WARNING,
              'WARN': logging.WARNING,
              'ERROR': logging.ERROR,
              'FATAL': logging.FATAL,
              'CRITICAL': logging.CRITICAL}

    level = option.log_level.upper()
    logger = logging.getLogger('openswitch')
    if level in LEVELS:
        logger.setLevel(LEVELS[level])
    else:
        print('> Not support entered log level')
        print('> enter the NOTSET, DEBUG, INFO, WARN, ERROR, FATAL, CRITICAL')
        sys.exit(1)

    file = option.log_file
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    if file == '' or file == 'stdout':
        h = logging.StreamHandler()
    else:
        h = logging.FileHandler(file, 'a+', 'utf-8')
    h.setFormatter(formatter)
    logger.addHandler(h)
    return logger


def main():
    usage = 'usage: python ./openswitch.py [options]... '
    parser = OptionParser(usage=usage)
    parser.add_option('-u', '--url', dest='url', default='127.0.0.1',
                      help='specifying an url')
    parser.add_option('-p', '--port', dest='port', default=8080,
                      help='specifying a port')
    parser.add_option('-l', '--log-level', dest='log_level', default='info',
                      help='specifying a log level')
    parser.add_option('-f', '--log-file', dest='log_file', default='./openswitch.log',
                      help='specifying the output destination of the log file')
    parser.add_option('-o', '--ovsdb-sock', dest='ovsdb', default='unix:/var/run/openvswitch/db.sock',
                      help='specifying the connection destination of the ovsdb    '
                           'Example                                               '
                           ' - unix:<socket file path>                            '
                           ' - tcp:<address>:<port>')

    (options, args) = parser.parse_args()
    global log
    log = logger(options)
    log.info('Run openswitch client')
    c = Connection(options.ovsdb, "OpenSwitch")
    c.start(options.url, options.port)

    # TODO It plans to implement a process for propagating the path of gobgp to openswitch
    while True:
        time.sleep(10)


if __name__ == '__main__':
    main()
