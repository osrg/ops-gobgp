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
import signal
import socket
import threading
import traceback
from ovs.db import idl
from ovs.unixctl.client import *
from ovs import poller
from six.moves import queue as Queue
from grpc.beta import implementations

import handle
from lib import logger
from lib import utils
from api import gobgp_pb2 as api

AFI_IP = 1
SAFI_UNICAST = 1
RF_IPv4_UC = AFI_IP<<16 | SAFI_UNICAST


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
    def __init__(self):
        self.timeout = 5
        self.retry_limit = 5
        self.wait_time = 3
        self.o_hdr = None
        self.poller =None
        self.th = None
        self.conn_f = None
        signal.signal(signal.SIGINT, utils.receive_signal)

    def get_handler(self):
        return self.o_hdr

    def connect(self):
        connected = False
        retry = 0
        while not connected:
            if retry >= self.retry_limit:
                os._exit(1)
            try:
                self.conn_f()

                self.th = threading.Thread(target=self.run)
                self.th.setDaemon(True)
                logger.log.info('Connected')
                connected = True
            except Exception as e:
                logger.log.error('Faild to connect: {0}'.format(e))
                time.sleep(self.wait_time)
                retry += 1

        self.th = threading.Thread(target=self.run)
        self.th.setDaemon(True)

    def start(self):
        self.th.start()

    def run(self):
        raise NotImplementedError


class OpsConnection(Connection):
    def __init__(self, ovsdb):
        self.idl = None
        self.ovsdb = ovsdb
        self.txns = TransactionQueue(1)
        self.lock = threading.Lock()
        self.schema_name = "OpenSwitch"
        super(OpsConnection, self).__init__()

    def connect(self):
        with self.lock:
            if self.idl is not None:
                return

            def conn():
                logger.log.info('Connecting to OpenSwitch...')
                helper = utils.get_schema_helper(self.ovsdb, self.schema_name)
                helper.register_all()
                self.idl = idl.Idl(self.ovsdb, helper)
                utils.wait_for_change(self.idl, self.timeout)
                self.poller = poller.Poller()

                self.o_hdr = handle.OpsHandler(self.idl)
            self.conn_f = conn
            super(OpsConnection, self).connect()

    def start(self):
        logger.log.info('Run run_ops_to_gogbp thread...')
        super(OpsConnection, self).start()
        return self.th

    def run(self):
        first_time = True
        while True:
            self.idl.txn = None
            try:
                self.idl.wait(self.poller)
                self.poller.fd_wait(self.txns.alert_fileno, poller.POLLIN)
                if not first_time:
                    self.poller.block()
                if self.idl.txn:
                    self.idl.txn = None
                self.idl.run()

                self.o_hdr.handle_update()
            except Exception as ex:
                logger.log.warn(ex)

            txn = self.txns.get_nowait()
            if txn is not None:
                try:
                    txn.results.put(txn.do_commit())
                except Exception as ex:
                    er = utils.ExceptionResult(ex=ex, tb=traceback.format_exc())
                    txn.results.put(er)
                self.txns.task_done()
            first_time = False
        logger.log.info('run_ops_to_gogbp thread is end')

    def queue_txn(self, txn):
        self.txns.put(txn)


class GobgpConnection(Connection):
    def __init__(self, gobgp_url, gobgp_port):
        self.gobgp_url = gobgp_url
        self.gobgp_port = gobgp_port
        self.channel = implementations.insecure_channel(gobgp_url, gobgp_port)
        super(GobgpConnection, self).__init__()

    def connect(self):
        def conn():
            logger.log.info('Connecting to Gobgp...')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.gobgp_url, self.gobgp_port))
            s.close()
            g_conn = api.beta_create_GobgpApi_stub(self.channel)

            self.o_hdr = handle.GobgpHandler(g_conn)
        self.conn_f = conn
        super(GobgpConnection, self).connect()

    def start(self):
        logger.log.info('Run run_gogbp_to_ops thread...')
        super(GobgpConnection, self).start()
        return self.th

    def run(self):
        while True:
            logger.log.info('Wait for a change the bestpath from gobgp...')
            monitor_argument = {'rf': RF_IPv4_UC}
            self.o_hdr.monitor_bestpath_chenged(monitor_argument)
            time.sleep(3)
        logger.log.info('run_ops_to_gogbp thread is end')

