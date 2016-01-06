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
import socket
import threading
import traceback
import logging
from ovs.db import idl
from ovs.unixctl.client import *
from ovs import poller
from grpc.beta import implementations

import handle
from lib import utils
from lib import transaction
from api import gobgp_pb2 as api

log = logging.getLogger('connection')


class Connection(object):
    def __init__(self):
        self.timeout = 5
        self.retry_limit = 5
        self.wait_time = 3
        self.hdr = None
        self.th = None
        self.conn_f = None

    def get_handler(self):
        return self.hdr

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
                log.info('Connected')
                connected = True
            except Exception as e:
                log.error('Faild to connect: {0}'.format(e))
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
        self.poller = None
        self.ovsdb = ovsdb
        self.txns = transaction.TransactionQueue(1)
        self.schema_name = "OpenSwitch"
        super(OpsConnection, self).__init__()

    def connect(self):
        if self.idl is not None:
            return

        def conn():
            log.info('Connecting to OpenSwitch...')
            helper = utils.get_schema_helper(self.ovsdb, self.schema_name)
            helper.register_all()
            self.idl = idl.Idl(self.ovsdb, helper)
            utils.wait_for_change(self.idl, self.timeout)
            self.poller = poller.Poller()

            self.hdr = handle.OpsHandler(self.idl, self)
        self.conn_f = conn
        super(OpsConnection, self).connect()

    def start(self):
        log.info('Run run_ops_to_gogbp thread...')
        super(OpsConnection, self).start()
        return self.th

    def run(self):
        first_time = True
        while True:
            self.idl.txn = None
            self.idl.wait(self.poller)
            self.poller.fd_wait(self.txns.alert_fileno, poller.POLLIN)
            if not first_time:
                self.poller.block()
            self.idl.run()

            self.hdr.handle_update()

            txn = self.txns.get_nowait()
            if txn is not None:
                try:
                    txn.results.put(txn.do_commit())
                except Exception as ex:
                    er = utils.ExceptionResult(ex=ex, tb=traceback.format_exc())
                    txn.results.put(er)
                self.txns.task_done()
            first_time = False
        log.info('run_ops_to_gogbp thread is end')

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
            log.info('Connecting to Gobgp...')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.gobgp_url, self.gobgp_port))
            s.close()
            g_conn = api.beta_create_GobgpApi_stub(self.channel)

            self.hdr = handle.GobgpHandler(g_conn)
        self.conn_f = conn
        super(GobgpConnection, self).connect()

    def start(self):
        log.info('Run run_gogbp_to_ops thread...')
        super(GobgpConnection, self).start()
        return self.th

    def run(self):
        while True:
            log.info('Wait for a change the bestpath from gobgp...')
            monitor_argument = {'rf': utils.RF_IPv4_UC}
            self.hdr.monitor_bestpath_chenged(monitor_argument)
            time.sleep(3)
        log.info('run_ops_to_gogbp thread is end')
