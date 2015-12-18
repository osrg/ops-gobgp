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
import threading
import traceback
from ovs.db import idl
from ovs.unixctl.client import *
from ovs import poller
from six.moves import queue as Queue

import utils
import handle
import logger


AFI_IP = 1
SAFI_UNICAST = 1
RF_IPv4_UC = AFI_IP<<16 | SAFI_UNICAST


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


class OpsConnection(object):
    def __init__(self, ovsdb):
        self.idl = None
        self.ovsdb = ovsdb
        self.timeout = 5
        self.txns = TransactionQueue(1)
        self.lock = threading.Lock()
        self.schema_name = "OpenSwitch"

    def get_handler(self):
        return self.o_hdr

    def connect(self):
        with self.lock:
            if self.idl is not None:
                return
            logger.log.info('Connecting to OpenSwitch...')
            try:
                helper = utils.get_schema_helper(self.ovsdb, self.schema_name)
                logger.log.info('Connected...')
                helper.register_all()
                self.idl = idl.Idl(self.ovsdb, helper)
                utils.wait_for_change(self.idl, self.timeout)
                self.poller = poller.Poller()

                self.o_hdr = handle.OpsHandler(self.idl)

                self.th = threading.Thread(target=self.run_ops_to_gogbp)
                self.th.setDaemon(True)
            except Exception as e:
                logger.log.error('Exception: {0}'.format(e))

    def start(self):
        logger.log.info('run run_ops_to_gogbp thread...')
        self.th.start()
        return self.th

    def run_ops_to_gogbp(self):
        first_time = True
        while True:
            self.idl.txn = None
            self.idl.wait(self.poller)
            self.poller.fd_wait(self.txns.alert_fileno, poller.POLLIN)
            if not first_time:
                self.poller.block()
            self.idl.run()

            self.o_hdr.handle_update()

            txn = self.txns.get_nowait()
            if txn is not None:
                try:
                    txn.results.put(txn.do_commit())
                except Exception as ex:
                    er = ExceptionResult(ex=ex, tb=traceback.format_exc())
                    txn.results.put(er)
                self.txns.task_done()
            first_time = False
        logger.log.info('run_ops_to_gogbp thread is end')

    def queue_txn(self, txn):
        self.txns.put(txn)


class GobgpConnection():
    def __init__(self, gobgp_url, gobgp_port):
        self.url = gobgp_url
        self.port = gobgp_port

    def get_handler(self):
        return self.g_hdr

    def connect(self):
        self.g_hdr = handle.GobgpHandler(self.url, self.port)

        self.th = threading.Thread(target=self.run_gobgp_to_ops)
        self.th.setDaemon(True)

    def start(self):
        logger.log.info('run run_gogbp_to_ops thread...')
        self.th.start()
        return self.th

    def run_gobgp_to_ops(self):
        while True:
            logger.log.info('Wait for a change the bestpath from gobgp...')
            monitor_argument = {'rf': RF_IPv4_UC}
            self.g_hdr.monitor_bestpath_chenged(monitor_argument)
            time.sleep(3)
        logger.log.info('run_ops_to_gogbp thread is end')


class Connection():
    def __init__(self, ovsdb, gobgp_url, gobgp_port):
        signal.signal(signal.SIGINT, utils.receive_signal)

        # connection with each
        self.ops = OpsConnection(ovsdb)
        self.ops.connect()
        self.gobgp = GobgpConnection(gobgp_url, gobgp_port)
        self.gobgp.connect()

        # get handler
        o_hdr = self.ops.get_handler()
        g_hdr = self.gobgp.get_handler()

        # set each other's handler
        self.ops.o_hdr.set_handler(g_hdr)
        self.gobgp.g_hdr.set_handler(o_hdr)

    def run(self):
        # run thread
        threads = []
        threads.append(self.ops.start())
        threads.append(self.gobgp.start())


        for th in threads:
            while th.isAlive():
                time.sleep(1)
            th.join()
