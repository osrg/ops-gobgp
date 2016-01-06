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
from optparse import OptionParser

from lib import log
from lib import utils
from connection import OpsConnection
from connection import GobgpConnection


def main():
    usage = 'usage: python ./openswitch.py [options]... '
    parser = OptionParser(usage=usage)
    parser.add_option('-u', '--gobpg-url', dest='gobgp_url', default='127.0.0.1',
                      help='specifying an url')
    parser.add_option('-p', '--gobgp-port', dest='gobgp_port', default=50051,
                      help='specifying a port')
    parser.add_option('-o', '--ovsdb-sock', dest='ovsdb', default='unix:/var/run/openvswitch/db.sock',
                      help='specifying the connection destination of the ovsdb    '
                           'Example                                               '
                           ' - unix:<socket file path>                            '
                           ' - tcp:<address>:<port>')
    parser.add_option('-l', '--log-level', dest='log_level', default='info',
                      help='specifying a log level')
    parser.add_option('-f', '--log-file', dest='log_file', default=None,
                      help='specifying the output destination of the log file')

    (options, args) = parser.parse_args()

    log.init_log(options.log_level, options.log_file)
    signal.signal(signal.SIGINT, utils.receive_signal)

    # connection with each
    ops = OpsConnection(options.ovsdb)
    ops.connect()
    gobgp = GobgpConnection(options.gobgp_url, int(options.gobgp_port))
    gobgp.connect()

    # get handler
    ops_hdr = ops.get_handler()
    gobgp_hdr = gobgp.get_handler()

    # set each other's handler
    ops.hdr.set_handler(gobgp_hdr)
    gobgp.hdr.set_handler(ops_hdr)

    # run thread
    threads = []
    threads.append(ops.start())
    threads.append(gobgp.start())

    for th in threads:
        while th.isAlive():
            time.sleep(1)
        th.join()


if __name__ == '__main__':
    main()
