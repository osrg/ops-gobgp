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

from optparse import OptionParser

from lib import logger
from connection import Connection


def main():
    usage = 'usage: python ./openswitch.py [options]... '
    parser = OptionParser(usage=usage)
    parser.add_option('-u', '--gobpg-url', dest='gobgp_url', default='127.0.0.1',
                      help='specifying an url')
    parser.add_option('-p', '--gobgp-port', dest='gobgp_port', default=8080,
                      help='specifying a port')
    parser.add_option('-o', '--ovsdb-sock', dest='ovsdb', default='unix:/var/run/openvswitch/db.sock',
                      help='specifying the connection destination of the ovsdb    '
                           'Example                                               '
                           ' - unix:<socket file path>                            '
                           ' - tcp:<address>:<port>')
    parser.add_option('-l', '--log-level', dest='log_level', default='info',
                      help='specifying a log level')
    parser.add_option('-f', '--log-file', dest='log_file', default='./openswitch.log',
                      help='specifying the output destination of the log file')

    (options, args) = parser.parse_args()

    log = logger.logger(options.log_level, options.log_file)
    logger.log = log
    log.info('Run openswitch client')

    conn = Connection(options.ovsdb, options.gobgp_url, options.gobgp_port)
    conn.run()


if __name__ == '__main__':
    main()
