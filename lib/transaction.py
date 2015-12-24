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


import os
from six.moves import queue as Queue

from lib import utils
from lib import logger


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


class Transaction():
    def __init__(self, commit_f, check_error=False, log_errors=False):
        self.timeout = 5
        self.check_error = check_error
        self.log_errors = log_errors
        self.commands = []
        self.results = Queue.Queue(1)
        self.commit_f = commit_f

    def commit(self, conn):
        conn.queue_txn(self)
        result = self.results.get()
        if self.check_error:
            if isinstance(result, utils.ExceptionResult):
                if self.log_errors:
                    logger.log.error(result.tb)
                raise result.ex
        return result

    def do_commit(self):
        self.commit_f()
