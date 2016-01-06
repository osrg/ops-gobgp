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


import sys
import logging


def init_log(log_level, log_file):
    LEVELS = {'NOTSET': logging.NOTSET,
              'DEBUG': logging.DEBUG,
              'INFO': logging.INFO,
              'WARNING': logging.WARNING,
              'WARN': logging.WARNING,
              'ERROR': logging.ERROR,
              'FATAL': logging.FATAL,
              'CRITICAL': logging.CRITICAL}

    level = log_level.upper()
    log = logging.getLogger()
    if level in LEVELS:
        log.setLevel(LEVELS[level])
    else:
        print('> Not support entered log level')
        print('> enter the NOTSET, DEBUG, INFO, WARN, ERROR, FATAL, CRITICAL')
        sys.exit(1)

    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    if log_file is None:
        h = logging.StreamHandler()
    else:
        h = logging.FileHandler(log_file, 'a+', 'utf-8')
    h.setFormatter(formatter)
    log.addHandler(h)
