#!/usr/bin/env python3

# (C) 2013 by Jacob Erlbeck <jerlbeck@sysmocom.de>
# (C) 2014 by Holger Hans Peter Freyther
# based on vty_test_runner.py:
# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
# based on bsc_control.py.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import time
import unittest
import socket
import sys
import struct

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import Ctrl, IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')
verbose = False

class TestCtrlBase(unittest.TestCase):

    def ctrl_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def ctrl_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_ctrl_cmd = self.ctrl_command()[:]
        config_index = osmo_ctrl_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_ctrl_cmd[cfi] = os.path.join(confpath, osmo_ctrl_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_ctrl_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)
        time.sleep(2)

        appstring = self.ctrl_app()[2]
        appport = self.ctrl_app()[0]
        self.connect("127.0.0.1", appport)
        self.next_id = 1000

    def tearDown(self):
        self.disconnect()
        rc = osmoutil.end_proc(self.proc)
        if rc is not None and rc != 0:
            raise Exception("Process returned %d" % rc)

    def disconnect(self):
        if not (self.sock is None):
            self.sock.close()

    def connect(self, host, port):
        if verbose:
            print("Connecting to host %s:%i" % (host, port))

        retries = 30
        while True:
            try:
                sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sck.setblocking(1)
                sck.connect((host, port))
            except IOError:
                retries -= 1
                if retries <= 0:
                    raise
                time.sleep(.1)
                continue
            break
        self.sock = sck
        return sck

    def send(self, data):
        if verbose:
            print("Sending \"%s\"" %(data))
        data = Ctrl().add_header(data)
        return self.sock.send(data) == len(data)

    def send_set(self, var, value, id):
        setmsg = "SET %s %s %s" %(id, var, value)
        return self.send(setmsg)

    def send_get(self, var, id):
        getmsg = "GET %s %s" %(id, var)
        return self.send(getmsg)

    def do_set(self, var, value):
        id = self.next_id
        self.next_id += 1
        self.send_set(var, value, id)
        return self.recv_msgs()[id]

    def do_get(self, var):
        id = self.next_id
        self.next_id += 1
        self.send_get(var, id)
        return self.recv_msgs()[id]

    def recv_msgs(self):
        responses = {}
        data = self.sock.recv(4096)
        while (len(data)>0):
            (head, data) = IPA().split_combined(data)
            answer = Ctrl().rem_header(head)
            if verbose:
                print("Got message:", answer)
            (mtype, id, msg) = answer.split(None, 2)
            id = int(id)
            rsp = {'mtype': mtype, 'id': id}
            if mtype == "ERROR":
                rsp['error'] = msg
            else:
                split = msg.split(None, 1)
                rsp['var'] = split[0]
                if len(split) > 1:
                    rsp['value'] = split[1]
                else:
                    rsp['value'] = None
            responses[id] = rsp

        if verbose:
            print("Decoded replies: ", responses)

        return responses


class TestCtrlMSC(TestCtrlBase):
    def ctrl_command(self):
        return ["./src/osmo-msc/osmo-msc", "-c",
                "doc/examples/osmo-msc/osmo-msc.cfg"]

    def ctrl_app(self):
        return (4255, "./src/osmo-msc/osmo-msc", "OsmoMSC", "msc")

    def testRateCounters(self):
        r = self.do_get('rate_ctr.*')

    # FIXME: add MSC-specific CTRL test in here

if __name__ == '__main__':
    import argparse
    import sys

    workdir = '.'

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", dest="verbose",
                        action="store_true", help="verbose mode")
    parser.add_argument("-p", "--pythonconfpath", dest="p",
                        help="searchpath for config")
    parser.add_argument("-w", "--workdir", dest="w",
                        help="Working directory")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2
        verbose = True

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific control commands")
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestCtrlMSC))
    res = unittest.TextTestRunner(verbosity=verbose_level).run(suite)
    sys.exit(len(res.errors) + len(res.failures))
