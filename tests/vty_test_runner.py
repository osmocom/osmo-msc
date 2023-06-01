#!/usr/bin/env python3

# (C) 2013 by Katerina Barone-Adesi <kat.obsc@gmail.com>
# (C) 2013 by Holger Hans Peter Freyther
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

import os, sys
import time
import unittest
import socket
import subprocess

import osmopy.obscvty as obscvty
import osmopy.osmoutil as osmoutil
from osmopy.osmo_ipa import IPA

# to be able to find $top_srcdir/doc/...
confpath = os.path.join(sys.path[0], '..')

class TestVTYBase(unittest.TestCase):

    def checkForEndAndExit(self):
        res = self.vty.command("list")
        #print ('looking for "exit"\n')
        self.assertTrue(res.find('  exit\r') > 0)
        #print 'found "exit"\nlooking for "end"\n'
        self.assertTrue(res.find('  end\r') > 0)
        #print 'found "end"\n'

    def vty_command(self):
        raise Exception("Needs to be implemented by a subclass")

    def vty_app(self):
        raise Exception("Needs to be implemented by a subclass")

    def setUp(self):
        osmo_vty_cmd = self.vty_command()[:]
        config_index = osmo_vty_cmd.index('-c')
        if config_index:
            cfi = config_index + 1
            osmo_vty_cmd[cfi] = os.path.join(confpath, osmo_vty_cmd[cfi])

        try:
            self.proc = osmoutil.popen_devnull(osmo_vty_cmd)
        except OSError:
            print("Current directory: %s" % os.getcwd(), file=sys.stderr)
            print("Consider setting -b", file=sys.stderr)

        appstring = self.vty_app()[2]
        appport = self.vty_app()[0]
        self.vty = obscvty.VTYInteract(appstring, "127.0.0.1", appport)

    def tearDown(self):
        if self.vty:
            self.vty._close_socket()
        self.vty = None
        rc = osmoutil.end_proc(self.proc)
        if rc is not None and rc != 0:
            raise Exception("Process returned %d" % rc)

class TestVTYMSC(TestVTYBase):

    def vty_command(self):
        return ["./src/osmo-msc/osmo-msc", "-c",
                "doc/examples/osmo-msc/osmo-msc.cfg"]

    def vty_app(self):
        return (4254, "./src/osmo-msc/osmo-msc", "OsmoMSC", "msc")

    def testConfigNetworkTree(self, include_bsc_items=True):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal",['']))
        self.assertEqual(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify("network",['']))
        self.assertEqual(self.vty.node(), 'config-net')
        self.checkForEndAndExit()
        self.vty.command("write terminal")
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertEqual(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit",['']))
        self.assertTrue(self.vty.node() is None)

    def checkForSmpp(self):
        """SMPP is not always enabled, check if it is"""
        res = self.vty.command("list")
        return "smpp" in res

    def testSmppFirst(self):
        # enable the configuration
        self.vty.enable()
        self.vty.command("configure terminal")

        if not self.checkForSmpp():
            return

        self.vty.command("smpp")

        # check the default
        res = self.vty.command("write terminal")
        self.assertTrue(res.find(' no smpp-first') > 0)

        self.vty.verify("smpp-first", [''])
        res = self.vty.command("write terminal")
        self.assertTrue(res.find(' smpp-first') > 0)
        self.assertEqual(res.find('no smpp-first'), -1)

        self.vty.verify("no smpp-first", [''])
        res = self.vty.command("write terminal")
        self.assertTrue(res.find('no smpp-first') > 0)

    def testVtyTree(self):
        self.vty.enable()
        self.assertTrue(self.vty.verify("configure terminal", ['']))
        self.assertEqual(self.vty.node(), 'config')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('mncc-int', ['']))
        self.assertEqual(self.vty.node(), 'config-mncc-int')
        self.checkForEndAndExit()
        self.assertTrue(self.vty.verify('exit', ['']))

        if self.checkForSmpp():
            self.assertEqual(self.vty.node(), 'config')
            self.assertTrue(self.vty.verify('smpp', ['']))
            self.assertEqual(self.vty.node(), 'config-smpp')
            self.checkForEndAndExit()
            self.assertTrue(self.vty.verify("exit", ['']))

        self.assertEqual(self.vty.node(), 'config')
        self.assertTrue(self.vty.verify("exit", ['']))
        self.assertTrue(self.vty.node() is None)

        # Check searching for outer node's commands
        self.vty.command("configure terminal")
        self.vty.command('mncc-int')

        if self.checkForSmpp():
            self.vty.command('smpp')
            self.assertEqual(self.vty.node(), 'config-smpp')
            self.vty.command('mncc-int')

        self.assertEqual(self.vty.node(), 'config-mncc-int')

    def testSi2Q(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")
        before = self.vty.command("show running-config")
        self.vty.command("si2quater neighbor-list add earfcn 1911 threshold 11 2")
        self.vty.command("si2quater neighbor-list add earfcn 1924 threshold 11 3")
        self.vty.command("si2quater neighbor-list add earfcn 2111 threshold 11")
        self.vty.command("si2quater neighbor-list del earfcn 1911")
        self.vty.command("si2quater neighbor-list del earfcn 1924")
        self.vty.command("si2quater neighbor-list del earfcn 2111")
        self.assertEqual(before, self.vty.command("show running-config"))
        self.vty.command("si2quater neighbor-list add uarfcn 1976 13 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 38 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 44 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 120 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 140 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 163 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 166 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 217 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 224 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 225 1")
        self.vty.command("si2quater neighbor-list add uarfcn 1976 226 1")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 13")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 38")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 44")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 120")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 140")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 163")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 166")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 217")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 224")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 225")
        self.vty.command("si2quater neighbor-list del uarfcn 1976 226")
        self.assertEqual(before, self.vty.command("show running-config"))

    def testEnableDisablePeriodicLU(self):
        self.vty.enable()
        self.vty.command("configure terminal")
        self.vty.command("network")
        self.vty.command("bts 0")

        # Test invalid input
        self.vty.verify("periodic location update 0", ['% Unknown command.'])
        self.vty.verify("periodic location update 5", ['% Unknown command.'])
        self.vty.verify("periodic location update 1531", ['% Unknown command.'])

        depr_str = "% 'periodic location update' is now deprecated: " \
                   "use 'timer T3212' to change subscriber expiration timeout."
        set_str  = "% Setting T3212 to 121 minutes (emulating the old behaviour)."

        # Enable periodic LU (deprecated command)
        self.vty.verify("periodic location update 60", [depr_str, set_str])
        res = self.vty.command("write terminal")
        self.assertTrue(res.find('timer vlr T3212 121') > 0)
        self.assertEqual(res.find('periodic location update 60'), -1)
        self.assertEqual(res.find('no periodic location update'), -1)

        # Now disable it (deprecated command)
        self.vty.verify("no periodic location update", [depr_str])
        res = self.vty.command("write terminal")
        self.assertEqual(res.find('no periodic location update'), -1)
        self.assertEqual(res.find('timer vlr T3212 121'), -1)

    def testShowNetwork(self):
        res = self.vty.command("show network")
        self.assertTrue(res.startswith('BSC is on Country Code') >= 0)

def ipa_handle_small(x, verbose = False):
    s = data2str(x.recv(4))
    if len(s) != 4*2:
      raise Exception("expected to receive 4 bytes, but got %d (%r)" % (len(s)/2, s))
    if "0001fe00" == s:
        if (verbose):
            print("\tBSC <- NAT: PING?")
        x.send(IPA().pong())
    elif "0001fe06" == s:
        if (verbose):
            print("\tBSC <- NAT: IPA ID ACK")
        x.send(IPA().id_ack())
    elif "0001fe00" == s:
        if (verbose):
            print("\tBSC <- NAT: PONG!")
    else:
        if (verbose):
            print("\tBSC <- NAT: ", s)

def ipa_handle_resp(x, tk, verbose = False, proc=None):
    s = data2str(x.recv(38))
    if "0023fe040108010701020103010401050101010011" in s:
        retries = 3
        while True:
            print("\tsending IPA identity(%s) at %s" % (tk, time.strftime("%T")))
            try:
                x.send(IPA().id_resp(IPA().identity(name = tk.encode('utf-8'))))
                print("\tdone sending IPA identity(%s) at %s" % (tk,
                                                            time.strftime("%T")))
                break
            except:
                print("\tfailed sending IPA identity at", time.strftime("%T"))
                if proc:
                  print("\tproc.poll() = %r" % proc.poll())
                if retries < 1:
                    print("\tgiving up")
                    raise
                print("\tretrying (%d attempts left)" % retries)
                retries -= 1
    else:
        if (verbose):
            print("\tBSC <- NAT: ", s)

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
    parser.add_argument("test_name", nargs="*", help="(parts of) test names to run, case-insensitive")
    args = parser.parse_args()

    verbose_level = 1
    if args.verbose:
        verbose_level = 2

    if args.w:
        workdir = args.w

    if args.p:
        confpath = args.p

    print("confpath %s, workdir %s" % (confpath, workdir))
    os.chdir(workdir)
    print("Running tests for specific VTY commands")
    suite = unittest.TestSuite()
    suite.addTest(unittest.TestLoader().loadTestsFromTestCase(TestVTYMSC))

    if args.test_name:
        osmoutil.pick_tests(suite, *args.test_name)

    res = unittest.TextTestRunner(verbosity=verbose_level, stream=sys.stdout).run(suite)
    sys.exit(len(res.errors) + len(res.failures))

# vim: shiftwidth=4 expandtab nocin ai
