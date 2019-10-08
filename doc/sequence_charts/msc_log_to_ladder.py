#!/usr/bin/env python3
doc=r'''
Reading a log, it can be hard to figure out what is the important bit going on.
This is a tool that reads an osmo-msc log and tries to compose a ladder diagram from it automatically.
'''

import argparse
import sys
import re
import tempfile
import os

def error(*msg):
	sys.stderr.write('%s\n' % (''.join(msg)))
	exit(1)

def quote(msg, quote='"'):
	return '"%s"' % (msg.replace('"', r'\"'))

class Entity:
	def __init__(self, name, descr=None, attrs={}):
		self.name = name
		self.descr = descr
		self.attrs = attrs
	
class Arrow:
	def __init__(self, mo_mt, left, arrow, right, descr=None, attrs={}, ran_conn=None, imsi=None, tmsi=None):
		self.mo_mt = mo_mt
		self.left = left
		self.arrow = arrow
		self.right = right
		self.descr = descr
		self.attrs = attrs
		self.ran_conn = ran_conn
		self.imsi = imsi
		self.tmsi = tmsi

	def __repr__(self):
		return 'Arrow(%s %s %s %s: %s IMSI=%s)' % (self.mo_mt, self.left, self.arrow, self.right, self.descr, self.imsi)

class Separator:
	def __init__(self):
		self.separator = None
		self.descr = None
		self.attrs = {}

class EmptyLine:
	def __init__(self):
		self.count = 1

MS = 'ms'
UE = 'ms' #'ue'
MS_UE_UNKNOWN = 'ms' #None
MSC = 'msc'
MGW = 'mgw'
SIP = 'sip'

MO = 'mo'
MT = 'mt'
MO_MT_UNKNOWN = None


class OutputLadder:

	def __init__(self, write_to):
		self._write_to = write_to

	def render(self, diagram):
		if diagram.root_attrs:
			self.root_attrs(diagram.root_attrs)
		for entity in diagram.entities:
			self.entity(entity)

		for line in diagram.lines:
			self.add(line)

	def write(self, line):
		self._write_to.write(line)

	def writeln(self, line):
		self.write('%s\n' % line)

	def attrs_str(self, attrs, prefix=' '):
		if not attrs:
			return ''
		return '%s{%s}' % (prefix or '', ','.join('%s=%s' % (k,v) for k,v in attrs.items()))

	def root_attrs(self, attrs):
		self.writeln(self.attrs_str(attrs, prefix=None))

	def entity(self, entity):
		self.writeln('%s = %s%s' % (entity.name, entity.descr, self.attrs_str(entity.attrs)))

	def arrow(self, arrow):
		mo_mt = arrow.mo_mt or MO

		def prepend_mo_mt(name):
			if name in ('.', SIP):
				return name
			return '%s%s' % (mo_mt, name)

		self.writeln('%s %s %s%s%s%s'
			     % (prepend_mo_mt(arrow.left),
			        arrow.arrow,
				prepend_mo_mt(arrow.right),
				' ' if arrow.descr else '',
				arrow.descr or '',
				self.attrs_str(arrow.attrs)))

	def separator(self, sep_str, descr, attrs):
		self.writeln('%s%s%s%s'
			     % (separator.separator,
				' ' if separator.descr else '',
				separator.descr or '',
				self.attrs_str(separator.attrs)))

	def emptyline(self, emptyline):
		self.write('\n' * emptyline.count);

	def add(self, thing):
		func = getattr(self, thing.__class__.__name__.lower())
		func(thing)

def ms_from_ran(ran_type_or_conn):
	if ran_type_or_conn.startswith('UTRAN-Iu'):
		return UE
	if ran_type_or_conn.startswith('RANAP'):
		return UE
	if ran_type_or_conn.startswith('GERAN-A'):
		return MS
	if ran_type_or_conn.startswith('BSS'):
		return MS
	return MS_UE_UNKNOWN

class Diagram:
	def __init__(self):
		self.root_attrs = {}
		self.entities = []
		self.lines = []
		self.mo_mt_unknown_lines = []

	def add_line(self, line):
		self.lines.append(line)

	def resolve_unknown_mo_mt(self):

		def try_match(a, b):
			if a < 0 or a >= len(self.lines):
				return False
			if b < 0 or b >= len(self.lines):
				return False
			la = self.lines[a]
			lb = self.lines[b]

			if not hasattr(lb, 'mo_mt'):
				return False
			if lb.mo_mt == MO_MT_UNKNOWN:
				return False

			for match_attr in ('imsi', 'tmsi', 'ran_conn'):
				if not hasattr(la, match_attr):
					continue
				if not hasattr(lb, match_attr):
					continue
				la_attr = getattr(la, match_attr)
				if la_attr is None:
					continue
				lb_attr = getattr(lb, match_attr)
				if la_attr == lb_attr:
					la.mo_mt = lb.mo_mt
					return True
			return False


		while True:
			changes = 0
			for i in range(len(self.lines)):
				line = self.lines[i]

				if not hasattr(line, 'mo_mt'):
					continue
				if line.mo_mt is not MO_MT_UNKNOWN:
					continue

				# don't know MO/MT, try to resolve from near messages
				for j in range(1,100):
					if try_match(i, i-j):
						break
					if try_match(i, i+j):
						break
				if line.mo_mt is not MO_MT_UNKNOWN:
					changes += 1
			if not changes:
				break


re_source_file_last = re.compile(r'(.*) \(([^):]+:[0-9]+)\)$')

class Rule:
	def __init__(self, name, re_str, handler):
		self.name = name
		self.re = re.compile(re_str)
		self.handler = handler

	def match(self, line):
		m = self.re.match(line)
		if not m:
			return False
		return self.handler(m)
	

def mo_mt_from_l3type(l3type):
	if l3type == 'PAGING_RESP':
		return MT
	elif l3type == 'CM_SERVICE_REQ':
		return MO
	else:
		return MO_MT_UNKNOWN

def int_to_hex(val, bits):
	return hex((int(val) + (1 << bits)) % (1 << bits))

class Callref:
	MAX = 0x7fffffff
	MIN = -0x80000000
	BITS = 32

	def int_to_hex(val):
		return int_to_hex(val, Callref.BITS)

	def hex_to_int(hexstr):
		val = int(hexstr, 16)
		if val > Callref.MAX:
			val = Callref.MIN + (val & Callref.MAX)
		return val
		
class Parse:
	
	def __init__(self, output):

		self.diagram = Diagram()
		self.output = output
		self.linenr = 0
		self.rules = []

		self.callrefs_mo_mt = {}

		for member in dir(self):
			if not member.startswith('rule_'):
				continue
			func = getattr(self, member)
			if not callable(func):
				continue
				
			docstr = func.__doc__
			if not docstr:
				continue
			re_str = docstr.splitlines()[0]

			self.rules.append(Rule(name=member, re_str=re_str, handler=func))



	def error(self, *msg):
		error('line %d: ' % self.linenr, *msg)

	def start(self):
		self.diagram.root_attrs = {'hscale': '3'}
		for name, descr in (
				('moms', 'MS,BSS (MO)\\nUE,hNodeB (MO)'),
				#('moue', 'UE,hNodeB (MO)'),
				('momgw', 'MGW for MSC (MO)'),
				('momsc', 'MSC (MO)'),
				('sip', 'MNCC to PBX via\n\tosmo-sip-connector'),
				('mtmsc', 'MSC (MT)'),
				('mtmgw', 'MGW for MSC (MT)'),
				('mtms', 'BSS,MS (MT)\\nhNodeB,UE (MT)'),
				#('mtue', 'hNodeB,UE (MT)'),
				):
			self.diagram.entities.append(Entity(name, descr))

	def end(self):
		self.diagram.resolve_unknown_mo_mt()
		self.output.render(self.diagram)

	def add_line(self, line):
		self.linenr += 1
		if line.endswith('\n'):
			line = line[:-1]
		if line.endswith('\r'):
			line = line[:-1]

		self.interpret(line)

	def interpret(self, line):

		m = re_source_file_last.match(line)
		if m:
			line = m.group(1)

		for rule in self.rules:
			if rule.match(line):
				break

	RE_DTAP_NAME = re.compile('.*GSM48_MT_([^_]+)_(.+)')

	def rule_paging(self, m):
		r'.*ran_peer\(([^:]+):.* Paging for ([^ ]+) on ([^ ]+)'
		ran_type, subscr, cell = m.groups()

		self.diagram.add_line(Arrow(MT, ms_from_ran(ran_type), '<', MSC, 'Paging'))
		return True

	RE_IMSI = re.compile('IMSI-([0-9]+)')
	RE_TMSI = re.compile('TMSI-0x([0-9a-fA-F]+)')

	def rule_dtap(self, m):
		r'.*msc_a\(([^)]*):([^:]+):([^:]+)\).* (Dispatching 04.08 message|Sending DTAP): (.+)$'

		subscr, ran_conn, l3type, rx_tx, dtap = m.groups()
		tx = (rx_tx == 'Sending DTAP')

		m = self.RE_DTAP_NAME.match(dtap)
		if m:
			dtap = '%s %s' % m.groups()

		if 'IMSI_DETACH_IND' in dtap:
			# detecting IMSI Detach separately
			return True

		if l3type == 'NONE' and not tx and dtap.endswith('PAG_RESP'):
			e = MT
		else:
			e = mo_mt_from_l3type(l3type)

		imsi = None
		for m in Parse.RE_IMSI.finditer(subscr):
			imsi = m.group(1)
		tmsi = None
		for m in Parse.RE_TMSI.finditer(subscr):
			tmsi = m.group(1)

		self.diagram.add_line(Arrow(e, ms_from_ran(ran_conn), '<' if tx else '>', MSC, dtap,
			ran_conn=ran_conn, imsi=imsi, tmsi=tmsi))
		return True

	def rule_imsi_detach(self, m):
		r'.*IMSI DETACH for IMSI-([0-9]+):.*'
		imsi = m.group(1)
		e = MO_MT_UNKNOWN
		self.diagram.add_line(Arrow(e, MS_UE_UNKNOWN, '>', MSC, 'IMSI Detach', imsi=imsi))

	def rule_mgcp_tx(self, m):
		r'.*mgw-endp\([^)]*:([^:]+):([^:]+)\).* (rtpbridge[^ ]+) .* RTP_TO_(RAN|CN)( CI=([^:]+)|): ([^ :]+).*: Sending'
		ran, l3type, endp, rtp_to, cond_ci, ci, verb = m.groups()
		e = mo_mt_from_l3type(l3type)
		ci_str = ''
		if ci:
			ci_str = ' %s' % ci
		self.diagram.add_line(Arrow(e, MGW, '<', MSC, 'for %s: %s\\n%s%s' % (rtp_to, verb, endp, ci_str)))
		return True

	def rule_mgcp_rx(self, m):
		r'.*mgw-endp\([^)]*:([^:]+):([^:]+)\).* (rtpbridge[^ ]+) .* RTP_TO_(RAN|CN)( CI=([^:]+)|).*: received successful response to ([^:]+): (.*)'
		ran, l3type, endp, rtp_to, cond_ci, ci, verb, details = m.groups()
		e = mo_mt_from_l3type(l3type)
		ci_str = ''
		if ci:
			ci_str = ' %s' % ci
		self.diagram.add_line(Arrow(e, MGW, '>', MSC, 'for %s: %s OK\\n%s%s' % (rtp_to, verb, endp, ci_str)))
		return True

	def rule_ran_tx(self, m):
		r'.*msc_a\(([^)]*):([^:]+):([^:]+)\).* RAN encode: ([^: ]+): (.+)$'

		subscr, ran_conn, l3type, ran_type, msg_type = m.groups()

		if msg_type in ('DTAP', 'DirectTransfer'):
			# will get DTAP details from rule_dtap() instead, not from BSSMAP logging
			return True
		if msg_type.startswith('Tx'):
			# skip 'Tx RANAP SECURITY MODE COMMAND to RNC, ik 47...'
			return True
		if '=' in msg_type:
			# skip 'RAB Assignment: rab_id=1, rtp=192.168.178.66:50008, use_x213_nsap=1'
			return True

		if l3type == 'NONE':
			return True

		e = mo_mt_from_l3type(l3type)

		imsi = None
		for m in Parse.RE_IMSI.finditer(subscr):
			imsi = m.group(1)
		tmsi = None
		for m in Parse.RE_TMSI.finditer(subscr):
			tmsi = m.group(1)

		self.diagram.add_line(Arrow(e, ms_from_ran(ran_conn), '<', MSC, '(%s) %s' % (ran_type, msg_type),
				            ran_conn=ran_conn, imsi=imsi, tmsi=tmsi))
		return True

	def rule_ran_rx(self, m):
		r'.*msc_a\(([^)]*):([^:]+):([^:]+)\).* RAN decode: ([^: ]+) (.+)$'

		subscr, ran_conn, l3type, ran_type, msg_type = m.groups()

		if msg_type in ('DTAP', 'DirectTransfer', 'DirectTransfer RAN PDU'):
			# will get DTAP details from rule_dtap() instead, not from BSSMAP logging
			return True

		if l3type == 'NONE':
			return True

		e = mo_mt_from_l3type(l3type)

		imsi = None
		for m in Parse.RE_IMSI.finditer(subscr):
			imsi = m.group(1)
		tmsi = None
		for m in Parse.RE_TMSI.finditer(subscr):
			tmsi = m.group(1)

		self.diagram.add_line(Arrow(e, ms_from_ran(ran_type), '>', MSC, '(%s) %s' % (ran_type, msg_type),
					    ran_conn=ran_conn, imsi=imsi, tmsi=tmsi))
		return True

	def rule_cc_state(self, m):
		r'.*trans\(CC[^) ]* [^ )]+:([^:)]+) callref-([^ ]+) [^)]+\) new state ([^ ]+) -> ([^ ]+)'
		l3type, callref_hex, from_state, to_state = m.groups()

		e = mo_mt_from_l3type(l3type)
		self.callrefs_mo_mt[callref_hex] = e

		self.diagram.add_line(Arrow(e, MSC, '<>', '.', 'CC state:\\n%s' % to_state))
		return True

	RE_MNCC_RTP = re.compile(' ip := ([^, ]+), rtp_port := ([0-9]+),')

	def rule_udtrace_mncc(self, m):
		r'.*(write|recv).* (Tx|Rx): \{ msg_type := ([^ ]+) .* u := \{ (.* callref := ([^ ,]+), .*) \} \}$'
		write_recv, tx_rx, msg_type, u, callref_intstr = m.groups()

		tx = (tx_rx == 'Tx')
		
		try:
			e = self.callrefs_mo_mt.get(Callref.int_to_hex(callref_intstr), MT)
		except:
			e = MT

		descr = msg_type

		for m in Parse.RE_MNCC_RTP.finditer(u):
			ip_str, port_str = m.groups()
			try:
				if int(ip_str) == 0 or int(port_str) == 0:
					break
			except:
				break
			ip_hex = int_to_hex(ip_str, 32)
			ip = []
			ip_val = int(ip_hex, 16)
			for byte in range(4):
				ip.insert(0, (ip_val & (0xff << (8*byte))) >> (8*byte))
			rtp_info = '%s:%s' % ('.'.join(str(b) for b in ip), port_str)
			descr = '%s\\n%s' % (descr, rtp_info)
			break

		self.diagram.add_line(Arrow(e, MSC, '>' if tx else '<', 'sip', descr))
		return True

	def rule_cc_timer(self, m):
		r'.*trans\(CC.*IMSI-([0-9]+):.*\) (starting|stopping pending) (guard timer|timer T[0-9]+)( with ([0-9]+) seconds|)'
		imsi, start_stop, t, with_cond, s = m.groups()
		start = (start_stop == 'starting')
		e = MO_MT_UNKNOWN
		if start:
			self.diagram.add_line(Arrow(e, MSC, '[]', '.', 'CC starts %s (%ss)' % (t, s), imsi=imsi))
		else:
			self.diagram.add_line(Arrow(e, MSC, '[]', '.', 'CC stops %s' % (t), imsi=imsi))
		return True


def translate(inf, outf, cmdline):
	output = OutputLadder(outf)
	parse = Parse(output)

	parse.start()

	while inf.readable():
		line = inf.readline()
		if not line:
			break;
		parse.add_line(line)
	parse.end()

def open_output(inf, cmdline):
	if cmdline.output_file == '-':
		translate(inf, sys.stdout, cmdline)
	else:
		with tempfile.NamedTemporaryFile(dir=os.path.dirname(cmdline.output_file), mode='w', encoding='utf-8') as tmp_out:
			translate(inf, tmp_out, cmdline)
			if os.path.exists(cmdline.output_file):
				os.unlink(cmdline.output_file)
			os.link(tmp_out.name, cmdline.output_file)
	
def open_input(cmdline):
	if cmdline.input_file == '-':
		open_output(sys.stdin, cmdline)
	else:
		with open(cmdline.input_file, 'r') as f:
			open_output(f, cmdline)

def main(cmdline):
	open_input(cmdline)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=doc)
	parser.add_argument('-i', '--input-file', dest='input_file', default="-",
			help='Read from this file, or stdin if "-"')
	parser.add_argument('-o', '--output-file', dest='output_file', default="-",
			help='Write to this file, or stdout if "-"')

	cmdline = parser.parse_args()

	main(cmdline)

# vim: shiftwidth=8 noexpandtab tabstop=8 autoindent nocindent
