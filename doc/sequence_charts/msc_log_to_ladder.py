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
MNCC = 'mncc'

MO = 'mo'
MT = 'mt'
MO_MT_UNKNOWN = None


class OutputBase:
	def __init__(self, write_to, start_with_re=None):
		self._write_to = write_to

		self.start_with_re = None
		if start_with_re is not None:
			self.start_with_re = re.compile(start_with_re)

	def head(self):
		self.writeln('# Generated by osmo-msc.git/doc/sequence_charts/msc_log_to_ladder.py')

	def tail(self):
		pass

	def render(self, diagram):
		self.head()
		if diagram.root_attrs:
			self.root_attrs(diagram.root_attrs)
		self.entities(diagram.entities)

		started = (self.start_with_re is None)

		for line in diagram.lines:
			if not started:
				if hasattr(line, 'descr') and self.start_with_re.match(line.descr):
					started = True
				else:
					continue
			self.add(line)
		self.tail()

	def entities(self, entities):
		for entity in entities:
			self.entity(entity)

	def write(self, line):
		self._write_to.write(line)

	def writeln(self, line):
		self.write('%s\n' % line)

	def emptyline(self, emptyline):
		self.write('\n' * emptyline.count);

	def add(self, thing):
		func = getattr(self, thing.__class__.__name__.lower())
		func(thing)


class OutputLadder(OutputBase):

	def indent_multiline(self, s):
		return s.replace('\n', '\n\t')

	def attrs_str(self, attrs, prefix=' '):
		if not attrs:
			return ''
		return '%s{%s}' % (prefix or '', ','.join('%s=%s' % (k,v) for k,v in attrs.items()))

	def root_attrs(self, attrs):
		self.writeln(self.attrs_str(attrs, prefix=None))

	def entity(self, entity):
		self.writeln('%s = %s%s' % (entity.name, self.indent_multiline(entity.descr), self.attrs_str(entity.attrs)))

	def arrow(self, arrow):
		mo_mt = arrow.mo_mt or MO

		def prepend_mo_mt(name):
			if name in ('.', MNCC):
				return name
			return '%s%s' % (mo_mt, name)

		self.writeln('%s %s %s%s%s%s'
			     % (prepend_mo_mt(arrow.left),
				arrow.arrow,
				prepend_mo_mt(arrow.right),
				'\t' if arrow.descr else '',
				self.indent_multiline(arrow.descr or ''),
				self.attrs_str(arrow.attrs)))

	def separator(self, sep_str, descr, attrs):
		self.writeln('%s%s%s%s'
			     % (separator.separator,
				' ' if separator.descr else '',
				self.indent_multiline(separator.descr or ''),
				self.attrs_str(separator.attrs)))

class OutputMscgen(OutputBase):
	ARROWS = {
		'>' : '=>>',
		'->' : '=>',
		'-->' : '>>',
		'~>' : '->',
		'=>' : ':>',
		'-><' : '-x',

		'<' : '<<=',
		'<-' : '<=',
		'<--' : '<<',
		'<~' : '<-',
		'<=' : '<:',
		'><-' : 'x-',

		'<>' : 'abox',
		'()' : 'rbox',
		'[]' : 'note',
		}

	def head(self):
		super().head()
		self.writeln('msc {')

	def tail(self):
		self.writeln('}')

	def entities(self, entities):
		estr = []
		for entity in entities:
			estr.append('%s%s' % (entity.name, self.attrs_str(self.all_attrs(entity.descr, entity.attrs), prefix='')))
		if not estr:
			return
		self.writeln('%s;' % (','.join(estr)))

	def attrs_list_str(self, attrs):
		if not attrs:
			return ''
		def escape(s):
			return s.replace('\n', r'\n').replace('\r', '').replace('\t', r'\t')
		return ','.join('%s="%s"' % (k,escape(v)) for k,v in attrs.items())

	def attrs_str(self, attrs, prefix=' '):
		attrs_list_str = self.attrs_list_str(attrs)
		if not attrs_list_str:
			return ''
		return '%s[%s]' % (prefix or '', attrs_list_str)

	def root_attrs(self, attrs):
		if not attrs:
			return
		self.writeln('%s;' % self.attrs_list_str(attrs))

	def all_attrs(self, descr, attrs):
		a = {}
		if descr:
			a['label'] = descr
		a.update(attrs)
		return a

	def entity(self, entity):
		error('OutputMscgen.entity() should not be called')

	def arrow_txlate(self, arrow):
		txlate = OutputMscgen.ARROWS.get(arrow)
		if not txlate:
			error('Unknown arrow: %r' % arrow)
		return txlate

	def arrow(self, arrow):
		mo_mt = arrow.mo_mt or MO

		def prepend_mo_mt(name):
			if name in ('.', MNCC):
				return name
			return '%s%s' % (mo_mt, name)

		l = prepend_mo_mt(arrow.left)
		r = arrow.right
		if r == '.':
			r = l
		else:
			r = prepend_mo_mt(r)

		a = {'label': arrow.descr}
		a.update(arrow.attrs)
		attrs = self.attrs_str(a)

		self.writeln('%s %s %s%s;'
			     % (l, self.arrow_txlate(arrow.arrow), r,
				self.attrs_str(self.all_attrs(arrow.descr, arrow.attrs), prefix='\t')))

	def separator(self, sep_str, descr, attrs):
		self.writeln('%s%s%s%s;'
			     % (separator.separator,
				self.attrs_str(self.all_attrs(descr, attrs), prefix='\t')))

	def emptyline(self, emptyline):
		self.write('\n' * emptyline.count);


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

	def __init__(self, output, mask_values=False):

		self.diagram = Diagram()
		self.output = output
		self.linenr = 0
		self.rules = []
		self.rules_hit = {}
		self.seen_udtrace_mncc = False

		self.callrefs_mo_mt = {}
		self.mask_values = mask_values
		self.masked_values = {}

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
			self.rules_hit[member] = 0



	def error(self, *msg):
		error('line %d: ' % self.linenr, *msg)

	def start(self):
		self.diagram.root_attrs = {'hscale': '3'}
		for name, descr in (
				('moms', 'MS,BSS (MO)\\nUE,hNodeB (MO)'),
				#('moue', 'UE,hNodeB (MO)'),
				('momgw', 'MGW for MSC (MO)'),
				('momsc', 'MSC (MO)'),
				('mncc', 'MNCC'),
				('mtmsc', 'MSC (MT)'),
				('mtmgw', 'MGW for MSC (MT)'),
				('mtms', 'BSS,MS (MT)\\nhNodeB,UE (MT)'),
				#('mtue', 'hNodeB,UE (MT)'),
				):
			self.diagram.entities.append(Entity(name, descr))

	def end(self):
		self.diagram.resolve_unknown_mo_mt()
		self.output.render(self.diagram)

	def mask_value(self, name, val):
		if not self.mask_values:
			return val
		if not val:
			return val
		name_dict = self.masked_values.get(name)
		if not name_dict:
			name_dict = {}
			self.masked_values[name] = name_dict

		masked_val = name_dict.get(val)
		if masked_val is None:
			masked_val = '%s-%d' % (name, len(name_dict) + 1)
			name_dict[val] = masked_val
		return masked_val

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
				self.rules_hit[rule.name] = self.rules_hit.get(rule.name, 0) + 1
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
			# detecting IMSI Detach separately, because this log line does not contain the IMSI.
			# By using the rule_imsi_detach(), we can accurately put it on the MO/MT side.
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
		return True

	def rule_mgcp_tx(self, m):
		r'.*mgw-endp\([^)]*:([^:]+):([^:]+)\).* (rtpbridge[^ ]+) .* RTP_TO_(RAN|CN)( CI=([^:]+)|): ([^ :]+).*: Sending'
		ran, l3type, endp, rtp_to, cond_ci, ci, verb = m.groups()
		e = mo_mt_from_l3type(l3type)
		if '*' not in endp:
			endp = self.mask_value('EP', endp)
		ci = self.mask_value('CI', ci)
		ci_str = ''
		if ci:
			ci_str = ' %s' % ci
		self.diagram.add_line(Arrow(e, MGW, '<', MSC, 'for %s: %s\\n%s%s' % (rtp_to, verb, endp, ci_str)))
		return True

	def rule_mgcp_rx(self, m):
		r'.*mgw-endp\(([^)]+):([^:)]+):([^:)]+)\).* (rtpbridge[^ ]+) .* RTP_TO_(RAN|CN)( CI=([^:]+)|).*: received successful response to ([^:]+): RTP=[^:]+:([0-9.:]+)'
		subscr, ran_conn, l3type, endp, rtp_to, cond_ci, ci, verb, rtp = m.groups()
		e = mo_mt_from_l3type(l3type)
		endp = self.mask_value('EP', endp)
		ci = self.mask_value('CI', ci)
		ci_str = ''
		if ci:
			ci_str = ' %s' % ci
		rtp = self.mask_value('IP:port', rtp)
		self.diagram.add_line(Arrow(e, MGW, '>', MSC, 'for %s: %s OK\\n%s%s %s' % (rtp_to, verb, endp, ci_str, rtp)))
		return True

	def rule_ran_tx(self, m):
		r'.*msc_a\(([^)]+):([^:)]+):([^:)]+)\).* RAN encode: ([^: ]+): (.+)$'

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
		r'.*msc_a\(([^)]+):([^:)]+):([^:)]+)\).* RAN decode: ([^: ]+) (.+)$'

		subscr, ran_conn, l3type, ran_type, msg_type = m.groups()

		if msg_type in ('DTAP', 'DirectTransfer', 'DirectTransfer RAN PDU'):
			# will get DTAP details from rule_dtap() instead, not from BSSMAP logging
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

	def rule_log_mncc_no_rtp(self, m):
		r'.*trans\(CC[^) ]* [^ )]+:([^:)]+) callref-([^ ]+) [^)]+\) (tx|rx) (MNCC_[^ ]*)$'
		l3type, callref_hex, tx_rx, mncc_msg = m.groups()

		if self.seen_udtrace_mncc:
			# If no udtrace is present, take the MNCC logging.
			# But if there is udtrace logging available, we should not duplicate those MNCC lines.
			return True

		tx = (tx_rx == 'tx')

		try:
			e = self.callrefs_mo_mt.get(callref_hex, MT)
		except:
			e = MT

		self.diagram.add_line(Arrow(e, MSC, '>' if tx else '<', 'mncc', mncc_msg))
		return True

	def rule_log_mncc_with_rtp(self, m):
		r'.*trans\(CC[^) ]* [^ )]+:([^:)]+) callref-([^ ]+) [^)]+\) (tx|rx) (MNCC_[^ ]*) \(RTP=([^){]+)(|{.*})\)$'
		l3type, callref_hex, tx_rx, mncc_msg, rtp, codec = m.groups()

		if self.seen_udtrace_mncc:
			# If no udtrace is present, take the MNCC logging.
			# But if there is udtrace logging available, we should not duplicate those MNCC lines.
			return True

		tx = (tx_rx == 'tx')

		try:
			e = self.callrefs_mo_mt.get(callref_hex, MT)
		except:
			e = MT

		rtp = self.mask_value('IP:port', rtp)
		self.diagram.add_line(Arrow(e, MSC, '>' if tx else '<', 'mncc', f'{mncc_msg}\\n{rtp}'))
		return True

	RE_MNCC_RTP = re.compile(' ip := ([^, ]+), rtp_port := ([0-9]+),')
	RE_MNCC_CALLREF = re.compile(' callref := ([^ ,]+), ')

	# detecting MNCC with udtrace has the advantage that we also get an indication whether RTP information is
	# present
	def rule_udtrace_mncc(self, m):
		r'.*(write|recv).* (Tx|Rx): \{ msg_type := ([^ ]+) .* u := \{ (.*) \} \}$'
		write_recv, tx_rx, msg_type, u = m.groups()

		self.seen_udtrace_mncc = True

		tx = (tx_rx == 'Tx')

		callref_intstr = None
		for m in Parse.RE_MNCC_CALLREF.finditer(u):
			callref_intstr = m.group(1)
		if not callref_intstr:
			# log only MNCC that has a callref
			return True

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
			rtp_info = self.mask_value('IP:port', rtp_info)
			descr = '%s\\n%s' % (descr, rtp_info)
			break

		self.diagram.add_line(Arrow(e, MSC, '>' if tx else '<', 'mncc', descr))
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
	if cmdline.output_format == 'mscgen':
		output = OutputMscgen(outf, cmdline.start_with_re)
	else:
		output = OutputLadder(outf, cmdline.start_with_re)
	parse = Parse(output, cmdline.mask_values)

	parse.start()

	while inf.readable():
		line = inf.readline()
		if not line:
			break;
		parse.add_line(line)
	parse.end()
	if cmdline.verbose:
		for name, count in parse.rules_hit.items():
			print(f" {name}: {count}")

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
	parser.add_argument('-t', '--output-format', dest='output_format', default="mscgen",
			choices=('mscgen','ladder'),
			help='Pick output format: mscgen format or libosmocore/contrib/ladder_to_msc.py format')
	parser.add_argument('-m', '--mask-values', dest='mask_values', action='store_true',
			help='Do not output specific values like IP address, port, endpoint CI, instead just indicate that a value is'
			     ' present. This makes the output reproducible across various logs.')
	parser.add_argument('-s', '--start-with', dest='start_with_re', default=None,
			help='Skip until the first message with this label (regex), e.g. -s "CC SETUP"')
	parser.add_argument('-v', '--verbose', dest='verbose', action='store_true',
			help='show some debug info, like which regex rules were hit and which were not.')

	cmdline = parser.parse_args()

	main(cmdline)

# vim: shiftwidth=8 noexpandtab tabstop=8 autoindent nocindent
