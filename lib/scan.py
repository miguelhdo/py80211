import sys
import traceback

import netlink.capi as nl
import netlink.core as nlc
import netlink.genl.capi as genl
import generated.defs as nl80211

from generated.policy import nl80211_policy
from base import *

bss_policy = nl.nla_policy_array(nl80211.BSS_MAX + 1)
bss_policy[nl80211.BSS_TSF].type = nl.NLA_U64
bss_policy[nl80211.BSS_FREQUENCY].type = nl.NLA_U32
bss_policy[nl80211.BSS_BSSID].type = nl.NLA_UNSPEC
bss_policy[nl80211.BSS_BEACON_INTERVAL].type = nl.NLA_U16
bss_policy[nl80211.BSS_CAPABILITY].type = nl.NLA_U16
bss_policy[nl80211.BSS_INFORMATION_ELEMENTS].type = nl.NLA_UNSPEC
bss_policy[nl80211.BSS_SIGNAL_MBM].type = nl.NLA_U32
bss_policy[nl80211.BSS_SIGNAL_UNSPEC].type = nl.NLA_U8
bss_policy[nl80211.BSS_STATUS].type = nl.NLA_U32
bss_policy[nl80211.BSS_SEEN_MS_AGO].type = nl.NLA_U32
bss_policy[nl80211.BSS_BEACON_IES].type = nl.NLA_UNSPEC

class bss(nl80211_object):
	pass

class scan_request(custom_handler):
	def __init__(self, ifidx, level=nl.NL_CB_DEFAULT):
		self._ifidx = ifidx
		self._access = access80211(level)
		self._ssids = None
		self._freqs = None
		self._flags = 0
		self._ies = None

	def add_ssids(self, ssids):
		if self._ssids == None:
			self._ssids = ssids
		elif ssids == None:
			self._ssids = None
		else:
			self._ssids = self._ssids + ssids

	def add_freqs(self, freqs):
		if self._freqs == None:
			self._freqs = freqs
		elif freqs == None:
			self._freqs = None
		else:
			self._freqs = self._freqs + freqs

	def set_ies(self, ies):
		self._ies = ies

	def set_flags(self, flags):
		self._flags = flags

	def wait_for_scan_completion(self):
		while self.scan_busy:
			self._access._sock.recvmsgs(self._access._rx_cb)

	def send(self):
		flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK
		m = self._access.alloc_genlmsg(nl80211.CMD_TRIGGER_SCAN, flags)
		nl.nla_put_u32(m._msg, nl80211.ATTR_IFINDEX, self._ifidx)

		if self._ssids:
			i = 0
			nest = nl.nla_nest_start(m._msg, nl80211.ATTR_SCAN_SSIDS)
			for ssid in self._ssids:
				nl.nla_put(m._msg, i, ssid)
				i += 1
			nl.nla_nest_end(m._msg, nest)
		if self._freqs:
			i = 0
			nest = nl.nla_nest_start(m._msg, nl80211.ATTR_SCAN_FREQUENCIES)
			for freq in self._freqs:
				nl.nla_put_u32(m._msg, i, freq)
				i += 1
			nl.nla_nest_end(m._msg, nest)
		if self._flags != 0:
			nl.nla_put_u32(m._msg, nl80211.ATTR_SCAN_FLAGS, self._flags)
		if self._ies:
			nl.nla_put(m._msg, nl80211.ATTR_IE, self._ies)

		self.scan_busy = True
		self._access.disable_seq_check()
		mcid = self._access.subscribe_multicast('scan')
		ret = self._access.send(m, self)
		if ret < 0:
			self.scan_busy = False
			return None

		self.wait_for_scan_completion()
		self.bss_list = []
		self._access.drop_multicast(mcid)
                flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK | nlc.NLM_F_DUMP
                m = self._access.alloc_genlmsg(nl80211.CMD_GET_SCAN, flags)
                nl.nla_put_u32(m._msg, nl80211.ATTR_IFINDEX, self._ifidx)
		self._access.send(m, self)
		return self.bss_list

	def get_scan(self, msg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			if not nl80211.ATTR_BSS in attrs:
				return
			e, nattrs = nl.py_nla_parse_nested(len(bss_policy), attrs[nl80211.ATTR_BSS], bss_policy)
			self.bss_list.append(bss(nattrs, bss_policy))
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)

	def handle(self, msg, arg):
		genlh = genl.genlmsg_hdr(nl.nlmsg_hdr(msg))
		if genlh.cmd == nl80211.CMD_SCAN_ABORTED:
			self.scan_busy = False
		elif genlh.cmd == nl80211.CMD_NEW_SCAN_RESULTS:
			if self.scan_busy:
				self.scan_busy = False
			else:
				self.get_scan(msg)
		return nl.NL_SKIP

