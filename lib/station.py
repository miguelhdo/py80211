##
# Module providing station information

#
# Copyright 2015 Arend van Spriel <aspriel@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
import sys
import traceback
import struct

import netlink.capi as nl
import netlink.core as nlc
import netlink.genl.capi as genl
import generated.defs as nl80211

from generated.policy import nl80211_policy
from base import *

bss_param_policy = nl.nla_policy_array(nl80211.STA_BSS_PARAM_MAX + 1)
bss_param_policy[nl80211.STA_BSS_PARAM_CTS_PROT].type = nl.NLA_FLAG
bss_param_policy[nl80211.STA_BSS_PARAM_SHORT_PREAMBLE].type = nl.NLA_FLAG
bss_param_policy[nl80211.STA_BSS_PARAM_SHORT_SLOT_TIME].type = nl.NLA_FLAG
bss_param_policy[nl80211.STA_BSS_PARAM_DTIM_PERIOD].type = nl.NLA_U8
bss_param_policy[nl80211.STA_BSS_PARAM_BEACON_INTERVAL].type = nl.NLA_U16

class bss_param(nl80211_object):
	pass

bitrate_policy = nl.nla_policy_array(nl80211.RATE_INFO_MAX + 1)
bitrate_policy[nl80211.RATE_INFO_BITRATE].type = nl.NLA_U16
bitrate_policy[nl80211.RATE_INFO_BITRATE32].type = nl.NLA_U32
bitrate_policy[nl80211.RATE_INFO_MCS].type = nl.NLA_U8
bitrate_policy[nl80211.RATE_INFO_40_MHZ_WIDTH].type = nl.NLA_FLAG
bitrate_policy[nl80211.RATE_INFO_SHORT_GI].type = nl.NLA_FLAG

class bitrate(nl80211_object):
	pass

stats_policy = nl.nla_policy_array(nl80211.STA_INFO_MAX + 1)
stats_policy[nl80211.STA_INFO_INACTIVE_TIME].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_RX_BYTES].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_TX_BYTES].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_RX_PACKETS].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_TX_PACKETS].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_SIGNAL].type = nl.NLA_U8
stats_policy[nl80211.STA_INFO_SIGNAL].signed = True
stats_policy[nl80211.STA_INFO_SIGNAL_AVG].type = nl.NLA_U8
stats_policy[nl80211.STA_INFO_SIGNAL_AVG].signed = True
stats_policy[nl80211.STA_INFO_T_OFFSET].type = nl.NLA_U64
stats_policy[nl80211.STA_INFO_TX_BITRATE].type = nl.NLA_NESTED
stats_policy[nl80211.STA_INFO_TX_BITRATE].single = True
stats_policy[nl80211.STA_INFO_RX_BITRATE].type = nl.NLA_NESTED
stats_policy[nl80211.STA_INFO_RX_BITRATE].single = True
stats_policy[nl80211.STA_INFO_LLID].type = nl.NLA_U16
stats_policy[nl80211.STA_INFO_PLID].type = nl.NLA_U16
stats_policy[nl80211.STA_INFO_PLINK_STATE].type = nl.NLA_U8
stats_policy[nl80211.STA_INFO_TX_RETRIES].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_TX_FAILED].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_STA_FLAGS].minlen = 8
stats_policy[nl80211.STA_INFO_LOCAL_PM].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_PEER_PM].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_NONPEER_PM].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL].type = nl.NLA_NESTED
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL].list_type = nl.NLA_U8
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL].signed = True
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL_AVG].type = nl.NLA_NESTED
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL_AVG].list_type = nl.NLA_U8
stats_policy[nl80211.STA_INFO_CHAIN_SIGNAL_AVG].signed = True
stats_policy[nl80211.STA_INFO_RX_BYTES64].type = nl.NLA_U64
stats_policy[nl80211.STA_INFO_TX_BYTES64].type = nl.NLA_U64
stats_policy[nl80211.STA_INFO_BEACON_LOSS].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_CONNECTED_TIME].type = nl.NLA_U32
stats_policy[nl80211.STA_INFO_BSS_PARAM].type = nl.NLA_NESTED
stats_policy[nl80211.STA_INFO_BSS_PARAM].single = True

class station_stats(nl80211_object):
	nest_attr_map = {
		nl80211.STA_INFO_TX_BITRATE: (bitrate, len(bitrate_policy), bitrate_policy),
		nl80211.STA_INFO_RX_BITRATE: (bitrate, len(bitrate_policy), bitrate_policy),
		nl80211.STA_INFO_BSS_PARAM: (bss_param, len(bss_param_policy), bss_param_policy)
	}
	def __init__(self, attrs, policy):
		nl80211_object.__init__(self, attrs, policy)
		if nl80211.STA_INFO_STA_FLAGS in self.attrs:
			flags = sta_flags(self.attrs[nl80211.STA_INFO_STA_FLAGS])
			self._attrs[nl80211.STA_INFO_STA_FLAGS] = flags

class sta_flags(object):
	def __init__(self, bytes):
		if len(bytes) < 8:
			raise Exception("not enough sta_flags bytes")
		self.fmask, self.fset = struct.unpack('ii', bytes)

class station(nl80211_managed_object):
	nest_attr_map = {
		nl80211.ATTR_STA_INFO: (station_stats, len(stats_policy), stats_policy)
	}
	_cmd = nl80211.CMD_GET_STATION
	def __init__(self, ifidx, mac, access=None, attrs=None):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._ifidx = ifidx
		if nl80211.ATTR_MAC in self.attrs:
			self._mac = self.attrs[nl80211.ATTR_MAC]
		elif mac == None:
			raise Exception("need to provide a mac address")
		elif not isinstance(mac, bytearray):
			raise Exception("mac address must be bytearray")
		else:
			self._mac = mac
			self.refresh()

	def put_obj_id(self, msg):
		nl.nla_put_u32(msg._msg, nl80211.ATTR_IFINDEX, self._ifidx)
		nl.nla_put(msg._msg, nl80211.ATTR_MAC, self._mac)

	def __hash__(self):
		mac_hash = self._mac[1:3] + self._mac[4:6]
		return struct.unpack('i', mac_hash)[0]

	def __cmp__(self, other):
		return self.__hash__() - other.__hash__()

class station_list(custom_handler):
	def __init__(self, ifidx, access=None, kind=nl.NL_CB_DEFAULT):
		self._station = []
		self._ifidx = ifidx
		if access == None:
			access = access80211(kind)
		flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK | nlc.NLM_F_DUMP
		m = access.alloc_genlmsg(nl80211.CMD_GET_STATION, flags)
		nl.nla_put_u32(m._msg, nl80211.ATTR_IFINDEX, ifidx)
		self._access = access
		access.send(m, self)

	def __iter__(self):
		return iter(self._station)

	def store_station(self, sta):
		for s in self._station:
			if s == sta:
				s._attrs = sta._attrs
				return
		self._station.append(sta)

	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			sta = station(self._ifidx, None, self._access, attrs)
			s = self.store_station(sta)
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)
