##
# Module providing interface information

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
import factory

class interface(nl80211_managed_object):
	_cmd = nl80211.CMD_GET_INTERFACE
	def __init__(self, access, attrs):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._wdevid = nl.nla_get_u64(attrs[nl80211.ATTR_WDEV])

	@property
	def wdevid(self):
		return self._wdevid

	def put_obj_id(self, msg):
		nl.nla_put_u64(msg._msg, nl80211.ATTR_WDEV, self._wdevid)

class interface_list(custom_handler):
	def __init__(self, access=None, kind=nl.NL_CB_DEFAULT):
		self._iface = {}
		if access == None:
			access = access80211(kind)
		flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK | nlc.NLM_F_DUMP
		m = access.alloc_genlmsg(nl80211.CMD_GET_INTERFACE, flags)
		self._access = access
		access.send(m, self)

	def __iter__(self):
		return iter(self._iface.values())

	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			if nl80211.ATTR_WDEV in attrs:
				wdevid = nl.nla_get_u64(attrs[nl80211.ATTR_WDEV])
				if wdevid in self._iface.keys():
					self._iface[wdevid].store_attrs(attrs)
				else:
					iface = factory.get_inst().create(interface, self._access, attrs)
					self._iface[iface.wdevid] = iface
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)
