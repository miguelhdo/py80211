##
# Module provide the core classes used in py80211.

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
from abc import *

import netlink.capi as nl
import netlink.genl.capi as genl
import netlink.core as nlc
import generated.defs as nl80211
from generated import strmap

NLA_NUL_STRING = nl.NLA_NESTED + 2
NLA_BINARY = nl.NLA_NESTED + 3

from abc import *

##
# Exception which is raised when netlink socket is already
# doing a transaction.
class AccessBusyError(Exception):
	pass

##
# Abstract class specifying the interface for object class which
# can be used to provide a custom netlink callback function.
class custom_handler(object):
	__metaclass__ = ABCMeta

	@abstractmethod
	def handle(self, msg, arg):
		pass

##
# This class provides socket connection to the nl80211 genl family.
class access80211(object):
	""" provide access to the nl80211 API """
	def __init__(self, level=nl.NL_CB_DEFAULT):
		self._tx_cb = nlc.Callback(level)
		self._rx_cb = nlc.Callback(level)
		self._sock = nlc.Socket(self._tx_cb)

		self._rx_cb.set_err(nl.NL_CB_CUSTOM, self.error_handler, None)
		self._rx_cb.set_type(nl.NL_CB_FINISH, nl.NL_CB_CUSTOM, self.finish_handler, None)
		self._rx_cb.set_type(nl.NL_CB_ACK, nl.NL_CB_CUSTOM, self.ack_handler, None)

		self._sock.connect(nlc.NETLINK_GENERIC)
		self._family = genl.genl_ctrl_resolve(self._sock._sock, 'nl80211')
		self.busy = 0

	##
	# Allocates a netlink message setup with genl header for nl80211 family.
	def alloc_genlmsg(self, cmd, flags=0):
		msg = nlc.Message()
		genl.genlmsg_put(msg._msg, 0, 0, self._family, 0, flags, cmd, 0)
		return msg

	##
	# Send netlink message to the kernel and wait for response. The provided
	# handler will be called for NL_CB_VALID callback.
	def send(self, msg, handler):
		if not isinstance(handler, custom_handler):
			raise Exception("provided 'handler' is not a custom_handler instance")
		if self.busy == 1:
			raise AccessBusyError()
		self.busy = 1
		self._rx_cb.set_type(nl.NL_CB_VALID, nl.NL_CB_CUSTOM, handler.handle, None)
		err = self._sock.send_auto_complete(msg)
		while self.busy > 0 and not err < 0:
			self._sock.recvmsgs(self._rx_cb)
			err = self.busy
		return err

	##
	# Function effectively disables sequence number check.
	def noseq(self, m, a):
		return nl.NL_OK

	##
	# Disable sequence number checking, which is required for receiving
	# multicast notifications.
	def disable_seq_check(self):
		self._rx_cb.set_type(nl.NL_CB_SEQ_CHECK, nl.NL_CB_CUSTOM, self.noseq, None)

	##
	# Enable sequence number checking.
	def enalbe_seq_check(self):
		self._rx_cb.set_type(nl.NL_CB_SEQ_CHECK, nl.NL_CB_DEFAULT, None, None)

	##
	# Subscribe to the provided multicast group for notifications.
	def subscribe_multicast(self, mcname):
		mcid = genl.genl_ctrl_resolve_grp(self._sock._sock, 'nl80211', mcname)
		nl.nl_socket_add_membership(self._sock._sock, mcid)
		return mcid

	##
	# Unsubscribe from the provided multicast group.
	def drop_multicast(self, mcid):
		if isinstance(mcid, str):
			mcid = genl.genl_ctrl_resolve_grp(self._sock._sock, 'nl80211', mcid)
		nl.nl_socket_drop_membership(self._sock._sock, mcid)

	##
	# Property (GET) for obtaining the generic netlink family.
	@property
	def family(self):
		return self._family

	##
	# Default finish handler which clears the busy flag causing send() to
	# stop receiving and return.
	def finish_handler(self, m, a):
		self.busy = 0
		return nl.NL_SKIP

	##
	# Defaul ack handler.
	def ack_handler(self, m, a):
		self.busy = 0
		return nl.NL_STOP

	##
	# Default error handler passing error value in busy flag.
	def error_handler(self, err, a):
		self.busy = err.error
		return nl.NL_STOP

##
# main object which deals with storing the attributes converting them to
# python objects as specified by provided policy and nest_attr_map. The
# nest_attr_map is a class variable to be provided by derived objects,
# which consists of tuple specifying class, maximum number of attributes and
# the policy of each nested attribute.
class nl80211_object(object):
	def __init__(self, attrs, policy=None):
		self._attrs = {}
		self._policy = policy
		if attrs != None:
			self.store_attrs(attrs)

	##
	# Creates a new instance for the nested attribute according
	# the nest_attr_map.
	def create_nested(self, attr, aid):
		try:
			if aid in self.nest_attr_map.keys():
				(nest_class, max_nest, nest_policy) = self.nest_attr_map[aid]
			e, nattr = nl.py_nla_parse_nested(max_nest, attr, nest_policy)
			return nest_class(nattr, nest_policy)
		except Exception as e:
			return nl.nla_type(attr)

	##
	# Creates a nested attribute list adding a new instance
	# for each nested element.
	def create_nested_list(self, attr_list, aid):
		nest_list = []
		for nest_element in nl.nla_get_nested(attr_list):
			nest_obj = self.create_nested(nest_element, aid)
			nest_list.append(nest_obj)
		return nest_list

	##
	# Creates a list of attributes that are a basic type.
	def create_list(self, attr_list, pol):
		nest_list = []
		item_type = pol.list_type
		for item in nl.nla_get_nested(attr_list):
			if item_type == NLA_NUL_STRING:
				nest_obj = nl.nla_get_string(item)
			elif item_type == nl.NLA_U64:
				nest_obj = nl.nla_get_u64(item)
			elif item_type == nl.NLA_U32:
				nest_obj = nl.nla_get_u32(item)
			elif item_type == nl.NLA_U16:
				nest_obj = nl.nla_get_u16(item)
			elif item_type == nl.NLA_U8:
				nest_obj = nl.nla_get_u8(item)
			else:
				raise Exception("type (%d) not supported for list" % item_type)
			nest_list.append(nest_obj)
		return nest_list

	##
	# Do a 2s complement sign conversion on attribute
	# which may be a list of values.
	def convert_sign(self, attr, pol):
		conv_tab = {
			nl.NLA_U32: 0x80000000,
			nl.NLA_U16: 0x8000,
			nl.NLA_U8: 0x80
		}
		pol_type = pol.type
		if pol.type == nl.NLA_NESTED:
			pol_type = pol.list_type
		if not pol_type in conv_tab:
			raise Exception("invalid type (%d) for sign conversion" % pol_type)
		conv_check = conv_tab[pol_type]
		if pol.type != nl.NLA_NESTED:
			if attr & conv_check:
				return -conv_check + (attr & (conv_check - 1))
		else:
			for aid in range(len(attr)):
				attr[aid] = -conv_check + (attr[aid] & (conv_check - 1))
		return attr

	##
	# Called after storing the netlink attributes. This allows doing any custom
	# post-processing of the netlink attributes by overriding this method.
	def post_store_attrs(self, attrs):
		pass

	##
	# Stores the attributes using the appropriate nla_get function
	# according the provided policy.
	def store_attrs(self, attrs):
		for aid in attrs.keys():
			try:
				pol = self._policy[aid]
				if pol.type == NLA_NUL_STRING:
					self._attrs[aid] = nl.nla_get_string(attrs[aid])
				elif pol.type == nl.NLA_U64:
					self._attrs[aid] = nl.nla_get_u64(attrs[aid])
				elif pol.type == nl.NLA_U32:
					self._attrs[aid] = nl.nla_get_u32(attrs[aid])
				elif pol.type == nl.NLA_U16:
					self._attrs[aid] = nl.nla_get_u16(attrs[aid])
				elif pol.type == nl.NLA_U8:
					self._attrs[aid] = nl.nla_get_u8(attrs[aid])
				elif pol.type == nl.NLA_FLAG:
					self._attrs[aid] = True
				elif pol.type == nl.NLA_NESTED:
					if hasattr(pol, 'single') and pol.single:
						obj = self.create_nested(attrs[aid], aid)
					elif hasattr(pol, 'list_type'):
						obj = self.create_list(attrs[aid], pol)
					else:
						obj = self.create_nested_list(attrs[aid], aid)
					self._attrs[aid] = obj
				elif pol.type in [ NLA_BINARY, nl.NLA_UNSPEC ]:
					self._attrs[aid] = nl.nla_data(attrs[aid])
				if hasattr(pol, 'signed') and pol.signed:
					self._attrs[aid] = self.convert_sign(self._attrs[aid], pol)
			except Exception as e:
				print e.message
				self._attrs[aid] = nl.nla_data(attrs[aid])
		self.post_store_attrs(attrs)

	##
	# Property (GET) for obtaining the attributes.
	@property
	def attrs(self):
		return self._attrs

	##
	# Gets specified attribute.
	def get_nlattr(self, attr_id):
		return self._attrs[attr_id]

##
# The managed object can be used for objects whose data is obtained
# using a specific command. The derived class needs to specify the
# NL80211 command (self._cmd) to use and implement abstract method
# put_obj_id() putting PHY, NETDEV, or WDEV as needed.
class nl80211_managed_object(nl80211_object, custom_handler):
	def __init__(self, access, attrs, policy=None):
		nl80211_object.__init__(self, attrs, policy)
		if access == None:
			self._access = access80211()
		else:
			self._access = access

	##
	# Property (GET) to obtain command.
	@property
	def objcmd(self):
		try:
			return self._cmd
		except Exception:
			raise Exception('class need to define _cmd attribute')

	##
	# Abstract method to fill object identifier in netlink message.
	@abstractmethod
	def put_obj_id(m):
		pass

	##
	# Refresh object data by sending a new netlink message to the kernel.
	def refresh(self):
		m = self._access.alloc_genlmsg(self.objcmd, nlc.NLM_F_REQUEST | nlc.NLM_F_ACK)
		self.put_obj_id(m)
		self._access.send(m, self)

	##
	# Valid handler parsing the response(s) and store the attributes.
	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			self.store_attrs(attrs)
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)

