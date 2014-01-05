import sys
import traceback

import netlink.capi as nl
import netlink.core as nlc
import netlink.genl.capi as genl
import generated.defs as nl80211

from generated.policy import nl80211_policy
from base import *

rate_policy = nl.nla_policy_array(nl80211.BITRATE_ATTR_MAX + 1)
rate_policy[nl80211.BITRATE_ATTR_RATE].type = nl.NLA_U32
rate_policy[nl80211.BITRATE_ATTR_2GHZ_SHORTPREAMBLE].type = nl.NLA_FLAG

class wiphy_rate(nl80211_object):
	policy = rate_policy
	max_attr = len(rate_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, rate_policy)

	def __str__(self):
		s = '%3.1f' % (0.1 * self.attrs[nl80211.BITRATE_ATTR_RATE])
		if nl80211.BITRATE_ATTR_2GHZ_SHORTPREAMBLE in self.attrs:
			s += ' (short)'
		return s

freq_policy = nl.nla_policy_array(nl80211.FREQUENCY_ATTR_MAX + 1)
freq_policy[nl80211.FREQUENCY_ATTR_FREQ].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DISABLED].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_IBSS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_IR].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_RADAR].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_MAX_TX_POWER].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_MINUS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_HT40_PLUS].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_80MHZ].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_NO_160MHZ].type = nl.NLA_FLAG
freq_policy[nl80211.FREQUENCY_ATTR_DFS_STATE].type = nl.NLA_U32
freq_policy[nl80211.FREQUENCY_ATTR_DFS_TIME].type = nl.NLA_U32

class wiphy_freq(nl80211_object):
	policy = freq_policy
	max_attr = len(freq_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, freq_policy)

	@property
	def channel(self):
		freq = self.attrs[nl80211.FREQUENCY_ATTR_FREQ]
		# see 802.11 17.3.8.3.2 and Annex J
		if freq == 2484:
			return 14
		elif freq < 2484:
			return (freq - 2407) / 5
		elif freq >= 4910 and freq <= 4980:
			return (freq - 4000) / 5
		elif freq <= 45000:
			# DMG band lower limit
			return (freq - 5000) / 5
		elif freq >= 58320 and freq <= 64800:
			return (freq - 56160) / 2160
		else:
			raise Exception('invalid channel frequency: %d' % freq)


	def __str__(self):
		s = '%6d MHz (%d)' % (self.attrs[nl80211.FREQUENCY_ATTR_FREQ], self.channel)
		if nl80211.FREQUENCY_ATTR_DISABLED in self.attrs:
			s += ' (disabled)'
			return s
		s += ' [%.2f dBm]' % (0.01 * self.attrs[nl80211.FREQUENCY_ATTR_MAX_TX_POWER])
		return s


band_policy = nl.nla_policy_array(nl80211.BAND_ATTR_MAX + 1)
band_policy[nl80211.BAND_ATTR_FREQS].type = nl.NLA_NESTED
band_policy[nl80211.BAND_ATTR_RATES].type = nl.NLA_NESTED
band_policy[nl80211.BAND_ATTR_HT_MCS_SET].type = nl.NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_HT_CAPA].type = nl.NLA_U16
band_policy[nl80211.BAND_ATTR_HT_AMPDU_FACTOR].type = nl.NLA_U8
band_policy[nl80211.BAND_ATTR_HT_AMPDU_DENSITY].type = nl.NLA_U8
band_policy[nl80211.BAND_ATTR_VHT_MCS_SET].type = nl.NLA_UNSPEC
band_policy[nl80211.BAND_ATTR_VHT_CAPA].type = nl.NLA_U32

class wiphy_band(nl80211_object):
	nest_attr_map = {
		nl80211.BAND_ATTR_FREQS: wiphy_freq,
		nl80211.BAND_ATTR_RATES: wiphy_rate,
	}
	policy = band_policy
	max_attr = len(band_policy)
	def __init__(self, attrs):
		nl80211_object.__init__(self, attrs, band_policy)

	def __str__(self):
		s = ''
		if nl80211.BAND_ATTR_HT_CAPA in self.attrs:
			s += 'ht capability 0x%04x\n' % self.attrs[nl80211.BAND_ATTR_HT_CAPA]
		if nl80211.BAND_ATTR_VHT_CAPA in self.attrs:
			s += 'vht capability 0x%08x\n' % self.attrs[nl80211.BAND_ATTR_HT_CAPA]
		s += 'channels:\n'
		for f in self.attrs[nl80211.BAND_ATTR_FREQS]:
			s += '\t%s\n' % str(f)
		s += 'legacy rates:\n'
		for r in self.attrs[nl80211.BAND_ATTR_RATES]:
			s += '\t%s\n' % str(r)
		return s

class wiphy(nl80211_managed_object):
	nest_attr_map = {
		nl80211.ATTR_WIPHY_BANDS: wiphy_band,
	}
	_cmd = nl80211.CMD_GET_WIPHY
	def __init__(self, access, attrs):
		nl80211_managed_object.__init__(self, access, attrs, nl80211_policy)
		self._phynum = nl.nla_get_u32(attrs[nl80211.ATTR_WIPHY])

	def put_obj_id(self, msg):
		nl.nla_put_u32(msg._msg, nl80211.ATTR_WIPHY, self.phynum)

	@property
	def phynum(self):
		return self._phynum

	def __hash__(self):
		return self._phynum


class wiphy_list(ValidHandler):
	def __init__(self, kind=nl.NL_CB_DEFAULT):
		self._wiphy = {}
		a = access80211(kind)
		flags = nlc.NLM_F_REQUEST | nlc.NLM_F_ACK | nlc.NLM_F_DUMP
		m = a.alloc_genlmsg(nl80211.CMD_GET_WIPHY, flags)
		self._access = a
		a.send(m, self)

	def __iter__(self):
		return iter(self._wiphy.values())

	def handle(self, msg, arg):
		try:
			e, attrs = genl.py_genlmsg_parse(nl.nlmsg_hdr(msg), 0, nl80211.ATTR_MAX, None)
			if nl80211.ATTR_WIPHY in attrs:
				phynum = nl.nla_get_u32(attrs[nl80211.ATTR_WIPHY])
				if phynum in self._wiphy.keys():
					self._wiphy[phynum].store_attrs(attrs)
				else:
					phy = wiphy(self._access, attrs)
					self._wiphy[phy.phynum] = phy
			return nl.NL_SKIP
		except Exception as e:
			(t,v,tb) = sys.exc_info()
			print v.message
			traceback.print_tb(tb)

if __name__ == '__main__':
	from generated import strmap

	wl = wiphy_list()
	for w in wl:
		print('phy#%d: %s' % (w.phynum, str(w)))
		w.refresh()
		print('name: %s' % (w.get_nlattr(nl80211.ATTR_WIPHY_NAME)))
		iftypes = w.get_nlattr(nl80211.ATTR_SUPPORTED_IFTYPES)
		for ift in iftypes:
			print('%s' % strmap.nl80211_iftype2str[ift])
