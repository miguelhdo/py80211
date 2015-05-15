from py80211.station import *
import netlink.capi as nl
import sys

ifidx = nl.if_nametoindex(sys.argv[1])
sl = station_list(ifidx, None, nl.NL_CB_DEBUG)
for sta in sl:
	print sta.attrs[nl80211.ATTR_STA_INFO].attrs
