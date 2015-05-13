from py80211.scan import *
import netlink.capi as nl
from py80211.cli import bss_info
import sys

def find_ie(ies, eid):
	while len(ies) > 2 and ies[0] != eid:
		ies = ies[ies[1]+2:]
	if len(ies) < 2:
		return None
	if len(ies) < 2 + ies[1]:
		return None
	return ies[0:2+ies[1]]

ifidx = nl.if_nametoindex(sys.argv[1])
rh = scan_request(ifidx)
rh.add_ssids(['Ziggo'])
sr = rh.send()
for bss in sr:
	print str(bss_info(bss))

