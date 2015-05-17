from py80211.scan import *
import netlink.capi as nl
from py80211.cli import bss_info
import sys

ifidx = nl.if_nametoindex(sys.argv[1])
rh = scan_request(ifidx)
rh.add_ssids(['Ziggo'])
err = rh.send()
if err == 0:
	for bss in bss_list(ifidx):
		print str(bss_info(bss))
