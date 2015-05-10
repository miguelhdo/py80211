from py80211.scan import *
import netlink.capi as nl

WLAN_EID_SSID = 0

def find_ie(ies, eid):
	while len(ies) > 2 and ies[0] != eid:
		ies = ies[ies[1]+2:]
	if len(ies) < 2:
		return None
	if len(ies) < 2 + ies[1]:
		return None
	return ies[0:2+ies[1]]

rh = scan_request(3)
rh.add_ssids(['Ziggo'])
sr = rh.send()
for bss in sr:
	bssid = bss.attrs[nl80211.BSS_BSSID]
	print "bssid: %02x:%02x:%02x:%02x:%02x:%02x" % (bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5])
	ies = bss.attrs[nl80211.BSS_INFORMATION_ELEMENTS]
	ssid = find_ie(ies, WLAN_EID_SSID)
	print "ssid: %s\n" % str(ssid[2:])
