import netlink.capi as nl
import py80211.iface

iflist = py80211.iface.interface_list(None, nl.NL_CB_DEBUG)

print "iflist:"
print iflist._iface
for iface in iflist:
	print "iface attributes:"
	print iface.attrs
