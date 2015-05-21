##
# client-server example
#
# This requires Pyro4 package to be installed. You need to start a Pyro4
# name server which you can start in seperate terminal running 'pyro4-ns'.
# In yet another terminal you can start the server using
# 'python -m py80211.server'.
#
# By default it works on localhost. See [1] for details.
#
# [1] https://pythonhosted.org/Pyro4/tutorials.html#running-it-on-different-machines
#
import Pyro4 as pyro
import sys

import py80211.generated.defs as nl80211
import py80211.wiphy
import py80211.cli

servername = sys.argv[1]
pf = pyro.Proxy('PYRONAME:py80211.server.%s' % servername)
phylist = pf.create_instance('py80211.wiphy.wiphy_list')

for phy in phylist.wiphys:
	print('%s:' % phy.attrs[nl80211.ATTR_WIPHY_NAME])
	for b in phy.attrs[nl80211.ATTR_WIPHY_BANDS]:
		print('%s' % str(py80211.cli.wiphy_band_info(b)))
