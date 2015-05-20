##
# Module dealing with ojbect created in py80211

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
import Pyro4 as pyro

##
# default py80211_factory which simply instantiates the class
# provided.
class py80211_factory(object):
	def create(self, cls, *args, **kwargs):
		return cls(*args, **kwargs)

##
# factory for remote use of py80211 which instantiates the class
# and registers the object instance with pyro daemon.
class py80211_remote_factory(object):
	def __init__(self, daemon):
		if daemon == None:
			daemon = pyro.Daemon()
		self._daemon = daemon

	def create(self, cls, *args, **kwargs):
		obj = cls(*args, **kwargs)
		self._daemon.register(obj)
		return obj

_inst = py80211_factory()

def use_remote(daemon=None):
	globals()['_inst'] = py80211_remote_factory(daemon)

def get_inst():
	return globals()['_inst']
