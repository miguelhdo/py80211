import Pyro4 as pyro
import socket
import imp
import sys

from py80211 import factory

pyro.config.THREADPOOL_SIZE = 32

def import_package(name):
	parent = determine_parent(globals())
	q, tail = find_head_package(parent, name)
	m = load_tail(q, tail)
	return m

def find_head_package(parent, name):
	if '.' in name:
		i = name.find('.')
		head = name[:i]
		tail = name[i+1:]
	else:
		head = name
		tail = ""
	if parent:
		qname = "%s.%s" % (parent.__name__, head)
	else:
		qname = head
	q = import_module(head, qname, parent)
	if q: return q, tail
	if parent:
		qname = head
		parent = None
		q = import_module(head, qname, parent)
		if q: return q, tail
	raise ImportError, "No module named " + qname

def determine_parent(globals):
	if not globals or  not globals.has_key("__name__"):
		return None
	pname = globals['__name__']
	if globals.has_key("__path__"):
		parent = sys.modules[pname]
		assert globals is parent.__dict__
		return parent
	if '.' in pname:
		i = pname.rfind('.')
		pname = pname[:i]
		parent = sys.modules[pname]
		assert parent.__name__ == pname
		return parent
	return None

def load_tail(q, tail):
	m = q
	while tail:
		i = tail.find('.')
		if i < 0: i = len(tail)
		head, tail = tail[:i], tail[i+1:]
		mname = "%s.%s" % (m.__name__, head)
		m = import_module(head, mname, m)
		if not m:
			raise ImportError, "No module named " + mname
	return m

def import_module(partname, fqname, parent):
	try:
		return sys.modules[fqname]
	except KeyError:
		pass
	try:
		fp, pathname, stuff = imp.find_module(partname,
						      parent and parent.__path__)
	except ImportError:
		return None
	try:
		m = imp.load_module(fqname, fp, pathname, stuff)
	finally:
		if fp: fp.close()
	if parent:
		setattr(parent, partname, m)
	return m

class py80211_server(object):
	def __init__(self):
		ns = pyro.naming.locateNS()
		self._daemon = pyro.Daemon()
		ns.register('py80211.server.%s' % socket.gethostname(), self._daemon.register(self))

	def create_instance(self, class_name, *args, **kwargs):
		if not class_name.startswith('py80211.'):
			raise Exception('must be py80211 class')
		i = class_name.rfind('.')
		pkg_name = class_name[:i]
		submod = class_name[8:]
		submod = submod[:submod.find('.')]
		if not submod in ['wiphy', 'iface', 'station', 'scan']:
			raise Exception('module %s not for remote operation' % pkg_name)
		m = import_package(pkg_name)
		i += 1
		cls = getattr(m, class_name[i:])
		o = cls(*args, **kwargs)
		self._pyroDaemon.register(o)
		return o

if __name__ == "__main__":
	ns = pyro.naming.locateNS()
	server = py80211_server()
	factory.use_remote(server._daemon)
	print('server started')
	server._daemon.requestLoop()
