#!/usr/bin/env python

"""
Rewrite Map Manager/Handler
by Mark Nottingham <mnot@yahoo-inc.com>.

This program is designed to run as a redirect handler
 for Squid; the configuration line MUST look like this:
  url_rewrite_program /path/to/this/program /path/to/conf/file
  url_rewrite_children 1
  url_rewrite_concurrency 10000

It requires Python 2.5+ and the following additional libraries:
 - Twisted <http://twistedmatrix.com/>

See the sample configuration file for details of its content.

Note that logging is synchronous (because it writes to disk), and 
therefore can slow down this process. As a result, we use the response 
to Squid to log most runtime events; debugging is log-intensive and 
should not be turned on in production.
"""
  
import os
import sys
import time
import re
import getopt
import logging
import traceback
import cgi
import ConfigParser
from logging.handlers import RotatingFileHandler
from urllib import quote
from urlparse import urljoin, urlsplit, urlunsplit
from xml.parsers import expat
from xml.dom import minidom
from twisted.internet import reactor, stdio
from twisted.protocols.basic import LineReceiver
from twisted.internet import error as internet_error
from twisted.web import client, error as web_error

__copyright__ = """\
Copyright (c) 2008-2010 Yahoo! Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""


# FIXME: clear URL cache when maps are updated (selectively?)
# TODO: HTTP/YCA authentication
# TODO: review log strings

def main(configfile, test=False):        
    # load config
    try:
        config = ConfigParser.SafeConfigParser(
           {
            'pidfile': None,
            'logfile': None,
            'dbfile': None,
            'log_level': "WARNING", 
            'log_backup': '5',
            'remote_map_lookup': 'yes',
            'remote_map_location': "/map.xml",
            'remote_map_wait': "yes",
            'local_map_dir': None,
            'local_map_check': "60",
            'http_proxy': None,
            'fetch_timeout': "10",
            }
        )
        config.add_section("main")
        config.read(configfile)
        pidfile = config.get("main", "pidfile")
        logfile = config.get("main", "logfile")
        log_level = config.get("main", "log_level").strip().upper()
        log_backup = config.getint("main", "log_backup")
    except ConfigParser.Error, why:
        error("Configuration file: %s\n" % why)
    
    # logging
    logger = logging.getLogger()
    #set root-logger
    if logger.getEffectiveLevel()>0:
        logger.setLevel('NOTSET')

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    if not test:
        try:
            hdlr = RotatingFileHandler(
                logfile, 
                maxBytes=1024 * 1024 * 10, 
                backupCount=log_backup
            )
        except IOError, why:
            error("Can't open log file (%s)" % why)
        hdlr.setLevel(logging._levelNames.get(log_level, logging.INFO))
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
    else:
        ch = logging.StreamHandler()
        ch.setLevel(logging.DEBUG)
        ch.setFormatter(formatter)
        logger.addHandler(ch)
        logging.info("Running in test mode.")

    # PID management
    if pidfile and not test:
        if os.path.exists(pidfile):
            error("Already running (PID %s)." % open(pidfile).read())
        try:
            pid_fh = open(pidfile, 'w')
            pid_fh.write(str(os.getpid()))
            pid_fh.close()
        except IOError, why:
            error("Can't write PID file (%s)." % why)
    
    # run
    try:
        try:
            cm = Redirector(reactor, config, test)
            stdio.StandardIO(SquidHandlerProtocol(cm, test))
            cm.start()
        except IOError, why:
            error(why)
        except ConfigParser.Error, why:
            error("Configuration file: %s\n" % why)
    finally:
        if pidfile and not test:
            try:
                os.unlink(pidfile)
            except OSError, why:
                error("Can't remove PID file (%s)." % why)

    

class Redirector:
    def __init__(self, reactor, config, test=False):
        """
        Responsible for managing the process, holding state (e.g., config, maps), 
        and managing the maps.
        """
        self.reactor = reactor
        self.config = config
        self.test = test
        self.local_maps = {} # maps loaded from local disk
        self.site_maps = {} # maps found on the net
        self.error_check = 30  # how often to look to see if an error 
                               # has cleared (seconds)
        self.gc_period = 60 * 30  # how often to garbage collect old maps
        self.min_check_time = 60  # minimum number of seconds between checks
        
        self.url_cache = CacheDict(auto_trim=False)
        self.url_cache_period = 60 * 30
        self.reactor.callLater(self.url_cache_period, self._trim_url_cache)

    def start(self):
        logging.info("start")
        # load local sites
        self._load_local_maps()
        # load remote sites
        if (not self.test) and self.config.getboolean(
            "main", "remote_map_lookup"
        ):
            dbfile = self.config.get("main", "dbfile")
            if dbfile:
                try:
                    db = open(dbfile, 'r')
                    for line in db:
                        self.add_site(line.strip())
                    db.close()
                except IOError, why:
                    logging.info("db_read_error (%s)" % why)
# FIXME: gc is borked; need to keep state about last_seen between invocations
#            self.reactor.callLater(self.gc_period, self._gc_remote_maps)     
        self.reactor.run()

    def shutdown(self):
        logging.info("stop")
        try:
            self.reactor.stop()
        except:
            pass
        if (not self.test) and self.config.getboolean(
            "main", "remote_map_lookup"
        ):
            dbfile = self.config.get("main", "dbfile")
            if dbfile:
                try:
                    db = open(dbfile, 'w')
                    for uri in self.site_maps.keys():
                        db.write("%s\n" % uri)
                    db.close()
                except IOError, why:
                    logging.error("db_write_error (%s)" % why)

    def add_site(self, base_uri):
        if not base_uri in self.site_maps.keys():
            self.site_maps[base_uri] = {'uri': base_uri}
            self._schedule_check(base_uri)
            logging.info("new_site_added <%s>" % base_uri)

    def add_callback(self, base_uri, cb):
        """ Call cb when base_uri's site info is updated."""
        if self.site_maps[base_uri].has_key('callbacks'):
            self.site_maps[base_uri]['callbacks'].append(cb)
        else:
            self.site_maps[base_uri]['callbacks'] = [cb]

    def _load_local_maps(self):
        map_dir = self.config.get("main", "local_map_dir")
        self.local_maps = {}
        if map_dir and os.path.isdir(map_dir):
            for filename in os.listdir(map_dir):
                # TODO: remember stat() mtime?
                try:
                    fh = open(os.path.join(map_dir, filename))
                except IOError, why:
                    logging.critical("Can't open local map %s: %s" % \
                        (filename, why)
                    )
                    continue
                try:
                    instr = fh.read()
                except IOError, why:
                    logging.critical("can't read local map %s: %s" % \
                        (filename, why)
                    )
                    continue
                finally:
                    fh.close()
                site = {}
                try:
                    # TODO: faster parser
                    site['map'] = minidom.parseString(instr) 
                    site['uri'] = site['map'].documentElement.getAttribute(
                        "base").lower()
                except expat.ExpatError, why:
                    logging.critical("Can't parse local map %s: %s" % \
                        (filename, why)
                    )
                    continue
                try:
                    assert site['uri']
                except AssertionError:
                    logging.critical("Base uri not found in local map %s" % \
                        filename
                    )
                    continue
                if site['uri'] == 'default' and \
                self.local_maps.has_key('default'):
                    logging.critical("Multiple default local maps found!")
                    continue
                logging.info("loaded local map %s with base <%s>" % (
                    filename, site['uri']
                ))
                self.local_maps[site['uri']] = site
        self.url_cache.clear() # TODO: something a bit more elegant?
        self.reactor.callLater(
            self.config.getint("main", "local_map_check"),
            self._load_local_maps
        )

    def _schedule_check(self, uri, when=0):
        logging.debug("scheduling check for <%s>..." % uri)
        def check():
            site = self.site_maps[uri]
            s = SiteMap(site, self._check_done, 
                        self._check_error, self.config, self.reactor
            )
            logging.debug("checking <%s>" % uri)
            s.check()
        logging.debug("schedule_check <%s> %2.2f" % (uri, when))
        self.reactor.callLater(when, check)

    def _check_done(self, site):
        logging.debug("check_done <%s> %2.2f" % (
            site['uri'], site['last_check_elapsed']
        ))
        now = time.time()
        site['last_check'] = now
        callbacks = self.site_maps[site['uri']].get("callbacks", [])
        site['callbacks'] = []
        self.site_maps[site['uri']] = site        
        while True:
            try:
                callbacks.pop()()
            except IndexError:
                break
        if not self.test:
            wait = max(self.min_check_time, site.get('expires', now) - now)
            self._schedule_check(site['uri'], wait)

    def _check_error(self, site, message=""):
        logging.warning("check_error <%s> %s" % (site['uri'], message))
        now = time.time()
        site['last_check'] = now
        callbacks = self.site_maps[site['uri']].get("callbacks", [])
        site['callbacks'] = []
        self.site_maps[site['uri']] = site
        while True:
            try:
                callbacks.pop()()
            except IndexError:
                break
        if not self.test:
            self._schedule_check(site['uri'], self.error_check) 
            # TODO: back-off algorithm

    def _gc_remote_maps(self):
        logging.info("garbage_collection")
        now = time.time()
        for uri in self.site_maps:
            last_activity_seen = self.site_maps[uri].get('last_access', 0)
            if (last_activity_seen < now - self.gc_period) and \
                self.site_maps[uri].hasattr('last_check'):
                logging.info("stopping monitoring of %s" % uri)
                del self.site_maps[uri]
        self.reactor.callLater(self.gc_period, self._gc_remote_maps)

    def _trim_url_cache(self):
        logging.info("trimming URL cache.")
        self.url_cache.trim()
        self.reactor.callLater(self.url_cache_period, self._trim_url_cache)


class SiteMap:
    """ A site's map. """
    def __init__(self, site, done_cb, error_cb, config, reactor):
        self.site = site
        self.done_cb = done_cb
        self.error_cb = error_cb
        self.reactor = reactor
        self.start_time = None
        self.map_location = config.get("main", "remote_map_location")
        self.fetch_timeout = config.getint("main", "fetch_timeout")
#        self.http_proxy = config.get("main", "http_proxy").strip()
        
    def check(self):
        self.start_time = time.time()
        self.fetch(urljoin(self.site['uri'], self.map_location))
                
    def fetch(self, uri, req_headers=None):
        # TODO: ims
        c = client.HTTPClientFactory(str(uri), 
            timeout=self.fetch_timeout, 
            headers=req_headers,
#            proxy=self.http_proxy  # TODO: proxy support
        )
        scheme, host, port, path = client._parse(uri)
        def callback(data):
            if data is None:
                self.site['map'] = None
            else:
                self.site['map'] = minidom.parseString(data)
            self.site['last_check_elapsed'] = time.time() - self.start_time
            remaining_lifetime = 0
            try:
                cc_str = ", ".join(
                    c.response_headers.get('cache-control', '')
                )
                max_age = int(parse_cc(cc_str).get('max-age', "0"))
                age = int(c.response_headers.get('age', ["0"])[-1])
                self.site['expires'] = time.time() + max_age - age
            except ValueError:
                logging.info("Bad CC or Age header on <%s>" % uri)
            
            self.done_cb(self.site)
        c.deferred.addCallback(callback)
        def errback(data):
            if data.type == web_error.Error:
                if data.value[0] in ["404", "410"]:
                    logging.warning("%s: %s" % (data.value[0], uri))
                    return callback(None)
                else:
                    msg = '"%s"' % (data.value)
            elif data.type == expat.ExpatError:
                msg = '"XML parsing error (%s)"' % data.value
            elif data.type == internet_error.DNSLookupError:
                msg = '"DNS lookup error"'
            elif data.type == internet_error.TimeoutError:
                msg = '"Timeout"'
            elif data.type == internet_error.ConnectionRefusedError:
                msg = '"Connection refused"'
            elif data.type == internet_error.ConnectError:
                msg = '"Connection error"'
            else:
                msg = '"Unknown error (%s)"' % traceback.format_exc()
            self.error_cb(self.site, msg)
        c.deferred.addErrback(errback)
        self.reactor.connectTCP(host, port, c)


default_port = {
                "http": "80",
                "https": "443",
                }


class SquidHandlerProtocol(LineReceiver):
    """
    Twisted protocol handler to talk to Squid via STDIN and STDOUT using
    Squid's redirector protocol.
    """
    delimiter = '\n'
    clock_fuzz = 5

    def __init__(self, manager, test=False):
        self.manager = manager
        self.test = test
        self.outstanding_reqnums = []
        
    def lineReceived(self, line):
        line = line.rstrip()
        logging.debug('handler_request %s' % line)
        if self.test:
            rest = line.strip()
            reqnum = None
        else:
            try:
                reqnum, rest = line.split(None, 1)
            except ValueError:
                logging.error("Cannot determine request number!")
                self.transport.write("\n") # attempt to keep things sane
                return
        if reqnum in self.outstanding_reqnums:
            logging.error("Duplicate request! %s - ignoring" % reqnum)
            self.transport.write("\n") # attempt to keep things sane
        else:
            self.outstanding_reqnums.append(reqnum)
            self.process(reqnum, rest)
        
    def sendResponse(self, reqnum, result, prefix=""):
        if self.test:
            self.transport.write("%s%s\n" % (prefix, result))
        else:
            self.transport.write("%s %s%s\n" % (reqnum, prefix, result))
        self.outstanding_reqnums.remove(reqnum)
        logging.debug("handler_response %s %s %s" % (reqnum, prefix, result))

    def connectionLost(self, reason):
        self.manager.shutdown()

    def process(self, reqnum, rest):
        """
        For each requested URL rewriter will receive on line with the format
        URL <SP> client_ip "/" fqdn <SP> user <SP> method <SP> urlgroup <NL>
        """
        
        try:
            if self.test:
                url = rest
            else:
                url, ip_fqdn, user, method, urlgroup = rest.split(None, 4)
            scheme, authority, path, query, fragid = urlsplit(url)
        except (IndexError, ValueError): 
            logging.warning("malformed line: %s" % rest)
            return self.sendResponse(reqnum, rest)

        # ignore squid internal URLs; using url.startswith 
        # cause urlsplit doesn't like _
        if url.startswith("cache_object:") or url.startswith("internal:"):
            logging.debug("leaving cachemgr/internal request alone")
            return self.sendResponse(reqnum, url)

        # ignore map requests
        if path == self.manager.config.get("main", "remote_map_location"):
            logging.debug("leaving map request alone")
            return self.sendResponse(reqnum, url)
            
        # cache lookup; cheap and easy
        if self.manager.url_cache.has_key(url):
            return self.sendResponse(reqnum, self.manager.url_cache[url])
            
        try:
            host, port = authority.split(":", 1)
        except ValueError:
            host, port = authority, default_port.get(scheme, None)
        host = host.lower()
        if host and host[-1] == '.':
            host = host[:-1]

        # see if we have a map
        if port == default_port.get(scheme, None):
            authority = host
        else:
            authority = "%s:%s" % (host, port)
        base_uri = urlunsplit((scheme, authority, '/', '' , ''))
        if self.manager.local_maps.has_key(base_uri):
            logging.debug("Using local map for <%s>" % base_uri)
            site = self.manager.local_maps[base_uri]
        elif self.manager.local_maps.has_key('default'):
            logging.debug("Using default map for <%s>" % base_uri)
            site = self.manager.local_maps['default']
            # don't allow someone to use default map as a proxy
            host, port = "", ""
        elif self.manager.config.getboolean("main", "remote_map_lookup"):
            if self.manager.site_maps.has_key(base_uri):
                logging.debug("Using net map for <%s>" % base_uri)
                site = self.manager.site_maps[base_uri]
                if not site.has_key('last_check'):
                    logging.info("site startup: <%s>" % base_uri)
                    if self.manager.config.getboolean(
                        "main", "remote_map_wait"
                    ):
                        def cb2():
                            self.process(reqnum, rest)
                        return self.manager.add_callback(base_uri, cb2)
                    else:
                        return self.sendResponse(reqnum, url) 
            else:
                logging.info("site not monitored: <%s>" % base_uri)
                self.manager.add_site(base_uri)
                if self.manager.config.getboolean("main", "remote_map_wait"):
                    def cb1():
                        self.process(reqnum, rest)
                    return self.manager.add_callback(base_uri, cb1)
                else:
                    return self.sendResponse(reqnum, url) 
        else:
            # we don't allow remote maps, and didn't find a local one, 
            # so deny the request.
            return self.sendResponse(reqnum, url, prefix="!deny!")
  
        if site.get('map', None) is None:
            return self.sendResponse(reqnum, url)
        
        path_list = path.split("/")
        query_list = cgi.parse_qsl(query, keep_blank_values=1)

        try:
            (host, port), path_list, query_list = \
                self.walk(
                    site['map'].documentElement, 
                    (host, port), 
                    path_list, 
                    query_list
                )
        except Exception, why:
            logging.error("can't walk map: %s (%s)" % (base_uri, why))
            return self.sendResponse(reqnum, url)

        # recalculate authority; map may have changed
        if port == default_port.get(scheme, None) or port == "":
            authority = host
        else:
            authority = "%s:%s" % (host, port)            
        result = urlunsplit((
            scheme, 
            authority, 
            "/".join(path_list), 
            urlencode(query_list), 
            ""
        ))
        self.manager.url_cache[url] = result
        return self.sendResponse(reqnum, result)

    def walk(self, node, authority_list, path_list, query_list):
        for n in node.childNodes:
            if n.nodeType != n.ELEMENT_NODE: 
                continue
            if n.nodeName == 'path':  
                continue
            try:
                authority_list, path_list, query_list = getattr(
                    self, 
                    "PROCESS_%s" % n.nodeName, 
                    self.default_process
                )(
                    n, 
                    authority_list, 
                    path_list, 
                    query_list
                )
            except Exception, why:
                logging.error("Problem processing %s: %s" % (n.nodeName, why))
        if len(path_list) > 1:
            current_seg = path_list[0]
            next_seg = path_list[1]
            path_conf = [n for n in \
                         node.childNodes \
                         if n.nodeType is n.ELEMENT_NODE and \
                         n.getAttribute('seg') == next_seg \
                        ]
            if path_conf:
                authority_list, path_list, query_list = self.walk(
                    path_conf[-1], 
                    authority_list, 
                    path_list[1:], 
                    query_list
                )
                path_list.insert(0, current_seg)
        return authority_list, path_list, query_list
        
    def PROCESS_authority(self, conf, authority_list, path_list, query_list):
        host = str(conf.getAttribute("host"))
        port = str(conf.getAttribute("port"))
        return (host, port), path_list, query_list

    def PROCESS_rewrite(self, conf, authority_list, path_list, query_list):
        new_path = str(conf.getAttribute("path"))
        if new_path == "":
            path_list.pop(0)
        else:
            path_list[0] = new_path 
        return authority_list, path_list, query_list
        
    def PROCESS_query(self, conf, authority_list, path_list, query_list):
        if len(conf.parentNode.getElementsByTagName("query")) > 1: 
            # deeper query overrides this one
            return authority_list, path_list, query_list
        if conf.getAttribute("sort") == "true":
            query_list.sort()
        if conf.getAttribute("lower_keys") == "true":
            query_list = [(k.lower(), v) for (k, v) in query_list]
        o = []
        for (k, v) in query_list:
            k_conf = conf.getElementsByTagName(k)
            if k_conf:
                k_conf = k_conf[-1]
                v = v.strip()
                type = k_conf.getAttribute("type")
                if type.startswith("bool"):
                    if v.lower() in ['0', 'no', 'off']: 
                        v = "0"
                    if v.lower() in ['1', 'yes', 'on']: 
                        v = "1"
                elif type.startswith("int"):
                    try:
                        v = str(int(round(float(v))))
                    except:
                        pass
                elif type == "lower":
                    v = str(v.lower())
                elif type == "upper":
                    v = str(v.upper())
                elif type == "fixed": 
                    # TODO: doesn't catch it if it's missing...
                    v = str(conf.getAttribute("value"))
                elif type == "none":
                    v = None
            elif conf.getAttribute("delete") == "true":
                k = None
            if k:
                o.append((k, v))
        return authority_list, path_list, o

# TODO: matrix c14n
            
    def default_process(self, conf, authority_list, path_list, query_list):
        logging.warning("Can't process %s" % conf.nodeName)
        return authority_list, path_list, query_list


def error(msg):
    logging.critical(msg)
    sys.stderr.write("FATAL: %s\n" % msg)
    sys.exit(1)


#############################################################################
# Support 
#############################################################################

from UserDict import UserDict
from heapq import nsmallest
class CacheDict(UserDict):
    def __init__(self, max_size=10000, trim_to=.8, auto_trim=True, **args):
        UserDict.__init__(self, **args)
        self.max_size = max_size
        self.auto_trim = auto_trim
        self._trim_size = max_size * trim_to
        self._serial = 0
        
    def __getitem__(self, key):
        self._serial += 1
        self.data[key][1] = self._serial
        return self.data[key][0]
        
    def __setitem__(self, key, value):
        self.data[key] = [value, len(self.data)]
        if self.auto_trim and len(self.data) > self.max_size:
            self.trim()

    def trim(self):
        if len(self.data) < self.max_size:
            return
        expired = nsmallest(
            self.max_size - int(self._trim_size), self.data, self.getkey
        )
        for key in expired:
            del self.data[key]
        self._serial = 0

    def getkey(self, key):
        return key[1]


try:
    unicode
except NameError:
    def _is_unicode(x):
        return 0
else:
    def _is_unicode(x):
        return isinstance(x, unicode)

def urlencode(query):
    """Encode a sequence of two-element tuples into a URL query string.
    Stolen from urllib.py; that one sucked.
    """

    # it's a bother at times that strings and string-like objects are
    # sequences...
    try:
        # non-sequence items should not work with len()
        # non-empty strings will fail this
        if len(query) and not isinstance(query[0], tuple):
            raise TypeError
        # zero-length sequences of all types will get here and succeed,
        # but that's a minor nit - since the original implementation
        # allowed empty dicts that type of behavior probably should be
        # preserved for consistency
    except TypeError:
        ty, va, tb = sys.exc_info()
        raise TypeError, \
            "not a valid non-string sequence or mapping object", tb

    l = []
    for k, v in query:
        k = quote(str(k))
        if isinstance(v, str):
            v = quote(v)
            l.append(k + '=' + v)
        elif _is_unicode(v):
            # is there a reasonable way to convert to ASCII?
            # encode generates a string, but "replace" or "ignore"
            # lose information and "strict" can raise UnicodeError
            v = quote(v.encode("ASCII","replace"))
            l.append(k + '=' + v)
        elif v is None:
            l.append(k)
        else:
            try:
                # is this a sufficient test for sequence-ness?
                x = len(v)
            except TypeError:
                # not a sequence
                v = quote(str(v))
                l.append(k + '=' + v)
            else:
                # loop over the sequence
                for elt in v:
                    l.append(k + '=' + quote(str(elt)))
    return '&'.join(l)

def parse_cc(instr, force_list=None):
    TOKEN = r'(?:[^\(\)<>@,;:\\"/\[\]\?={} \t]+?)'
    QUOTED_STRING = r'(?:"(?:\\"|[^"])*")'
    PARAMETER = r'(?:%(TOKEN)s(?:=(?:%(TOKEN)s|%(QUOTED_STRING)s))?)' % locals()
    COMMA = r'(?:\s*(?:,\s*)+)'
    PARAM_SPLIT = r'%s(?=%s|\s*$)' % (PARAMETER, COMMA)
    param_splitter = re.compile(PARAM_SPLIT)
    def _unquotestring(instr):
        if instr[0] == instr[-1] == '"':
            instr = instr[1:-1]
            instr = re.sub(r'\\(.)', r'\1', instr)
        return instr
    out = {}
    if not instr: 
        return out
    for param in [h.strip() for h in param_splitter.findall(instr)]:
        try:
            attr, value = param.split("=", 1)
            value = _unquotestring(value)
        except ValueError:
            attr = param
            value = True
        attr = attr.lower()
        if force_list and attr in force_list:
            if out.has_key(attr):
                out[attr].append(value)
            else:
                out[attr] = [value]
        else:
            out[attr] = value
    return out



if __name__ == '__main__':
    try:
        optlist, args = getopt.getopt(sys.argv[1:], 't')
    except getopt.GetoptError, why:
        error(why)        
    try:
        conf_loc = args[0]
    except IndexError:
        logging.info("No configuration file specified; running with defaults")
        conf_loc = ""
    test = False
    for o, a in optlist:
        if o == "-t":
            test = True
    if conf_loc and not os.path.exists(conf_loc):
        error("Can't find config file %s." % conf_loc)
    main(conf_loc, test)
