Squid Director
==============

Copyright (c) 2008-2010 Yahoo! Inc.
See src/director.py for license.


Overview
~~~~~~~~

**Director** is a `Squid <http://www.squid-cache.org/>`_ add-on
that allows you to easily:

-  **Canonicalise URLs** - to increase cache efficiency. For
   example, you can sort query terms, normalise typed query arguments,
   and drop ones that aren't recognised.
-  **Rewrite URLs** - to provide deployment flexibility. For
   example, you can change path segments (``index.html`` to
   ``index.php``) and change origin servers based on path segments
   (e.g., rewrite ``example.com/foo`` to
   ``another.example.com/foo`` while leaving the rest of
   example.com alone).
-  **Provide URL-based access control and processing** - to
   implement things like signed URLs, appid enforcement, etc (coming
   soon).

Director does this by reading a *map* for the site in question and
using that to change URIs before they're looked up in Squid's
cache.

**Maps** are simple XML files that describe the layout of the
origin server. They can be loaded from a directory on the Squid
server, or they can be
loaded from the origin server site itself, in a well-known location
(by default, ``/map.xml``; e.g.,
``http://example.com/map.xml``).


Local maps have precedence over remote ones; if a local map is
present, the remote map for that origin server will be ignored.


Using Director
~~~~~~~~~~~~~~

Director requires that you have:
- a recent Squid-2 installation <http://www.squid-cache.org>
- Python 2.6 or greater <http://www.python.org>
- Twisted <http://twistedmatrix.com/>

To use Director with your Squid installation, add the following to your
squid.conf::

  # setup Director
  url_rewrite_program /usr/local/libexec/squid/director.py /usr/local/etc/squid/director.conf
  url_rewrite_children 1
  # we run with a large concurrency in case fetching a map for a popular site is slow.
  url_rewrite_concurrency 10000
  # setup an urlgroup acl to allow Director to refuse requests.
  acl director_deny urlgroup deny
  http_access2 deny director_deny

adjusting the paths in the url_rewrite_program line as necessary.

The second argument to url_rewrite_program should point to the director.conf
file; a sample is included. Make sure that it is readable by the Squid user,
and that the paths refered to in the configuration file are writiable by
the Squid user as appropriate.

Then, restart your Squid::

  > /usr/local/bin/squid -k shutdown
  [wait]
  > /usr/local/bin/squid

After that, you can start writing maps for your sites. If you're
using Director in a proxy deployment, remote maps may be best for
you; if you're using it in an accelerator, try a local map with a
``base`` of ``default`` (see below).



Director Configuration Settings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**log\_level**
    How much detail to log. One of ( ``DEBUG``, ``INFO``, ``WARNING``,
    ``ERROR``, ``CRITICAL`` ). Default is ``INFO``.
**local\_map\_check**
    How often to check the local map director for updates. Integer
    number of seconds; default is ``60``.
**remote\_map\_lookup**
    Whether to look for remote maps. Default is ``on``.
**remote\_map\_location**
    Where to look for remote maps on origin servers. Default is
    ``/map.xml``.
**remote\_map\_wait**
    Whether to wait for remote maps to be loaded; otherwise, URLs for a
    given site will pass through without rewriting until the map is
    loaded, when rewriting will commence. Boolean (``on=/=off``),
    default is ``on``.


Note that if you change any of these settings after starting
Squid, you must **restart** it (not just reconfigure).


Writing Maps
~~~~~~~~~~~~

Maps are simple XML files (i.e., they don't even use namespaces).
The root element is ``map``. If the map file is local (i.e., loaded
from the Squid box's filesystem), it MUST have a ``base`` attribute
that indicates the base URI of the site it applies to (including
the port, if it's not the default port). E.g.::

  <map base="http://example.com:80/">

Note that the trailing slash **must** be included, as must the port
number if it isn't ``80``.

There is one special value for ``base``; ``default``. when
``base="default'``, the nominated local map will be used for
**all** requests that don't have a local map; remote maps won't be
used. ``base`` is ignored when the map is loaded from a remote
server.

``map`` can contain directives (see below), as well as one or more
``path`` elements. A path element represents a **single** path
segment in the URI space of that server, as indicated by the
``seg`` attribute, and can contain more ``path`` elements, as well
as directives. For example::

      <map base="http://example.com:80/">
         <path seg="images">
         </path>
         <path seg="scripts">
             <path seg="old">
                 <path seg="prototype.js">
                  </path>
             </path>
         </path>
      </map>


This indicates that on ``http://example.com:80``, the
following paths are interesting: ``/images``, ``/scripts``,
``/scripts/old``, ``/scripts/old/prototype.js``. Note that the
trailing '/' isn't significant; the innermost ``path`` will match
``/scripts/old/prototype.js/`` as well.


Map Directives
--------------

**Map directives** indicate what processing Director should apply
to URIs that match that path. Currently, the following directives
are supported;

authority
^^^^^^^^^

Matching URIs will have their authority (i.e., hostname and port)
rewritten to the specified values. MUST have a ``host`` attribute,
and MAY have a ``port`` attribute. E.g.::

      <map base="http://example.com:80/">
         <path seg="images">
             <authority host="images.example.com" port="8000"/>
         </path>
      </map>

will rewrite the URIs ``http://example.com:4080/images``,
``http://example.com/images/``,
``http://example.com/images/foo.jpg`` and
``http://example.com/images/foo/bar.jpg`` to all use the
origin server ``images.example.com``, port ``8000``.

Note that when Squid is running as an accelerator,
rewriting the authority will only have an effect if you don't specify any
accelerator origin servers as cache_peers. If you do this, you
MUST set ``remote_map_lookup`` to ``off``, so that the accelerator
can't be used as a proxy.

rewrite
^^^^^^^

Matching URIs will have the segment this directive occurs in
replaced with the specified value. MUST have a ``path`` attribute;
e.g.::

      <map base="http://example.com:80/">
         <path seg="images">
             <rewrite path="pix">
         </path>
      </map>

will rewrite the URIs:

-  ``http://example.com/images`` to
   ``http://example.com/pix``
-  ``http://example.com/images/`` to
   ``http://example.com/pix/``
-  ``http://example.com/images/foo.jpg`` to
   ``http://example.com/pix/foo.jpg``
-  ``http://example.com/images/foo/bar.jpg`` to
   ``http://example.com/pix/foo/bar.jpg``

query
^^^^^

Matching URIs will have their query arguments rewritten and
canonicalised as directed. This includes the following attributes:

``sort`` attribute
    if ``true``, will alphabetically sort the query arguments (using
    their keys, and values for identical keys). E.g., ``foo=1&bar=2``
    to ``bar=2&foo=1``.
``lower_keys`` attribute
    if ``true``, will lowercase all query argument keys; e.g.,
    ``FOo=bar`` to ``foo=bar``.
``delete`` attribute
    if ``true``, will delete any query arguments that aren't specified
    in element children (see below).

Additionally, you can **normalize query values** by specifying
element children of ``query``. For example::

      <map base="http://example.com:80/">
         <query lower_keys="true">
             <foo type="bool"/>
             <bar type="lower"/>
         </query>
      </map>

This indicates that the ``foo`` attribute, when present, is a
boolean, and will be normalised to ``0`` or ``1`` (from a variety
of values), while the ``bar`` attribute, when present, should be
lowercase-normalised.

The following value type normalisations are available;

-  ``bool``: ``0`` or ``1`` (e.g., ``foo=yes`` to ``foo=1``)
-  ``lower`` lowercase (e.g., ``foo=Bar`` to ``foo=bar``)
-  ``upper``: uppercase (e.g., ``foo=Bar`` to ``foo=BAR``)
-  ``int``: convert to integer (e.g., ``foo=04.3`` to ``foo=4``)
-  ``fixed`` use a fixed value (e.g., ``foo=abc`` to ``foo=def``)
-  ``none`` omit the value (e.g., ``foo=123`` to ``foo``)

Note that if a query argument is not present in the request-URI, it
will not be added (this includes fixed values, presently). If the
``delete`` attribute on ``query`` is ``true``, any arguments that
aren't specified in this manner will be deleted.

Also, note that only the most specifically matching ``query`` will
be applied; e.g., the following map::

      <map base="http://example.com:80/">
         <query lower_keys="true"/>
         <path seg="images">
             <query sort="true">
         </path>
      </map>

will only apply the innermost ``path`` to
``/http://example.com:80/images`` (etc.).


Frequently Asked Questions
~~~~~~~~~~~~~~~~~~~~~~~~~~

Using Director
--------------

Why should I put maps on my origin servers?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are two reasons;

#. Separating the configuration from the application it applies to
   is more likely to lead to them becoming out-of-sync; it's easy to
   forget configuration on another box.
#. If other parties consume your services and also use Director,
   they can benefit from increased efficiency -- lessening load on
   your servers.


What will happen when the map isn't loaded? Will users get errors?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a local map is present, it will always be loaded, so this isn't
a concern. However, if you're using remote maps, the first request
kicks off the request for the map. In this case, Director can
operate in two different modes;

#. ``always_wait=on`` - Director will wait for the
   map to load, so it can rewrite the URL. This is the default, and
   may result in added latency while the map is loaded.
#. ``always_wait=off`` - Director will start
   loading the map in the background, but immediately reply without
   modifying the URL, to avoid latency.

If your site depends on Director to rewrite URIs (e.g., in a
accelerator configuration),
and the back-end server can't cope with URLs that aren't rewritten,
the best strategy is to use local maps, so that users are always
sent to the correct place.

However, if you're using Director for canonicalisation or other
more forgiving transformations, try using remote maps, and consider
turning ``always_wait`` off.

How do I test my maps with Director?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Director has a command-line test mode; use it like this::

  > /usr/local/libexec/squid/director.py -t /usr/local/etc/squid/director.conf

Then, you can type in **only** the URI to be redirected; it will
respond with the rewritten URI. When doing this, you can see what's
happening in the log. Try setting ``log_level=DEBUG`` (reloading Ssquid
afterwards) if you want more information.

How often are maps refreshed?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Local maps will be re-checked every
``local_map_check`` seconds.

Remote maps will be refreshed according to their
``Cache-Control: max-age`` response header. If one isn't present,
or if it's too low, it will be checked every 60 seconds.

In both cases, maps will also be refreshed each time Squid is
reloaded or restarted.

How does Director handle errors?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There are a variety of errors that may happen in the process of
handling URIs from Squid, as well as working with maps.

Generally, Director will fall back to regurgitating the original
request-URI in the event of an error in communicating with Squid
(which is very unlikely).

In the event of a problem getting a map file (e.g., DNS problems,
TCP errors, XML parsing issues), Director will schedule a re-check
in the near future, and then regurgitate the request-URI.

In both cases, the problem will be noted in Director's log.

About Director
--------------

Director doesn't do what I need. Can I get something added to it?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Probably. We're very open to feature requests and new
functionality, provided that they don't affect overall performance.

Features that may be coming up (feedback appreciated!) include:

-  More flexible rewriting (e.g., rewriting the path base, not just
   the current segment, or rewriting all \*.html to \*.php)
-  Handling appid checks and signed URLs
-  Generating redirects for clients
-  Generating urlgroups that can be used with Squid ACLs
-  Rewriting, etc. based upon request headers (e.g., Cookie),
   request method, etc.
-  Per-IP (or even ynet) access control in the map
-  Matrix URI canonicalisation
-  Bucket (A/B) testing

Additionally, there are a number of things we can do to improve its
performance and manageability.

How does Director work?
^^^^^^^^^^^^^^^^^^^^^^^

Director is a Squid "helper process"; when squid starts, it
launches an instance of the helper and communicates with it on
STDIN and STDOUT. It's written in Python using the Twisted
event-driven framework.


How much overhead does Director add to a Squid box?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Director does use some CPU; in pathological circumstances, it may
even use nearly as much CPU as Squid itself. However, since most
modern deployments are on dual-CPU or multi-core boxes, it
shouldn't compete with Squid for resources.

Running a redirector of any kind does impose some overhead on Squid
processing; in our testing, for example,
a 4K response out of memory gets around 6,000 requests per second
without Director being used; when used with a redirector, this
drops to about 4,500 requests/sec. Although this is an absolute
drop in capacity, it's in pathological circumstances, where all
responses are served out of memory cache. In real-world
deployments, where the hit rate is lower because URLs aren't
canonicalised, Director can help increase the throughput and cache
efficiency you'll see.

Director shouldn't use noticable amounts of memory unless you have
a **very** large number of maps in active use.


How much latency does Director add to requests?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Popular URLs are cached in Director, to provide the fastest
possible service. In these cases, much less than a millisecond of
latency will be added to requests.

If a URL isn't cached, but the relevant map is already loaded in
Director, service is still very fast, often still far less than a
millisecond.

It is only when a map isn't loaded that Director may introduce noticeable
amounts of latency. There are a few ways to mitigate this;
- Use local maps; they are loaded at startup and therefore always available.
- Set always_wait to off; this will cause Director to return the request-URI
as-is immediately if it doesn't have the map loaded.
- Set Cache-Control: max-age as high as you can tolerate, to reduce the
  frequency of map reloads.

Why not just implement Apache's mod_rewrite in Squid?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

mod_rewrite is very powerful -- much more so than Director -- but because of
this is it often difficult to configure, and more importantly, CPU-intensive.
While Apache boxes are usually too busy to notice the overhead of evaluating
lots of regexen, Squid boxes -- which can easily handle thousands of requests
a second -- would quickly be bogged down if they had that much to do.

This is why the map is designed as a tree that can be walked on a per-request
basis with little overhead.

How does Director compare with other Squid redirectors (e.g., Squirm, Jesred)?
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Most existing redirectors use regex, which is fine if you only have one or two
rules. However, regex doesn't scale well when you have a large number of
rules; each rule has to be evaluated for each request, until a match is found.
This is why Director takes a tree-based approach.

Director is also somewhat specialised for URL canonicalisation; while this is
possible using regex, it's hard to get right every time.

Also, Director's ability to get site maps from the origin server on demand
makes it easier to use optimistically with a large number of clients that you
don't control, especially for URL canonicalisation.

This isn't to say that these other redirectors don't have their uses; they may
be faster or more flexible than Director in some scenarios.

  