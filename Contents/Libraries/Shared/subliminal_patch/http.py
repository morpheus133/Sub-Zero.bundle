# coding=utf-8
import urllib2
import xmlrpclib
from xmlrpclib import SafeTransport, ProtocolError, Fault, Transport

import certifi
import ssl
import os
import socket
import logging
import requests
from requests import Session, exceptions
from retry.api import retry_call

from subzero.lib.io import get_viable_encoding

logger = logging.getLogger(__name__)

pem_file = os.path.normpath(os.path.join(os.path.dirname(os.path.normpath(unicode(__file__, get_viable_encoding()))), "..", certifi.where()))
try:
    default_ssl_context = ssl.create_default_context(cafile=pem_file)
except AttributeError:
    # < Python 2.7.9
    default_ssl_context = None


class RetryingSession(Session):
    proxied_functions = ("get", "post")

    def __init__(self):
        super(RetryingSession, self).__init__()
        self.verify = pem_file

    def retry_method(self, method, *args, **kwargs):
        return retry_call(getattr(super(RetryingSession, self), method), fargs=args, fkwargs=kwargs, tries=3, delay=5,
                          exceptions=(exceptions.ConnectionError,
                                      exceptions.ProxyError,
                                      exceptions.SSLError,
                                      exceptions.Timeout,
                                      exceptions.ConnectTimeout,
                                      exceptions.ReadTimeout,
                                      socket.timeout))

    def get(self, *args, **kwargs):
        return self.retry_method("get", *args, **kwargs)

    def post(self, *args, **kwargs):
        return self.retry_method("post", *args, **kwargs)


class SubZeroTransport(SafeTransport):
    """
    Timeout and proxy support for ``xmlrpc.client.(Safe)Transport``
    """
    def __init__(self, timeout, url, *args, **kwargs):
        SafeTransport.__init__(self, *args, **kwargs)
        self.timeout = timeout
        self.host = None
        self.proxy = None
        self.scheme = url.split('://', 1)[0]
        self.https = url.startswith('https')
        if self.https:
            self.proxy = os.environ.get('SZ_HTTPS_PROXY')
            self.context = default_ssl_context
        else:
            self.proxy = os.environ.get('SZ_HTTP_PROXY')
        if self.proxy:
            logger.debug("Using proxy: %s", self.proxy)
            self.https = self.proxy.startswith('https')

    def make_connection(self, host):
        self.host = host
        if self.proxy:
            host = self.proxy.split('://', 1)[-1]
        if self.https:
            c = SafeTransport.make_connection(self, host)
        else:
            c = Transport.make_connection(self, host)

        c.timeout = self.timeout

        return c

    def send_request(self, connection, handler, request_body):
        handler = '%s://%s%s' % (self.scheme, self.host, handler)
        Transport.send_request(self, connection, handler, request_body)


class Urllib2Transport(xmlrpclib.Transport):
    def __init__(self, opener=None, https=False, use_datetime=0):
        xmlrpclib.Transport.__init__(self, use_datetime)
        self.opener = opener or urllib2.build_opener()
        self.https = https

    def request(self, host, handler, request_body, verbose=0):
        proto = ('http', 'https')[bool(self.https)]
        req = urllib2.Request('%s://%s%s' % (proto, host, handler), request_body)
        req.add_header('User-agent', self.user_agent)
        self.verbose = verbose
        return self.parse_response(requests.get('https://remotehost/info', proxies=proxies))


class HTTPProxyTransport(Urllib2Transport):
    def __init__(self, proxies, use_datetime=0):
        opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
        Urllib2Transport.__init__(self, opener, use_datetime=use_datetime)


class HTTPSProxyTransport(Urllib2Transport):
    def __init__(self, proxies, use_datetime=0):
        logger.exception("PING PONG YOLO", proxies)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        opener = urllib2.build_opener(urllib2.ProxyHandler(proxies))
        Urllib2Transport.__init__(self, opener, https=True, use_datetime=use_datetime)


class RequestsTransport(xmlrpclib.Transport):
    """
    Drop in Transport for xmlrpclib that uses Requests instead of httplib
    """
    # change our user agent to reflect Requests
    user_agent = "Python XMLRPC with Requests (python-requests.org)"

    # override this if you'd like to https
    use_https = True

    def __init__(self, proxies, user_agent, use_datetime=0):
        self.proxies = proxies
        self.user_agent = user_agent

    def request(self, host, handler, request_body, verbose):
        """
        Make an xmlrpc request.
        """
        headers = {'User-Agent': self.user_agent}
        #headers = {}
        url = self._build_url(host, handler)
        try:
            resp = requests.post(url, data=request_body, headers=headers, proxies=self.proxies)
        except ValueError:
            raise
        except Exception:
            raise # something went wrong
        else:
            try:
                resp.raise_for_status()
            except requests.RequestException as e:
                raise xmlrpclib.ProtocolError(url, resp.status_code,
                                                        str(e), resp.headers)
            else:
                return self.parse_response(resp)

    def parse_response(self, resp):
        """
        Parse the xmlrpc response.
        """
        p, u = self.getparser()
        p.feed(resp.text)
        p.close()
        return u.close()

    def _build_url(self, host, handler):
        """
        Build a url for our request based on the host, handler and use_http
        property
        """
        scheme = 'https' if self.use_https else 'http'
        return '%s://%s/%s' % (scheme, host, handler)
