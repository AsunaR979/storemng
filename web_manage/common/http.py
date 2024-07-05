import copy
import logging
import socket
import hashlib
import requests
import six
import six.moves.urllib.parse as urlparse
from web_manage.cluster.models import *

try:
    import json
except ImportError:
    import simplejson as json

from . import encodeutils
from . import constants
from .errcode import get_error_result

USER_AGENT = 'storesys'
SENSITIVE_HEADERS = ('X-Auth-Token', )
TOKEN_HEADERS = ['X-Auth-Token', 'X-Service-Token']

logger = logging.getLogger(__name__)

def safe_header(name, value):
    if value is not None and name in SENSITIVE_HEADERS:
        h = hashlib.sha1(value)
        d = h.hexdigest()
        return name, "{SHA1}%s" % d
    else:
        return name, value


def encode_headers(headers):
    """Encodes headers.

    Note: This should be used right before
    sending anything out.

    :param headers: Headers to encode
    :returns: Dictionary with encoded headers'
              names and values
    """
    # NOTE(rosmaita): This function's rejection of any header name without a
    # corresponding value is arguably justified by RFC 7230.  In any case, that
    # behavior was already here and there is an existing unit test for it.

    # Bug #1766235: According to RFC 8187, headers must be encoded as ASCII.
    # So we first %-encode them to get them into range < 128 and then turn
    # them into ASCII.
    encoded_dict = {}
    for h, v in headers.items():
        if v is not None:
            # if the item is token, do not quote '+' as well.
            # NOTE(imacdonn): urlparse.quote() is intended for quoting the
            # path part of a URL, but headers like x-image-meta-location
            # include an entire URL. We should avoid encoding the colon in
            # this case (bug #1788942)
            safe = '=+/' if h in TOKEN_HEADERS else '/:'
            if six.PY2:
                # incoming items may be unicode, so get them into something
                # the py2 version of urllib can handle before percent encoding
                key = urlparse.quote(encodeutils.safe_encode(h), safe)
                value = urlparse.quote(encodeutils.safe_encode(v), safe)
            else:
                key = urlparse.quote(h, safe)
                value = urlparse.quote(v, safe)
            encoded_dict[key] = value
    return dict((encodeutils.safe_encode(h, encoding='ascii'),
                 encodeutils.safe_encode(v, encoding='ascii'))
                for h, v in encoded_dict.items())


class _BaseHTTPClient(object):

    @staticmethod
    def _chunk_body(body):
        chunk = body
        while chunk:
            chunk = body.read(constants.CHUNKSIZE)
            if not chunk:
                break
            yield chunk

    def _set_common_request_kwargs(self, headers, kwargs):
        """Handle the common parameters used to send the request."""
        # Default Content-Type is octet-stream
        content_type = headers.get('Content-Type', 'application/octet-stream')

        data = kwargs.pop("data", None)
        if data is not None and not isinstance(data, six.string_types):
            try:
                data = json.dumps(data)
                content_type = 'application/json'
            except TypeError:
                # Here we assume it's
                # a file-like object
                # and we'll chunk it
                data = self._chunk_body(data)
        json_data = kwargs.pop("json", None)
        if json_data is not None and not isinstance(data, six.string_types):
            content_type = 'application/json'

        headers['Content-Type'] = content_type
        kwargs['stream'] = content_type == 'application/octet-stream'

        return data

    def _handle_response(self, resp):
        if not resp.ok:
            logger.error("Request returned failure status %s.", resp.status_code)
            raise Exception("Request return is not ok")

        content_type = resp.headers.get('Content-Type')

        # Read body into string if it isn't obviously image data
        if content_type == 'application/octet-stream':
            logger.debug("the content_type is application/octet-stream")
            # Do not read all response in memory when downloading an image.
            body_iter = _close_after_stream(resp, constants.CHUNKSIZE)
        else:
            content = resp.text
            if content_type and content_type.startswith('application/json'):
                # Let's use requests json method, it should take care of
                # response encoding
                logger.debug("the content_type is application/json")
                body_iter = resp.json()
            else:
                body_iter = six.StringIO(content)
                try:
                    body_iter = json.loads(''.join([c for c in body_iter]))
                except ValueError:
                    body_iter = None

        return resp, body_iter


class HTTPClient(_BaseHTTPClient):

    def __init__(self, endpoint, **kwargs):
        self.endpoint = endpoint
        self.auth_token = kwargs.get('token')
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.timeout = float(kwargs.get('timeout', 600))
        self.peerIp = ""

    @staticmethod
    def log_http_response(resp):
        status = (resp.raw.version / 10.0, resp.status_code, resp.reason)
        dump = ['\nHTTP/%.1f %s %s' % status]
        headers = resp.headers.items()
        dump.extend(['%s: %s' % safe_header(k, v) for k, v in headers])
        dump.append('')
        content_type = resp.headers.get('Content-Type')

        if content_type != 'application/octet-stream':
            dump.extend([resp.text, ''])
        logger.debug('\n'.join([encodeutils.safe_decode(x, errors='ignore')
                                 for x in dump]))

    def _request(self, method, url, **kwargs):
        """Send an http request with the specified characteristics.

        Wrapper around httplib.HTTP(S)Connection.request to handle tasks such
        as setting headers and error handling.
        """
        # Copy the kwargs so we can reuse the original in case of redirects
        headers = copy.deepcopy(kwargs.pop('headers', {}))

        data = self._set_common_request_kwargs(headers, kwargs)
        logger.debug("the request data:%s", data)

        # add identity header to the request
        if not headers.get('X-Auth-Token'):
            headers['X-Auth-Token'] = self.auth_token

        headers = encode_headers(headers)

        if self.endpoint.endswith("/") or url.startswith("/"):
            conn_url = "%s%s" % (self.endpoint, url)
        else:
            conn_url = "%s/%s" % (self.endpoint, url)
        try:
            logger.debug("start requests, method:%s, url:%s", method, conn_url)
            resp = self.session.request(method,
                                        conn_url,
                                        data=data,
                                        headers=headers,
                                        timeout=self.timeout,
                                        **kwargs)
        except requests.exceptions.Timeout as e:
            message = ("Error communicating with %(url)s: %(e)s" %
                       dict(url=conn_url, e=e))
            logger.error(message)
            raise e
        except requests.exceptions.ConnectionError as e:
            message = ("Error finding address for %(url)s: %(e)s" %
                       dict(url=conn_url, e=e))
            logger.error(message)
            raise e
        except socket.gaierror as e:
            message = "Error finding address for %s: %s" % (
                conn_url, e)
            logger.error(message)
            raise e
        except (socket.error, socket.timeout, IOError) as e:
            endpoint = self.endpoint
            message = ("Error communicating with %(endpoint)s %(e)s" %
                       {'endpoint': endpoint, 'e': e})
            logger.error(message)
            raise e

        resp, body_iter = self._handle_response(resp)
        self.log_http_response(resp)
        return resp, body_iter

    def head(self, url, **kwargs):
        return self._request('HEAD', url, **kwargs)

    def get(self, url, **kwargs):
        return self._request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self._request('POST', url, **kwargs)

    def put(self, url, **kwargs):
        return self._request('PUT', url, **kwargs)

    def patch(self, url, **kwargs):
        return self._request('PATCH', url, **kwargs)

    def delete(self, url, **kwargs):
        return self._request('DELETE', url, **kwargs)


def _close_after_stream(response, chunk_size):
    """Iterate over the content and ensure the response is closed after."""
    # Yield each chunk in the response body
    for chunk in response.iter_content(chunk_size=chunk_size):
        yield chunk
    # Once we're done streaming the body, ensure everything is closed.
    # This will return the connection to the HTTPConnectionPool in urllib3
    # and ideally reduce the number of HTTPConnectionPool full warnings.
    logger.info("close after stream")
    response.close()


def peer_post(url, data, peerIp=None, version=None, timeout=180):
    if not version:
        version = "v1.0"
    port = constants.WEB_DEFAULT_PORT
    # 从数据库中获取对端机器的接口请求ip地址(peerIp 主机绑定前必须输入)
    if peerIp == None:
        try:
            peerIp =  ClusterNode.objects.values("ip", "host_name").first()["ip"]
        except Exception as e:
            logger.error("数据库获取对端主机ip失败，可能是主机没有绑定导致")
            ret = get_error_result("SystemError")
            ret['data'] = "主机绑定异常"
            return ret
    endpoint = 'http://%s:%s' % (peerIp, port)
    http_client = HTTPClient(endpoint, timeout=timeout)
    headers = {
        "Content-Type": "application/json",
        # backend request, not authenticate
        "AUTHORIZATION": b"backend" 
    }
    if not url.startswith("/api/"):
        url = "/api/%s/%s"% (version, url.lstrip('/'))

    try:
        resp, body = http_client.post(url, data=data, headers=headers)
    except requests.exceptions.ConnectionError as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "节点server服务连接失败"
        return ret
    except requests.exceptions.Timeout as e:
        ret = get_error_result("ServerServiceTimeout")
        ret['data'] = "节点server服务请求超时"
        return ret
    except socket.gaierror as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "节点server服务连接失败"
        return ret
    except (socket.error, socket.timeout, IOError) as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "节点server服务连接失败"
        return ret
    except Exception as e:
        return get_error_result("ServerServiceUnavaiable")
    return body

def activate_post(url, data, authIp, authPort, timeout=180):
    endpoint = 'http://%s:%s' % (authIp, authPort)
    http_client = HTTPClient(endpoint, timeout=timeout)
    headers = {
        "Content-Type": "application/json",
        # backend request, not authenticate
        "AUTHORIZATION": b"backend" 
    }
    try:
        resp, body = http_client.post(url, data=data, headers=headers)
    except requests.exceptions.ConnectionError as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "激活server服务连接失败"
        return ret
    except requests.exceptions.Timeout as e:
        ret = get_error_result("ServerServiceTimeout")
        ret['data'] = "激活server服务请求超时"
        return ret
    except socket.gaierror as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "激活server服务连接失败"
        return ret
    except (socket.error, socket.timeout, IOError) as e:
        ret = get_error_result("ServerServiceUnavaiable")
        ret['data'] = "激活server服务连接失败"
        return ret
    except Exception as e:
        return get_error_result("ServerServiceUnavaiable")
    return body

