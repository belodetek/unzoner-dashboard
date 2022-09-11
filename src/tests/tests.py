import json

from nose.tools import ok_, eq_

try:
    from httplib import OK, FOUND
except ImportError:
    from http.client import OK, FOUND

from app import create_app
from hashlib import md5
from uuid import uuid4


TEST_GUID = 'b55b561ea8fcc9b11105f05f1e8b5095'


application = create_app()
app = application.test_client()


class Endpoint(object):
    def __init__(self, url, status_code, content_type):
        self.url = url
        self.status_code = status_code
        self.content_type = content_type


class ResponseContent(object):
    def __init__(self, url, md5):
        self.url = url
        self.md5 = md5


def test_status_endpoint():
    response = app.get('/ping')
    ok_(response.status_code == OK)
    eq_(json.loads(response.data), {'ping': 'pong'})


def test_endpoints_return_correct_content_type_and_response_code():
    def check_endpoint_content_type_and_response_code(endpoint):
        response = app.get(endpoint.url)
        ok_(response.status_code == endpoint.status_code)
        ok_(response.headers['Content-Type'])
        eq_(response.headers['Content-Type'], endpoint.content_type)

    for endpoint in [
        Endpoint('/OneSignalSDKUpdaterWorker.js', OK, 'application/javascript'),
        Endpoint('/OneSignalSDKWorker.js', OK, 'application/javascript'),
        Endpoint('/sub', OK, 'text/html; charset=utf-8'),
        Endpoint('/?guid={}'.format(TEST_GUID), OK, 'text/html; charset=utf-8'),
        Endpoint(
            '/config?guid={}&device_type={}&name={}&value={}'.format(
                TEST_GUID,
                5,
                'TARGET_COUNTRY',
                'United States'
            ),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/vpn?guid={}&device_type={}'.format(TEST_GUID, 5),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/service?guid={}&device_type={}&alpha2={}&country={}'.format(
                TEST_GUID,
                5,
                'gb',
                'United Kingdom'
            ),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/pair?guid={}&device_type={}&PAIRED_DEVICE_GUID={}'.format(
                TEST_GUID,
                5,
                uuid4().hex
            ),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/unpair?guid={}&device_type={}'.format(TEST_GUID, 5),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/set?guid={}&device_type={}&value={}'.format(TEST_GUID, 5, 2),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/speedtest?guid={}'.format(TEST_GUID),
            FOUND,
            'text/html; charset=utf-8'
        ),
        Endpoint(
            '/control?guid={}&action={}'.format(TEST_GUID, 'restart'),
            FOUND,
            'text/html; charset=utf-8'
        )
    ]:
        yield check_endpoint_content_type_and_response_code, endpoint


def test_endpoints_return_correct_content():
    def check_endpoint_content(res):
        response = app.get(res.url)
        ok_(response.status_code == OK)
        m = md5()
        checksum = m.update(response.data)
        digest = m.hexdigest()
        eq_(res.md5, digest)

    for response in [
        ResponseContent('/OneSignalSDKUpdaterWorker.js', 'f515315e2e1824a323af6ca6859fc69a'),
        ResponseContent('/OneSignalSDKWorker.js', 'f515315e2e1824a323af6ca6859fc69a')
    ]:
        yield check_endpoint_content, response

