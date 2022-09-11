# -*- coding: utf-8 -*-

import json
import requests
import inspect
from inspect import stack
from traceback import print_exc
from datetime import (datetime, time)

try:
    from httplib import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN
    )
except ImportError:
    from http.client import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN
    )

from .utils import retry
from .config import *


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_device(guid=None):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/device/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    device = dict()
    try:
        device = json.loads(res.content)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
    return device


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_device(guid=None, device_type=2, af=4):
    if not guid: return None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/device/{}/{}/{}'.format(
            API_HOST,
            API_VERSION,
            device_type,
            guid,
            af
        ),
        headers=headers
    )
    device = dict()
    try:
        device = json.loads(res.content)
    except:
        pass
    return device


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def resin_device_action(guid=None, action='restart'):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/device/{}/{}'.format(
            API_HOST,
            API_VERSION,
            guid,
            action
        ),
        headers=headers
    )
    return res


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def disable_device_status(guid=None, device_type=None):
    assert guid and device_type
    for af in AF_TYPES:
        data =  {
            'bytesin': 0,
            'bytesout': 0,
            'conns': 0,
            'weight': 0,
            'city': None,
            'country': None,
            'guid': guid,
            'ip': None,
            'proto': af,
            'status': 0,
            'type': device_type
        }
        headers = {
            'X-Auth-Token': API_SECRET
        }
        res = requests.put(
            '{}/api/v{}/device/{}/{}/{}'.format(
                API_HOST,
                API_VERSION,
                device_type,
                guid,
                af
            ),
            data=json.dumps(data),
            headers=headers
        )
        if res.status_code not in [OK]:
            raise AssertionError((res.status_code, res.content))
        return (res.status_code, res.content)


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_resin_envs(guid=None, appid=None):
    if not guid: return None
    result = None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/device/{}/env'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    try:
        return json.loads(res.content)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()

    if appid:
        res = requests.get(
            '{}/api/v{}/app/{}/env'.format(
                API_HOST,
                API_VERSION,
                appid
            ),
            headers=headers
        )
        try:
            return json.loads(res.content)
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def delete_resin_device_env(guid=None, name=None):
    if not guid and not name: return None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.delete(
        '{}/api/v{}/device/{}/env/{}'.format(
            API_HOST,
            API_VERSION,
            guid,
            name
        ),
        headers=headers
    )
    result = None
    try:
        try:
            result = res.content.decode('utf-8')
        except:
            result = res.content
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def update_resin_env_var(guid=None, name=None, value=None):
    if not guid and not name: return None
    headers = {
        'X-Auth-Token': API_SECRET,
        'Content-Type': 'application/json'
    }
    res = requests.get(
        '{}/api/v{}/device/{}/env'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    evs = None
    if res.status_code in [OK]: evs = json.loads(res.content)
    if evs:
        env_id = None
        for ev in evs['d']:
            if ev['env_var_name'] == name:
                device_id = ev['device']['__id']
                env_id = ev['id']
                if not value:
                    # delete env var
                    res = requests.delete(
                        '{}/api/v{}/env/{}/dev/{}'.format(
                            API_HOST,
                            API_VERSION,
                            env_id,
                            device_id
                        ),
                        headers=headers
                    )
                    if res.status_code in [OK]: return True
                else:
                    data = {
                        'value': value
                    }
                    # update env var
                    res = requests.patch(
                        '{}/api/v{}/env/{}/dev/{}'.format(
                            API_HOST,
                            API_VERSION,
                            env_id,
                            device_id
                        ),
                        data=json.dumps(data),
                        headers=headers
                    )
                    if res.status_code in [OK]: return True
        if not env_id:
            # create env var
            device = get_resin_device(guid=guid)
            data = {
                'env_var_name': name,
                'value': value
            }
            res = requests.put(
                '{}/api/v{}/device/{}/env'.format(
                    API_HOST,
                    API_VERSION,
                    guid
                ),
                headers=headers,
                data=json.dumps(data)
            )
            if res.status_code in [OK]: return True
    return False


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_speedtest(guid=None):
    result = dict()
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/speedtest/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    if DEBUG: print('{}: {}, {}'.format(
        stack()[0][3],
        res.status_code,
        res.content
    ))
    result = None
    try:
        result = json.loads(res.content)
    except:
        pass
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def enqueue_speedtest(guid=None):
    result = dict()
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.put(
        '{}/api/v{}/speedtest/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    result = None
    try:
        result = json.loads(res.content)
    except Exception as e:
        if DEBUG: print_exc()
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def dequeue_speedtest(guid=None):
    result = False
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.head(
        '{}/api/v{}/speedtest/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    if res.status_code in [NO_CONTENT]: result = True
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_iotest(test=0, guid=None):
    result = dict()
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/iotest/{}/guid/{}'.format(
            API_HOST,
            API_VERSION,
            test,
            guid
        ),
        headers=headers
    )
    if DEBUG: print(
        '{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        )
    )
    result = None
    try:
        result = json.loads(res.content)
    except:
        pass
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def enqueue_iotest(test=0, guid=None):
    result = dict()
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.put(
        '{}/api/v{}/iotest/{}/guid/{}'.format(
            API_HOST,
            API_VERSION,
            test,
            guid
        ),
        headers=headers
    )
    result = None
    try:
        result = json.loads(res.content)
    except Exception as e:
        if DEBUG: print_exc()
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def dequeue_iotest(guid=None):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/iotest/queue/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_country_alpha2(country=None, default='US'):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    try:
        res = requests.get(
            '{}/api/v{}/country/{}'.format(
                API_HOST,
                API_VERSION,
                country
            ),
            headers=headers
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    return default


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_available_countries():
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/countries/available'.format(
            API_HOST,
            API_VERSION
        ),
        headers=headers
    )
    if res.status_code in [OK]:
        return json.loads(res.content)
    else:
        return dict()


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_available_services(alpha=None, default=False):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/alpha/{}/services/default/{}'.format(
            API_HOST,
            API_VERSION,
            alpha.upper(),
            str(int(default))
        ),
        headers=headers
    )
    if res.status_code in [OK]:
        try:
            return res.content.decode('utf-8').split()
        except:
            return res.content.split()
    else:
        return dict()

    
@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_test_screenshot(alpha='US'):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/screenshot/{}'.format(
            API_HOST,
            API_VERSION,
            alpha.upper()
        ),
        headers=headers
    )
    try:
        result = json.loads(res.content)
    except Exception:
        result = None
    return result


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_test_tag_screenshots(limit=3):
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/screenshot/tags/{}'.format(
            API_HOST,
            API_VERSION,
            limit
        ),
        headers=headers
    )
    try:
        result = json.loads(res.content)
    except Exception:
        result = list()
    return result
