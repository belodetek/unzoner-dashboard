# -*- coding: utf-8 -*-

import json
import requests
import inspect
from inspect import stack
from traceback import print_exc
from base64 import b64encode

try:
    from httplib import OK
except ImportError:
    from http.client import OK

from .utils import retry
from .config import *


def get_paypal_subscription_url(data=None):
    if not data: return None
    return '{}/api/v{}/paypal/billing-agreements/{}/create'.format(
        API_HOST,
        API_VERSION,
        b64encode(data.encode('utf-8')).decode('utf-8')
    )    


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_paypal_subscription(baid=None):
    if not baid: return None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/paypal/billing-agreements/{}'.format(
            API_HOST,
            API_VERSION,
            baid
        ),
        headers=headers
    )
    if DEBUG: print('{}: status_code={} content={}'.format(
        stack()[0][3],
        res.status_code,
        res.content
    ))
    if res.status_code in [OK]:
        sub = json.loads(res.content)
        return sub


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def check_active_paypal_subscription(guid=None):
    if not guid: return None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/device/{}/env/{}'.format(
            API_HOST,
            API_VERSION,
            guid,
            'PAYPAL_BILLING_AGREEMENT'
        ),
        headers=headers
    )
    if DEBUG: print('{}: status_code={} content={}'.format(
        stack()[0][3],
        res.status_code,
        res.content
    ))
    if res.status_code in [OK]:
        try:
            baid = res.content.decode('utf-8')
        except:
            baid = res.content
        res = requests.get(
            '{}/api/v{}/paypal/billing-agreements/{}/confirm'.format(
                API_HOST,
                API_VERSION,
                baid
            ),
            headers=headers
        )
        if DEBUG: print('{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        ))
        if res.status_code in [OK]:
            payload = json.loads(res.content)
            if payload['agreement_state'] in ['active']: return baid
    return False
