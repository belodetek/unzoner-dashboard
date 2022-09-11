# -*- coding: utf-8 -*-

import json
import requests
import inspect
from pprint import pprint
from inspect import stack
from datetime import datetime

from .utils import retry
from .config import *


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def get_btc_price(currency=DEFAULT_CURRENCY):
    res = requests.get('{}/api/v{}/bitcoin/btc_price/{}'.format(
        API_HOST,
        API_VERSION,
        currency
    ))
    if DEBUG: print('{}: {}'.format(stack()[0][3], res))
    if res.status_code == 200:
        try:
            return int(res.content.decode('utf-8'))
        except:
            return int(res.content)
    return None
    

@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def generate_payment_address(guid=None):
    if not guid: return None
    headers = {
        'X-Auth-Token': API_SECRET
    }
    res = requests.get(
        '{}/api/v{}/bitcoin/payment_address/guid/{}'.format(
            API_HOST,
            API_VERSION,
            guid
        ),
        headers=headers
    )
    if DEBUG: print('{}: {}'.format(stack()[0][3], res))
    if res.status_code == 200:
        try:
            return res.content.decode('utf-8')
        except:
            return res.content
    return None
