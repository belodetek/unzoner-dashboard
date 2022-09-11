# -*- coding: utf-8 -*-

import time
import smtplib
import jwt

try:
    from secrets import token_urlsafe
except:
    from base64 import b64encode
    from hashlib import sha256
    from random import choice, getrandbits

from inspect import stack
from traceback import print_exc
from functools import wraps
from multiprocessing import Process
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import TemplateNotFound
from flask import render_template, abort

try:
    from httplib import INTERNAL_SERVER_ERROR
except:
    from http.client import INTERNAL_SERVER_ERROR

from .config import *


def retry(ExceptionToCheck, tries=DEFAULT_TRIES, delay=DEFAULT_DELAY, backoff=DEFAULT_BACKOFF, cdata=None):
    '''Retry calling the decorated function using an exponential backoff.
    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry
    :param ExceptionToCheck: the exception to check. may be a tuple of
        exceptions to check
    :type ExceptionToCheck: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    '''
    def deco_retry(f):
        @wraps(f)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 0:
                try:
                    return f(*args, **kwargs)
                except ExceptionToCheck as e:
                    print('{}, retrying in {} seconds (mtries={}): {}'.format(
                        repr(e),
                        mdelay,
                        mtries,
                        str(cdata)
                    ))
                    if DEBUG: print_exc()
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            return f(*args, **kwargs)
        return f_retry  # true decorator
    return deco_retry


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def generate_hash_key(bits=256):
    try:
        return token_urlsafe(32)
    except:
        return b64encode(
            sha256(str(getrandbits(bits))).digest(),
            choice(['rA', 'aZ', 'gQ', 'hH', 'hG', 'aR', 'DD'])
        ).rstrip('==')


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def smtp_send(
    subject=None,
    rcpt_to=None,
    body=None,
    preamble='Dashboard alert',
    daemon=False
):

    def smtp_send(subject, rcpt_to, preamble, body):
        if not SMTP_FROM: return False
        msg = MIMEMultipart('alternative')
        plain = MIMEText(body[0], 'plain')
        html = MIMEText(body[1], 'html')
        msg.attach(plain)
        msg.attach(html)
        msg['From'] = SMTP_FROM
        msg['To'] = rcpt_to
        msg['Subject'] = subject
        msg.preamble = preamble
        if DEBUG: print('msg={}'.format(msg))
        smtp = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT)
        print('smtp={} ehlo={} login={} sendmail={} quit={}'.format(
            smtp,
            smtp.ehlo(),
            smtp.login(SMTP_USERNAME, SMTP_PASSWORD),
            smtp.sendmail(SMTP_FROM, rcpt_to, msg.as_string()),
            smtp.quit()
        ))
        return True
    
    if subject and body:
        if daemon:
            p = Process(
                target=smtp_send,
                args=(subject, rcpt_to, preamble, body)
            )
            p.daemon = True
            p.start()
            return p
        return smtp_send(subject, rcpt_to, preamble, body)


@retry(Exception, cdata='method={}'.format(stack()[0][3]))
def decode_jwtoken(encrypted=None):
    try:
        hdr = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[0]
        sig = jwt.encode({}, '', algorithm='HS256').decode('utf-8').split('.')[2]
        decrypted = jwt.decode(
            '{}.{}.{}'.format(
                hdr,
                encrypted,
                sig
            ),
            verify=False
        )
        print('{}: hdr={} sig={} decrypted={}'.format(
            stack()[0][3],
            hdr,
            sig,
            decrypted
        ))
    except:
        decrypted = None
    return decrypted


def error_handler(error):
    code = int(getattr(error, 'code', None))
    template = render_template(
        'maintenance.html',
        code=code,
        error=error
    )
    try:
        if code == 404:
            template = render_template(
                '{}.html'.format(
                    code,
                    code=code,
                    error=error
            ))
        if code >= 400 and code < 500:
            template = render_template(
                '40x.html',
                code=code,
                error=error
            )
        if code >= 500:
            template = render_template(
                '50x.html',
                code=code,
                error=error
            )
    except TemplateNotFound:
        abort(INTERNAL_SERVER_ERROR)
    return template
