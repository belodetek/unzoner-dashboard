# -*- coding: utf-8 -*-

import json

from inspect import stack
from functools import wraps
from markupsafe import Markup
from traceback import print_exc
from datetime import datetime, timedelta
from base64 import b64decode, b64encode

from werkzeug.exceptions import NotFound, Forbidden

from flask import (
    Blueprint,
    render_template,
    request,
    abort,
    redirect,
    flash,
    jsonify,
    make_response
)

try:
    from httplib import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN,
        INTERNAL_SERVER_ERROR,
        CREATED,
        CONFLICT
    )
except ImportError:
    from http.client import (
        NO_CONTENT,
        UNAUTHORIZED,
        BAD_REQUEST,
        NOT_FOUND,
        OK,
        FORBIDDEN,
        INTERNAL_SERVER_ERROR,
        CREATED,
        CONFLICT
    )


from .config import *
from .api import *
from .paypal import *
from .bitcoin import *
from .utils import *


frontend = Blueprint('frontend', __name__)


@frontend.route('/ping')
def ping_pong():
    return json.dumps({'ping': 'pong'})


def add_response_headers(headers={}):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            resp = make_response(f(*args, **kwargs))
            h = resp.headers
            for header, value in headers.items():
                h[header] = value
            return resp
        return decorated_function
    return decorator


def add_content_type(f):
    return add_response_headers({
        'Content-Type': 'application/javascript'
    })(f)


@frontend.route('/OneSignalSDKUpdaterWorker.js')
@add_content_type
def OneSignalSDKUpdaterWorker():
    return "importScripts('https://cdn.onesignal.com/sdks/OneSignalSDK.js');"


@frontend.route('/OneSignalSDKWorker.js')
@add_content_type
def OneSignalSDKWorker():
    return "importScripts('https://cdn.onesignal.com/sdks/OneSignalSDK.js');"


@frontend.route('/sub')
def sub():
    try:
        args = request.args.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        try:
            username = args['billing_id']
        except:
            username = None
        try:
            encrypted = args['jwtoken']
        except:
            encrypted = None
        try:
            decrypted = decode_jwtoken(encrypted=encrypted)
            print('{}: encrypted={} decrypted={}'.format(
                stack()[0][3],
                args['jwtoken'],
                decrypted
            ))
            guid = decrypted['i']
            device_type = decrypted['t']
            ip = decrypted['u']
            tun_passwd = decrypted['p']
            print('{}: guid={} device_type={} ip={} tun_passwd={}'.format(
                stack()[0][3],
                guid,
                device_type,
                ip,
                tun_passwd
            ))
        except:
            guid = None
            device_type = None
            ip = None
            tun_passwd = None
        category = 'info'
        if 'type' in args: category = args['type']
        if 'msg' in args:
            flash(Markup(args['msg']), category)

        avail_countries = get_available_countries()
        if DEBUG: print('get_available_countries(): {}'.format(
            avail_countries
        ))
        return render_template(
            'sub.html',
            api_host=API_HOST,
            username=username,
            password=tun_passwd,
            avail_countries=avail_countries,
            paypal_sandbox=PAYPAL_SANDBOX
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/test')
def test():
    try:
        args = request.args.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        screenshots = list()
        if not 'tags' in args:
            avail_countries = get_available_countries()
            if DEBUG: print(
                'get_available_countries: {}'.format(
                    avail_countries
                )
            )
            for c in avail_countries:
                screenshot = get_test_screenshot(alpha=c['alpha2'])
                if screenshot: screenshots.append(screenshot)
                if DEBUG: print('get_test_screenshot: {}'.format(screenshots))
        else:
            limit = args['tags']
            if not limit: limit = 3
            screenshots = get_test_tag_screenshots(limit=limit)
            if DEBUG: print('get_test_tag_screenshots: {}'.format(screenshots))

        return render_template(
            'test.html',
            api_host=API_HOST,
            screenshots=screenshots
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)

  
@frontend.route('/')
def index():
    try:
        args = request.args.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert args['guid']
        try:
            assert args['guid'] not in BLOCKED_DEVICE_LIST
        except:
            return error_handler(Forbidden)
        sub_btn = 'TRIAL'
        if 'trial' in args and args['trial'] == '0':
            sub_btn = 'REGULAR'
        if 'result' in args and args['result'] in ['200', '201', '204']:
            flash(Markup('Subscribed successfully, please <a href="/?guid=%s">reload</a> in a few moments to update status...' % args['guid']), 'success')
        if 'result' in args and args['result'] in ['402']:
            flash(Markup('Your trial period expired, you have not been charged. Please create a regular subscription using the button below to continue using the service.'), 'error')
            sub_btn = 'REGULAR'             
        resin = get_resin_device(guid=args['guid'])
        if DEBUG: print('get_resin_device(): {}'.format(resin))
        try:
            assert resin
        except:
            return error_handler(NotFound)
        location = resin['location']
        resin_status = resin['status']
        online_status = 'Offline'
        if resin['is_online']:
            online_status = 'Online'
        ipaddr = None
        try:
            ipaddr = [
                ip for ip in resin['ip_address'].split(' ')
                if ip != DEFAULT_WIP4
            ][0]
        except IndexError:
            pass
        device_info = '{} ({}) is {} and {}'.format(
            resin['is_of__device_type'][-1]['slug'],
            resin['is_of__device_type'][-1]['name'],
            online_status,
            resin_status
        )
        appid = None
        if 'appid' in args: appid = args['appid']
        env_data = [{'name': 'TARGET_COUNTRY', 'value': None, 'default': DEFAULT_TARGET_COUNTRY},
                    {'name': 'PAIRED_DEVICE_GUID', 'value': None, 'default': ''},
                    {'name': 'DEVICE_TYPE', 'value': None, 'default': DEFAULT_DEVICE_TYPE},
                    {'name': 'SSID', 'value': None, 'default': DEFAULT_SSID},
                    {'name': 'PASSPHRASE', 'value': None, 'default': DEFAULT_PASSPHRASE},
                    {'name': 'TUN_IPV6', 'value': None, 'default': DEFAULT_TUN_IPV6},
                    {'name': 'HW_MODE', 'value': None, 'default': DEFAULT_HW_MODE},
                    {'name': 'WPA2', 'value': None, 'default': DEFAULT_WPA2},
                    {'name': 'IEEE80211AC', 'value': None, 'default': DEFAULT_IEEE80211AC},
                    {'name': 'IEEE80211D', 'value': None, 'default': DEFAULT_IEEE80211D},
                    {'name': 'IEEE80211H', 'value': None, 'default': DEFAULT_IEEE80211H},
                    {'name': 'IEEE80211N', 'value': None, 'default': DEFAULT_IEEE80211N},
                    {'name': 'WMM', 'value': None, 'default': DEFAULT_WMM},
                    {'name': 'STUNNEL', 'value': None, 'default': DEFAULT_STUNNEL},
                    {'name': 'WANPROXY', 'value': None, 'default': DEFAULT_WANPROXY},
                    {'name': 'TUN_MTU', 'value': None, 'default': DEFAULT_TUN_MTU},
                    {'name': 'FRAGMENT', 'value': None, 'default': DEFAULT_FRAGMENT},
                    {'name': 'VPN_PROVIDER', 'value': None, 'default': None},
                    {'name': 'VPN_LOCATION_GROUP', 'value': None, 'default': None},
                    {'name': 'VPN_LOCATION', 'value': None, 'default': None},
                    {'name': 'VPN_USERNAME', 'value': None, 'default': ''},
                    {'name': 'VPN_PASSWD', 'value': None, 'default': ''},
                    {'name': 'TUN_PASSWD', 'value': None, 'default': None},
                    {'name': 'VPN_USER_CERT', 'value': None, 'default': ''},
                    {'name': 'VPN_USER_KEY', 'value': None, 'default': ''},
                    {'name': 'PAYPAL_PAYER_EMAIL', 'value': None, 'default': None},
                    {'name': 'PAYPAL_PAYER_ID', 'value': None, 'default': None},
                    {'name': 'PAYPAL_TRIAL_EXPIRED', 'value': None, 'default': None},
                    {'name': 'BITCOIN_PAYMENT_ADDRESS', 'value': None, 'default': None},
                    {'name': 'BITCOIN_LAST_PAYMENT_DATE', 'value': None, 'default': None},
                    {'name': 'BITCOIN_LAST_PAYMENT_AMOUNT', 'value': None, 'default': None},
                    {'name': 'BITCOIN_LAST_TRANSACTION_ID', 'value': None, 'default': None},
                    {'name': 'BITCOIN_DAILY_AMOUNT', 'value': None, 'default': None},
                    {'name': 'IPASN_DB', 'value': None, 'default': DEFAULT_IPASNDB},
                    {'name': 'CIPHER', 'value': None, 'default': None},
                    {'name': 'AUTH', 'value': None, 'default': None},
                    {'name': 'SERVICES', 'value': None, 'default': None},
                    {'name': 'POLICY_ROUTING', 'value': None, 'default': DEFAULT_POLICY_ROUTING},
                    {'name': 'LOCAL_DNS', 'value': None, 'default': DEFAULT_LOCAL_DNS},
                    {'name': 'AF', 'value': None, 'default': DEFAULT_AF},
                    {'name': 'LIVE_LOGS', 'value': None, 'default': DEFAULT_LIVE_LOGS},
                    {'name': 'STATS', 'value': None, 'default': DEFAULT_STATS},
                    {'name': 'OPENVPN_PORT', 'value': None, 'default': DEFAULT_OPENVPN_PORT},
                    {'name': 'DNS_SERVERS', 'value': None, 'default': DEFAULT_DNS_SERVERS},
                    {'name': 'DNS6_SERVERS', 'value': None, 'default': DEFAULT_DNS6_SERVERS}]

        res = get_resin_envs(guid=args['guid'], appid=appid)
        if DEBUG: print('get_resin_envs({}): {}'.format(args['guid'], res))
        for env in env_data:
            for ev in res['d']:
                if ev['env_var_name'] == env['name']: env['value'] = ev['value']
            if not env['value']: env['value'] = env['default']
        if DEBUG: print(env_data)
        trial_expired = [
            n['value'] for n in env_data
            if n['name'] == 'PAYPAL_TRIAL_EXPIRED'
        ][0]
        if trial_expired: sub_btn = 'REGULAR'   
        debug_info = 'supervisor v{} on {}<br>{}<br>{}'.format(
            resin['supervisor_version'],
            resin['os_version'],
            resin['os_variant'],
            [n['value'] for n in env_data if n['name'] == 'IPASN_DB'][0]
        )
        tun_passwd = [
            n['value'] for n in env_data
            if n['name'] == 'TUN_PASSWD'
        ][0]
        if not tun_passwd:
            tun_passwd = generate_hash_key()
            res = update_resin_env_var(
                guid=args['guid'],
                name='TUN_PASSWD',
                value=tun_passwd
            )
            if DEBUG: print('update_resin_env_var(TUN_PASSWD): {}'.format(res))
        services = list()      
        try:
            services = [
                k['value'].split(',') for k in env_data
                if k['name'] == 'SERVICES'
            ][0]
            if DEBUG: print('services: {}'.format(services))
        except AttributeError:
            pass

        af = int([n['value'] for n in env_data if n['name'] == 'AF'][0])
        openvpn_port = int([n['value'] for n in env_data if n['name'] == 'OPENVPN_PORT'][0])
        policy_routing = bool(int([n['value'] for n in env_data if n['name'] == 'POLICY_ROUTING'][0]))
        device_type = int([n['value'] for n in env_data if n['name'] == 'DEVICE_TYPE'][0])
        vpn_username = [n['value'] for n in env_data if n['name'] == 'VPN_USERNAME'][0]
        vpn_passwd = [n['value'] for n in env_data if n['name'] == 'VPN_PASSWD'][0]
        vpn_provider = [n['value'] for n in env_data if n['name'] == 'VPN_PROVIDER'][0]
        vpn_location_group = [n['value'] for n in env_data if n['name'] == 'VPN_LOCATION_GROUP'][0]
        vpn_location = [n['value'] for n in env_data if n['name'] == 'VPN_LOCATION'][0]
        client_country = None
        upnp = 0
        hostapd = 0
        
        # search for an active device
        for af_inet in AF_TYPES:
            try:
                device = get_device(
                    guid=args['guid'],
                    device_type=device_type,
                    af=af_inet
                )
                if DEBUG: print('get_device({}): {}'.format(args['guid'], device))
                status = int(device['status'])
            except:
                device = None
                status = 0

            if status > 0:
                try:
                    af = int(device['proto'])
                except:
                    pass

                try:
                    client_country = device['country']
                except:
                    pass

                try:
                    upnp = int(device['upnp'])
                except:
                    pass

                try:
                    hostapd = int(device['hostapd'])
                except:
                    pass
                    
                break
        if DEBUG:
            print(
                'status={} af={} client_country={} upnp={} hostapd={}'.format(
                    status,
                    af,
                    client_country,
                    upnp,
                    hostapd
            ))
        country = [
            n['value'] for n in env_data if n['name'] == 'TARGET_COUNTRY'
        ][0]
        if device_type == 5 and vpn_username and vpn_passwd\
           and vpn_provider and vpn_location and vpn_location_group:
            if not client_country: status = 0
            if client_country: country = client_country

        alpha2 = get_country_alpha2(country=country).lower()
        if DEBUG: print('get_country_alpha2({}): {}'.format(country, alpha2))
        assert alpha2

        avail_services = get_available_services(alpha=alpha2)
        if DEBUG: print('get_available_services({}): {}'.format(
            alpha2,
            avail_services
        ))

        avail_countries = get_available_countries()
        if DEBUG: print('get_available_countries(): {}'.format(avail_countries))

        screenshots = list()
        for c in avail_countries:
            screenshots.append(get_test_screenshot(alpha=c['alpha2']))
            if DEBUG: print('get_test_screenshot: {}'.format(screenshots))

        data = {
            'i': args['guid'][:32],
            'p': tun_passwd[:16],
            't': 'RESIN', 'u': ''
        }
        paypal_base_url = get_paypal_subscription_url(data=json.dumps(data))
        if DEBUG: print('get_paypal_subscription_url(): {}'.format(
            paypal_base_url
        ))
        assert paypal_base_url

        paypal = None
        if PAYPAL_PAYMENTS:
            paypal = check_active_paypal_subscription(guid=args['guid'])
            if DEBUG: print('check_active_paypal_subscription(): {}'.format(
                paypal
            ))

        btc_price = None
        btc_expires = None
        btc_expired = True
        btc_payment_address = [n['value'] for n in env_data if n['name'] == 'BITCOIN_PAYMENT_ADDRESS'][0]
        btc_daily_amount = [n['value'] for n in env_data if n['name'] == 'BITCOIN_DAILY_AMOUNT'][0]
        last_payment_date = [n['value'] for n in env_data if n['name'] == 'BITCOIN_LAST_PAYMENT_DATE'][0]
        last_payment_amount = [n['value'] for n in env_data if n['name'] == 'BITCOIN_LAST_PAYMENT_AMOUNT'][0]    

        if BITCOIN_PAYMENTS:
            if not btc_payment_address:
                payload = json.loads(generate_payment_address(guid=args['guid']))
                btc_payment_address = payload['payment_address']
                webhook_id = payload['webhook_id']
                assert btc_payment_address and webhook_id

                res = update_resin_env_var(
                    guid=args['guid'],
                    name='BITCOIN_PAYMENT_ADDRESS',
                    value=btc_payment_address
                )
                if DEBUG: print('update_resin_env_var(BITCOIN_PAYMENT_ADDRESS): {}'.format(
                    res
                ))

                res = update_resin_env_var(
                    guid=args['guid'],
                    name='BITCOIN_BLOCKCYPHER_WEBHOOK_ID',
                    value=webhook_id
                )
                if DEBUG: print('update_resin_env_var(BITCOIN_BLOCKCYPHER_WEBHOOK_ID): {}'.format(
                    res
                ))

            btc_price = get_btc_price()
            assert btc_price
            if DEBUG: print('get_btc_price(): {}'.format(btc_price))

            if not btc_daily_amount:
                btc_daily_amount = btc_price
                res = update_resin_env_var(
                    guid=args['guid'],
                    name='BITCOIN_DAILY_AMOUNT',
                    value=str(btc_price)
                )
                if DEBUG: print('update_resin_env_var(BITCOIN_DAILY_AMOUNT): {}'.format(
                    res
                ))

            if last_payment_date and last_payment_amount and btc_daily_amount:
                btc_expires = datetime.strptime(
                    last_payment_date,
                    '%Y-%m-%dT%H:%M:%SZ'
                ) + timedelta(days=float(last_payment_amount) / float(btc_daily_amount))
                if DEBUG: print('{}: {}'.format(stack()[0][3], btc_expires))

                if datetime.today() > btc_expires:
                    res = update_resin_env_var(
                        guid=args['guid'],
                        name='BITCOIN_DAILY_AMOUNT',
                        value=str(btc_price)
                    )
                    if DEBUG: print('update_resin_env_var(BITCOIN_DAILY_AMOUNT): {}'.format(
                        res
                    ))
                else:
                    btc_expired = False

            if btc_expires: btc_expires = datetime.strftime(
                btc_expires,
                '%b %d %Y %I:%M%p'
            )
            if btc_price: btc_price = float(round(float('%.8f' % btc_price), 8))

        speedtest_enqueue = dequeue_speedtest(guid=args['guid'])
        if DEBUG: print('dequeue_speedtest(): {}'.format(speedtest_enqueue))
    
        speedtest = get_speedtest(guid=args['guid'])
        if DEBUG: print('get_speedtest():{}'.format(speedtest))

        iotest_enqueue = dequeue_iotest(guid=args['guid'])
        if DEBUG: print('dequeue_iotest: {}'.format(iotest_enqueue))

        iotests = list()
        for test in IOTESTS:
            iotest = get_iotest(test=test, guid=args['guid'])
            if DEBUG: print('get_iotest: {}'.format(iotest))
            if iotest: iotests.append(iotest)
        if DEBUG: print('iotests: {}'.format(iotests))

        free = False
        paired = [n['value'] for n in env_data if n['name'] == 'PAIRED_DEVICE_GUID'][0]
        if device_type in [1, 3, 4, 5] or (paired and device_type == 2): free = True

        disabled = False
        if device_type == 0: disabled = True

        server = False
        if device_type in [1, 4]: server = True

        vpn_user_cert = ''
        vpn_user_key = ''
        try:
            vpn_user_cert = [
                b64decode(n['value']).decode('utf-8') for n in env_data
                if n['name'] == 'VPN_USER_CERT'
            ][0]
            vpn_user_key = [
                b64decode(n['value']).decode('utf-8') for n in env_data
                if n['name'] == 'VPN_USER_KEY'
            ][0]
        except Exception as e:
            print(repr(e))
            if DEBUG: print_exc()
            
        return render_template(
            'index.html',
            guid=args['guid'],
            free=free,
            disabled=disabled,
            paired=paired,
            server=server,
            device=device_info,
            ipaddr=ipaddr,
            info=debug_info,
            location=location,
            alpha2=alpha2,
            avail_countries=avail_countries,
            avail_services=avail_services,
            services=services,
            country=country,
            status=status,
            resin_status=resin_status,
            online_status=online_status,
            policy_routing=policy_routing,
            device_type=device_type,
            dns_sub_domain=DNS_SUB_DOMAIN,
            sub_btn=sub_btn,
            paypal=paypal,
            paypal_base_url=paypal_base_url,
            paypal_payments=PAYPAL_PAYMENTS,
            paypal_sandbox=PAYPAL_SANDBOX,
            paypal_sandbox_login=PAYPAL_SANDBOX_LOGIN,
            paypal_sandbox_password=PAYPAL_SANDBOX_PASSWORD,
            btc_payments=BITCOIN_PAYMENTS,
            btc_testnet=BITCOIN_TESTNET,
            btc_payment_address=btc_payment_address,
            btc_price=btc_price,
            btc_expires=btc_expires,
            btc_expired=btc_expired,
            btc_confirm=BITCOIN_MAX_CONFIRMATIONS,
            btc_confirm_event=BITCOIN_CONFIRMATION_EVENT,
            wss_host=BLOCKCYPHER_WEBSOCKET_HOST,
            onesignal_appid=ONESIGNAL_APPID,
            onesignal_safari_webid=ONESIGNAL_SAFARI_WEBID,
            screenshots=screenshots,
            openvpn_port=openvpn_port,
            af=af,
            hostapd=hostapd,
            upnp=upnp,
            dns_servers=[n['value'] for n in env_data if n['name'] == 'DNS_SERVERS'][0],
            dns6_servers=[n['value'] for n in env_data if n['name'] == 'DNS6_SERVERS'][0],
            ssid=[n['value'] for n in env_data if n['name'] == 'SSID'][0],
            passphrase=[n['value'] for n in env_data if n['name'] == 'PASSPHRASE'][0],
            ipv6=int([n['value'] for n in env_data if n['name'] == 'TUN_IPV6'][0]),
            hw_mode=[n['value'] for n in env_data if n['name'] == 'HW_MODE'][0],
            wpa2=[n['value'] for n in env_data if n['name'] == 'WPA2'][0],
            ieee80211ac=int([n['value'] for n in env_data if n['name'] == 'IEEE80211AC'][0]),
            ieee80211d=int([n['value'] for n in env_data if n['name'] == 'IEEE80211D'][0]),
            ieee80211h=int([n['value'] for n in env_data if n['name'] == 'IEEE80211H'][0]),
            ieee80211n=int([n['value'] for n in env_data if n['name'] == 'IEEE80211N'][0]),
            wmm=[n['value'] for n in env_data if n['name'] == 'WMM'][0],
            stunnel=int([n['value'] for n in env_data if n['name'] == 'STUNNEL'][0]),
            wanproxy=[n['value'] for n in env_data if n['name'] == 'WANPROXY'][0],
            tun_mtu=[n['value'] for n in env_data if n['name'] == 'TUN_MTU'][0],
            fragment=[n['value'] for n in env_data if n['name'] == 'FRAGMENT'][0],
            paypal_payer_email=[n['value'] for n in env_data if n['name'] == 'PAYPAL_PAYER_EMAIL'][0],
            paypal_payer_id=[n['value'] for n in env_data if n['name'] == 'PAYPAL_PAYER_ID'][0],
            btc_hash=[n['value'] for n in env_data if n['name'] == 'BITCOIN_LAST_TRANSACTION_ID'][0],
            cipher=[n['value'] for n in env_data if n['name'] == 'CIPHER'][0],
            auth=[n['value'] for n in env_data if n['name'] == 'AUTH'][0],
            local_dns=int([n['value'] for n in env_data if n['name'] == 'LOCAL_DNS'][0]),
            live_logs=int([n['value'] for n in env_data if n['name'] == 'LIVE_LOGS'][0]),
            stats=int([n['value'] for n in env_data if n['name'] == 'STATS'][0]),
            logs_host=LOGS_HOST,
            api_host=API_HOST,
            api_version=API_VERSION,
            vpn_username=vpn_username,
            vpn_passwd=vpn_passwd,
            vpn_provider=vpn_provider,
            vpn_location=vpn_location,
            vpn_location_group=vpn_location_group,
            vpn_user_cert=vpn_user_cert,
            vpn_user_key=vpn_user_key,
            speedtest=speedtest,
            speedtest_enqueue=speedtest_enqueue,
            iotests=iotests,
            iotest_enqueue=iotest_enqueue,
            feature_wanproxy=FEATURE_WANPROXY,
            feature_stunnel=FEATURE_STUNNEL
        )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/config', methods=['GET', 'POST'])
def config():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()            
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'name' in args and 'device_type' in args

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))

        if args['name'] in ALLOWED_CONFIG_ELEMENTS:
            if request.form.getlist('value'):
                # update multi value
                value = ' '.join(request.form.getlist('value'))
                if value:
                    args['value'] = value
                    if DEBUG: print('{}: {}'.format(stack()[0][3], value))
                    res = update_resin_env_var(
                        guid=args['guid'],
                        name=args['name'],
                        value=args['value']
                    )
                    if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                        stack()[0][3],
                        res
                    ))
                else:
                    res = delete_resin_device_env(
                        guid=args['guid'],
                        name=args['name']
                    )
                    if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                        stack()[0][3],
                        res
                    ))
            else:
                # update single value
                res = update_resin_env_var(
                    guid=args['guid'],
                    name=args['name'],
                    value=args['value']
                )
                if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                    stack()[0][3],
                    res
                ))
        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(
                DASHBOARD_HOST,
                args['guid']
            )
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/vpn', methods=['GET', 'POST'])
def vpn():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()            
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'device_type' in args
        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))
        for item in ['usercert', 'userkey']:
            if item in args:
                try:
                    args[item] = b64encode(bytes(args[item], 'utf-8')).decode('utf-8')
                except Exception as e:
                    print(repr(e))
                    if DEBUG: print_exc()
                
        if 'username' in args and 'password' in args and 'providers' in args and 'locations' in args:
            env_data = [
                {'name': 'VPN_PROVIDER', 'value': args['providers']},
                {'name': 'VPN_LOCATION', 'value': args['locations']},
                {'name': 'VPN_LOCATION_GROUP', 'value': args['groups']},
                {'name': 'VPN_USERNAME', 'value': args['username']},
                {'name': 'VPN_PASSWD', 'value': args['password']},
                {'name': 'VPN_USER_CERT', 'value': args['usercert']},
                {'name': 'VPN_USER_KEY', 'value': args['userkey']}
            ]
            if DEBUG: print('{}: {}'.format(stack()[0][3], env_data))

            for env in env_data:
                if env['value']:
                    res = update_resin_env_var(
                        guid=args['guid'],
                        name=env['name'],
                        value=env['value']
                    )
                    if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                        stack()[0][3],
                        res
                    ))
                else:
                    res = delete_resin_device_env(
                        guid=args['guid'],
                        name=env['name']
                    )
                    if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                        stack()[0][3],
                        res
                    ))
        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/service', methods=['GET', 'POST'])
def service():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()            
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'alpha2' in args and 'device_type' in args and 'country' in args

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))

        services = request.form.getlist('services')
        services.append(DEFAULT_SERVICES)

        if len(services) <= 0:
            services = args['services']
        else:
            services = ','.join(services)

        if DEBUG: print('{}: {}'.format(stack()[0][3], services))

        if 'all' in services.split(','):
            services = get_available_services(alpha=args['alpha2'])
            services.append(DEFAULT_SERVICES)
            services = ','.join(services)

        if 'none' in services.split(','): services = DEFAULT_SERVICES

        if DEBUG: print('get_available_services(): {}'.format(services))

        env_data = [
            {'name': 'TARGET_COUNTRY', 'value': args['country']},
            {'name': 'SERVICES', 'value': services}
        ]
            
        if DEBUG: print('{}: {}'.format(stack()[0][3], env_data))

        for env in env_data:
            res = update_resin_env_var(
                guid=args['guid'],
                name=env['name'],
                value=env['value']
            )
            if DEBUG: print('{}: update_resin_env_var({}): {}'.format(
                stack()[0][3],
                env['name'],
                res
            ))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/pair', methods=['GET', 'POST'])
def pair():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'PAIRED_DEVICE_GUID' in args and 'device_type' in args

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))

        if args['PAIRED_DEVICE_GUID']:
            for env in [
                'WANPROXY',
                'STUNNEL',
                'VPN_USERNAME',
                'VPN_PASSWD',
                'VPN_PROVIDER',
                'VPN_LOCATION_GROUP',
                'VPN_LOCATION'
            ]:
                res = delete_resin_device_env(
                    guid=args['guid'],
                    name=env
                )
                
                if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                    stack()[0][3],
                    res
                ))
           
            for env in [
                {'name': 'PAIRED_DEVICE_GUID', 'value': args['PAIRED_DEVICE_GUID']},
                {'name': 'AUTH', 'value': 'SHA1'},
                {'name': 'CIPHER', 'value': 'BF-CBC'},
                {'name': 'DEVICE_TYPE', 'value': '2'},
                {'name': 'CLIENT_CERT', 'value': '1'}
            ]: 
                res = update_resin_env_var(
                    guid=args['guid'],
                    name=env['name'],
                    value=env['value']
                )
                if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                    stack()[0][3],
                    res
                ))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(
                DASHBOARD_HOST,
                args['guid']
            )
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/unpair', methods=['GET', 'POST'])
def unpair():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'device_type' in args

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))

        for env in [
            'PAIRED_DEVICE_GUID',
            'AUTH',
            'CLIENT_CERT',
            'CIPHER',
            'WANPROXY',
            'STUNNEL',
            'VPN_USERNAME',
            'VPN_PROVIDER',
            'VPN_LOCATION_GROUP',
            'VPN_LOCATION',
            'VPN_PASSWD'
        ]:
            res = delete_resin_device_env(
                guid=args['guid'],
                name=env
            )
            if DEBUG: print ('{}: delete_resin_device_env(): {}'.format(
                stack()[0][3],
                res
            ))

        res = update_resin_env_var(
            guid=args['guid'],
            name='DEVICE_TYPE',
            value='2'
        )
        if DEBUG: print('{}: update_resin_env_var(): {}'.format(
            stack()[0][3],
            res
        ))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/set', methods=['GET', 'POST'])
def set():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'value' in args and args['value'] in ALLOWED_MODES

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))
        
        if args['value'] == '5':
            for env in [
                'PAIRED_DEVICE_GUID',
                'WANPROXY',
                'STUNNEL',
                'MAX_CONNS',
                'UPNP_ENABLED',
                'AUTH',
                'CIPHER'
            ]:
                res = delete_resin_device_env(
                    guid=args['guid'],
                    name=env
                )
                if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                    stack()[0][3],
                    res
                ))

            for env in [{
                'name': 'LOCAL_DNS',
                'value': 0
            }]:
                res = update_resin_env_var(
                    guid=args['guid'],
                    name=env['name'],
                    value=env['value']
                )
                if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                    stack()[0][3],
                    res
                ))

        if args['value'] == '4':
            for env in [
                'PAIRED_DEVICE_GUID',
                'WANPROXY',
                'STUNNEL',
                'VPN_USERNAME',
                'VPN_PROVIDER',
                'VPN_LOCATION_GROUP',
                'VPN_LOCATION',
                'VPN_PASSWD',
                'MAX_CONNS',
                'LOCAL_DNS'
            ]:
                res = delete_resin_device_env(
                    guid=args['guid'],
                    name=env
                )
                if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                    stack()[0][3],
                    res
                ))

            for env in [
                {'name': 'TCP_PORTS', 'value': '#'},
                {'name': 'UDP_PORTS', 'value': '#'},
                {'name': 'AUTH', 'value': 'SHA1'},
                {'name': 'CIPHER', 'value': 'BF-CBC'},
                {'name': 'CLIENT_CERT', 'value': '1'},
                {'name': 'UPNP_ENABLED', 'value': '1'},
                {'name': 'MAX_CONNS', 'value': '5'}
            ]:
                res = update_resin_env_var(
                    guid=args['guid'],
                    name=env['name'],
                    value=env['value']
                )
                if DEBUG: print('{}: update_resin_env_var(): {}'.format(
                    stack()[0][3],
                    res
                ))

        if args['value'] == '2':
            for env in [
                'PAIRED_DEVICE_GUID',
                'VPN_USERNAME',
                'VPN_PROVIDER',
                'VPN_LOCATION_GROUP',
                'VPN_LOCATION',
                'WANPROXY',
                'STUNNEL',
                'TCP_PORTS',
                'UDP_PORTS',
                'AUTH',
                'CIPHER',
                'CLIENT_CERT',
                'UPNP_ENABLED',
                'VPN_PASSWD',
                'MAX_CONNS',
                'LOCAL_DNS'
            ]:
                res = delete_resin_device_env(
                    guid=args['guid'],
                    name=env
                )
                if DEBUG: print('{}: delete_resin_device_env(): {}'.format(
                    stack()[0][3],
                    res
                ))

        res = update_resin_env_var(
            guid=args['guid'],
            name='DEVICE_TYPE',
            value=args['value']
        )
        if DEBUG: print('{}: update_resin_env_var(): {}'.format(
            stack()[0][3],
            res
        ))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/speedtest', methods=['GET', 'POST'])
def speedtest():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args
        res = enqueue_speedtest(guid=args['guid'])
        if DEBUG: print('{}: enqueue_speedtest(): {}'.format(stack()[0][3], res))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG == 1: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/iotest', methods=['GET', 'POST'])
def iotest():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args
        try:
            assert 'iotest' in args
            test = args['iotest']
        except:
            test = 0
        res = enqueue_iotest(test=test, guid=args['guid'])
        if DEBUG: print(
            '{}: enqueue_iotest: {}'.format(
                stack()[0][3],
                res
            )
        )
        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(
                DASHBOARD_HOST,
                args['guid']
            )
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/control', methods=['GET', 'POST'])
def resin_device_control():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))
        assert 'guid' in args and 'action' in args

        for device_type in DEVICE_TYPES:
            print('disable_device_status({}): {}'.format(
                device_type,
                disable_device_status(
                    guid=args['guid'],
                    device_type=device_type
                )
            ))

        res = resin_device_action(guid=args['guid'], action=args['action'])
        if DEBUG: print('{}: status_code={} content={}'.format(
            stack()[0][3],
            res.status_code,
            res.content
        ))

        if 'appid' in args:
            location = '{}/?guid={}&appid={}'.format(
                DASHBOARD_HOST,
                args['guid'],
                args['appid']
            )
        else:
            location = '{}/?guid={}'.format(DASHBOARD_HOST, args['guid'])
        return redirect(location, code=302)
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)


@frontend.route('/passwd', methods=['GET', 'POST'])
def retrieve_vpn_credentials():
    try:
        if request.method == 'GET': args = request.args.to_dict()
        if request.method == 'POST': args = request.form.to_dict()
        if DEBUG: print('{}: {}'.format(stack()[0][3], args))

        try:
            baid = args['baid']
            assert baid
        except:
            return redirect(
                '{}/sub?type=warning&msg={}'.format(
                    DASHBOARD_HOST,
                    'PayPal automatic payment ID required'
                ),
                code=302
            )
        sub = get_paypal_subscription(baid=baid)
        try:
            email = sub['payer']['payer_info']['email']
        except:
            email = None
        try:
            decoded = decode_jwtoken(encrypted=sub['description'])
            url = '{}/sub?type=success&msg={}&jwtoken={}&billing_id={}'.format(
                DASHBOARD_HOST,
                'Credentials retrieved',
                sub['description'],
                baid
            )
            body = [
                'click {0} to view'.format(url),
                'click <a target="_blank" href="{}">here</a> to view<br>'.format(url)
            ]
        except:
            body = None

        if body and email:
            subj = 'Your black.box Unzoner OpenVPN credentials'
            p = smtp_send(subject=subj, rcpt_to=email, body=body, daemon=True)
            if DEBUG: print('smtp_send: p={}'.format(p))
            msg = 'Email with credentials sent to {}'.format(email)
            return redirect(
                '{}/sub?type=info&msg={}'.format(
                    DASHBOARD_HOST,
                    msg
                ),
                code=302
            )
        else:
            msg = 'Unable to retrieve credentials'
            return redirect(
                '{}/sub?type=error&msg={}'.format(
                    DASHBOARD_HOST,
                    msg
                ),
                code=302
            )
    except Exception as e:
        print(repr(e))
        if DEBUG: print_exc()
        abort(BAD_REQUEST)
