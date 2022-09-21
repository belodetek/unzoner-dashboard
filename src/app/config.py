# -*- coding: utf-8 -*-

import os


SMTP_FROM = os.getenv('SMTP_FROM', None)
SMTP_HOST = os.getenv('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = os.getenv('SMTP_PORT', 465)
SMTP_USERNAME = os.getenv('SMTP_USERNAME', None)
SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', None)
LISTEN_ADDR = os.getenv('LISTEN_ADDR', '0.0.0.0')
PORT = int(os.getenv('PORT', 8000))
THREADED = bool(int(os.getenv('THREADED', 0)))
ALLOWED_MODES = os.getenv('ALLOWED_MODES', '2 4 5').split()
IOTESTS = [int(iot) for iot in os.getenv('IOTESTS', '0 1 2').split()]
AF_TYPES = [int(aft) for aft in os.getenv('AF_TYPES', '4 6').split()]

DEVICE_TYPES = [
    int(dt) for dt in os.getenv('DEVICE_TYPES', '1 2 3 4 5').split()
]

PAYPAL_PAYMENTS = int(os.getenv('PAYPAL_PAYMENTS', 1))
BITCOIN_PAYMENTS = int(os.getenv('BITCOIN_PAYMENTS', 1))
PAYPAL_SANDBOX = int(os.getenv('PAYPAL_SANDBOX', 1))

PAYPAL_SANDBOX_LOGIN = os.getenv(
    'PAYPAL_SANDBOX_LOGIN',
    'blackbox-preview@belodedenko.me'
)

PAYPAL_SANDBOX_PASSWORD = os.getenv('PAYPAL_SANDBOX_PASSWORD', 'fY8MlNb7Q8RH')
BITCOIN_TESTNET =  int(os.getenv('BITCOIN_TESTNET', 1))
BITCOIN_SATOSHI = int(os.getenv('BITCOIN_SATOSHI', 100000000))
BITCOIN_MAX_CONFIRMATIONS =  int(os.getenv('BITCOIN_MAX_CONFIRMATIONS', 0))

BITCOIN_CONFIRMATION_EVENT = os.getenv(
    'BITCOIN_CONFIRMATION_EVENT',
    'unconfirmed-tx'
)

BLOCKCYPHER_WEBSOCKET_HOST = os.getenv(
    'BLOCKCYPHER_WEBSOCKET_HOST',
    'wss://socket.blockcypher.com/v1/btc/test3'
)

ONESIGNAL_APPID = os.getenv(
    'ONESIGNAL_APPID',
    '57c4f16a-12f7-4cfb-b0f7-59dc6be23578'
)

ONESIGNAL_SAFARI_WEBID = os.getenv(
    'ONESIGNAL_SAFARI_WEBID',
    'web.onesignal.auto.1947bcbb-3df5-45a5-b464-0be0e15f4a2c'
)

DEFAULT_TRIES = int(os.getenv('DEFAULT_TRIES', 3))
DEFAULT_DELAY = int(os.getenv('DEFAULT_DELAY', 2))
DEFAULT_BACKOFF = int(os.getenv('DEFAULT_BACKOFF', 2))
DEBUG = bool(int(os.getenv('DEBUG', 0)))
DEBUGGER = bool(int(os.getenv('DEBUGGER', 0)))
DNS_DOMAIN = os.getenv('DNS_DOMAIN', 'belodedenko.me')
DNS_SUB_DOMAIN = os.getenv('DNS_SUB_DOMAIN', 'blackbox')
API_HOST = os.getenv('API_HOST', 'https://api-dev.{}'.format(DNS_DOMAIN))

DASHBOARD_HOST = os.getenv(
    'DASHBOARD_HOST',
    'https://dash-dev.{}'.format(
        DNS_DOMAIN
    )
)

LOGS_HOST = os.getenv(
    'LOGS_HOST',
    'https://{}.local:5000/'.format(
        DNS_SUB_DOMAIN
    )
)

API_VERSION = os.getenv('API_VERSION', '1.0')
API_SECRET = os.getenv('API_SECRET', None)
DEFAULT_TARGET_COUNTRY = os.getenv('DEFAULT_TARGET_COUNTRY', 'United States')
DEFAULT_SSID = os.getenv('DEFAULT_SSID', 'black.box')
DEFAULT_PASSPHRASE = os.getenv('DEFAULT_PASSPHRASE', 'blackbox')
DEFAULT_WPA2 = os.getenv('DEFAULT_WPA2', '1')
DEFAULT_TUN_IPV6 = os.getenv('DEFAULT_TUN_IPV6', '0')
DEFAULT_HW_MODE = os.getenv('DEFAULT_HW_MODE', 'g')
DEFAULT_IEEE80211AC = os.getenv('DEFAULT_IEEE80211AC', '0')
DEFAULT_IEEE80211D = os.getenv('DEFAULT_IEEE80211D', '0')
DEFAULT_IEEE80211H = os.getenv('DEFAULT_IEEE80211H', '0')
DEFAULT_IEEE80211N = os.getenv('DEFAULT_IEEE80211N', '1')
DEFAULT_WMM = os.getenv('DEFAULT_WMM', '1')
FEATURE_STUNNEL = bool(int(os.getenv('FEATURE_STUNNEL', 1)))
DEFAULT_STUNNEL = os.getenv('DEFAULT_STUNNEL', '0')
FEATURE_WANPROXY = bool(int(os.getenv('FEATURE_WANPROXY', 0)))
DEFAULT_WANPROXY = os.getenv('DEFAULT_WANPROXY', None)
DEFAULT_IPASNDB = os.getenv('DEFAULT_IPASNDB', 'ipasn_20170201.1600.dat.gz')
DEFAULT_WIP4 = os.getenv('DEFAULT_WIP4', '172.24.255.254')
DEFAULT_CURRENCY = os.getenv('DEFAULT_CURRENCY', 'EUR')
DEFAULT_DEVICE_TYPE = int(os.getenv('DEFAULT_DEVICE_TYPE', 2))
DEFAULT_SERVICES = os.getenv('DEFAULT_SERVICES', 'common')
DEFAULT_TUN_MTU = os.getenv('DEFAULT_TUN_MTU', '1500')
DEFAULT_FRAGMENT = os.getenv('DEFAULT_FRAGMENT', '')
DEFAULT_LOCAL_DNS = os.getenv('DEFAULT_LOCAL_DNS', '1')
DEFAULT_AF = os.getenv('DEFAULT_AF', '0')
DEFAULT_LIVE_LOGS = os.getenv('DEFAULT_LIVE_LOGS', '0')
DEFAULT_STATS = os.getenv('DEFAULT_STATS', '1')
DEFAULT_DNS_SERVERS = os.getenv('DEFAULT_DNS_SERVERS', '8.8.8.8 8.8.4.4')

DEFAULT_DNS6_SERVERS = os.getenv(
    'DEFAULT_DNS6_SERVERS',
    '2001:4860:4860::8888 2001:4860:4860::8844'
)

DEFAULT_POLICY_ROUTING = os.getenv('DEFAULT_POLICY_ROUTING', '1')
DEFAULT_OPENVPN_PORT = os.getenv('DEFAULT_OPENVPN_PORT', '1194')
BLOCKED_DEVICE_LIST = os.getenv('BLOCKED_DEVICE_LIST', '').split(',')

ALLOWED_CONFIG_ELEMENTS = [
    'TARGET_COUNTRY',
    'SSID',
    'PASSPHRASE',
    'TUN_IPV6',
    'HW_MODE',
    'IEEE80211AC',
    'IEEE80211D',
    'IEEE80211H',
    'IEEE80211N',
    'WMM',
    'STUNNEL',
    'WANPROXY',
    'TUN_MTU',
    'FRAGMENT',
    'VPN_LOCATION',
    'VPN_PROVIDER',
    'VPN_PASSWD',
    'VPN_USERNAME',
    'POLICY_ROUTING',
    'LOCAL_DNS',
    'AF',
    'LIVE_LOGS',
    'DNS_SERVERS',
    'DNS6_SERVERS',
    'WPA2'
]
