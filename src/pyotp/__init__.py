from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import hashlib

from re import split

from pyotp.hotp import HOTP  # noqa
from pyotp.otp import OTP  # noqa
from pyotp.totp import TOTP  # noqa
from pyotp.compat import unquote, urlparse, parse_qsl  # noqa
from . import utils  # noqa


def random_base32(length=16, random=None,
                  chars=list('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567')):
    if length < 16:
        raise Exception("Secrets should be at least 128 bits")
    # Use secrets module if available (Python version >= 3.6) per PEP 506
    try:
        import secrets
        random = secrets.SystemRandom()
    except ImportError:
        import random as _random
        random = _random.SystemRandom()

    return ''.join(
        random.choice(chars)
        for _ in range(length)
    )


def random_hex(length=32, random=None,
               chars=list('ABCDEF0123456789')):
    if length < 32:
        raise Exception("Secrets should be at least 128 bits")
    return random_base32(length=length, random=None, chars=chars)


def parse_uri(uri):
    """
    Parses the provisioning URI for the OTP; works for either TOTP or HOTP.

    See also:
        https://github.com/google/google-authenticator/wiki/Key-Uri-Format

    :param uri: the hotp/totp URI to parse
    :type uri: str
    :returns: OTP object
    :rtype: OTP
    """

    # Secret (to be filled in later)
    secret = None

    # Data we'll parse to the correct constructor
    otp_data = {}

    # Parse with URLlib
    parsed_uri = urlparse(unquote(uri))

    if parsed_uri.scheme != 'otpauth':
        raise ValueError('Not an otpauth URI')

    # Parse issuer/accountname info
    accountinfo_parts = split(':|%3A', parsed_uri.path[1:], maxsplit=1)
    if len(accountinfo_parts) == 1:
        otp_data['name'] = accountinfo_parts[0]
    else:
        otp_data['issuer'] = accountinfo_parts[0]
        otp_data['name'] = accountinfo_parts[1]

    # Parse values
    for key, value in parse_qsl(parsed_uri.query):
        if key == 'secret':
            secret = value
        elif key == 'issuer':
            if 'issuer' in otp_data and otp_data['issuer'] is not None and otp_data['issuer'] != value:
                raise ValueError('If issuer is specified in both label and parameters, it should be equal.')
            otp_data['issuer'] = value
        elif key == 'algorithm':
            if value == 'SHA1':
                otp_data['digest'] = hashlib.sha1
            elif value == 'SHA256':
                otp_data['digest'] = hashlib.sha256
            elif value == 'SHA512':
                otp_data['digest'] = hashlib.sha512
            else:
                raise ValueError('Invalid value for algorithm, must be SHA1, SHA256 or SHA512')
        elif key == 'digits':
            digits = int(value)
            if digits not in [6, 8]:
                raise ValueError('Digits may only be 6 or 8')
            otp_data['digits'] = digits
        elif key == 'period':
            otp_data['interval'] = value
        elif key == 'counter':
            otp_data['initial_count'] = value
        else:
            raise ValueError('{} is not a valid parameter'.format(key))

    if not secret:
        raise ValueError('No secret found in URI')

    # Create objects
    if parsed_uri.netloc == 'totp':
        return TOTP(secret, **otp_data)
    elif parsed_uri.netloc == 'hotp':
        return HOTP(secret, **otp_data)

    raise ValueError('Not a supported OTP type')
