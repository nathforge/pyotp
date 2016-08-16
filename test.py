#!/usr/bin/env python
# coding: utf-8

from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

import base64
import datetime
import hashlib
import os
import sys
import unittest
try:
    from urllib.parse import urlparse, parse_qsl
except ImportError:
    from urlparse import urlparse, parse_qsl

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import pyotp


class HOTPExampleValuesFromTheRFC(unittest.TestCase):
    def test_match_rfc(self):
        # 12345678901234567890 in Bas32
        # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertEqual(hotp.at(0), '755224')
        self.assertEqual(hotp.at(1), '287082')
        self.assertEqual(hotp.at(2), '359152')
        self.assertEqual(hotp.at(3), '969429')
        self.assertEqual(hotp.at(4), '338314')
        self.assertEqual(hotp.at(5), '254676')
        self.assertEqual(hotp.at(6), '287922')
        self.assertEqual(hotp.at(7), '162583')
        self.assertEqual(hotp.at(8), '399871')
        self.assertEqual(hotp.at(9), '520489')

    def test_verify_otp_reuse(self):
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertTrue(hotp.verify('520489', 9))
        self.assertFalse(hotp.verify('520489', 10))
        self.assertFalse(hotp.verify('520489', 10))

    def test_provisioning_uri(self):
        hotp = pyotp.HOTP('wrn3pqx5uqxqvnqr')

        url = urlparse(
            hotp.provisioning_uri('mark@percival'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '0'})

        url = urlparse(
            hotp.provisioning_uri('mark@percival', initial_count=12))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '12'})

        url = urlparse(
            hotp.provisioning_uri('mark@percival', issuer_name='FooCorp!'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/FooCorp%21:mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '0',
                          'issuer': 'FooCorp!'})

        key = 'c7uxuqhgflpw7oruedmglbrk7u6242vb'
        hotp = pyotp.HOTP(key, digits=8, digest=hashlib.sha256)
        url = urlparse(
            hotp.provisioning_uri('baco@peperina', issuer_name='FooCorp'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'counter': '0', 'issuer': 'FooCorp',
                          'digits': '8', 'algorithm': 'SHA256'})

        hotp = pyotp.HOTP(key, digits=8)
        url = urlparse(
            hotp.provisioning_uri('baco@peperina', issuer_name='FooCorp',
                                  initial_count=10))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'counter': '10', 'issuer': 'FooCorp',
                          'digits': '8'})

    def test_other_secret(self):
        hotp = pyotp.HOTP(
            'N3OVNIBRERIO5OHGVCMDGS4V4RJ3AUZOUN34J6FRM4P6JIFCG3ZA')
        self.assertEqual(hotp.at(0), '737863')
        self.assertEqual(hotp.at(1), '390601')
        self.assertEqual(hotp.at(2), '363354')
        self.assertEqual(hotp.at(3), '936780')
        self.assertEqual(hotp.at(4), '654019')


class TOTPExampleValuesFromTheRFC(unittest.TestCase):
    RFC_VALUES = {
        (hashlib.sha1, b'12345678901234567890'): (
            (59, '94287082'),
            (1111111109, '07081804'),
            (1111111111, '14050471'),
            (1234567890, '89005924'),
            (2000000000, '69279037'),
            (20000000000, '65353130'),
        ),

        (hashlib.sha256, b'12345678901234567890123456789012'): (
            (59, 46119246),
            (1111111109, '68084774'),
            (1111111111, '67062674'),
            (1234567890, '91819424'),
            (2000000000, '90698825'),
            (20000000000, '77737706'),
        ),

        (hashlib.sha512,
         b'1234567890123456789012345678901234567890123456789012345678901234'):
        (
            (59, 90693936),
            (1111111109, '25091201'),
            (1111111111, '99943326'),
            (1234567890, '93441116'),
            (2000000000, '38618901'),
            (20000000000, '47863826'),
        ),
    }

    def test_match_rfc(self):
        for digest, secret in self.RFC_VALUES:
            totp = pyotp.TOTP(base64.b32encode(secret), 8, digest)
            for utime, code in self.RFC_VALUES[(digest, secret)]:
                value = totp.at(utime)
                msg = "%s != %s (%s, time=%d)"
                msg %= (value, code, digest().name, utime)
                self.assertEqual(value, str(code), msg)

    def test_match_rfc_digit_length(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertEqual(totp.at(1111111111), '050471')
        self.assertEqual(totp.at(1234567890), '005924')
        self.assertEqual(totp.at(2000000000), '279037')

    def test_match_google_authenticator_output(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        with Timecop(1297553958):
            self.assertEqual(totp.now(), '102705')

    def test_validate_totp(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        with Timecop(1297553958):
            self.assertTrue(totp.verify('102705'))
            self.assertTrue(totp.verify('102705'))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify('102705'))

    def test_validate_totp_with_digit_length(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        with Timecop(1111111111):
            self.assertTrue(totp.verify('050471'))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify('050471'))

    def test_provisioning_uri(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        url = urlparse(
            totp.provisioning_uri('mark@percival'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr'})

        url = urlparse(
            totp.provisioning_uri('mark@percival', issuer_name='FooCorp!'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp%21:mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr',
                          'issuer': 'FooCorp!'})

        key = 'c7uxuqhgflpw7oruedmglbrk7u6242vb'
        totp = pyotp.TOTP(key, digits=8, interval=60, digest=hashlib.sha256)
        url = urlparse(
                totp.provisioning_uri('baco@peperina', issuer_name='FooCorp'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8', 'period': '60',
                          'algorithm': 'SHA256'})

        totp = pyotp.TOTP(key, digits=8, interval=60)
        url = urlparse(
                totp.provisioning_uri('baco@peperina', issuer_name='FooCorp'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8', 'period': '60'})

        totp = pyotp.TOTP(key, digits=8)
        url = urlparse(
                totp.provisioning_uri('baco@peperina', issuer_name='FooCorp'))
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8'})

    def test_random_key_generation(self):
        self.assertEqual(len(pyotp.random_base32()), 16)
        self.assertEqual(len(pyotp.random_base32(length=20)), 20)


class CompareDigestTest(unittest.TestCase):
    method = staticmethod(pyotp.utils.compare_digest)

    def test_comparisons(self):
        self.assertTrue(self.method("", ""))
        self.assertTrue(self.method("a", "a"))
        self.assertTrue(self.method("a" * 1000, "a" * 1000))

        self.assertFalse(self.method("", "a"))
        self.assertFalse(self.method("a", ""))
        self.assertFalse(self.method("a" * 999 + "b", "a" * 1000))


class FallBackCompareDigestTest(CompareDigestTest):
    method = staticmethod(pyotp.utils._compare_digest)


class StringComparisonTest(CompareDigestTest):
    method = staticmethod(pyotp.utils.strings_equal)

    def test_fullwidth_input(self):
        self.assertTrue(self.method("ｘs１２３45", "xs12345"))


class CounterOffsetTest(unittest.TestCase):
    def test_counter_offset(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertEqual(totp.at(200), "028307")
        self.assertTrue(totp.at(200, 1), "681610")


class ValidWindowTest(unittest.TestCase):
    def test_valid_window(self):
        totp = pyotp.TOTP("ABCDEFGH")
        self.assertTrue(totp.verify("451564", 200, 1))
        self.assertTrue(totp.verify("028307", 200, 1))
        self.assertTrue(totp.verify("681610", 200, 1))
        self.assertFalse(totp.verify("195979", 200, 1))


class Timecop(object):
    """
    Half-assed clone of timecop.rb, just enough to pass our tests.
    """

    def __init__(self, freeze_timestamp):
        self.freeze_timestamp = freeze_timestamp

    def __enter__(self):
        self.real_datetime = datetime.datetime
        datetime.datetime = self.frozen_datetime()

    def __exit__(self, type, value, traceback):
        datetime.datetime = self.real_datetime

    def frozen_datetime(self):
        class FrozenDateTime(datetime.datetime):
            @classmethod
            def now(cls, **kwargs):
                return cls.fromtimestamp(timecop.freeze_timestamp)

        timecop = self
        return FrozenDateTime

if __name__ == '__main__':
    unittest.main()
