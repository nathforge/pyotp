#!/usr/bin/env python
# coding: utf-8

import base64, datetime, hashlib, os, sys, unittest
from warnings import warn

from urllib.parse import urlparse, parse_qsl

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

    def test_invalid_input(self):
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        with self.assertRaises(ValueError):
            hotp.at(-1)

    def test_verify_otp_reuse(self):
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertTrue(hotp.verify('520489', 9))
        self.assertFalse(hotp.verify('520489', 10))
        self.assertFalse(hotp.verify('520489', 10))

    def test_provisioning_uri(self):
        hotp = pyotp.HOTP('wrn3pqx5uqxqvnqr', name='mark@percival')

        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '0'})
        self.assertEqual(
            hotp.provisioning_uri(),
            pyotp.parse_uri(
                hotp.provisioning_uri()
            ).provisioning_uri()
        )

        hotp = pyotp.HOTP('wrn3pqx5uqxqvnqr', name='mark@percival', initial_count=12)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '12'})
        self.assertEqual(
            hotp.provisioning_uri(),
            pyotp.parse_uri(
                hotp.provisioning_uri()
            ).provisioning_uri()
        )

        hotp = pyotp.HOTP('wrn3pqx5uqxqvnqr', name='mark@percival',
                          issuer='FooCorp!')
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/FooCorp%21:mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr', 'counter': '0',
                          'issuer': 'FooCorp!'})
        self.assertEqual(
            hotp.provisioning_uri(),
            pyotp.parse_uri(
                hotp.provisioning_uri()
            ).provisioning_uri()
        )

        key = 'c7uxuqhgflpw7oruedmglbrk7u6242vb'
        hotp = pyotp.HOTP(key, digits=8, digest=hashlib.sha256,
                          name='baco@peperina', issuer='FooCorp')
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'counter': '0', 'issuer': 'FooCorp',
                          'digits': '8', 'algorithm': 'SHA256'})
        self.assertEqual(
            hotp.provisioning_uri(),
            pyotp.parse_uri(
                hotp.provisioning_uri()
            ).provisioning_uri()
        )

        hotp = pyotp.HOTP(key, digits=8, name='baco@peperina',
                          issuer='Foo Corp', initial_count=10)
        url = urlparse(hotp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'hotp')
        self.assertEqual(url.path, '/Foo%20Corp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'counter': '10', 'issuer': 'Foo Corp',
                          'digits': '8'})
        self.assertEqual(
            hotp.provisioning_uri(),
            pyotp.parse_uri(
                hotp.provisioning_uri()
            ).provisioning_uri()
        )

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
                if utime > sys.maxsize:
                    warn("32-bit platforms use native functions to handle timestamps, so they fail this test" +
                         " (and will fail after 19 January 2038)")
                    continue
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

    def test_input_before_epoch(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        # -1 and -29.5 round down to 0 (epoch)
        self.assertEqual(totp.at(-1), '755224')
        self.assertEqual(totp.at(-29.5), '755224')
        with self.assertRaises(ValueError):
            totp.at(-30)

    def test_validate_totp_with_digit_length(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        with Timecop(1111111111):
            self.assertTrue(totp.verify('050471'))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify('050471'))

    def test_provisioning_uri(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr', name='mark@percival')
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr'})
        self.assertEqual(
            totp.provisioning_uri(),
            pyotp.parse_uri(
                totp.provisioning_uri()
            ).provisioning_uri()
        )

        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr', name='mark@percival',
                          issuer='FooCorp!')
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp%21:mark%40percival')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'wrn3pqx5uqxqvnqr',
                          'issuer': 'FooCorp!'})
        self.assertEqual(
            totp.provisioning_uri(),
            pyotp.parse_uri(
                totp.provisioning_uri()
            ).provisioning_uri()
        )

        key = 'c7uxuqhgflpw7oruedmglbrk7u6242vb'
        totp = pyotp.TOTP(key, digits=8, interval=60, digest=hashlib.sha256,
                          name='baco@peperina', issuer='FooCorp')
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8', 'period': '60',
                          'algorithm': 'SHA256'})
        self.assertEqual(
            totp.provisioning_uri(),
            pyotp.parse_uri(
                totp.provisioning_uri()
            ).provisioning_uri()
        )

        totp = pyotp.TOTP(key, digits=8, interval=60,
                          name='baco@peperina', issuer='FooCorp')
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8', 'period': '60'})
        self.assertEqual(
            totp.provisioning_uri(),
            pyotp.parse_uri(
                totp.provisioning_uri()
            ).provisioning_uri()
        )

        totp = pyotp.TOTP(key, digits=8, name='baco@peperina', issuer='FooCorp')
        url = urlparse(totp.provisioning_uri())
        self.assertEqual(url.scheme, 'otpauth')
        self.assertEqual(url.netloc, 'totp')
        self.assertEqual(url.path, '/FooCorp:baco%40peperina')
        self.assertEqual(dict(parse_qsl(url.query)),
                         {'secret': 'c7uxuqhgflpw7oruedmglbrk7u6242vb',
                          'issuer': 'FooCorp',
                          'digits': '8'})
        self.assertEqual(
            totp.provisioning_uri(),
            pyotp.parse_uri(
                totp.provisioning_uri()
            ).provisioning_uri()
        )

    def test_random_key_generation(self):
        self.assertEqual(len(pyotp.random_base32()), 16)
        self.assertEqual(len(pyotp.random_base32(length=20)), 20)
        self.assertEqual(len(pyotp.random_hex()), 32)
        self.assertEqual(len(pyotp.random_hex(length=64)), 64)
        with self.assertRaises(Exception):
            pyotp.random_base32(length=15)
        with self.assertRaises(Exception):
            pyotp.random_hex(length=24)


class CompareDigestTest(unittest.TestCase):
    method = staticmethod(pyotp.utils.compare_digest)

    def test_comparisons(self):
        self.assertTrue(self.method("", ""))
        self.assertTrue(self.method("a", "a"))
        self.assertTrue(self.method("a" * 1000, "a" * 1000))

        self.assertFalse(self.method("", "a"))
        self.assertFalse(self.method("a", ""))
        self.assertFalse(self.method("a" * 999 + "b", "a" * 1000))


class StringComparisonTest(CompareDigestTest):
    method = staticmethod(pyotp.utils.strings_equal)

    def test_fullwidth_input(self):
        self.assertTrue(self.method("ｘs１２３45", "xs12345"))

    def test_unicode_equal(self):
        self.assertTrue(self.method("ěšč45", "ěšč45"))


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

class ParseUriTest(unittest.TestCase):
    def test_invalids(self):
        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('http://hello.com')
        self.assertEqual('Not an otpauth URI', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://totp')
        self.assertEqual('No secret found in URI', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://derp?secret=foo')
        self.assertEqual('Not a supported OTP type', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://totp?foo=secret')
        self.assertEqual('foo is not a valid parameter', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://totp?digits=-1')
        self.assertEqual('Digits may only be 6 or 8', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://totp/SomeIssuer:?issuer=AnotherIssuer')
        self.assertEqual('If issuer is specified in both label and parameters, it should be equal.', str(cm.exception))

        with self.assertRaises(ValueError) as cm:
            pyotp.parse_uri('otpauth://totp?algorithm=aes')
        self.assertEqual('Invalid value for algorithm, must be SHA1, SHA256 or SHA512', str(cm.exception))

    def test_algorithms(self):
        otp = pyotp.parse_uri('otpauth://totp?algorithm=SHA1&secret=123456&algorithm=SHA1')
        self.assertEqual(hashlib.sha1, otp.digest)

        otp = pyotp.parse_uri('otpauth://totp?algorithm=SHA1&secret=123456&algorithm=SHA256')
        self.assertEqual(hashlib.sha256, otp.digest)

        otp = pyotp.parse_uri('otpauth://totp?algorithm=SHA1&secret=123456&algorithm=SHA512')
        self.assertEqual(hashlib.sha512, otp.digest)

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
