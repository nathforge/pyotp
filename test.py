from __future__ import with_statement
import datetime
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
import pyotp


class HOTPExampleValuesFromTheRFC(unittest.TestCase):
    def testMatchTheRFC(self):
        # 12345678901234567890 in Bas32
        # GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertEqual(hotp.at(0), 755224)
        self.assertEqual(hotp.at(1), 287082)
        self.assertEqual(hotp.at(2), 359152)
        self.assertEqual(hotp.at(3), 969429)
        self.assertEqual(hotp.at(4), 338314)
        self.assertEqual(hotp.at(5), 254676)
        self.assertEqual(hotp.at(6), 287922)
        self.assertEqual(hotp.at(7), 162583)
        self.assertEqual(hotp.at(8), 399871)
        self.assertEqual(hotp.at(9), 520489)

    def testVerifyAnOTPAndNowAllowReuse(self):
        hotp = pyotp.HOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertTrue(hotp.verify(520489, 9))
        self.assertFalse(hotp.verify(520489, 10))
        self.assertFalse(hotp.verify("520489", 10))

        self.assertTrue(hotp.verify('520489', 9))
        self.assertTrue(hotp.verify('0000520489', 9))
        self.assertFalse(hotp.verify('1520489', 9))
        self.assertFalse(hotp.verify('abcdef', 9))

    def testProvisioningURI(self):
        hotp = pyotp.HOTP('wrn3pqx5uqxqvnqr')

        self.assertEqual(
            hotp.provisioning_uri('mark@percival'),
            'otpauth://hotp/mark@percival?secret=wrn3pqx5uqxqvnqr&counter=0')

        self.assertEqual(
            hotp.provisioning_uri('mark@percival', initial_count=12),
            'otpauth://hotp/mark@percival?secret=wrn3pqx5uqxqvnqr&counter=12')

        self.assertEqual(
            hotp.provisioning_uri('mark@percival', issuer_name='FooCorp!'),
            'otpauth://hotp/FooCorp%21:mark@percival?secret=wrn3pqx5uqxqvnqr&counter=0&issuer=FooCorp%21')


class TOTPExampleValuesFromTheRFC(unittest.TestCase):
    def testMatchTheRFC(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        self.assertEqual(totp.at(1111111111), 50471)
        self.assertEqual(totp.at(1234567890), 5924)
        self.assertEqual(totp.at(2000000000), 279037)

    def testMatchTheGoogleAuthenticatorOutput(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        with Timecop(1297553958):
            self.assertEqual(totp.now(), 102705)

    def testValidateATimeBasedOTP(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        with Timecop(1297553958):
            self.assertTrue(totp.verify(102705))
            self.assertTrue(totp.verify("102705"))
        with Timecop(1297553958 + 30):
            self.assertFalse(totp.verify(102705))

    def testProvisioningURI(self):
        totp = pyotp.TOTP('wrn3pqx5uqxqvnqr')
        self.assertEqual(
            totp.provisioning_uri('mark@percival'),
            'otpauth://totp/mark@percival?secret=wrn3pqx5uqxqvnqr')

        self.assertEqual(
            totp.provisioning_uri('mark@percival', issuer_name='FooCorp!'),
            'otpauth://totp/FooCorp%21:mark@percival?secret=wrn3pqx5uqxqvnqr&issuer=FooCorp%21')

    def testVerify(self):
        totp = pyotp.TOTP('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ')
        # verify must work with integers
        self.assertTrue(totp.verify(50471, 1111111111))
        self.assertTrue(totp.verify(5924, 1234567890))
        self.assertTrue(totp.verify(279037, 2000000000))
        # if the input is a string with <= 6 chars, accept it too
        self.assertTrue(totp.verify('50471', 1111111111))
        self.assertTrue(totp.verify('5924', 1234567890))
        self.assertTrue(totp.verify('279037', 2000000000))
        # 0 padded strings must be accepted
        self.assertTrue(totp.verify('050471', 1111111111))
        self.assertTrue(totp.verify('005924', 1234567890))
        # 0 padded strings must be accepted even if they have more digits than
        # allowed
        self.assertTrue(totp.verify('0279037', 2000000000))
        # unicode objects must be accepted
        self.assertTrue(totp.verify(u'050471', 1111111111))
        # verify must deny wrong codes
        self.assertFalse(totp.verify(50472, 1111111111))
        self.assertFalse(totp.verify('abcdef', 2000000000))
        self.assertFalse(totp.verify('1279037', 2000000000))

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
            def now(cls):
                return cls.fromtimestamp(timecop.freeze_timestamp)

        timecop = self
        return FrozenDateTime


if __name__ == '__main__':
    unittest.main()
