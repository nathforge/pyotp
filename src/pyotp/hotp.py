from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from pyotp.otp import OTP
from pyotp import utils
from future.builtins import str


class HOTP(OTP):
    def at(self, count):
        """
        Generates the OTP for the given count
        @param [Integer] count counter
        @returns [Integer] OTP
        """
        return self.generate_otp(count)

    def verify(self, otp, counter):
        """
        Verifies the OTP passed in against the current time OTP
        @param [String/Integer] otp the OTP to check against
        @param [Integer] counter the counter of the OTP
        """
        return utils.strings_equal(str(otp), str(self.at(counter)))

    def provisioning_uri(self, name, initial_count=0, issuer_name=None):
        """
        Returns the provisioning URI for the OTP
        This can then be encoded in a QR Code and used
        to provision the Google Authenticator app
        @param [String] name of the account
        @param [Integer] initial_count starting counter value, defaults to 0
        @param [String] the name of the OTP issuer; this will be the
            organization title of the OTP entry in Authenticator
        @return [String] provisioning uri
        """
        return utils.build_uri(
            self.secret,
            name,
            initial_count=initial_count,
            issuer_name=issuer_name,
            algorithm=self.digest().name,
            digits=self.digits
        )
