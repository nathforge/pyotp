import base64
import hashlib
import hmac


class OTP(object):
    def __init__(self, s, digits=6, digest=hashlib.sha1):
        """
        @param [String] secret in the form of base32
        @option options digits [Integer] (6)
            Number of integers in the OTP
            Google Authenticate only supports 6 currently
        @option options digest [Callable] (hashlib.sha1)
            Digest used in the HMAC
            Google Authenticate only supports 'sha1' currently
        @returns [OTP] OTP instantiation
        """
        self.digits = digits
        self.digest = digest
        self.secret = s
    
    def generate_otp(self, input):
        """
        @param [Integer] input the number used seed the HMAC
        Usually either the counter, or the computed integer
        based on the Unix timestamp
        """
        hmac_hash = hmac.new(
            self.byte_secret(),
            self.int_to_bytestring(input),
            self.digest,
        ).digest()
        
        offset = ord(hmac_hash[19]) & 0xf
        code = ((ord(hmac_hash[offset]) & 0x7f) << 24 |
            (ord(hmac_hash[offset + 1]) & 0xff) << 16 |
            (ord(hmac_hash[offset + 2]) & 0xff) << 8 |
            (ord(hmac_hash[offset + 3]) & 0xff))
        
        str_code = str(code % 10 ** self.digits)
        while len(str_code) < self.digits:
            str_code = '0' + str_code
            
        return str_code
    
    def byte_secret(self):
        return base64.b32decode(self.secret, casefold=True)
    
    def int_to_bytestring(self, int, padding=8):
        """
        Turns an integer to the OATH specified
        bytestring, which is fed to the HMAC
        along with the secret
        """
        result = []
        while int != 0:
            result.append(chr(int & 0xFF))
            int = int >> 8
        return ''.join(reversed(result)).rjust(padding, '\0')
