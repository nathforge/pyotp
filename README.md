## PyOTP - Python One Time Password Library

A Python library for generating one time passcodes according to [RFC
6238](http://tools.ietf.org/html/rfc6238). This version is ported from
https://github.com/nathforge/pyotp to generate accurate 6 digit codes.

This is compatible with Google Authenticator apps available for Android and
iPhone, and now in use on GMail

### Quick overview of using One Time Passwords on your phone

* OTP's involve a shared secret, stored both on the phone and the server
* OTP's can be generated on a phone without internet connectivity(AT&T mode)
* OTP's should always be used as a second factor of authentication(if your
    phone is lost, you account is still secured with a password) * Google
    Authenticator allows you to store multiple OTP secrets and provision those
    using a QR Code(no more typing in the secret)

### Usage

#### Time based OTP's

    totp = pyotp.TOTP('base32secret3232') totp.now() # => 492039

    # OTP verified for current time totp.verify(492039) # => True
    time.sleep(30) totp.verify(492039) # => False

#### Counter based OTP's

    hotp = pyotp.HOTP('base32secret3232') hotp.at(0) # => 260182 hotp.at(1)
    # => 55283 hotp.at(1401) # => 316439

    # OTP verified with a counter hotp.verify(316439, 1401) # => True
    hotp.verify(316439, 1402) # => False

#### Generating a Base32 Secret key

    pyotp.random_base32()

#### Google Authenticator Compatible

The library works with the Google Authenticator iPhone and Android app, and
also includes the ability to generate provisioning URI's for use with the QR
Code scanner built into the app.

    totp.provisioning_uri("alice@google.com") # =>
    'otpauth://totp/alice@google.com?secret=JBSWY3DPEHPK3PXP'

    hotp.provisioning_uri("alice@google.com", 0) # =>
    'otpauth://hotp/alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=0'

This can then be rendered as a QR Code which can then be scanned and added to
the users list of OTP credentials.

##### Working example

Scan the following barcode with your phone, using Google Authenticator

![QR Code for
OTP](http://chart.apis.google.com/chart?cht=qr&chs=250x250&chl=otpauth%3A%2F%2Ftotp%2Falice%40google.com%3Fsecret%3DJBSWY3DPEHPK3PXP)

Now run the following and compare the output

    import pyotp totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    print "Current OTP: %s" % totp.now()

#### Changelog

#### 1.3.1

- Added support to generate accurate 6 digit codes as per RFC

#### 1.3.0

- Ported to Python

### See also:

Original Ruby version of ROTP by [Mark Percival](https://github.com/mdp)
- [ROTP](https://github.com/mdp/rotp) PHP port of ROTP by [Le
    Lag](https://github.com/lelag) - [OTPHP](https://github.com/lelag/otphp)
