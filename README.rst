PyOTP - The Python One-Time Password Library
============================================

PyOTP is a Python library for generating and verifying one-time passwords. It can be used to implement two-factor (2FA)
or multi-factor (MFA) authentication methods in web applications and in other systems that require users to log in.

Open MFA standards are defined in `RFC 4226 <https://tools.ietf.org/html/rfc4226>`_ (HOTP: An HMAC-Based One-Time
Password Algorithm) and in `RFC 6238 <https://tools.ietf.org/html/rfc6238>`_ (TOTP: Time-Based One-Time Password
Algorithm). PyOTP implements server-side support for both of these standards. Client-side support can be enabled by
sending authentication codes to users over SMS or email (HOTP) or, for TOTP, by instructing users to use `Google
Authenticator <https://en.wikipedia.org/wiki/Google_Authenticator>`_, `Authy <https://www.authy.com/>`_, or another
compatible app. Users can set up auth tokens in their apps easily by using their phone camera to scan `otpauth://
<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>`_ QR codes provided by PyOTP.

We recommend that implementers read the `OWASP Authentication Cheat Sheet <https://www.owasp.org/index.php/Authentication_Cheat_Sheet>`_ and `NIST SP 800-63-3: Digital Authentication Guideline <https://pages.nist.gov/800-63-3/>`_ for a high level overview of authentication best practices.

Quick overview of using One Time Passwords on your phone
--------------------------------------------------------

* OTPs involve a shared secret, stored both on the phone and the server
* OTPs can be generated on a phone without internet connectivity
* OTPs should always be used as a second factor of authentication (if your phone is lost, you account is still secured with a password)
* Google Authenticator and other OTP client apps allow you to store multiple OTP secrets and provision those using a QR Code

Installation
------------
::

    pip install pyotp

Usage
-----

Time-based OTPs
~~~~~~~~~~~~~~~
::

    totp = pyotp.TOTP('base32secret3232')
    totp.now() # => 492039

    # OTP verified for current time
    totp.verify(492039) # => True
    time.sleep(30)
    totp.verify(492039) # => False

Counter-based OTPs
~~~~~~~~~~~~~~~~~~
::

    hotp = pyotp.HOTP('base32secret3232')
    hotp.at(0) # => 260182
    hotp.at(1) # => 55283
    hotp.at(1401) # => 316439

    # OTP verified with a counter
    hotp.verify(316439, 1401) # => True
    hotp.verify(316439, 1402) # => False

Generating a base32 Secret Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
::

    pyotp.random_base32() # returns a 16 character base32 secret. Compatible with Google Authenticator and other OTP apps

Google Authenticator Compatible
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

PyOTP works with the Google Authenticator iPhone and Android app, as well as other OTP apps like Authy. PyOTP includes the
ability to generate provisioning URIs for use with the QR Code scanner built into these MFA client apps::

    pyotp.totp.TOTP('JBSWY3DPEHPK3PXP').provisioning_uri("alice@google.com", issuer_name="Secure App")

    >>> 'otpauth://totp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure%20App'

    pyotp.hotp.HOTP('JBSWY3DPEHPK3PXP').provisioning_uri("alice@google.com", initial_count=0, issuer_name="Secure App")

    >>> 'otpauth://hotp/Secure%20App:alice%40google.com?secret=JBSWY3DPEHPK3PXP&issuer=Secure%20App&counter=0'

This URL can then be rendered as a QR Code (for example, using https://github.com/neocotic/qrious) which can then be scanned
and added to the users list of OTP credentials.

Working example
~~~~~~~~~~~~~~~

Scan the following barcode with your phone's OTP app (e.g. Google Authenticator):

.. image:: http://chart.apis.google.com/chart?cht=qr&chs=250x250&chl=otpauth%3A%2F%2Ftotp%2Falice%40google.com%3Fsecret%3DJBSWY3DPEHPK3PXP

Now run the following and compare the output::

    import pyotp
    totp = pyotp.TOTP("JBSWY3DPEHPK3PXP")
    print("Current OTP:", totp.now())

Links
~~~~~

* `Project home page (GitHub) <https://github.com/pyotp/pyotp>`_
* `Documentation (Read the Docs) <https://pyotp.readthedocs.io/en/latest/>`_
* `Package distribution (PyPI) <https://pypi.python.org/pypi/pyotp>`_
* `Change log <https://github.com/pyotp/pyotp/blob/master/Changes.rst>`_
* `RFC 4226: HOTP: An HMAC-Based One-Time Password <https://tools.ietf.org/html/rfc4226>`_
* `RFC 6238: TOTP: Time-Based One-Time Password Algorithm <https://tools.ietf.org/html/rfc6238>`_
* `ROTP <https://github.com/mdp/rotp>`_ - Original Ruby OTP library by `Mark Percival <https://github.com/mdp>`_
* `OTPHP <https://github.com/lelag/otphp>`_ - PHP port of ROTP by `Le Lag <https://github.com/lelag>`_
* `OWASP Authentication Cheat Sheet <https://www.owasp.org/index.php/Authentication_Cheat_Sheet>`_
* `NIST SP 800-63-3: Digital Authentication Guideline <https://pages.nist.gov/800-63-3/>`_

.. image:: https://img.shields.io/travis/pyotp/pyotp.svg
        :target: https://travis-ci.org/pyotp/pyotp
.. image:: https://img.shields.io/codecov/c/github/pyotp/pyotp/master.svg
        :target: https://codecov.io/github/pyotp/pyotp?branch=master
.. image:: https://img.shields.io/pypi/v/pyotp.svg
        :target: https://pypi.python.org/pypi/pyotp
.. image:: https://img.shields.io/pypi/l/pyotp.svg
        :target: https://pypi.python.org/pypi/pyotp
.. image:: https://readthedocs.org/projects/pyotp/badge/?version=latest
        :target: https://pyotp.readthedocs.io/
