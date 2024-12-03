from pyotp import __version__, TOTP, HOTP, random_base32, random_hex
from sys import argv


def argument_parser():
    if len(argv) > 1:
        if argv[1] in ('-v', '--version'):
            print(f'PyOTP v.{__version__}')
        else:
            print(f'''PyOTP v.{__version__} usage:\
            \n  pyotp  - Generate a 32-character base32 secret\
            \n  pyotph - Generate a  hex-encoded base32 secret\
            \n  pytotp - Return TOTP digits from base32 secret\
            \n  pyhotp - Return HOTP digits from base32 secret\
            ''')
        exit()
 

def generate(hex=False): 
    argument_parser()
    if not hex:
        print(random_base32())
    else:
        print(random_hex())


def generate_hex(): 
    generate(hex=True)


def otp(is_totp=True):
    argument_parser()
    try:
        if is_totp:
            print("Enter base32 secret: ", end='')
            secret = input()
            print(TOTP(secret).now())
        else:
            print("Enter base32 secret: ", end='')
            secret = input()
            print("Enter number: ", end='')
            number = int(input())
            print(HOTP(secret).at(number))
    except:
        print(f'Invalid secret: {secret}')


def hotp(): 
    otp(is_totp=False)


if __name__ == "__main__":
    generate()
