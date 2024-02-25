from pyotp import __version__, TOTP, HOTP, random_base32, random_hex
import argparse

parser = argparse.ArgumentParser()


def parse_terminal_arguments():
    parser.add_argument('secret', nargs='?', help=f'Base32 secret')
    parser.add_argument('--hotp', action='store', metavar='NUMBER', type=int, help='Specify HOTP position\\number ')
    parser.add_argument('--hex', action='store_true', help='returns a 40-character hex-encoded secret')
    parser.add_argument('-v', '--version', action='version', version=f'PyOTP v.{__version__}')
    return vars(parser.parse_args())


def main(): # TODO: pass args to set_global_server_repo() set_github_token('')
    args = parse_terminal_arguments()

    if not args['secret']:
        if not args['hex']:
            print(random_base32())
        else:
            print(random_hex())
        exit()

    try:
        if not args['hotp']:
            print(TOTP(args['secret']).now())
        else:
            print(HOTP(args['secret']).at(args['hotp']))
    except:
        print(f'Invalid secret: {args["secret"]}')



if __name__ == "__main__":
    main()
