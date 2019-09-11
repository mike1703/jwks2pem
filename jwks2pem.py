import argparse
import base64
import json
import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def intarr2long(arr):
    return int(''.join(["%02x" % byte for byte in arr]), 16)


def base64_to_long(data):
    if isinstance(data, str):
        data = data.encode("ascii")

    # urlsafe_b64decode will happily convert b64encoded data
    _d = base64.urlsafe_b64decode(bytes(data) + b'==')
    return intarr2long(struct.unpack('%sB' % len(_d), _d))


# load key parameters from a JWK Set (https://tools.ietf.org/html/rfc7517)
# only n, e and d are necessary
def load_keys_from_jwks(jwks_filename):
    keys = []
    with open(jwks_filename, 'r') as jwks_file:
        jwk = json.load(jwks_file)

        for key in jwk.get('keys'):
            if not ('n' in key and 'e' in key and 'd' in key):
                # this key does not contain all necessary parameters
                continue

            # convert base64 encoded longs to actual longs
            key['n'] = base64_to_long(key.get('n'))
            key['e'] = base64_to_long(key.get('e'))
            key['d'] = base64_to_long(key.get('d'))
            keys.append(key)

    return keys


def convert_to_pem(jwks_keys):
    pem_keys = []
    for jwk_key in jwks_keys:
        e = jwk_key.get('e')
        n = jwk_key.get('n')
        d = jwk_key.get('d')

        # We don't have p, q, dp, dq and qi but you can recover it with knowledge of d
        # if you have p and q you wouldn't need the d but could calculate d from this.

        (p, q) = rsa.rsa_recover_prime_factors(n, e, d)

        dp = rsa.rsa_crt_dmp1(d, p)
        dq = rsa.rsa_crt_dmq1(d, q)
        qi = rsa.rsa_crt_iqmp(p, q)

        public_numbers = rsa.RSAPublicNumbers(e=e, n=n)

        key = rsa.RSAPrivateNumbers(p, q, d, dp, dq, qi, public_numbers).private_key(default_backend())
        pem_string = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption())

        pem_keys.append(pem_string.decode('ascii'))

    return pem_keys


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='convert jwks to pem')
    parser.add_argument('--input', help='input file (jwks)', required=True)
    parser.add_argument('--output', help='output filename base string (without .pem)', required=True)

    args = parser.parse_args()

    # load the keys from the file
    jwks_keys = load_keys_from_jwks(args.input)

    # transform the keys to PEM format
    pem_keys = convert_to_pem(jwks_keys)

    # output the keys to files
    i = 0
    for pem_key in pem_keys:
        with open("{}_{}.pem".format(args.output, i), 'w') as pem_file:
            pem_file.write(pem_key)
        i += 1

    print('{} keys successfully converted to PEM format'.format(i))
