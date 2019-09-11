# jwks2pem
This tool can convert a JWK Set (https://tools.ietf.org/html/rfc7517) to standard PEM keys.

# Installation
Install the requirements for jwks2pem

```shell script
pip install -r requirements.txt
```

# Usage
Simple example given a keystore ```keystore.jwks```
```shell script
python3 jwks2pem.py [-h] --input keystore.jwks --output key
```

this produces one PEM file per key in ```keystore.jwks``` with a name of ```key_0.pem``` ... ```key_n.pem```
and shows the following message if successful:

```1 keys successfully converted to PEM format```
