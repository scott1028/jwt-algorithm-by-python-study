#/usr/bin/env python
# coding: utf-8
# JWT 演算法生成與驗證(驗證方根生成方都必須有 Secret Key)
# https://gxnotes.com/article/105795.html

import json
import base64
import hmac
import hashlib
import base64
from collections import OrderedDict


def hmac_sha256_sign(key, msg):
    digest = hmac.new(key, msg=msg, digestmod=hashlib.sha256).digest()
    signature = base64forJwt(digest)
    return signature

def base64forJwt(data):
    return base64.urlsafe_b64encode(data).rstrip('=')

def verify(key, msg, inpurt_signature):
    return hmac_sha256_sign(key, msg) == inpurt_signature    

# Keep order
header = OrderedDict([
    ("alg", "HS256"),
    ("typ", "JWT")
])

# Keep order
preload = OrderedDict([
    ("sub", "1234567890"),
    ("name", "John Doe"),
    ("admin", True)
])

key = 'secret'

separators=(',', ':')

print json.dumps(header, separators=separators, sort_keys=False)
print json.dumps(preload, separators=separators, sort_keys=False)

h = base64forJwt(json.dumps(header, separators=separators, sort_keys=False))
p = base64forJwt(json.dumps(preload, separators=separators, sort_keys=False))

data = h + '.' + p

print
print data
print

sign = hmac_sha256_sign(key, data)

print sign
print
print 'JWT: ', h + '.' + p + '.' + sign
print 'JWT: ', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ'
print
print 'Server Verify JWT', verify(key, h + '.' + p, sign)
