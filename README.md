
# emqx-auth-custom_jwt

EMQ X JWT Authentication Plugin 

Build
-----

```
make && make tests
```

Configure the Plugin
--------------------

File: etc/plugins/emqx_auth_custom_jwt.conf

```

## From where the JWT string can be got
##
## Value: username | password
## Default: password
auth.custom_jwt.from = password

#authority url address for JWK retrieval from openId .well_known
auth.custom_jwt.authority = https://sts.skoruba.local

#verify ssl cert for authority endpoint defaults to true
# auth.custom_jwt.verify_ssl = false

## Enable to verify claims fields
##
## Value: on | off
auth.custom_jwt.verify_claims = off

## The checklist of claims to validate
##
## Value: String
## auth.custom_jwt.verify_claims.$name = expected
##
## Variables:
##  - %u: username
##  - %c: clientid
# auth.custom_jwt.verify_claims.username = %u
```

Load the Plugin
---------------

```
./bin/emqx_ctl plugins load emqx_auth_custom_jwt
```

Example
-------

```
mosquitto_pub -t 'pub' -m 'hello' -i test -u test -P eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiYm9iIiwiYWdlIjoyOX0.bIV_ZQ8D5nQi0LT8AVkpM4Pd6wmlbpR9S8nOLJAsA8o
```

Algorithms
----------

The JWT spec supports several algorithms for cryptographic signing. This plugin currently supports:

* RS256 - RSA with the SHA-256 hash algorithm
* RS384 - RSA with the SHA-384 hash algorithm
* RS512 - RSA with the SHA-512 hash algorithm
License
-------

Apache License Version 2.0

Author
------

EMQ X Team and Stanisław Lutkiewicz.
