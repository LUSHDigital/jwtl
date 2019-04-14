# JWTDev

This is a tool to help you during development.
It relies on the fact that we can predict the source for RSA public keys, thanks
to the `keybroker` package from `core`.

```
usage:
[generate]:
	[keys]: generates a new rsa key pair under ~/.lushdev
	[jwt]: generates a new jwt, using the generated rsa key pair
```

In order to use this tool effectively, one should first generate keys, then export the required environment variable (this will be provided to you).

The broker knows where to look after that.

The tokens generated via this tool are valid for 24 hours.