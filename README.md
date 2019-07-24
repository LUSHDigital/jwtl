# jwtl (JSON Web Token Command Line tool)
This is a tool to help you during development. It relies on the fact that we can predict the source for RSA public keys, thanks to the [LUSHDigital/core/workers/keybroker](https://github.com/LUSHDigital/core/tree/master/workers/keybroker) package from [LUSHDigital/core](https://github.com/LUSHDigital/core).

In order to use this tool effectively, one should first generate keys, then export the required environment variable (this will be provided to you). The broker knows where to look after that. The tokens generated via this tool are valid for 24 hours.

## Install

```
$ go install github.com/LUSHDigital/jwtl
```

```
$ jwtl -path ~/.secrets -name jwt setup
```

## Usage

```
Usage of jwtl:
   jwtl new
	Generates a JWT token based on an RSA key pair
   jwtl setup
	Generates a new RSA key pair
Flags:
  -firstname string
    	First name of the consumer (default "John")
  -grants string
    	Grants of the consumer as a comma separated list (default "read,write")
  -lang string
    	Language of the consumer (default "en")
  -lastname string
    	Last name of the consumer (default "Doe")
  -name string
    	Name of the keys to use or generate in the location (default "jwt")
  -needs string
    	Needs of the consumer as a comma separated list (default "nothing")
  -path string
    	Path on disk to the location to use or generate the keys (default "/Users/me/.secrets")
  -roles string
    	Roles of the consumer as a comma separated list (default "guest")
  -uid int
    	ID of the consumer (default 1)
  -uuid string
    	UUID of the consumer (default "67e89fbc-41eb-4090-b67b-f22b80ced238")
  -valid_from string
    	Timestamp used to determine the time when a token is valid (default "2019-07-24T11:48:17+02:00")
  -valid_period string
    	Duration the generated keys are valid (default "60m")
```
