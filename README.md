Doppelganger
============

Doppelganger allows you to:
- Clone a locally available certificate in PEM/DER encoding
- Retrieve certificates from remote hosts and use them for cloning
- Create a mitm proxy to test client-side certificate validation
- Supports RSA and EC keys
- Allows SNI to override the hostname

Process of cloning:
1. Create a similar key pair (same exponent and key length)
2. Build a new certificate using the same properties and extensions
3. Self-sign that certificate using the key pair from step 1
4. *Optional:* Listen on a given port and forward all connections to a target host

## Usage

```
usage: Doppelganger [-h] [-c CERT] [--ca] [--copy-serial] [-t HOST] [-p PORT] [-s SNI] [-l PORT] [-P PROTOCOL] [-o OUTPUT] [-6] [-d] [-v] [--force]

A X.509 certificate cloner including a man-in-the-middle proxy to test if clients correctly validate certificates

optional arguments:
  -h, --help            show this help message and exit
  -c CERT, --cert CERT  Use the certificate in PEM format as template. If not set, will connect to target to grab the certificate.
  --ca                  If set the certificate will be signed by a fake CA, instead of being self-signed.
  --copy-serial         If set the serial of the certificate will be cloned as well. This could lead to problemsif the original serial is still cached somewhere, thus by default it will be randomized.
  -t HOST, --target HOST
                        The hostname/IP of the target server.
  -p PORT, --port PORT  The hostname/IP of the target server. (default: 443)
  -s SNI, --sni SNI     If set it's used as the hostname for SNI.
  -l PORT, --listen PORT
                        The port to listen on locally. If not set, proxy won't be started.
  -P PROTOCOL, --protocol PROTOCOL
                        Fix the SSL/TLS version to use. (default: python default)
  -o OUTPUT, --output OUTPUT
                        Location to store the certificate and private key. (default: temp directory)
  -6                    Use IPv6. (default: False)
  -d, --der             Switches to DER format for file imported certificate.
  -v, --verbose         Increases log output. Use multiple times to further increase log output.
  --force               Overwrite certificates in output folder if already exists. Use with caution.
```

### Clone local cert

Given a certificate in PEM format named `certificate.pem`, it can be cloned by running.

```shell
python doppelganger.py -c certificate.pem
```

To store the output outside the temp directory of the os add `-o $directory`, for example `-o certs/`.

### Create a mitm proxy

In this example we impersonate `exmaple.com` and open a proxy on port `8443` and enable debug output with `vv`.
The debug output includes all bytes received from the client and server.

```shell
python doppelganger.py -t example.com -l 8443 -vv
```

## Installation

The easiest way to install Doppelganger is to clone this repository (or download the `doppelganger.py` file) and install the dependencies through pip.

```shell
pip install -r requirements.txt
```

The repository also includes a `Pipfile` for those that prefer `pipenv`.

## Example

In the following example, the debug output when a client uses the proxy to connect to `example.com` can be seen. 

![Demo](/hnzlmnn/doppelganger/blob/assets/demo.gif?raw=true)