#!/usr/bin/env python
# Malte Heinzelmann 2021
#
# MIT License
#
# Copyright (c) 2021 Malte Heinzelmann
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import argparse
import contextlib
import logging
import os
import select
import socket
import ssl
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Union, Callable, List, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509 import load_pem_x509_certificate, CertificateBuilder, Certificate, load_der_x509_certificate, \
    random_serial_number

log = logging.getLogger("doppelganger")

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)
# The background is set with 40 plus the number of the color, and the foreground with 30

# These are the sequences need to get colored output
RESET_SEQ = "\033[0m"
COLOR_SEQ = "\033[1;%dm"
BOLD_SEQ = "\033[1m"


def formatter_message(message, use_color=True):
    if use_color:
        message = message.replace("$RESET", RESET_SEQ).replace("$BOLD", BOLD_SEQ)
    else:
        message = message.replace("$RESET", "").replace("$BOLD", "")
    return message


COLORS = {
    "WARNING": YELLOW,
    "INFO": WHITE,
    "DEBUG": BLUE,
    "CRITICAL": RED,
    "ERROR": RED
}

NAMES = {
    "WARNING": "WARN",
    "INFO": "INFO",
    "DEBUG": "DEBG",
    "CRITICAL": "CRIT",
    "ERROR": "ERR "
}


class ColoredFormatter(logging.Formatter):
    def __init__(self, msg, use_color=True):
        logging.Formatter.__init__(self, msg)
        self.use_color = use_color

    def format(self, record):
        levelname = record.levelname
        if self.use_color and levelname in COLORS:
            levelname_color = COLOR_SEQ % (30 + COLORS[levelname]) + NAMES[levelname] + RESET_SEQ
            record.levelname = levelname_color
        return logging.Formatter.format(self, record)


def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"File not found {arg}")
    else:
        try:
            with open(arg, "r"):
                return arg
        except Exception as e:
            parser.error(f"Couldn't open file {e}")


def is_valid_directory(parser, arg):
    if not os.path.exists(arg):
        parser.error(f"Directory not found {arg}")
    elif not os.path.isdir(arg):
        parser.error(f"File is not a directory {arg}")
    else:
        return Path(arg)


def is_valid_port(parser, arg):
    try:
        if not isinstance(arg, int):
            arg = int(arg)
        if arg < 1 or arg > 65535:
            parser.error(f"Invalid port {arg} not in range 1-65535")
        else:
            return arg
    except ValueError:
        parser.error(f"Invalid port {arg} not a number")


NO_PROTO = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_3

PROTOS = {
    "ssl3": NO_PROTO & ~ssl.OP_NO_SSLv3,
    "tls1": NO_PROTO & ~ssl.OP_NO_TLSv1,
    "tls1_1": NO_PROTO & ~ssl.OP_NO_TLSv1_1,
    "tls1_2": NO_PROTO & ~ssl.OP_NO_TLSv1_2,
    "tls1_3": NO_PROTO & ~ssl.OP_NO_TLSv1_3,
}
CRYPTO_BACKEND = default_backend()


def parse_args():
    parser = argparse.ArgumentParser(
        prog="Doppelganger",
        description="A X.509 certificate cloner including a man-in-the-middle proxy to test if clients correctly "
                    "validate certificates")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-c", "--cert", dest="certificate",
                       metavar="CERT", type=lambda x: is_valid_file(parser, x),
                       help="Use the certificate in PEM format as template. If not set, will connect to target to "
                            "grab the certificate.")
    parser.add_argument("--ca", dest="ca", action="store_const", const=True, default=False,
                        help="If set the certificate will be signed by a fake CA, instead of being self-signed.")
    parser.add_argument("--copy-serial", dest="copy_serial", action="store_const", const=True, default=False,
                        help="If set the serial of the certificate will be cloned as well. This could lead to problems"
                             "if the original serial is still cached somewhere, thus by default it will be randomized.")
    group.add_argument("-t", "--target", dest="target", metavar="HOST", type=str,
                       help="The hostname/IP of the target server.")
    parser.add_argument("-p", "--port", dest="port", metavar="PORT", default=443,
                        type=lambda x: is_valid_port(parser, x),
                        help="The hostname/IP of the target server. (default: %(default)d)")
    parser.add_argument("-s", "--sni", dest="sni", metavar="SNI", type=str,
                        help="If set it's used as the hostname for SNI.")
    parser.add_argument("-l", "--listen", dest="listen",
                        metavar="PORT", type=lambda x: is_valid_port(parser, x),
                        help="The port to listen on locally. If not set, proxy won't be started.")
    parser.add_argument("-P", "--protocol", dest="protocol", metavar="PROTOCOL",
                        choices=list(PROTOS.keys()),
                        help="Fix the SSL/TLS version to use. (default: python default)")
    parser.add_argument("-o", "--output", dest="output",
                        type=lambda x: is_valid_directory(parser, x),
                        help="Location to store the certificate and private key. (default: temp directory)")
    parser.add_argument("-6", dest="ipv6", action="store_const", const=True, default=False,
                        help="Use IPv6. (default: %(default)s)")
    parser.add_argument("-d", "--der", dest="der", action="store_const", const=True, default=False,
                        help="Switches to DER format for file imported certificate.")
    parser.add_argument("-v", "--verbose", action="count", default=1,
                        help="Increases log output. Use multiple times to further increase log output.")
    parser.add_argument("-f", "--force", dest="force", action="store_const", const=True, default=False,
                        help="Overwrite certificates in output folder if already exists. Use with caution.")
    return parser.parse_args()


class Upstream:
    def __init__(self, host: str, port: int, ipv6: bool, sni=None):
        self.target = (host, port)
        self.ipv6 = ipv6
        self.sni = sni

    def __str__(self):
        if self.sni:
            return f"[{self.sni}]@{self.host}:{self.port}"
        return f"{self.host}:{self.port}"

    @property
    def host(self) -> str:
        return self.target[0]

    @property
    def port(self) -> int:
        return self.target[1]

    def test_connection(self) -> bool:
        try:
            return ssl.get_server_certificate(self.target) is not None
        except Exception as e:
            log.critical("Unable to connect to upstream")
            log.debug(e)
            return False

    @contextlib.contextmanager
    def connect(self) -> ssl.SSLSocket:
        dss = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        dss = ctx.wrap_socket(dss, server_hostname=self.sni)
        try:
            dss.connect(self.target)
            yield dss
        finally:
            dss.close()


PrivateKey = Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]
CertAndKey = Tuple[Certificate, PrivateKey]
PathLike = Union[str, Path]


class Cloner:
    def __init__(self, use_ca=False, copy_serial=False, workdir=None, *, force=False):
        self.use_ca = use_ca
        self.copy_serial = copy_serial
        self.workdir = workdir
        self.force = force

    def _get_server_certificate(self, upstream: Upstream) -> Certificate:
        with upstream.connect() as s:
            return load_der_x509_certificate(s.getpeercert(True), CRYPTO_BACKEND)

    def _gen_private_key(self, cert: Certificate) -> PrivateKey:
        pubkey = cert.public_key()
        if isinstance(pubkey, rsa.RSAPublicKey):
            return rsa.generate_private_key(pubkey.public_numbers().e, pubkey.key_size, CRYPTO_BACKEND)
        elif isinstance(pubkey, ec.EllipticCurvePublicKey):
            return ec.generate_private_key(pubkey.curve, CRYPTO_BACKEND)
        else:
            log.warning("Public key of cert is neither RSA nor EC falling back to RSA")
            log.debug("Found unhandled public key: %s", type(pubkey))
            return rsa.generate_private_key(0x10001, 2048, CRYPTO_BACKEND)

    def _build_ca(self, cert: Certificate, priv: Union[rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey]) -> Certificate:
        # Create builder
        builder = CertificateBuilder()

        # Set common fields
        builder = builder.subject_name(cert.issuer)
        builder = builder.issuer_name(cert.issuer)
        builder = builder.not_valid_before(datetime.utcnow() - timedelta(days=365))
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=3650))
        builder = builder.serial_number(random_serial_number())
        builder = builder.public_key(priv.public_key())

        return builder.sign(
            private_key=priv,
            algorithm=cert.signature_hash_algorithm,
            backend=CRYPTO_BACKEND
        )

    def _build_cert(self, cert: Certificate, priv: PrivateKey, *, ca: CertAndKey = None) -> Certificate:
        # Create builder
        builder = CertificateBuilder()

        # Set common fields
        builder = builder.subject_name(cert.subject)
        builder = builder.issuer_name(cert.issuer)
        builder = builder.not_valid_before(cert.not_valid_before)
        builder = builder.not_valid_after(cert.not_valid_after)
        builder = builder.serial_number(cert.serial_number if self.copy_serial else random_serial_number())
        builder = builder.public_key(priv.public_key())

        # Add all extensions
        for extension in cert.extensions:
            builder = builder.add_extension(extension.value, critical=extension.critical)

        # Sign the
        return builder.sign(
            private_key=priv,
            algorithm=cert.signature_hash_algorithm,
            backend=CRYPTO_BACKEND
        )

    def __save_cert_and_key(self, directory: Path, cert_and_key: CertAndKey, prefix: str = "") -> Optional[
        Tuple[Path, Path]]:
        certname = prefix + "certificate.pem"
        certfile = directory / certname
        keyname = prefix + "key.pem"
        keyfile = directory / keyname

        if certfile.exists():
            if not self.force:
                log.error("Certificate file %s exists in output directory, pass --force to overwrite", certname)
                return None

        cert, priv = cert_and_key

        # Write cert
        with open(certfile, "wb") as certw:
            certw.write(cert.public_bytes(Encoding.PEM))
        # Write key
        with open(keyfile, "wb") as keyw:
            keyw.write(priv.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            ))
        return certfile, keyfile

    def _save_all(self, cert: CertAndKey, directory: PathLike, *, ca: CertAndKey = None) -> Optional[Tuple[Path, Path]]:
        if directory is None:
            directory = tempfile.mkdtemp(prefix="doppelganger-")
        if isinstance(directory, str):
            directory = Path(directory)
        if not directory.exists():
            log.info("Creating output directory: %s", directory)
            directory.mkdir(parents=True)
        if not directory.is_dir():
            log.critical("File exists and is no directory: %s", directory)
            return None

        files = self.__save_cert_and_key(directory, cert)
        if files is None:
            return None
        if ca is not None:
            self.__save_cert_and_key(directory, ca, "ca-")
        log.info("Saved all certificates and private keys to %s/", directory)
        return files

    def clone_cert(self, cert: Certificate):
        # Generate a new key pair matching pub key infos
        ca = None
        if self.use_ca:
            log.info("Generating a new key pair for the CA")
            priv_ca = self._gen_private_key(cert)
            ca = self._build_ca(cert, priv_ca), priv_ca

        log.info("Generating a new key pair for the certificate")
        priv = self._gen_private_key(cert)

        # Update the certificate
        log.info("Updating certificate with new key")
        cert = self._build_cert(cert, priv, ca=ca)
        log.info("Created certificate")
        return self._save_all((cert, priv), self.workdir, ca=ca)

    def clone_cert_from_pem(self, pem: str):
        try:
            cert = load_pem_x509_certificate(pem.encode("ascii", "ignore"), CRYPTO_BACKEND)
        except Exception as e:
            log.critical("Unable to load file as PEM")
            log.debug(e)
            return None
        return self.clone_cert(cert)

    def clone_cert_from_der(self, der: bytes):
        try:
            cert = load_der_x509_certificate(der, CRYPTO_BACKEND)
        except Exception as e:
            log.critical("Unable to load file as DER")
            log.debug(e)
            return None
        return self.clone_cert(cert)

    def clone_cert_from_file(self, file: Union[str, Path], encoding: Encoding = Encoding.PEM):
        if encoding == Encoding.PEM:
            return self.clone_cert_from_pem(open(file, "r").read())
        elif encoding == Encoding.DER:
            return self.clone_cert_from_der(open(file, "rb").read())
        raise ValueError("Invalid encoding")

    def clone_cert_from_server(self, upstream: Upstream):
        log.info("Fetching certificate from %s", upstream)
        try:
            return self.clone_cert(self._get_server_certificate(upstream))
        except Exception as e:
            log.critical("Unable to connect to upstream")
            log.debug(e)


class Proxy:
    def __init__(self, upstream: Upstream, listen_port: int, ipv6: bool, protocol: str, certfile: Path, keyfile: Path):
        self.upstream = upstream
        self.listen_port = listen_port
        self.ipv6 = ipv6
        self.certfile = certfile
        self.keyfile = keyfile
        self.proto = PROTOS.get(protocol, 0)
        self.running = True
        self.c2s_hooks: List[Callable[[bytes], Optional[bytes]]] = []
        self.s2c_hooks: List[Callable[[bytes], Optional[bytes]]] = []

    def _handle_data(self, src, dst, hooks, size=1024):
        stuff = src.recv(size)
        if len(stuff) == 0:
            dst.close()
            return
        for hook in hooks:
            new = hook(stuff)
            if new is not None:
                stuff = new
        dst.send(stuff)

    def _handle_conn(self, css: ssl.SSLSocket, address):
        size = 4096
        sip, sport = address
        log.info(f"Incomming connection from %s:%d", sip, sport)
        try:
            with self.upstream.connect() as dss:
                streams = [css, dss]
                while True:
                    try:
                        inputready, outputready, exceptready = select.select(streams, [], [])
                        for s in inputready:
                            if s == css:
                                self._handle_data(s, dss, self.c2s_hooks, size)
                            elif s == dss:
                                self._handle_data(s, css, self.s2c_hooks, size)
                            else:
                                log.warning("Weird behavior")
                    except Exception as e:
                        log.info(f"Connection from %s:%d terminated", sip, sport)
                        log.debug(e)
                        break
        finally:
            css.close()

    def add_c2s_hook(self, hook: Callable[[bytes], Optional[bytes]]):
        self.c2s_hooks.append(hook)

    def add_s2c_hook(self, hook: Callable[[bytes], Optional[bytes]]):
        self.s2c_hooks.append(hook)

    def run(self):
        lss = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET, socket.SOCK_STREAM)
        lss.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lss.bind(("", self.listen_port))
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.options |= self.proto
        ctx.load_cert_chain(self.certfile, self.keyfile)
        lss = ctx.wrap_socket(lss, server_side=True)
        lss.listen(5)
        log.info("Proxy up and running on port %d", self.listen_port)
        while self.running:
            try:
                threading.Thread(target=self._handle_conn, args=lss.accept()).start()
            except KeyboardInterrupt:
                break
        lss.close()


def main():
    args = parse_args()

    # Setup logging
    args.verbose = max(logging.DEBUG, logging.ERROR - (10 * args.verbose) if args.verbose > 0 else logging.ERROR)
    syslog = logging.StreamHandler()
    syslog.setFormatter(ColoredFormatter(formatter_message("[$BOLD%(levelname)s$RESET] %(message)s")))
    log.setLevel(args.verbose)
    log.addHandler(syslog)

    # Upstream definition
    upstream = Upstream(args.target, args.port, args.ipv6, args.sni)

    # Init cloner
    cloner = Cloner(args.ca, args.copy_serial, args.output, force=args.force)
    tested_upstream = False
    if args.certificate:
        files = cloner.clone_cert_from_file(args.certificate, Encoding.DER if args.der else Encoding.PEM)
        if files is None:
            return
        certfile, keyfile = files
    elif args.target:
        files = cloner.clone_cert_from_server(upstream)
        if files is None:
            return
        certfile, keyfile = files
        tested_upstream = True
    else:
        # target and certificate are required and mutually exclusive
        return
    # Proxy mode?
    if args.listen is not None:
        # Don't test upstream twice, it's just to give instant feedback
        if not tested_upstream and not upstream.test_connection():
            return
        proxy = Proxy(upstream, args.listen, args.ipv6, args.protocol, certfile, keyfile)
        # Add some debugging hooks
        proxy.add_c2s_hook(lambda stuff: log.debug("****** Client => Server ******\n%s", stuff))
        proxy.add_s2c_hook(lambda stuff: log.debug("****** Server => Client ******\n%s", stuff))
        proxy.run()


if __name__ == "__main__":
    main()
