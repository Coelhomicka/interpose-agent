"""The broker's local certificate authority, used only for transparent HTTPS.

In ``HTTPS_PROXY`` mode a client asks the broker to ``CONNECT`` to a host and
then speaks TLS through it. To see the request (and put the credential in), the
broker answers that TLS itself with a certificate for the host, signed by this CA.

Limits that keep the CA from being worth much to anyone who is not the broker:

* The private key lives next to the vault. With the Windows service that folder
  is closed to the user's processes, agents included.
* The CA is never added to the operating system's trust store. ``interpose run``
  points only the agent's process tree at it (``SSL_CERT_FILE``,
  ``NODE_EXTRA_CA_CERTS``, ...), so browsers and other programs never trust it.
* Leaf certificates are issued only for hosts that some policy names, live for a
  few days, and carry ``serverAuth`` only. The CA itself cannot sign further CAs
  (``pathLenConstraint = 0``).
"""

from __future__ import annotations

import contextlib
import datetime as dt
import ipaddress
import os
import ssl
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ..config import _write_private_file

CA_LIFETIME = dt.timedelta(days=365)
CA_RENEW_BEFORE = dt.timedelta(days=30)
LEAF_LIFETIME = dt.timedelta(days=7)
LEAF_RENEW_BEFORE = dt.timedelta(days=1)
CLOCK_SKEW = dt.timedelta(hours=1)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


def _pem(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.PEM)


def _host_name(host: str) -> str:
    """``host`` without port or IPv6 brackets."""
    if host.startswith("["):
        return host[1 : host.index("]")]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


@dataclass
class _Leaf:
    context: ssl.SSLContext
    not_after: dt.datetime


class CertificateAuthority:
    """Loads or creates the CA in ``directory`` and issues per-host server contexts.

    ``public_certificate`` is where the CA certificate (public, no key) is copied
    for clients; with the service that is the user-readable client folder.
    """

    def __init__(self, directory: Path, *, public_certificate: Path | None = None) -> None:
        self.directory = Path(directory)
        self.key_file = self.directory / "ca.key"
        self.certificate_file = self.directory / "ca.pem"
        self.public_certificate = public_certificate or self.certificate_file
        self._lock = threading.Lock()
        self._leaves: dict[str, _Leaf] = {}
        self._key, self._certificate = self._load_or_create()
        self._publish()

    @property
    def certificate(self) -> x509.Certificate:
        return self._certificate

    @property
    def certificate_pem(self) -> bytes:
        return _pem(self._certificate)

    def _load_or_create(self) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        if self.key_file.exists() and self.certificate_file.exists():
            try:
                key = serialization.load_pem_private_key(self.key_file.read_bytes(), password=None)
                certificate = x509.load_pem_x509_certificate(self.certificate_file.read_bytes())
                if (
                    isinstance(key, ec.EllipticCurvePrivateKey)
                    and certificate.public_key().public_numbers() == key.public_key().public_numbers()
                    and certificate.not_valid_after_utc - CA_RENEW_BEFORE > _now()
                ):
                    return key, certificate
            except (ValueError, TypeError):
                pass
        return self._create()

    def _create(self) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
        self.directory.mkdir(parents=True, exist_ok=True)
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Interpose"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Interpose local broker CA"),
        ])
        now = _now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + CA_LIFETIME)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256())
        )
        for path in (self.key_file, self.certificate_file):
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
        _write_private_file(
            self.key_file,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        self.certificate_file.write_bytes(_pem(certificate))
        return key, certificate

    def _publish(self) -> None:
        if self.public_certificate == self.certificate_file:
            return
        self.public_certificate.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.public_certificate.with_name(f".{self.public_certificate.name}.tmp")
        temporary.write_bytes(self.certificate_pem)
        os.replace(temporary, self.public_certificate)

    def issue(self, host: str) -> tuple[bytes, bytes]:
        """A fresh leaf for ``host`` (``name``, ``name:port`` or an IP): (cert PEM, key PEM)."""
        name = _host_name(host)
        try:
            alternative: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(name))
        except ValueError:
            alternative = x509.DNSName(name)
        key = ec.generate_private_key(ec.SECP256R1())
        now = _now()
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name[:64])]))
            .issuer_name(self._certificate.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(min(now + LEAF_LIFETIME, self._certificate.not_valid_after_utc))
            .add_extension(x509.SubjectAlternativeName([alternative]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False, key_encipherment=False,
                    data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()), critical=False
            )
            .sign(self._key, hashes.SHA256())
        )
        key_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return _pem(certificate), key_pem

    def server_context(self, host: str) -> ssl.SSLContext:
        """A TLS server context presenting a certificate for ``host``; cached until near expiry."""
        name = _host_name(host).lower()
        with self._lock:
            leaf = self._leaves.get(name)
            if leaf is not None and leaf.not_after - LEAF_RENEW_BEFORE > _now():
                return leaf.context
            certificate_pem, key_pem = self.issue(name)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            # One request/response at a time over HTTP/1.1 is what the broker parses.
            context.set_alpn_protocols(["http/1.1"])
            # ``load_cert_chain`` only reads files. The key exists on disk for the
            # duration of the call, inside the CA's own (private) folder.
            handle, path = tempfile.mkstemp(dir=self.directory, prefix=".leaf-", suffix=".pem")
            try:
                with os.fdopen(handle, "wb") as stream:
                    stream.write(certificate_pem + self.certificate_pem + key_pem)
                context.load_cert_chain(path)
            finally:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(path)
            not_after = x509.load_pem_x509_certificate(certificate_pem).not_valid_after_utc
            self._leaves[name] = _Leaf(context, not_after)
            return context


def write_trust_bundle(authority_pem: bytes, destination: Path) -> Path:
    """The usual public roots plus the broker CA, for tools whose CA variable replaces
    rather than extends their trust store (``SSL_CERT_FILE``, ``REQUESTS_CA_BUNDLE``,
    ``CURL_CA_BUNDLE``). Hosts the broker does not intercept keep verifying normally.
    """
    import certifi

    roots = Path(certifi.where()).read_bytes()
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = roots.rstrip(b"\n") + b"\n\n# Interpose local broker CA\n" + authority_pem
    if destination.exists() and destination.read_bytes() == content:
        return destination
    temporary = destination.with_name(f".{destination.name}.tmp")
    temporary.write_bytes(content)
    os.replace(temporary, destination)
    return destination
