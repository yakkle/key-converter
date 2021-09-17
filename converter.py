from abc import ABC
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from eth_keyfile import load_keyfile, decode_keyfile_json


class Serializer(ABC):
    encoding = None

    @classmethod
    def serialize_private_key(cls, private_key: bytes, password: Optional[bytes]) -> bytes:
        pri_key = ec.derive_private_key(int.from_bytes(private_key, byteorder="big"),
                                        ec.SECP256K1(),
                                        default_backend())
        algorithm = \
            serialization.BestAvailableEncryption(password) if password is not None else serialization.NoEncryption()
        return pri_key.private_bytes(encoding=cls.encoding,
                                     format=serialization.PrivateFormat.PKCS8,
                                     encryption_algorithm=algorithm)

    @classmethod
    def serialize_private_key_file(cls, filename: str, private_key: bytes, password: Optional[bytes]):
        serialization_bytes = cls.serialize_private_key(private_key, password)
        with open(filename, "wb") as file:
            file.write(serialization_bytes)


class DerSerializer(Serializer):
    encoding = serialization.Encoding.DER

    @classmethod
    def load_private_key(cls, cert_private_key: bytes, password, backend):
        return serialization.load_der_private_key(cert_private_key, password, backend)

    @classmethod
    def load_public_key(cls, cert_public_key: bytes, backend):
        return serialization.load_der_public_key(cert_public_key, backend)


class PemSerializer(Serializer):
    encoding = serialization.Encoding.PEM

    @classmethod
    def load_private_key(cls, cert_private_key: bytes, password, backend):
        return serialization.load_pem_private_key(cert_private_key, password, backend)

    @classmethod
    def load_public_key(cls, cert_public_key: bytes, backend):
        return serialization.load_pem_public_key(cert_public_key, backend)


passwd = b"loopchain"  # keyfile password

keystore = load_keyfile("./my_keystore.json")
prikey = decode_keyfile_json(keystore, passwd)

PemSerializer.serialize_private_key_file("./my_key.pem", prikey, passwd)
DerSerializer.serialize_private_key_file("./my_key.der", prikey, passwd)