import base64
import hashlib
import secrets

from abc import ABC, abstractmethod
from collections.abc import Callable


class AuthenticationError(Exception):
    pass


class PasswordStoring(ABC):
    @abstractmethod
    def update_password(self):
        pass

    @abstractmethod
    def verify_password(self):
        pass


class HashFunction:
    # Return the name of the hash function
    def hash_name(self, hash_fn: Callable[[bytes], bytes]) -> str:
        if hash_fn.name == "blake2b":
            return "blake2b"
        raise ValueError

    # Return the hash function from the name
    def hash_from_name(self, name: str) -> Callable[[bytes], bytes]:
        if name == "blake2b":
            def hash_fn(b: bytes) -> bytes:
                return hashlib.blake2b(b).digest()

            hash_fn.name = "blake2b"
            return hash_fn
        raise ValueError

    def hash_str_and_b64_encode(self, hash_fn: Callable[[bytes], bytes], password: str) -> None:
        pw_bytes = password.encode("utf-8")
        hash_bytes = hash_fn(pw_bytes)
        hash_bytes = base64.b64encode(hash_bytes)
        hashed_password = hash_bytes.decode("ascii")
        return hashed_password


class SaltGeneration:
    def generate_salt(self, max_char=20) -> str:
        return secrets.token_urlsafe(max_char)


class PepperRetrieval:
    def get_pepper(self) -> str:
        return "Nei9w60jRl9Qsc)1!HrH!rjJkfFhTA_-nS[~F,dN=l@857emai"
