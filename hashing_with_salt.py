import hmac
from collections.abc import Callable

from base import PasswordStoring, AuthenticationError
from base import HashFunction, SaltGeneration


class HashingSaltStoring(PasswordStoring, HashFunction, SaltGeneration):
    def update_password(self, db, user, hash_fn: Callable[[bytes], bytes], password: str) -> None:
        salt = self.generate_salt()
        hashed_password = self.hash_str_and_b64_encode(hash_fn, salt + password)
        name = self.hash_name(hash_fn)
        user.password = f"{name}${salt}${hashed_password}"
        db.store(user)

    def verify_password(self, user, password: str) -> None:
        hash_fn_name, salt, hashed_password = user.password.split("$")
        hash_fn = self.hash_from_name(hash_fn_name)
        hashed_pw = self.hash_str_and_b64_encode(hash_fn, salt + password)

        if not hmac.compare_digest(hashed_password, hashed_pw):
            raise AuthenticationError()
