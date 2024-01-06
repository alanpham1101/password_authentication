import pytest
from dataclasses import dataclass

from base import AuthenticationError
from plaintext import PlainTextStoring
from hashing import HashingStoring
from hashing_with_salt import HashingSaltStoring
from hashing_with_salt_pepper import HashingSaltPepperStoring


class Database:
    def __init__(self) -> None:
        self.user = None

    def store(self, user):
        self.user = user
        print("Storing user:")
        print(f"{user.email=}")
        print(f"{user.password=}")
        print()


@dataclass
class User:
    email: str
    password: str


def main():
    email = "user@example.com"
    user = User(email, "")
    db = Database()
    new_password = "v3ry s3cur3"
    incorrect_password = "ncorrect pass"
    hash_fn = HashingStoring().hash_from_name("blake2b")

    # Plaintext
    obj = PlainTextStoring()
    obj.update_password(db, user, new_password)
    obj.verify_password(user, new_password)
    with pytest.raises(AuthenticationError):
        obj.verify_password(user, incorrect_password)

    # Hashing
    obj = HashingStoring()
    obj.update_password(db, user, hash_fn, new_password)
    obj.verify_password(user, new_password)
    with pytest.raises(AuthenticationError):
        obj.verify_password(user, incorrect_password)

    # Hashing + Salting
    obj = HashingSaltStoring()
    obj.update_password(db, user, hash_fn, new_password)
    obj.verify_password(user, new_password)
    with pytest.raises(AuthenticationError):
        obj.verify_password(user, incorrect_password)

    # Hashing + Salting + Peppering
    obj = HashingSaltPepperStoring()
    obj.update_password(db, user, hash_fn, new_password)
    obj.verify_password(user, new_password)
    with pytest.raises(AuthenticationError):
        obj.verify_password(user, incorrect_password)


if __name__ == '__main__':
    main()
