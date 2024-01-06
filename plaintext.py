import hmac
from base import PasswordStoring, AuthenticationError


class PlainTextStoring(PasswordStoring):
    def update_password(self, db, user, password: str) -> None:
        user.password = password
        db.store(user)

    def verify_password(self, user, password: str) -> None:
        pw = user.password
        if not hmac.compare_digest(pw, password):
            raise AuthenticationError
