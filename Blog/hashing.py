from passlib.context import CryptContext

# You can add multiple schemes (e.g. argon2) for flexibility
pwd_cxt = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Hash:
    @staticmethod
    def bcrypt(password: str) -> str:
        """
        Hash a password with bcrypt.
        Truncate if longer than 72 bytes (bcrypt limitation).
        """
        if len(password.encode("utf-8")) > 72:
            password = password[:72]  # truncate to avoid bcrypt error
        return pwd_cxt.hash(password)

    @staticmethod
    def verify(plain_password, hashed_password):
        """
        Verify a password against its hash.
        """
        if len(plain_password.encode("utf-8")) > 72:
            plain_password = plain_password[:72]
        return pwd_cxt.verify(plain_password, hashed_password)
