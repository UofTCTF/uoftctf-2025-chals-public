from typing import Union
from itsdangerous import Signer, BadSignature
import base64

# Utility functions
def want_bytes(s: Union[str, bytes], encoding: str = "utf-8", errors: str = "strict") -> bytes:
    """Ensure the input is in bytes."""
    if isinstance(s, str):
        s = s.encode(encoding, errors)
    return s


def base64_encode(string: Union[str, bytes]) -> bytes:
    """Base64 encode a string of bytes or text. The resulting bytes are safe to use in URLs."""
    string = want_bytes(string)
    return base64.urlsafe_b64encode(string).rstrip(b"=")


def base64_decode(string: Union[str, bytes]) -> bytes:
    """Base64 decode a URL-safe string of bytes or text. The result is bytes."""
    string = want_bytes(string, encoding="ascii", errors="ignore")
    string += b"=" * (-len(string) % 4)

    try:
        return base64.urlsafe_b64decode(string)
    except (TypeError, ValueError) as e:
        raise ValueError("Invalid base64-encoded data") from e


# Signing and verification class using provided Signer
class FlaskSigner:
    def __init__(self, secret_key: str):
        """Initialize the signer with a secret key and optional salt."""
        self.secret_key = secret_key
        self.salt = "flask-session"
        self.signer = Signer(secret_key, salt=self.salt, key_derivation="hmac")

    def sign(self, data: str) -> str:
        """
        Sign the given data.
        Args:
            data (str): The data to be signed.
        Returns:
            str: The signed data as a URL-safe base64 string.
        """
        data_bytes = want_bytes(data)
        signed_data = self.signer.sign(data_bytes)
        return signed_data.decode("utf-8")

    def unsign(self, signed_data: str) -> str:
        """
        Verify and retrieve the original data from the signed data.
        Args:
            signed_data (str): The signed data.
        Returns:
            str: The original data if the signature is valid.
        Raises:
            ValueError: If the signature is invalid or tampered with.
        """
        try:
            data_bytes = want_bytes(signed_data)
            original_data = self.signer.unsign(data_bytes)
            return original_data.decode("utf-8")
        except BadSignature as e:
            raise ValueError(f"Invalid or tampered data: {e}")