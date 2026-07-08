"""opensip — pure-Python SIP/RTP user-agent library."""

from .exceptions import (
    OpenSIPError,
    SIPParseError,
    TransactionError,
    AuthenticationError,
    RegistrationError,
)

__version__ = "0.2.1"

__all__ = [
    "__version__",
    "OpenSIPError",
    "SIPParseError",
    "TransactionError",
    "AuthenticationError",
    "RegistrationError",
    # The following are re-exported lazily as modules are implemented:
    #   UserAgent, Account, Call
]


def __getattr__(name: str):  # PEP 562 lazy attributes
    if name in {"UserAgent", "Account", "Call"}:
        from . import ua
        return getattr(ua, name)
    raise AttributeError(f"module 'opensip' has no attribute {name!r}")
