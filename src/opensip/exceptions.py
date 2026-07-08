"""Custom exception hierarchy for opensip."""

from __future__ import annotations


class OpenSIPError(Exception):
    """Base class for all opensip errors."""


class SIPParseError(OpenSIPError):
    """Raised when a SIP message cannot be parsed."""


class TransactionError(OpenSIPError):
    """Transaction layer error (timeout, unexpected response, ...)."""


class TransactionTimeout(TransactionError):
    """Non-INVITE client transaction expired (Timer F) without a final response."""


class AuthenticationError(OpenSIPError):
    """Digest authentication failed."""


class RegistrationError(OpenSIPError):
    """The registrar affirmatively refused the registration.

    Raised only for an explicit ``expires=0`` grant on a non-unregister
    REGISTER (matching Contact binding or response Expires header), i.e. the
    registrar granted a zero-length binding. Absent/malformed grants are
    tolerated (fall-through), not raised.
    """


class TransportError(OpenSIPError):
    """Transport / network error."""


class SDPError(OpenSIPError):
    """SDP parse or negotiation error."""
