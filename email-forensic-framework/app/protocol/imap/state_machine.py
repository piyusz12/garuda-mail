"""
app/protocol/imap/state_machine.py

    NON_AUTHENTICATED -> (CAPABILITY | STARTTLS | LOGIN) -> AUTHENTICATED -> SELECTED

Mirrors RFC 3501's state model closely enough for forensic purposes,
without implementing full IMAP semantics.
"""

from __future__ import annotations

from enum import Enum


class IMAPState(str, Enum):
    UNKNOWN = "UNKNOWN"
    NON_AUTHENTICATED = "NON_AUTHENTICATED"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    AUTHENTICATED = "AUTHENTICATED"
    SELECTED = "SELECTED"
    LOGOUT = "LOGOUT"


class IMAPStateMachine:
    def __init__(self) -> None:
        self.state = IMAPState.UNKNOWN

    def on_server_greeting(self) -> None:
        if self.state == IMAPState.UNKNOWN:
            self.state = IMAPState.NON_AUTHENTICATED

    def on_starttls_request(self) -> None:
        if self.state == IMAPState.NON_AUTHENTICATED:
            self.state = IMAPState.TLS_NEGOTIATION

    def on_starttls_reject(self) -> None:
        if self.state == IMAPState.TLS_NEGOTIATION:
            self.state = IMAPState.NON_AUTHENTICATED

    def on_login(self) -> None:
        if self.state in (IMAPState.NON_AUTHENTICATED, IMAPState.TLS_NEGOTIATION):
            self.state = IMAPState.AUTHENTICATED

    def on_select(self) -> None:
        if self.state == IMAPState.AUTHENTICATED:
            self.state = IMAPState.SELECTED

    def on_logout(self) -> None:
        self.state = IMAPState.LOGOUT

    def on_tls_client_hello(self) -> None:
        self.state = IMAPState.TLS_NEGOTIATION
