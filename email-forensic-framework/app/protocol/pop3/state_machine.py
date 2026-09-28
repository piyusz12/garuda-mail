"""
app/protocol/pop3/state_machine.py

    AUTHORIZATION -> (USER/PASS | STLS) -> TRANSACTION -> UPDATE
"""

from __future__ import annotations

from enum import Enum


class POP3State(str, Enum):
    UNKNOWN = "UNKNOWN"
    AUTHORIZATION = "AUTHORIZATION"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    TRANSACTION = "TRANSACTION"
    UPDATE = "UPDATE"


class POP3StateMachine:
    def __init__(self) -> None:
        self.state = POP3State.UNKNOWN

    def on_server_greeting(self) -> None:
        if self.state == POP3State.UNKNOWN:
            self.state = POP3State.AUTHORIZATION

    def on_stls_request(self) -> None:
        if self.state == POP3State.AUTHORIZATION:
            self.state = POP3State.TLS_NEGOTIATION

    def on_stls_reject(self) -> None:
        if self.state == POP3State.TLS_NEGOTIATION:
            self.state = POP3State.AUTHORIZATION

    def on_pass_accepted(self) -> None:
        if self.state in (POP3State.AUTHORIZATION, POP3State.TLS_NEGOTIATION):
            self.state = POP3State.TRANSACTION

    def on_quit(self) -> None:
        self.state = POP3State.UPDATE

    def on_tls_client_hello(self) -> None:
        self.state = POP3State.TLS_NEGOTIATION
