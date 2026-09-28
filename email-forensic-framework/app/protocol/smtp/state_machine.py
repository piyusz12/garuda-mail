"""
app/protocol/smtp/state_machine.py

Tracks SMTP application state across the reassembled stream:

    UNKNOWN -> GREETING -> COMMAND_PHASE -> STARTTLS_REQUESTED
             -> TLS_NEGOTIATION -> ENCRYPTED

State transitions are driven by the normalized line stream, not raw
regex-over-everything, so pipelined/fragmented commands are handled
correctly once Phase 1 has reassembled the stream.
"""

from __future__ import annotations

from enum import Enum


class SMTPState(str, Enum):
    UNKNOWN = "UNKNOWN"
    GREETING = "GREETING"
    COMMAND_PHASE = "COMMAND_PHASE"
    STARTTLS_REQUESTED = "STARTTLS_REQUESTED"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    ENCRYPTED = "ENCRYPTED"


class SMTPStateMachine:
    def __init__(self) -> None:
        self.state = SMTPState.UNKNOWN

    def on_server_greeting(self) -> None:
        if self.state == SMTPState.UNKNOWN:
            self.state = SMTPState.GREETING

    def on_client_hello(self) -> None:
        if self.state in (SMTPState.GREETING, SMTPState.UNKNOWN):
            self.state = SMTPState.COMMAND_PHASE

    def on_starttls_request(self) -> None:
        if self.state == SMTPState.COMMAND_PHASE:
            self.state = SMTPState.STARTTLS_REQUESTED

    def on_starttls_accept(self) -> None:
        if self.state == SMTPState.STARTTLS_REQUESTED:
            self.state = SMTPState.TLS_NEGOTIATION

    def on_starttls_reject(self) -> None:
        if self.state == SMTPState.STARTTLS_REQUESTED:
            # Server said no -- session drops back to plaintext command phase.
            self.state = SMTPState.COMMAND_PHASE

    def on_tls_client_hello(self) -> None:
        if self.state in (SMTPState.TLS_NEGOTIATION, SMTPState.COMMAND_PHASE, SMTPState.UNKNOWN):
            self.state = SMTPState.ENCRYPTED
