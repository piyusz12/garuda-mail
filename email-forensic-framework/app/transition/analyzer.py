"""
app/transition/analyzer.py

TLS Upgrade Analyzer — the Phase 7 orchestrator.

Takes an EmailSession (Phase 6 output) and produces a TLSUpgradeResult
by running the individual detectors in sequence and then applying the
classification decision table.

Architecture:

    EmailSession (Phase 6)
         ↓
    TLSUpgradeAnalyzer.analyze()
         ↓
    ┌─────────────────────────────────────────────┐
    │  detect_implicit_tls()                       │
    │  detect_capability()                         │
    │  detect_starttls_request()                   │
    │  detect_acceptance() / detect_rejection()    │
    │  detect_tls_handshake()                      │
    │  detect_authentication()                     │
    │  detect_plaintext_after_tls()                │
    └─────────────────────────────────────────────┘
         ↓
    determine_status()   (classification decision table)
         ↓
    TLSUpgradeResult (Phase 7 output → Phase 8)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from app.sessions.models import EmailSession
from app.transition.models import TLSUpgradeResult
from app.transition.rules import TLSMode, TransitionStatus
from app.transition.detectors import (
    detect_implicit_tls,
    detect_capability,
    detect_starttls_request,
    detect_acceptance,
    detect_rejection,
    detect_tls_handshake,
    detect_authentication,
    detect_plaintext_after_tls,
)


class TLSUpgradeAnalyzer:
    """
    Phase 7 orchestrator.

    Usage:
        analyzer = TLSUpgradeAnalyzer()
        result = analyzer.analyze(email_session)
        print(result.summary())
        print(json.dumps(result.to_dict(), indent=2))
    """

    def analyze(self, session: EmailSession) -> TLSUpgradeResult:
        """
        Analyze one EmailSession and produce a TLSUpgradeResult.

        The detection order matters only for the implicit-TLS early-return;
        all other detectors are independent.
        """
        result = TLSUpgradeResult(
            session_id=session.session_id,
            protocol=session.protocol,
        )

        # ── Step 1: Check for implicit TLS ──
        if detect_implicit_tls(session, result):
            result.transition_status = TransitionStatus.IMPLICIT_TLS
            # Still check auth timing — auth can happen over implicit TLS
            detect_authentication(session, result)
            result.confidence = min(result.confidence, 1.0)
            return result

        # ── Step 2: STARTTLS-specific detection pipeline ──
        result.tls_mode = TLSMode.STARTTLS

        detect_capability(session, result)
        detect_starttls_request(session, result)
        detect_acceptance(session, result)
        detect_rejection(session, result)
        detect_tls_handshake(session, result)
        detect_authentication(session, result)
        detect_plaintext_after_tls(session, result)

        # ── Step 3: Classify the transition ──
        result.transition_status = self._determine_status(result)

        # ── Step 4: Cap confidence ──
        result.confidence = min(result.confidence, 1.0)

        # ── Step 5: Adjust TLS mode if no STARTTLS at all ──
        if result.transition_status == TransitionStatus.PLAINTEXT_SESSION:
            result.tls_mode = TLSMode.PLAINTEXT

        if result.transition_status == TransitionStatus.STARTTLS_NOT_OBSERVED:
            result.tls_mode = TLSMode.PLAINTEXT

        return result

    def analyze_batch(
        self, sessions: list[EmailSession]
    ) -> list[TLSUpgradeResult]:
        """Analyze multiple sessions."""
        return [self.analyze(s) for s in sessions]

    def export_result(
        self, result: TLSUpgradeResult, output_dir: Path
    ) -> Path:
        """Write a single result to JSON."""
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{result.session_id}_transition.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        return path

    def export_batch(
        self, results: list[TLSUpgradeResult], output_dir: Path
    ) -> list[Path]:
        """Write all results to a directory."""
        return [self.export_result(r, output_dir) for r in results]

    # ── Decision table ──────────────────────────────────────────────

    @staticmethod
    def _determine_status(result: TLSUpgradeResult) -> str:
        """
        Classification decision table.

        Maps the combination of observed facts to a transition status.

        Priority order matters — the first matching rule wins.
        """

        # Plaintext after TLS is always the most severe finding
        if result.plaintext_after_tls:
            return TransitionStatus.PLAINTEXT_AFTER_TLS

        # STARTTLS requested → server rejected
        if result.tls_requested and result.tls_accepted is False:
            # Check if we have an explicit rejection event
            if any(
                ev.event_type in (
                    "STARTTLS_REJECTED", "STLS_REJECTED"
                )
                for ev in result.evidence
            ):
                return TransitionStatus.STARTTLS_REJECTED
            return TransitionStatus.STARTTLS_REJECTED

        # STARTTLS requested → accepted → handshake observed → success
        if (
            result.tls_requested
            and result.tls_accepted
            and result.tls_handshake_observed
        ):
            return TransitionStatus.STARTTLS_SUCCESS

        # STARTTLS requested → accepted → NO handshake
        if (
            result.tls_requested
            and result.tls_accepted
            and not result.tls_handshake_observed
        ):
            return TransitionStatus.STARTTLS_ACCEPTED_NO_HANDSHAKE

        # STARTTLS requested but we have no acceptance data and no
        # handshake → incomplete capture
        if (
            result.tls_requested
            and result.tls_accepted is None
            and not result.tls_handshake_observed
        ):
            return TransitionStatus.INCOMPLETE_CAPTURE

        # STARTTLS requested → no acceptance → handshake anyway?
        # (unusual, but could happen with incomplete event parsing)
        if result.tls_requested and result.tls_handshake_observed:
            return TransitionStatus.STARTTLS_SUCCESS

        # Capability advertised but never requested
        if result.capability_advertised and not result.tls_requested:
            return TransitionStatus.STARTTLS_AVAILABLE_NOT_USED

        # No STARTTLS anywhere but session had some data
        if (
            not result.capability_advertised
            and not result.tls_requested
            and not result.tls_handshake_observed
        ):
            # Was there enough data to tell?
            if not result.evidence:
                return TransitionStatus.INCOMPLETE_CAPTURE
            return TransitionStatus.PLAINTEXT_SESSION

        # TLS handshake observed without STARTTLS context
        if result.tls_handshake_observed and not result.tls_requested:
            # This might be implicit TLS that wasn't caught earlier
            return TransitionStatus.STARTTLS_NOT_OBSERVED

        return TransitionStatus.UNKNOWN
