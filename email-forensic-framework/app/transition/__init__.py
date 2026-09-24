"""
app/transition/

Phase 7: STARTTLS / STLS Transition Analysis.

Consumes Phase 6 EmailSession objects and produces TLSUpgradeResult
objects that describe *what happened* at the TLS transition point.

This phase answers:
  - Did the connection upgrade from plaintext to TLS?
  - Was STARTTLS advertised / requested / accepted?
  - Did authentication happen before or after encryption?
  - Was the transition successful, rejected, or incomplete?

Phase 7 reports FACTS.  Phase 14 interprets them as security findings.
"""
