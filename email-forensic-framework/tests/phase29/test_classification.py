"""Tests for Data Classification, Sensitive Data Detection, ML Confidence, and Review Workflows."""

import pytest
from data_security.inventory import ClassificationLevel, DataAsset, DataAssetType
from data_security.classification import (
    SensitiveDataPatterns,
    MLDataClassifier,
    ClassificationReviewManager,
    ReviewStatus,
    DataClassificationEngine,
)


def test_sensitive_data_patterns():
    """Verify regex patterns and schema heuristics accurately detect PII and credentials."""
    patterns = SensitiveDataPatterns()

    # Column name heuristic lookup
    assert "email" in patterns.COLUMN_NAME_SIGNALS
    cat, conf = patterns.COLUMN_NAME_SIGNALS["email"]
    assert cat == "IDENTITY_CONTACT"
    assert conf >= 0.90

    cat_p, conf_p = patterns.COLUMN_NAME_SIGNALS["payment_token"]
    assert cat_p == "FINANCIAL_PAYMENT"
    assert conf_p >= 0.90

    # Pattern regex testing
    email_pat = next(p for p in patterns.PATTERNS if p.pattern_name == "EMAIL_ADDRESS")
    assert email_pat.regex.search("user.test@corp.internal") is not None

    card_pat = next(p for p in patterns.PATTERNS if p.pattern_name == "CREDIT_CARD_NUMBER")
    assert card_pat.regex.search("4111111111111111") is not None


def test_ml_classifier_confidence():
    """Verify confidence calculation and multi-signal generation."""
    classifier = MLDataClassifier()

    # High confidence sensitive field
    signals = classifier.evaluate_column("customer_email", sample_values=["alice@corp.com", "bob@example.com"])
    assert len(signals) >= 1
    assert any(s.category == "IDENTITY_CONTACT" for s in signals)
    assert any(s.source in ("SCHEMA_NAME", "REGEX_PATTERN") for s in signals)

    # Clean non-sensitive field
    signals_counter = classifier.evaluate_column("item_counter", sample_values=["1", "2", "3"])
    assert len(signals_counter) == 0


def test_classification_engine_and_review_workflow():
    """Verify automated classification and human review workflow."""
    review_mgr = ClassificationReviewManager()
    engine = DataClassificationEngine(review_manager=review_mgr)

    asset = DataAsset(
        data_asset_id="DATA-AMBIGUOUS-99",
        name="legacy_blob_store",
        asset_type=DataAssetType.OBJECT,
        classification=ClassificationLevel.INTERNAL,
        schema_metadata={"columns": [{"name": "payment_token"}]},
    )

    result = engine.classify_asset(asset, sample_payload=[{"payment_token": "4111111111111111"}])
    assert result.level == ClassificationLevel.RESTRICTED
    assert result.confidence >= 0.85
    assert len(result.detected_categories) > 0

    # Human review request
    rec = review_mgr.create_review_request(
        data_asset_id="DATA-AMBIGUOUS-99",
        proposed_level=ClassificationLevel.SENSITIVE,
        confidence=0.72,
        signals=["SCHEMA_NAME:partial_match"],
    )
    assert rec.status == ReviewStatus.PENDING_HUMAN_REVIEW
    assert rec.review_id.startswith("REV-")

    # Steward review decision
    approved = review_mgr.submit_review(
        review_id=rec.review_id,
        reviewer="secops-lead",
        approved_level=ClassificationLevel.RESTRICTED,
        notes="Confirmed table contains unmasked card numbers and customer identity tokens.",
    )
    assert approved is not None
    assert approved.status == ReviewStatus.OVERRIDDEN
    assert approved.final_classification == ClassificationLevel.RESTRICTED
