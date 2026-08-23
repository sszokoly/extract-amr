"""Tests for structured extraction errors."""

from decimal import Decimal

from extract_amr.errors import AmbiguousSelectionError, RtpParseError
from extract_amr.models import CaptureProvenance


def test_parse_error_includes_capture_provenance() -> None:
    error = RtpParseError(
        "RTP header is truncated",
        provenance=CaptureProvenance(
            packet_number=17,
            capture_timestamp=Decimal("1.5"),
        ),
        details={"required_bytes": 12},
    )

    assert error.code == "malformed-rtp"
    assert error.details == {"required_bytes": 12}
    assert str(error) == "RTP header is truncated (capture packet 17)"


def test_ambiguity_error_retains_candidates() -> None:
    candidates = ("flow-a", "flow-b")

    error = AmbiguousSelectionError("multiple flows match", candidates)

    assert error.code == "ambiguous-selection"
    assert error.candidates == candidates
    assert error.details == {"candidate_count": 2}
