"""Normative codec-definition and normalized-frame tests."""

from dataclasses import FrozenInstanceError
from decimal import Decimal

import pytest

from extract_amr.codec import AMR_DEFINITION, AMR_WB_DEFINITION, CODEC_DEFINITIONS
from extract_amr.models import CaptureProvenance, Codec, EncodedFrame


def test_amr_definition_has_normative_values() -> None:
    assert AMR_DEFINITION.frame_bit_counts == (
        95,
        103,
        118,
        134,
        148,
        159,
        204,
        244,
        39,
        None,
        None,
        None,
        None,
        None,
        None,
        0,
    )
    assert AMR_DEFINITION.valid_frame_types == frozenset((*range(9), 15))
    assert dict(AMR_DEFINITION.special_frame_types) == {8: "SID", 15: "NO_DATA"}
    assert AMR_DEFINITION.clock_rate == 8000
    assert AMR_DEFINITION.timestamp_step == 160
    assert AMR_DEFINITION.storage_header == b"#!AMR\n"
    assert AMR_DEFINITION.default_extension == ".amr"


def test_amr_wb_definition_has_normative_values() -> None:
    assert AMR_WB_DEFINITION.frame_bit_counts == (
        132,
        177,
        253,
        285,
        317,
        365,
        397,
        461,
        477,
        40,
        None,
        None,
        None,
        None,
        0,
        0,
    )
    assert AMR_WB_DEFINITION.valid_frame_types == frozenset((*range(10), 14, 15))
    assert dict(AMR_WB_DEFINITION.special_frame_types) == {
        9: "SID",
        14: "SPEECH_LOST",
        15: "NO_DATA",
    }
    assert AMR_WB_DEFINITION.clock_rate == 16000
    assert AMR_WB_DEFINITION.timestamp_step == 320
    assert AMR_WB_DEFINITION.storage_header == b"#!AMR-WB\n"
    assert AMR_WB_DEFINITION.default_extension == ".awb"


def test_codec_tables_are_immutable() -> None:
    with pytest.raises(TypeError):
        CODEC_DEFINITIONS[Codec.AMR] = AMR_WB_DEFINITION
    with pytest.raises(TypeError):
        AMR_DEFINITION.special_frame_types[15] = "changed"


def test_encoded_frame_is_immutable_and_retains_normalized_data() -> None:
    provenance = CaptureProvenance(7, Decimal("1.25"))
    frame = EncodedFrame(
        codec=Codec.AMR,
        frame_type=0,
        quality=False,
        bit_length=95,
        data=b"\xaa" * 11 + b"\xa8",
        media_timestamp=1234,
        provenance=provenance,
    )

    assert frame.data == b"\xaa" * 11 + b"\xa8"
    assert frame.bit_length == 95
    assert frame.media_timestamp == 1234
    assert frame.provenance is provenance
    with pytest.raises(FrozenInstanceError):
        frame.quality = True
