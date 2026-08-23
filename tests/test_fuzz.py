"""Deterministic fuzz-style safety coverage for untrusted protocol bytes."""

import random
import struct

import pytest

from extract_amr.errors import Rfc4867Error, RtpParseError
from extract_amr.models import (
    CaptureProvenance,
    Codec,
    EncodedFrame,
    PayloadMode,
    RtpRecord,
    UdpRecord,
)
from extract_amr.rfc4867 import depacketize
from extract_amr.rtp import parse_rtp

VALID_PAYLOADS = {
    (Codec.AMR, PayloadMode.OCTET_ALIGNED): bytes.fromhex(
        "f00c0123456789abcdef1032547698",
    ),
    (Codec.AMR, PayloadMode.BANDWIDTH_EFFICIENT): bytes.fromhex(
        "f09555555555555555555555555500",
    ),
    (Codec.AMR_WB, PayloadMode.OCTET_ALIGNED): bytes.fromhex(
        "f00ccccccccccccccccccccccccccccccccccccccccccccc80",
    ),
    (Codec.AMR_WB, PayloadMode.BANDWIDTH_EFFICIENT): bytes.fromhex(
        "f0eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
    ),
}


def _random_bytes(generator: random.Random, length: int) -> bytes:
    return bytes(generator.getrandbits(8) for _ in range(length))


def _corpus(seed: int, count: int = 1500):
    generator = random.Random(seed)
    fixed = [b"", bytes(range(256)), bytes(256), bytes([0xFF]) * 256]
    fixed.extend(bytes([value]) for value in range(256))
    for value in fixed:
        yield value
    for _ in range(count):
        yield _random_bytes(generator, generator.randrange(0, 257))


def test_arbitrary_udp_payload_is_rtp_record_none_or_structured_error() -> None:
    valid_rtp = struct.pack("!BBHII", 0x80, 96, 7, 320, 0x11223344) + b"media"
    successful_records = 0
    structured_errors = 0
    for packet_number, payload in enumerate(
        (valid_rtp, *_corpus(0x525450)),
        start=1,
    ):
        record = UdpRecord(
            src_address="192.0.2.1",
            dst_address="192.0.2.2",
            src_port=4000,
            dst_port=5000,
            payload=payload,
            ip_version=4,
            provenance=CaptureProvenance(packet_number=packet_number),
        )
        try:
            result = parse_rtp(record)
        except RtpParseError as error:
            structured_errors += 1
            assert error.provenance == record.provenance
            assert error.code == "malformed-rtp"
        else:
            assert result is None or isinstance(result, RtpRecord)
            if result is not None:
                successful_records += 1
                assert result.provenance == record.provenance
                assert result.flow_key.src_address == record.src_address
                assert result.flow_key.dst_address == record.dst_address
                assert 0 <= result.flow_key.payload_type <= 127
    assert successful_records > 0
    assert structured_errors > 0


@pytest.mark.parametrize("codec", tuple(Codec))
@pytest.mark.parametrize("mode", tuple(PayloadMode))
def test_arbitrary_rfc4867_payload_is_frames_or_structured_error(
    codec: Codec,
    mode: PayloadMode,
) -> None:
    successful_payloads = 0
    structured_errors = 0
    corpus = (VALID_PAYLOADS[(codec, mode)], *_corpus(0x4867))
    for packet_number, payload in enumerate(corpus, start=1):
        provenance = CaptureProvenance(packet_number=packet_number)
        try:
            frames = depacketize(
                payload,
                codec,
                mode,
                provenance=provenance,
            )
        except Rfc4867Error as error:
            structured_errors += 1
            assert error.provenance == provenance
            assert error.details.get("reason")
        else:
            successful_payloads += 1
            assert isinstance(frames, tuple)
            assert frames
            assert all(isinstance(frame, EncodedFrame) for frame in frames)
            assert all(frame.codec is codec for frame in frames)
            assert all(frame.provenance == provenance for frame in frames)
            assert all(len(frame.data) == (frame.bit_length + 7) // 8 for frame in frames)
    assert successful_payloads > 0
    assert structured_errors > 0


def test_truncated_and_mutated_rtp_headers_never_raise_unrelated_errors() -> None:
    valid = bytes.fromhex("906000010000014011223344bede000100000000") + b"media"
    corpus = [valid[:length] for length in range(len(valid) + 1)]
    corpus.extend(
        valid[:index] + bytes([valid[index] ^ bit]) + valid[index + 1 :]
        for index in range(len(valid))
        for bit in (0x01, 0x80)
    )

    for packet_number, payload in enumerate(corpus, start=1):
        record = UdpRecord(
            src_address="2001:db8::1",
            dst_address="2001:db8::2",
            src_port=6000,
            dst_port=7000,
            payload=payload,
            ip_version=6,
            provenance=CaptureProvenance(packet_number=packet_number),
        )
        try:
            result = parse_rtp(record)
        except RtpParseError:
            continue
        assert result is None or isinstance(result, RtpRecord)
