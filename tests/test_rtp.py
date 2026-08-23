"""Byte-level RTP normalization and RTCP exclusion tests."""

import struct
from decimal import Decimal

import pytest

from extract_amr.errors import RtpParseError
from extract_amr.models import CaptureProvenance, UdpRecord
from extract_amr.rtp import is_rtcp, iter_rtp_records, parse_rtp


def _udp(payload: bytes, reverse: bool = False) -> UdpRecord:
    if reverse:
        src_address, dst_address = "192.0.2.2", "192.0.2.1"
        src_port, dst_port = 5000, 4000
    else:
        src_address, dst_address = "192.0.2.1", "192.0.2.2"
        src_port, dst_port = 4000, 5000
    return UdpRecord(
        src_address=src_address,
        dst_address=dst_address,
        src_port=src_port,
        dst_port=dst_port,
        payload=payload,
        ip_version=4,
        provenance=CaptureProvenance(
            packet_number=7,
            capture_timestamp=Decimal("1.25"),
        ),
    )


def _rtp(
    *,
    payload: bytes = b"media",
    sequence: int = 10,
    timestamp: int = 320,
    ssrc: int = 0x11223344,
    payload_type: int = 96,
    marker: bool = False,
    csrcs: tuple = (),
    extension_profile: int = 0,
    extension_data: bytes = b"",
    padding_length: int = 0,
) -> bytes:
    if len(extension_data) % 4:
        raise ValueError("extension_data must contain whole 32-bit words")
    first = 0x80 | len(csrcs)
    if extension_data:
        first |= 0x10
    if padding_length:
        first |= 0x20
    second = payload_type | (0x80 if marker else 0)
    data = struct.pack("!BBHII", first, second, sequence, timestamp, ssrc)
    if csrcs:
        data += struct.pack(f"!{len(csrcs)}I", *csrcs)
    if extension_data:
        data += struct.pack(
            "!HH",
            extension_profile,
            len(extension_data) // 4,
        )
        data += extension_data
    data += payload
    if padding_length:
        data += bytes(padding_length - 1) + bytes([padding_length])
    return data


def test_parses_csrc_extension_padding_and_media_payload() -> None:
    data = _rtp(
        payload=b"amr-payload",
        sequence=65535,
        timestamp=0xFFFFFF00,
        marker=True,
        csrcs=(0x01020304, 0x05060708),
        extension_profile=0xBEDE,
        extension_data=b"abcd",
        padding_length=4,
    )

    record = parse_rtp(_udp(data))

    assert record is not None
    assert record.sequence == 65535
    assert record.timestamp == 0xFFFFFF00
    assert record.marker
    assert record.flow_key.ssrc == 0x11223344
    assert record.flow_key.payload_type == 96
    assert record.csrcs == (0x01020304, 0x05060708)
    assert record.extension_profile == 0xBEDE
    assert record.extension_data == b"abcd"
    assert record.padding_length == 4
    assert record.payload == b"amr-payload"
    assert record.provenance.packet_number == 7


def test_structural_rtcp_is_excluded() -> None:
    receiver_report = struct.pack("!BBHI", 0x80, 201, 1, 0x11223344)

    assert is_rtcp(receiver_report)
    assert parse_rtp(_udp(receiver_report)) is None


def test_invalid_rtcp_shape_can_still_be_valid_rtp() -> None:
    marker_and_pt_72 = _rtp(payload_type=72, marker=True, sequence=1)

    assert marker_and_pt_72[1] == 200
    assert not is_rtcp(marker_and_pt_72)
    record = parse_rtp(_udp(marker_and_pt_72))
    assert record is not None
    assert record.marker
    assert record.flow_key.payload_type == 72


def test_definite_non_rtp_is_ignored() -> None:
    assert parse_rtp(_udp(b"ordinary UDP traffic")) is None
    assert parse_rtp(_udp(b"")) is None


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (b"\x80\x60" + bytes(9), "fixed header is truncated"),
        (b"\x81\x60" + bytes(10), "CSRC list is truncated"),
        (b"\x90\x60" + bytes(10), "extension header is truncated"),
        (
            b"\x90\x60" + bytes(10) + struct.pack("!HH", 0xBEDE, 2),
            "extension data is truncated",
        ),
        (b"\xa0\x60" + bytes(10) + b"\x00", "padding length is zero"),
        (b"\xa0\x60" + bytes(10) + b"\x05", "padding exceeds"),
    ],
)
def test_truncated_or_invalid_rtp_reports_provenance(
    payload: bytes,
    message: str,
) -> None:
    with pytest.raises(RtpParseError, match=message) as captured:
        parse_rtp(_udp(payload))

    assert captured.value.provenance is not None
    assert captured.value.provenance.packet_number == 7
    assert "capture packet 7" in str(captured.value)


def test_iterator_omits_non_rtp_and_rtcp_but_keeps_directions() -> None:
    receiver_report = struct.pack("!BBHI", 0x80, 201, 1, 0x11223344)
    records = [
        _udp(b"ordinary UDP traffic"),
        _udp(receiver_report),
        _udp(_rtp(sequence=1)),
        _udp(_rtp(sequence=2), reverse=True),
    ]

    parsed = list(iter_rtp_records(records))

    assert [record.sequence for record in parsed] == [1, 2]
    assert parsed[0].flow_key.ssrc == parsed[1].flow_key.ssrc
    assert parsed[0].flow_key.payload_type == parsed[1].flow_key.payload_type
    assert parsed[0].flow_key != parsed[1].flow_key
