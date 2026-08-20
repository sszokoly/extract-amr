"""Direct byte-level RTP normalization and RTCP exclusion."""

from __future__ import annotations

import struct
from typing import Any, Iterable, Iterator, Optional, Tuple

from .errors import RtpParseError
from .models import FlowKey, RtpRecord, UdpRecord

_RTP_FIXED_HEADER_LENGTH = 12
_RTCP_TYPE_MIN = 192
_RTCP_TYPE_MAX = 223


def _valid_rtcp_block_size(packet_type: int, count: int, size: int) -> bool:
    if packet_type == 200:
        return size >= 28 + count * 24
    if packet_type == 201:
        return size >= 8 + count * 24
    return size >= 4


def is_rtcp(data: bytes) -> bool:
    """Return whether bytes form one or more complete structural RTCP blocks."""

    if len(data) < 4 or data[0] >> 6 != 2:
        return False
    if not _RTCP_TYPE_MIN <= data[1] <= _RTCP_TYPE_MAX:
        return False

    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            return False
        first, packet_type, length = struct.unpack_from("!BBH", data, offset)
        if first >> 6 != 2:
            return False
        if not _RTCP_TYPE_MIN <= packet_type <= _RTCP_TYPE_MAX:
            return False

        count = first & 0x1F
        block_size = (length + 1) * 4
        if not _valid_rtcp_block_size(packet_type, count, block_size):
            return False
        block_end = offset + block_size
        if block_end > len(data):
            return False

        has_padding = bool(first & 0x20)
        if has_padding:
            if block_end != len(data):
                return False
            padding_length = data[block_end - 1]
            if padding_length == 0 or padding_length > block_size - 4:
                return False
        offset = block_end
    return offset == len(data)


def _parse_csrcs(data: bytes, count: int) -> Tuple[int, ...]:
    if count == 0:
        return ()
    return struct.unpack_from(f"!{count}I", data, _RTP_FIXED_HEADER_LENGTH)


def _malformed(record: UdpRecord, message: str, **details: Any) -> RtpParseError:
    return RtpParseError(
        message,
        provenance=record.provenance,
        details=details,
    )


def parse_rtp(record: UdpRecord) -> Optional[RtpRecord]:
    """Normalize one UDP datagram, returning None for definite non-RTP/RTCP."""

    data = record.payload
    if len(data) < 2 or data[0] >> 6 != 2:
        return None
    if is_rtcp(data):
        return None
    if len(data) < _RTP_FIXED_HEADER_LENGTH:
        raise _malformed(
            record,
            "RTP fixed header is truncated",
            captured_bytes=len(data),
            required_bytes=_RTP_FIXED_HEADER_LENGTH,
        )

    first, second, sequence, timestamp, ssrc = struct.unpack_from("!BBHII", data)
    flow_key = FlowKey(
        src_address=record.src_address,
        dst_address=record.dst_address,
        src_port=record.src_port,
        dst_port=record.dst_port,
        ssrc=ssrc,
        payload_type=second & 0x7F,
    )
    csrc_count = first & 0x0F
    header_length = _RTP_FIXED_HEADER_LENGTH + csrc_count * 4
    if header_length > len(data):
        raise _malformed(
            record,
            "RTP CSRC list is truncated",
            captured_bytes=len(data),
            required_bytes=header_length,
            flow_key=flow_key,
        )
    csrcs = _parse_csrcs(data, csrc_count)

    extension_profile = None
    extension_data = b""
    if first & 0x10:
        extension_header_end = header_length + 4
        if extension_header_end > len(data):
            raise _malformed(
                record,
                "RTP extension header is truncated",
                captured_bytes=len(data),
                required_bytes=extension_header_end,
                flow_key=flow_key,
            )
        extension_profile, extension_words = struct.unpack_from(
            "!HH",
            data,
            header_length,
        )
        extension_length = extension_words * 4
        extension_end = extension_header_end + extension_length
        if extension_end > len(data):
            raise _malformed(
                record,
                "RTP extension data is truncated",
                captured_bytes=len(data),
                required_bytes=extension_end,
                flow_key=flow_key,
            )
        extension_data = data[extension_header_end:extension_end]
        header_length = extension_end

    padding_length = 0
    payload_end = len(data)
    if first & 0x20:
        padding_length = data[-1]
        if padding_length == 0:
            raise _malformed(
                record,
                "RTP padding length is zero",
                flow_key=flow_key,
            )
        payload_end -= padding_length
        if payload_end < header_length:
            raise _malformed(
                record,
                "RTP padding exceeds the media payload",
                padding_bytes=padding_length,
                flow_key=flow_key,
            )

    return RtpRecord(
        flow_key=flow_key,
        sequence=sequence,
        timestamp=timestamp,
        marker=bool(second & 0x80),
        payload=data[header_length:payload_end],
        provenance=record.provenance,
        csrcs=csrcs,
        extension_profile=extension_profile,
        extension_data=extension_data,
        padding_length=padding_length,
    )


def iter_rtp_records(records: Iterable[UdpRecord]) -> Iterator[RtpRecord]:
    """Yield validated RTP records while omitting definite non-RTP and RTCP."""

    for record in records:
        rtp = parse_rtp(record)
        if rtp is not None:
            yield rtp
