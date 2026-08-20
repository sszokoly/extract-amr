"""RFC 4867 single-channel AMR and AMR-WB storage serialization."""

from __future__ import annotations

from io import BytesIO
from typing import BinaryIO, Iterable, Union

from .codec import codec_definition
from .errors import Rfc4867Error, UnsupportedFormatError
from .models import Codec, EncodedFrame


def _storage_codec(value: Union[Codec, str]) -> Codec:
    try:
        return Codec(value)
    except (TypeError, ValueError):
        raise UnsupportedFormatError(
            f"unsupported storage codec: {value}",
            details={"option": "codec"},
        ) from None


def serialize_storage_frame(frame: EncodedFrame) -> bytes:
    """Serialize one normalized frame without a file magic header."""

    definition = codec_definition(frame.codec)
    expected_bits = definition.bit_count(frame.frame_type)
    if frame.frame_type not in definition.valid_frame_types or expected_bits is None:
        raise Rfc4867Error(
            f"frame type {frame.frame_type} is invalid for {frame.codec.value}",
            provenance=frame.provenance,
            details={"reason": "invalid-frame-type"},
        )
    if frame.bit_length != expected_bits:
        raise Rfc4867Error(
            "encoded frame bit length does not match its frame type",
            provenance=frame.provenance,
            details={"reason": "invalid-frame-length"},
        )
    expected_bytes = (expected_bits + 7) // 8
    if len(frame.data) != expected_bytes:
        raise Rfc4867Error(
            "encoded frame byte length does not match its bit length",
            provenance=frame.provenance,
            details={"reason": "invalid-frame-length"},
        )
    padding_bits = expected_bytes * 8 - expected_bits
    if padding_bits and frame.data[-1] & ((1 << padding_bits) - 1):
        raise Rfc4867Error(
            "encoded frame alignment padding is non-zero",
            provenance=frame.provenance,
            details={"reason": "nonzero-padding"},
        )

    header = (frame.frame_type << 3) | (int(frame.quality) << 2)
    return bytes([header]) + frame.data


def write_storage(
    output: BinaryIO,
    codec: Union[Codec, str],
    frames: Iterable[EncodedFrame],
) -> int:
    """Write one magic header followed by normalized storage frames."""

    selected_codec = _storage_codec(codec)
    output.write(codec_definition(selected_codec).storage_header)
    count = 0
    for frame in frames:
        if frame.codec is not selected_codec:
            raise Rfc4867Error(
                "storage stream cannot contain frames from another codec",
                provenance=frame.provenance,
                details={"reason": "codec-mismatch"},
            )
        output.write(serialize_storage_frame(frame))
        count += 1
    return count


def storage_bytes(
    codec: Union[Codec, str],
    frames: Iterable[EncodedFrame],
) -> bytes:
    """Return a complete single-channel codec storage stream."""

    output = BytesIO()
    write_storage(output, codec, frames)
    return output.getvalue()
