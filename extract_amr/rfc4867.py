"""Payload-atomic RFC 4867 AMR and AMR-WB depacketization."""

from __future__ import annotations

from typing import List, Optional, Tuple, Union

from .bits import BIT_BACKEND, BitBackend, BitBufferContract
from .codec import CodecDefinition, codec_definition
from .errors import Rfc4867Error, UnsupportedFormatError
from .models import (
    CaptureProvenance,
    Codec,
    EncodedFrame,
    PayloadMode,
    Rfc4867Options,
)


def _rfc_error(
    message: str,
    reason: str,
    provenance: CaptureProvenance,
) -> Rfc4867Error:
    return Rfc4867Error(
        message,
        provenance=provenance,
        details={"reason": reason},
    )


def _unsupported(
    message: str,
    option: str,
    provenance: CaptureProvenance,
) -> UnsupportedFormatError:
    return UnsupportedFormatError(
        message,
        provenance=provenance,
        details={"option": option},
    )


def _coerce_codec(
    value: Union[Codec, str],
    provenance: CaptureProvenance,
) -> Codec:
    try:
        return Codec(value)
    except (TypeError, ValueError):
        raise _unsupported(
            f"unsupported codec: {value}",
            "codec",
            provenance,
        ) from None


def _coerce_mode(
    value: Union[PayloadMode, str],
    provenance: CaptureProvenance,
) -> PayloadMode:
    try:
        return PayloadMode(value)
    except (TypeError, ValueError):
        raise _unsupported(
            f"unsupported payload framing: {value}",
            "framing",
            provenance,
        ) from None


def _validate_options(
    options: Rfc4867Options,
    provenance: CaptureProvenance,
) -> None:
    if options.channels != 1:
        raise _unsupported(
            "RFC 4867 multichannel payloads are unsupported",
            "channels",
            provenance,
        )
    if options.crc:
        raise _unsupported(
            "RFC 4867 frame CRC is unsupported",
            "crc",
            provenance,
        )
    if options.interleaving:
        raise _unsupported(
            "RFC 4867 interleaving is unsupported",
            "interleaving",
            provenance,
        )
    if options.robust_sorting:
        raise _unsupported(
            "RFC 4867 robust sorting is unsupported",
            "robust-sorting",
            provenance,
        )


def _validated_bit_count(
    definition: CodecDefinition,
    frame_type: int,
    provenance: CaptureProvenance,
) -> int:
    bit_count = definition.bit_count(frame_type)
    if frame_type not in definition.valid_frame_types or bit_count is None:
        raise _rfc_error(
            f"frame type {frame_type} is invalid for {definition.codec.value}",
            "invalid-frame-type",
            provenance,
        )
    return bit_count


def _frame(
    definition: CodecDefinition,
    frame_type: int,
    quality: bool,
    bit_count: int,
    data: bytes,
    media_timestamp: int,
    provenance: CaptureProvenance,
) -> EncodedFrame:
    return EncodedFrame(
        codec=definition.codec,
        frame_type=frame_type,
        quality=quality,
        bit_length=bit_count,
        data=data,
        media_timestamp=media_timestamp,
        provenance=provenance,
    )


def _depacketize_octet_aligned(
    payload: bytes,
    definition: CodecDefinition,
    media_timestamp: int,
    provenance: CaptureProvenance,
) -> Tuple[EncodedFrame, ...]:
    if len(payload) < 2:
        raise _rfc_error(
            "octet-aligned payload is too short for CMR and ToC",
            "short-header",
            provenance,
        )
    if payload[0] & 0x0F:
        raise _rfc_error(
            "octet-aligned CMR padding bits are non-zero",
            "nonzero-padding",
            provenance,
        )

    offset = 1
    entries: List[Tuple[int, bool, int]] = []
    while True:
        if offset >= len(payload):
            raise _rfc_error(
                "octet-aligned ToC chain is incomplete",
                "incomplete-toc",
                provenance,
            )
        toc = payload[offset]
        offset += 1
        if toc & 0x03:
            raise _rfc_error(
                "octet-aligned ToC padding bits are non-zero",
                "nonzero-padding",
                provenance,
            )
        frame_type = (toc >> 3) & 0x0F
        bit_count = _validated_bit_count(definition, frame_type, provenance)
        entries.append((frame_type, bool(toc & 0x04), bit_count))
        if not toc & 0x80:
            break

    frames = []
    for index, (frame_type, quality, bit_count) in enumerate(entries):
        byte_count = (bit_count + 7) // 8
        end = offset + byte_count
        if end > len(payload):
            raise _rfc_error(
                f"speech data for frame {index} is truncated",
                "truncated-speech-data",
                provenance,
            )
        data = payload[offset:end]
        offset = end
        padding_bits = byte_count * 8 - bit_count
        if padding_bits and data[-1] & ((1 << padding_bits) - 1):
            raise _rfc_error(
                f"speech data padding for frame {index} is non-zero",
                "nonzero-padding",
                provenance,
            )
        frames.append(
            _frame(
                definition,
                frame_type,
                quality,
                bit_count,
                data,
                media_timestamp + index * definition.timestamp_step,
                provenance,
            ),
        )

    if offset != len(payload):
        raise _rfc_error(
            "octet-aligned payload contains unexpected trailing data",
            "trailing-data",
            provenance,
        )
    return tuple(frames)


def _bits_to_int(bits: BitBufferContract) -> int:
    value = 0
    for bit in bits:
        value = (value << 1) | bit
    return value


def _depacketize_bandwidth_efficient(
    payload: bytes,
    definition: CodecDefinition,
    media_timestamp: int,
    provenance: CaptureProvenance,
    backend: BitBackend,
) -> Tuple[EncodedFrame, ...]:
    bits = backend.from_bytes(payload)
    if len(bits) < 10:
        raise _rfc_error(
            "bandwidth-efficient payload is too short for CMR and ToC",
            "short-header",
            provenance,
        )

    position = 4
    entries: List[Tuple[int, bool, int]] = []
    while True:
        if len(bits) - position < 6:
            raise _rfc_error(
                "bandwidth-efficient ToC chain is incomplete",
                "incomplete-toc",
                provenance,
            )
        followed = bool(bits[position])
        frame_type = _bits_to_int(bits[position + 1 : position + 5])
        quality = bool(bits[position + 5])
        position += 6
        bit_count = _validated_bit_count(definition, frame_type, provenance)
        entries.append((frame_type, quality, bit_count))
        if not followed:
            break

    frames = []
    for index, (frame_type, quality, bit_count) in enumerate(entries):
        end = position + bit_count
        if end > len(bits):
            raise _rfc_error(
                f"speech data for frame {index} is truncated",
                "truncated-speech-data",
                provenance,
            )
        data_bits = bits[position:end]
        position = end
        frames.append(
            _frame(
                definition,
                frame_type,
                quality,
                bit_count,
                data_bits.to_bytes(),
                media_timestamp + index * definition.timestamp_step,
                provenance,
            ),
        )

    remaining = len(bits) - position
    if remaining > 7:
        raise _rfc_error(
            "bandwidth-efficient payload contains unexpected trailing data",
            "trailing-data",
            provenance,
        )
    if any(bits[position:]):
        raise _rfc_error(
            "bandwidth-efficient terminal padding is non-zero",
            "nonzero-padding",
            provenance,
        )
    return tuple(frames)


def depacketize(
    payload: bytes,
    codec: Union[Codec, str],
    mode: Union[PayloadMode, str],
    *,
    media_timestamp: int = 0,
    provenance: Optional[CaptureProvenance] = None,
    options: Optional[Rfc4867Options] = None,
    backend: Optional[BitBackend] = None,
) -> Tuple[EncodedFrame, ...]:
    """Validate and normalize one complete RFC 4867 RTP payload."""

    location = provenance or CaptureProvenance()
    selected_codec = _coerce_codec(codec, location)
    selected_mode = _coerce_mode(mode, location)
    selected_options = options or Rfc4867Options()
    _validate_options(selected_options, location)
    definition = codec_definition(selected_codec)
    raw = bytes(payload)

    if selected_mode is PayloadMode.OCTET_ALIGNED:
        return _depacketize_octet_aligned(
            raw,
            definition,
            media_timestamp,
            location,
        )
    return _depacketize_bandwidth_efficient(
        raw,
        definition,
        media_timestamp,
        location,
        backend or BIT_BACKEND,
    )
