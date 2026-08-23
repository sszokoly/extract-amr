"""Byte-exact RFC 4867 depacketization and storage tests."""

import importlib
from decimal import Decimal

import pytest

from extract_amr import bits
from extract_amr.codec import AMR_DEFINITION, AMR_WB_DEFINITION
from extract_amr.errors import Rfc4867Error, UnsupportedFormatError
from extract_amr.models import (
    CaptureProvenance,
    Codec,
    EncodedFrame,
    PayloadMode,
    Rfc4867Options,
)
from extract_amr.rfc4867 import depacketize
from extract_amr.storage import serialize_storage_frame, storage_bytes, write_storage


PROVENANCE = CaptureProvenance(23, Decimal("4.5"))


def _python_backend():
    def missing(name: str):
        raise ModuleNotFoundError(name)

    return bits._select_backend(missing)


def _accelerated_backend():
    pytest.importorskip("bitarray")
    return bits._select_backend(importlib.import_module)


BACKENDS = [_python_backend, _accelerated_backend]


def _speech_bits(bit_count: int, salt: int = 0) -> str:
    return "".join(str((index + salt) % 2) for index in range(bit_count))


def _pack(bit_string: str) -> bytes:
    padding = (-len(bit_string)) % 8
    padded = bit_string + "0" * padding
    if not padded:
        return b""
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def _octet_payload(entries, cmr: int = 15) -> bytes:
    toc = bytearray()
    speech = bytearray()
    for index, (frame_type, quality, bit_string) in enumerate(entries):
        followed = index < len(entries) - 1
        toc.append((int(followed) << 7) | (frame_type << 3) | (int(quality) << 2))
        speech.extend(_pack(bit_string))
    return bytes([cmr << 4]) + bytes(toc) + bytes(speech)


def _bandwidth_payload(entries, cmr: int = 15) -> bytes:
    fields = [f"{cmr:04b}"]
    for index, (frame_type, quality, bit_string) in enumerate(entries):
        followed = index < len(entries) - 1
        fields.append(f"{int(followed)}{frame_type:04b}{int(quality)}")
    fields.extend(bit_string for _, _, bit_string in entries)
    return _pack("".join(fields))


def _payload(mode: PayloadMode, entries) -> bytes:
    if mode is PayloadMode.OCTET_ALIGNED:
        return _octet_payload(entries)
    return _bandwidth_payload(entries)


@pytest.mark.parametrize("backend_factory", BACKENDS, ids=["python", "bitarray"])
@pytest.mark.parametrize("mode", list(PayloadMode))
@pytest.mark.parametrize("definition", [AMR_DEFINITION, AMR_WB_DEFINITION])
def test_every_supported_frame_type_is_byte_exact(
    backend_factory,
    mode: PayloadMode,
    definition,
) -> None:
    backend = backend_factory()
    for frame_type in sorted(definition.valid_frame_types):
        bit_count = definition.bit_count(frame_type)
        assert bit_count is not None
        speech = _speech_bits(bit_count, frame_type)
        quality = frame_type % 2 == 0
        frames = depacketize(
            _payload(mode, [(frame_type, quality, speech)]),
            definition.codec,
            mode,
            media_timestamp=1000,
            provenance=PROVENANCE,
            backend=backend,
        )

        assert len(frames) == 1
        frame = frames[0]
        assert frame.codec is definition.codec
        assert frame.frame_type == frame_type
        assert frame.quality is quality
        assert frame.bit_length == bit_count
        assert frame.data == _pack(speech)
        assert frame.media_timestamp == 1000
        assert frame.provenance is PROVENANCE
        assert serialize_storage_frame(frame) == bytes(
            [(frame_type << 3) | (int(quality) << 2)],
        ) + _pack(speech)
        assert storage_bytes(definition.codec, frames) == (
            definition.storage_header + serialize_storage_frame(frame)
        )


@pytest.mark.parametrize("mode", list(PayloadMode))
def test_compound_payload_preserves_order_quality_and_media_time(mode: PayloadMode) -> None:
    entries = [
        (0, True, _speech_bits(95)),
        (8, False, _speech_bits(39, 1)),
        (15, False, ""),
    ]

    frames = depacketize(
        _payload(mode, entries),
        Codec.AMR,
        mode,
        media_timestamp=8000,
        provenance=PROVENANCE,
        backend=_python_backend(),
    )

    assert [frame.frame_type for frame in frames] == [0, 8, 15]
    assert [frame.quality for frame in frames] == [True, False, False]
    assert [frame.media_timestamp for frame in frames] == [8000, 8160, 8320]
    assert [frame.bit_length for frame in frames] == [95, 39, 0]


@pytest.mark.parametrize("mode", list(PayloadMode))
def test_ft_14_and_15_have_codec_specific_semantics(mode: PayloadMode) -> None:
    wb_frames = depacketize(
        _payload(mode, [(14, False, ""), (15, True, "")]),
        Codec.AMR_WB,
        mode,
        backend=_python_backend(),
    )

    assert [frame.frame_type for frame in wb_frames] == [14, 15]
    assert [frame.data for frame in wb_frames] == [b"", b""]
    assert [serialize_storage_frame(frame) for frame in wb_frames] == [b"p", b"|"]

    with pytest.raises(Rfc4867Error, match="frame type 14 is invalid"):
        depacketize(
            _payload(mode, [(14, False, "")]),
            Codec.AMR,
            mode,
            backend=_python_backend(),
        )


@pytest.mark.parametrize("mode", list(PayloadMode))
@pytest.mark.parametrize(
    ("codec", "reserved_types"),
    [
        (Codec.AMR, range(9, 15)),
        (Codec.AMR_WB, range(10, 14)),
    ],
)
def test_every_reserved_frame_type_rejects_the_complete_payload(
    mode: PayloadMode,
    codec: Codec,
    reserved_types,
) -> None:
    for frame_type in reserved_types:
        with pytest.raises(Rfc4867Error, match=f"frame type {frame_type} is invalid"):
            depacketize(
                _payload(mode, [(frame_type, True, "")]),
                codec,
                mode,
                backend=_python_backend(),
            )


@pytest.mark.parametrize(
    ("options", "name"),
    [
        (Rfc4867Options(channels=2), "multichannel"),
        (Rfc4867Options(crc=True), "CRC"),
        (Rfc4867Options(interleaving=True), "interleaving"),
        (Rfc4867Options(robust_sorting=True), "robust sorting"),
    ],
)
def test_unsupported_rfc_options_are_rejected(options, name: str) -> None:
    with pytest.raises(UnsupportedFormatError, match=name) as captured:
        depacketize(b"", Codec.AMR, PayloadMode.OCTET_ALIGNED, options=options)

    assert captured.value.details["option"]


@pytest.mark.parametrize(
    ("codec", "mode", "message"),
    [
        ("evs", PayloadMode.OCTET_ALIGNED, "unsupported codec: evs"),
        (Codec.AMR, "iu-up", "unsupported payload framing: iu-up"),
    ],
)
def test_unsupported_codec_and_framing_are_structured(codec, mode, message: str) -> None:
    with pytest.raises(UnsupportedFormatError, match=message):
        depacketize(b"", codec, mode)


@pytest.mark.parametrize(
    ("payload", "message", "reason"),
    [
        (b"", "too short", "short-header"),
        (b"\xf0", "too short", "short-header"),
        (b"\xf1\x04", "CMR padding", "nonzero-padding"),
        (b"\xf0\x05", "ToC padding", "nonzero-padding"),
        (b"\xf0\x84", "ToC chain is incomplete", "incomplete-toc"),
        (b"\xf0\x4c", "frame type 9 is invalid", "invalid-frame-type"),
        (b"\xf0\x04" + bytes(11), "frame 0 is truncated", "truncated-speech-data"),
        (b"\xf0\x7c\x00", "unexpected trailing data", "trailing-data"),
        (b"\xf0\x04" + bytes(11) + b"\x01", "padding.*non-zero", "nonzero-padding"),
    ],
)
def test_octet_aligned_malformed_vectors_are_structured(
    payload: bytes,
    message: str,
    reason: str,
) -> None:
    with pytest.raises(Rfc4867Error, match=message) as captured:
        depacketize(
            payload,
            Codec.AMR,
            PayloadMode.OCTET_ALIGNED,
            provenance=PROVENANCE,
        )

    assert captured.value.code == "malformed-rfc4867"
    assert captured.value.details == {"reason": reason}
    assert captured.value.provenance is PROVENANCE
    assert "capture packet 23" in str(captured.value)


def _bandwidth_malformed_vectors():
    incomplete_toc = _pack("1111" + "100001" + "100001")
    invalid_ft = _pack("1111" + "010011")
    truncated = _bandwidth_payload([(0, True, _speech_bits(95))])[:-1]
    trailing = _bandwidth_payload([(15, True, "")]) + b"\x00"
    nonzero_padding = bytearray(_bandwidth_payload([(15, True, "")]))
    nonzero_padding[-1] |= 1
    return [
        (b"", "too short", "short-header"),
        (b"\xf0", "too short", "short-header"),
        (incomplete_toc, "ToC chain is incomplete", "incomplete-toc"),
        (invalid_ft, "frame type 9 is invalid", "invalid-frame-type"),
        (truncated, "frame 0 is truncated", "truncated-speech-data"),
        (trailing, "unexpected trailing data", "trailing-data"),
        (bytes(nonzero_padding), "terminal padding is non-zero", "nonzero-padding"),
    ]


@pytest.mark.parametrize(
    ("payload", "message", "reason"),
    _bandwidth_malformed_vectors(),
)
def test_bandwidth_efficient_malformed_vectors_are_structured(
    payload: bytes,
    message: str,
    reason: str,
) -> None:
    with pytest.raises(Rfc4867Error, match=message) as captured:
        depacketize(
            payload,
            Codec.AMR,
            PayloadMode.BANDWIDTH_EFFICIENT,
            provenance=PROVENANCE,
            backend=_python_backend(),
        )

    assert captured.value.details == {"reason": reason}
    assert captured.value.provenance is PROVENANCE


@pytest.mark.parametrize("mode", list(PayloadMode))
def test_later_malformed_frame_rejects_complete_payload(mode: PayloadMode) -> None:
    entries = [
        (15, True, ""),
        (0, True, _speech_bits(95)),
    ]
    payload = _payload(mode, entries)[:-1]

    with pytest.raises(Rfc4867Error, match="frame 1 is truncated"):
        depacketize(
            payload,
            Codec.AMR,
            mode,
            backend=_python_backend(),
        )


def _error_result(payload: bytes, mode: PayloadMode, backend):
    with pytest.raises(Rfc4867Error) as captured:
        depacketize(
            payload,
            Codec.AMR,
            mode,
            provenance=PROVENANCE,
            backend=backend,
        )
    error = captured.value
    return error.code, error.message, error.details, error.provenance


def test_bit_backends_have_identical_codec_behavior() -> None:
    python_backend = _python_backend()
    accelerated_backend = _accelerated_backend()
    entries = [
        (0, True, _speech_bits(95)),
        (8, False, _speech_bits(39, 1)),
        (15, False, ""),
    ]

    for mode in PayloadMode:
        payload = _payload(mode, entries)
        python_frames = depacketize(
            payload,
            Codec.AMR,
            mode,
            provenance=PROVENANCE,
            backend=python_backend,
        )
        accelerated_frames = depacketize(
            payload,
            Codec.AMR,
            mode,
            provenance=PROVENANCE,
            backend=accelerated_backend,
        )
        assert accelerated_frames == python_frames
        assert storage_bytes(Codec.AMR, accelerated_frames) == storage_bytes(
            Codec.AMR,
            python_frames,
        )

    for payload, _, _ in _bandwidth_malformed_vectors():
        assert _error_result(
            payload,
            PayloadMode.BANDWIDTH_EFFICIENT,
            accelerated_backend,
        ) == _error_result(
            payload,
            PayloadMode.BANDWIDTH_EFFICIENT,
            python_backend,
        )


def test_storage_writer_writes_one_header_and_returns_frame_count() -> None:
    frames = depacketize(
        _octet_payload([(15, False, ""), (0, True, _speech_bits(95))]),
        Codec.AMR,
        PayloadMode.OCTET_ALIGNED,
    )

    class Output:
        def __init__(self) -> None:
            self.data = bytearray()

        def write(self, data: bytes) -> int:
            self.data.extend(data)
            return len(data)

    output = Output()
    count = write_storage(output, Codec.AMR, frames)

    assert count == 2
    assert bytes(output.data) == storage_bytes(Codec.AMR, frames)
    assert bytes(output.data).count(b"#!AMR\n") == 1


@pytest.mark.parametrize(
    ("changes", "message", "reason"),
    [
        ({"bit_length": 94}, "bit length", "invalid-frame-length"),
        ({"data": bytes(11)}, "byte length", "invalid-frame-length"),
        ({"data": bytes(11) + b"\x01"}, "padding is non-zero", "nonzero-padding"),
    ],
)
def test_storage_rejects_invalid_normalized_frames(changes, message: str, reason: str) -> None:
    values = {
        "codec": Codec.AMR,
        "frame_type": 0,
        "quality": True,
        "bit_length": 95,
        "data": bytes(12),
        "media_timestamp": 0,
        "provenance": PROVENANCE,
    }
    values.update(changes)

    with pytest.raises(Rfc4867Error, match=message) as captured:
        serialize_storage_frame(EncodedFrame(**values))

    assert captured.value.details == {"reason": reason}


def test_storage_rejects_reserved_frame_type() -> None:
    frame = EncodedFrame(
        codec=Codec.AMR_WB,
        frame_type=10,
        quality=False,
        bit_length=0,
        data=b"",
        media_timestamp=0,
        provenance=PROVENANCE,
    )

    with pytest.raises(Rfc4867Error, match="frame type 10 is invalid") as captured:
        serialize_storage_frame(frame)

    assert captured.value.details == {"reason": "invalid-frame-type"}


def test_storage_rejects_frames_from_another_codec() -> None:
    frames = depacketize(
        _octet_payload([(15, False, "")]),
        Codec.AMR_WB,
        PayloadMode.OCTET_ALIGNED,
    )

    with pytest.raises(Rfc4867Error, match="another codec") as captured:
        storage_bytes(Codec.AMR, frames)

    assert captured.value.details == {"reason": "codec-mismatch"}
