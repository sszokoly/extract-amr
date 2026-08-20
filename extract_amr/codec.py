"""Immutable AMR and AMR-WB codec definitions."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import FrozenSet, Mapping, Optional, Tuple

from .models import Codec


@dataclass(frozen=True)
class CodecDefinition:
    """Normative framing values for one RFC 4867 codec."""

    codec: Codec
    clock_rate: int
    timestamp_step: int
    storage_header: bytes
    default_extension: str
    frame_bit_counts: Tuple[Optional[int], ...]
    valid_frame_types: FrozenSet[int]
    special_frame_types: Mapping[int, str]

    def bit_count(self, frame_type: int) -> Optional[int]:
        """Return the speech-bit count, or ``None`` for a reserved type."""

        if not 0 <= frame_type < len(self.frame_bit_counts):
            return None
        return self.frame_bit_counts[frame_type]


AMR_DEFINITION = CodecDefinition(
    codec=Codec.AMR,
    clock_rate=8000,
    timestamp_step=160,
    storage_header=b"#!AMR\n",
    default_extension=".amr",
    frame_bit_counts=(
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
    ),
    valid_frame_types=frozenset((*range(9), 15)),
    special_frame_types=MappingProxyType({8: "SID", 15: "NO_DATA"}),
)

AMR_WB_DEFINITION = CodecDefinition(
    codec=Codec.AMR_WB,
    clock_rate=16000,
    timestamp_step=320,
    storage_header=b"#!AMR-WB\n",
    default_extension=".awb",
    frame_bit_counts=(
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
    ),
    valid_frame_types=frozenset((*range(10), 14, 15)),
    special_frame_types=MappingProxyType(
        {9: "SID", 14: "SPEECH_LOST", 15: "NO_DATA"},
    ),
)

CODEC_DEFINITIONS: Mapping[Codec, CodecDefinition] = MappingProxyType(
    {
        Codec.AMR: AMR_DEFINITION,
        Codec.AMR_WB: AMR_WB_DEFINITION,
    },
)


def codec_definition(codec: Codec) -> CodecDefinition:
    """Return the immutable definition for a supported codec."""

    return CODEC_DEFINITIONS[codec]
