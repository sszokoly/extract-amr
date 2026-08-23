"""Backend-neutral bit operations used by RFC 4867 processing."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from itertools import chain
from typing import (
    Any,
    Callable,
    Iterable,
    Iterator,
    Optional,
    Protocol,
    Type,
    Union,
    overload,
)


class BitBufferContract(Protocol):
    """Minimal immutable bit-buffer behavior required by the codec layer."""

    def __init__(self, bits: Iterable[int] = ()) -> None:
        """Construct a buffer from an iterable of 0/1 bits."""
        ...


    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        bit_length: Optional[int] = None,
    ) -> "BitBufferContract":
        """Create a buffer from most-significant-bit-first bytes."""
        ...

    def __len__(self) -> int:
        """Return the number of significant bits."""
        ...

    def __iter__(self) -> Iterator[int]:
        """Iterate over bits as integers in transmission order."""
        ...

    @overload
    def __getitem__(self, key: int) -> int:
        """Return one bit."""
        ...

    @overload
    def __getitem__(self, key: slice) -> "BitBufferContract":
        """Return a contiguous bit slice."""
        ...

    def __getitem__(
        self,
        key: Union[int, slice],
    ) -> Union[int, "BitBufferContract"]:
        """Return one bit or a contiguous bit slice."""
        ...

    def __add__(self, other: "BitBufferContract") -> "BitBufferContract":
        """Concatenate two buffers."""
        ...

    def to_bytes(self) -> bytes:
        """Serialize bits with zero padding in the least-significant tail."""
        ...

    def to01(self) -> str:
        """Return a diagnostic string containing zero and one characters."""
        ...


def _validated_length(data: bytes, bit_length: Optional[int]) -> int:
    available = len(data) * 8
    if bit_length is None:
        return available
    if not 0 <= bit_length <= available:
        raise ValueError("bit_length must be between 0 and the available bits")
    return bit_length


def _validated_bits(bits: Iterable[int]) -> Iterator[int]:
    for bit in bits:
        if bit not in (0, 1, False, True):
            raise ValueError("bits must contain only 0 or 1")
        yield int(bit)


def _normalized_index(index: int, length: int) -> int:
    if index < 0:
        index += length
    if not 0 <= index < length:
        raise IndexError("bit index out of range")
    return index


def _slice_bounds(key: slice, length: int) -> tuple:
    start, stop, step = key.indices(length)
    if step != 1:
        raise ValueError("bit slices require a step of 1")
    if stop < start:
        stop = start
    return start, stop


class _PythonBitBuffer:
    """Compact pure-Python bit buffer backed by an integer and bit length."""

    __slots__ = ("_length", "_value")

    def __init__(self, bits: Iterable[int] = ()) -> None:
        value = 0
        length = 0
        for bit in _validated_bits(bits):
            value = (value << 1) | bit
            length += 1
        self._value = value
        self._length = length

    @classmethod
    def _from_value(cls, value: int, bit_length: int) -> "_PythonBitBuffer":
        instance = cls()
        instance._value = value
        instance._length = bit_length
        return instance

    @classmethod
    def from_bytes(
        cls,
        data: bytes,
        bit_length: Optional[int] = None,
    ) -> "_PythonBitBuffer":
        raw = bytes(data)
        length = _validated_length(raw, bit_length)
        value = int.from_bytes(raw, byteorder="big")
        value >>= len(raw) * 8 - length
        return cls._from_value(value, length)

    def __len__(self) -> int:
        return self._length

    def __iter__(self) -> Iterator[int]:
        for index in range(self._length):
            yield self[index]

    @overload
    def __getitem__(self, key: int) -> int:
        pass

    @overload
    def __getitem__(self, key: slice) -> "_PythonBitBuffer":
        pass

    def __getitem__(
        self,
        key: Union[int, slice],
    ) -> Union[int, "_PythonBitBuffer"]:
        if isinstance(key, slice):
            start, stop = _slice_bounds(key, self._length)
            length = stop - start
            shift = self._length - stop
            mask = (1 << length) - 1
            return self._from_value((self._value >> shift) & mask, length)
        index = _normalized_index(key, self._length)
        shift = self._length - index - 1
        return (self._value >> shift) & 1

    def __add__(self, other: BitBufferContract) -> "_PythonBitBuffer":
        other_buffer = self.__class__(other)
        value = (self._value << len(other_buffer)) | other_buffer._value
        return self._from_value(value, self._length + len(other_buffer))

    def __eq__(self, other: object) -> bool:
        if not hasattr(other, "to01"):
            return False
        return self.to01() == other.to01()  # type: ignore[union-attr]

    def __repr__(self) -> str:
        return f"PythonBitBuffer('{self.to01()}')"

    def to_bytes(self) -> bytes:
        if self._length == 0:
            return b""
        byte_length = (self._length + 7) // 8
        padding = byte_length * 8 - self._length
        return (self._value << padding).to_bytes(byte_length, byteorder="big")

    def to01(self) -> str:
        return "".join(str(bit) for bit in self)


def _make_bitarray_buffer(bitarray_type: Type[Any]) -> Type[BitBufferContract]:
    class _BitarrayBitBuffer:
        """Local wrapper that prevents third-party types escaping the module."""

        __slots__ = ("_bits",)

        def __init__(self, bits: Iterable[int] = ()) -> None:
            self._bits = bitarray_type(endian="big")
            self._bits.extend(_validated_bits(bits))

        @classmethod
        def _from_array(cls, array: Any) -> "_BitarrayBitBuffer":
            instance = cls()
            instance._bits = array
            return instance

        @classmethod
        def from_bytes(
            cls,
            data: bytes,
            bit_length: Optional[int] = None,
        ) -> "_BitarrayBitBuffer":
            raw = bytes(data)
            length = _validated_length(raw, bit_length)
            array = bitarray_type(endian="big")
            array.frombytes(raw)
            del array[length:]
            return cls._from_array(array)

        def __len__(self) -> int:
            return len(self._bits)

        def __iter__(self) -> Iterator[int]:
            return (int(bit) for bit in self._bits)

        @overload
        def __getitem__(self, key: int) -> int:
            pass

        @overload
        def __getitem__(self, key: slice) -> "_BitarrayBitBuffer":
            pass

        def __getitem__(
            self,
            key: Union[int, slice],
        ) -> Union[int, "_BitarrayBitBuffer"]:
            if isinstance(key, slice):
                start, stop = _slice_bounds(key, len(self))
                return self._from_array(self._bits[start:stop])
            index = _normalized_index(key, len(self))
            return int(self._bits[index])

        def __add__(self, other: BitBufferContract) -> "_BitarrayBitBuffer":
            array = self._bits.copy()
            array.extend(_validated_bits(other))
            return self._from_array(array)

        def __eq__(self, other: object) -> bool:
            if not hasattr(other, "to01"):
                return False
            return self.to01() == other.to01()  # type: ignore[union-attr]

        def __repr__(self) -> str:
            return f"BitarrayBitBuffer('{self.to01()}')"

        def to_bytes(self) -> bytes:
            return self._bits.tobytes()

        def to01(self) -> str:
            return self._bits.to01()

    _BitarrayBitBuffer.__name__ = "BitarrayBitBuffer"
    return _BitarrayBitBuffer


@dataclass(frozen=True)
class BitBackend:
    """Selected bit-buffer implementation and fallback diagnostics."""

    name: str
    buffer_type: Type[BitBufferContract]
    fallback_reason: Optional[str] = None

    def from_bytes(
        self,
        data: bytes,
        bit_length: Optional[int] = None,
    ) -> BitBufferContract:
        return self.buffer_type.from_bytes(data, bit_length)

    def from_iterable(self, bits: Iterable[int]) -> BitBufferContract:
        return self.buffer_type(bits)


def _fallback_reason(error: Exception) -> str:
    message = " ".join(str(error).split())
    if len(message) > 200:
        message = f"{message[:197]}..."
    if not message:
        return error.__class__.__name__
    return f"{error.__class__.__name__}: {message}"


def _select_backend(
    importer: Callable[[str], Any] = importlib.import_module,
) -> BitBackend:
    try:
        module = importer("bitarray")
        bitarray_type = module.bitarray
        probe = bitarray_type(endian="big")
        probe.frombytes(b"\x80")
        if len(probe) != 8 or int(probe[0]) != 1:
            raise RuntimeError("bitarray failed its initialization probe")
        return BitBackend(
            name="bitarray",
            buffer_type=_make_bitarray_buffer(bitarray_type),
        )
    except Exception as error:
        return BitBackend(
            name="python",
            buffer_type=_PythonBitBuffer,
            fallback_reason=_fallback_reason(error),
        )


BIT_BACKEND = _select_backend()
BitBuffer = BIT_BACKEND.buffer_type
bits_from_bytes = BIT_BACKEND.from_bytes
bits_from_iterable = BIT_BACKEND.from_iterable


def bits_to_bytes(bits: BitBufferContract) -> bytes:
    """Serialize a local bit buffer with zero tail padding."""

    return bits.to_bytes()


def concat_bits(*buffers: BitBufferContract) -> BitBufferContract:
    """Concatenate buffers into a value owned by the active backend."""

    return BitBuffer(chain.from_iterable(buffers))
