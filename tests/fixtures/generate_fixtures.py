"""Regenerate minimal capture fixtures from independent literal vectors."""

from pathlib import Path

from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter, PcapWriter

FIXTURE_DIR = Path(__file__).parent
GOLDEN_DIR = FIXTURE_DIR / "golden"

DIRECTIONAL_FRAMES = (
    "020000000002020000000001080045000037000100004011f6b1c0000201c0000202"
    "0fa0138800232b1d806000010000000011111111"
    "f00c0123456789abcdef1032547698",
    "020000000001020000000002080045000040000200004011f6a7c0000202c0000201"
    "13880fa0002c6e6a806000070000014011111111"
    "f0eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0",
)

MULTI_SSRC_FRAMES = (
    "02000000001402000000000a080045000037000300004011262ec633640ac6336414"
    "17701b580023ff0f80620064000003e801020304"
    "f09555555555555555555555555500",
    "02000000001402000000000a0800450000410004000040112623c633640ac6336414"
    "17701b58002d553c80620064000003e8a0b0c0d0"
    "f00ccccccccccccccccccccccccccccccccccccccccccccc80",
)

GOLDENS = {
    "directional_amr_oa.amr": "2321414d520a0c0123456789abcdef1032547698",
    "directional_amrwb_be.awb": "2321414d522d57420a0c" + "aa" * 22 + "80",
    "multi_ssrc_01020304_amr_be.amr": "2321414d520a08" + "55" * 12 + "54",
    "multi_ssrc_a0b0c0d0_amrwb_oa.awb": "2321414d522d57420a0c" + "cc" * 22 + "80",
}


def _write_pcap(path: Path, frames) -> None:
    writer = PcapWriter(str(path), linktype=1, sync=True)
    try:
        for index, frame in enumerate(frames):
            packet = Ether(bytes.fromhex(frame))
            packet.time = 1 + index / 50
            writer.write(packet)
    finally:
        writer.close()


def _write_pcapng(path: Path, frames) -> None:
    writer = PcapNgWriter(str(path))
    try:
        for index, frame in enumerate(frames):
            packet = Ether(bytes.fromhex(frame))
            packet.time = 2 + index / 50
            writer.write(packet)
    finally:
        writer.close()


def main() -> None:
    """Write every capture and golden vector next to this script."""

    GOLDEN_DIR.mkdir(exist_ok=True)
    _write_pcap(FIXTURE_DIR / "directional_modes.pcap", DIRECTIONAL_FRAMES)
    _write_pcapng(FIXTURE_DIR / "multi_ssrc_modes.pcapng", MULTI_SSRC_FRAMES)
    for name, value in GOLDENS.items():
        (GOLDEN_DIR / name).write_bytes(bytes.fromhex(value))


if __name__ == "__main__":
    main()
