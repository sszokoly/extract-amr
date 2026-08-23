"""Synthetic PCAP and PCAPNG tests for streaming UDP extraction."""

import gzip
import os
import struct
from dataclasses import FrozenInstanceError
from decimal import Decimal
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import EDecimal, PcapNgWriter, PcapWriter

from extract_amr.capture import CaptureProgress, iter_udp_records
from extract_amr.errors import CaptureInputError
from extract_amr.models import FlowKey, FlowSelector
from extract_amr.rtp import iter_rtp_records


def _write_capture(path: Path, packets: list) -> None:
    if path.suffix == ".pcapng":
        writer = PcapNgWriter(str(path))
    else:
        writer = PcapWriter(str(path), linktype=1, sync=True)
    try:
        for packet in packets:
            writer.write(packet)
    finally:
        writer.close()


def _timestamp(packet: Packet, value: str) -> Packet:
    packet.time = EDecimal(value)
    return packet


def _rtp_payload(sequence: int, ssrc: int = 0x11223344) -> bytes:
    return struct.pack("!BBHII", 0x80, 96, sequence, 320, ssrc) + b"media"


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_streams_exact_ipv4_and_ipv6_udp_payloads(
    tmp_path: Path,
    suffix: str,
) -> None:
    path = tmp_path / f"mixed{suffix}"
    dns_like_payload = b"\x12\x34\x01\x00\x00\x01\x00\x00"
    packets = [
        _timestamp(
            Ether() / IP(src="192.0.2.10", dst="192.0.2.20") / TCP(),
            "1.000000",
        ),
        _timestamp(
            Ether()
            / IP(src="192.0.2.1", dst="192.0.2.2")
            / UDP(sport=4000, dport=53)
            / Raw(dns_like_payload),
            "1.250000",
        ),
        _timestamp(
            Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::2")
            / UDP(sport=5000, dport=6000)
            / Raw(b"ipv6-media"),
            "1.500000",
        ),
    ]
    _write_capture(path, packets)

    records = list(iter_udp_records(path))

    assert len(records) == 2
    ipv4, ipv6 = records
    assert ipv4.payload == dns_like_payload
    assert ipv4.ip_version == 4
    assert ipv4.provenance.packet_number == 2
    assert ipv4.provenance.capture_timestamp == Decimal("1.250000")
    assert ipv6.payload == b"ipv6-media"
    assert ipv6.ip_version == 6
    assert ipv6.src_address == "2001:db8::1"
    assert ipv6.provenance.packet_number == 3


def test_directional_port_filters_are_independent(tmp_path: Path) -> None:
    path = tmp_path / "ports.pcap"
    packets = [
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=1000, dport=2000) / Raw(b"a"),
        Ether() / IP(src="192.0.2.1", dst="192.0.2.3") / UDP(sport=1000, dport=3000) / Raw(b"b"),
        Ether() / IP(src="192.0.2.4", dst="192.0.2.2") / UDP(sport=4000, dport=2000) / Raw(b"c"),
    ]
    _write_capture(path, packets)

    by_source = list(iter_udp_records(path, FlowSelector(src_port=1000)))
    by_destination = list(iter_udp_records(path, FlowSelector(dst_port=2000)))
    by_pair = list(
        iter_udp_records(
            path,
            FlowSelector(src_port=1000, dst_port=2000),
        ),
    )

    assert [record.payload for record in by_source] == [b"a", b"b"]
    assert [record.payload for record in by_destination] == [b"a", b"c"]
    assert [record.payload for record in by_pair] == [b"a"]


def test_fragmented_ipv4_and_ipv6_datagrams_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "fragments.pcapng"
    packets = [
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2", flags="MF")
        / UDP(sport=1000, dport=2000)
        / Raw(b"ipv4-fragment"),
        Ether() / IP(src="192.0.2.1", dst="192.0.2.2", frag=1) / Raw(b"later-ipv4-fragment"),
        Ether()
        / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrFragment(m=1)
        / UDP(sport=1000, dport=2000)
        / Raw(b"ipv6-fragment"),
        Ether()
        / IP(src="198.51.100.1", dst="198.51.100.2")
        / UDP(sport=3000, dport=4000)
        / Raw(b"complete"),
    ]
    _write_capture(path, packets)

    records = list(iter_udp_records(path))

    assert len(records) == 1
    assert records[0].payload == b"complete"
    assert records[0].provenance.packet_number == 4


def test_synthetic_capture_keeps_opposite_rtp_flows_distinct(tmp_path: Path) -> None:
    path = tmp_path / "directions.pcapng"
    packets = [
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=4000, dport=5000)
        / Raw(_rtp_payload(1)),
        Ether()
        / IP(src="192.0.2.2", dst="192.0.2.1")
        / UDP(sport=5000, dport=4000)
        / Raw(_rtp_payload(2)),
    ]
    _write_capture(path, packets)

    records = list(iter_rtp_records(iter_udp_records(path)))

    assert len(records) == 2
    assert records[0].flow_key.ssrc == records[1].flow_key.ssrc
    assert records[0].flow_key.payload_type == records[1].flow_key.payload_type
    assert records[0].flow_key != records[1].flow_key


def test_network_records_and_flow_keys_are_immutable(tmp_path: Path) -> None:
    path = tmp_path / "immutable.pcap"
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="192.0.2.2")
        / UDP(sport=4000, dport=5000)
        / Raw(_rtp_payload(1))
    )
    _write_capture(path, [packet])
    udp = next(iter_udp_records(path))
    rtp = next(iter_rtp_records([udp]))
    selector = FlowSelector(
        src_address="192.0.2.1",
        dst_address="192.0.2.2",
        src_port=4000,
        dst_port=5000,
        ssrc=0x11223344,
        payload_type=96,
    )

    assert selector.matches_udp(udp)
    assert selector.matches_flow(rtp.flow_key)
    assert rtp.flow_key == FlowKey(
        src_address="192.0.2.1",
        dst_address="192.0.2.2",
        src_port=4000,
        dst_port=5000,
        ssrc=0x11223344,
        payload_type=96,
    )
    with pytest.raises(FrozenInstanceError):
        udp.src_port = 1
    with pytest.raises(FrozenInstanceError):
        rtp.sequence = 2


def test_invalid_capture_is_reported_as_input_error(tmp_path: Path) -> None:
    path = tmp_path / "invalid.pcap"
    path.write_bytes(b"not a capture")

    with pytest.raises(CaptureInputError, match="unable to read capture"):
        list(iter_udp_records(path))


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_progress_accounts_for_every_capture_byte_before_filtering(
    tmp_path: Path,
    suffix: str,
) -> None:
    path = tmp_path / f"progress{suffix}"
    _write_capture(
        path,
        [
            Ether() / IP() / TCP(),
            Ether() / IP() / UDP(sport=4000, dport=5000) / Raw(b"filtered"),
        ],
    )
    deltas = []
    progress = CaptureProgress(path, 1, deltas.append)

    records = list(
        iter_udp_records(
            path,
            FlowSelector(src_port=9999),
            _progress=progress,
        ),
    )
    assert sum(deltas) < path.stat().st_size
    progress.ensure_complete()

    assert records == []
    assert deltas
    assert all(delta > 0 for delta in deltas)
    assert sum(deltas) == path.stat().st_size
    assert progress.completed_passes == 1


def test_progress_accounts_for_short_trailing_pcap_bytes(tmp_path: Path) -> None:
    path = tmp_path / "trailing.pcap"
    _write_capture(path, [Ether() / IP() / TCP()])
    with path.open("ab") as output:
        output.write(b"trailer")
    deltas = []
    progress = CaptureProgress(path, 1, deltas.append)

    list(iter_udp_records(path, _progress=progress))
    progress.ensure_complete()

    assert sum(deltas) == path.stat().st_size


def test_progress_accounts_for_trailing_pcapng_metadata(tmp_path: Path) -> None:
    path = tmp_path / "metadata.pcapng"
    _write_capture(path, [Ether() / IP() / TCP()])
    with path.open("ab") as output:
        output.write(struct.pack("<III", 0x00000BAD, 12, 12))
    deltas = []
    progress = CaptureProgress(path, 1, deltas.append)

    list(iter_udp_records(path, _progress=progress))
    progress.ensure_complete()

    assert sum(deltas) == path.stat().st_size


def test_progress_rejects_compressed_and_non_regular_inputs(tmp_path: Path) -> None:
    path = tmp_path / "source.pcap"
    compressed = tmp_path / "source.pcap.gz"
    fifo = tmp_path / "capture.fifo"
    _write_capture(path, [Ether() / IP() / TCP()])
    with gzip.open(str(compressed), "wb") as output:
        output.write(path.read_bytes())

    with pytest.raises(CaptureInputError, match="compressed capture"):
        CaptureProgress(compressed, 1)

    if hasattr(os, "mkfifo"):
        os.mkfifo(str(fifo))
        with pytest.raises(CaptureInputError, match="regular capture"):
            CaptureProgress(fifo, 1)


def test_progress_rejects_a_capture_changed_before_processing(tmp_path: Path) -> None:
    path = tmp_path / "changed.pcap"
    _write_capture(path, [Ether() / IP() / TCP()])
    progress = CaptureProgress(path, 1)
    with path.open("ab") as output:
        output.write(b"changed")

    with pytest.raises(CaptureInputError, match="capture changed"):
        list(iter_udp_records(path, _progress=progress))


def test_progress_rejects_invalid_and_incomplete_positions(tmp_path: Path) -> None:
    path = tmp_path / "positions.pcap"
    _write_capture(path, [Ether() / IP() / TCP()])

    out_of_range = CaptureProgress(path, 1)
    with path.open("rb") as source:
        out_of_range.start_pass(path, source)
        source.seek(out_of_range.size + 1)
        with pytest.raises(CaptureInputError, match="outside the expected file"):
            out_of_range.observe(source)

    incomplete = CaptureProgress(path, 1)
    with path.open("rb") as source:
        incomplete.start_pass(path, source)
        source.seek(incomplete.size - 1)
        with pytest.raises(CaptureInputError, match="ended before"):
            incomplete.finish_pass(path, source)

    class MissingPosition:
        def __init__(self, source) -> None:
            self.source = source

        def fileno(self):
            return self.source.fileno()

        def tell(self):
            raise OSError("no position")

    unavailable = CaptureProgress(path, 1)
    with path.open("rb") as source:
        with pytest.raises(CaptureInputError, match="position is unavailable"):
            unavailable.start_pass(path, MissingPosition(source))

    backwards = CaptureProgress(path, 1)
    with path.open("rb") as source:
        backwards.start_pass(path, source)
        source.seek(10)
        backwards.observe(source)
        source.seek(5)
        with pytest.raises(CaptureInputError, match="outside the expected file"):
            backwards.observe(source)

    class NonIntegralPosition:
        def __init__(self, source) -> None:
            self.source = source

        def fileno(self):
            return self.source.fileno()

        def tell(self):
            return 1.5

    non_integral = CaptureProgress(path, 1)
    with path.open("rb") as source:
        with pytest.raises(CaptureInputError, match="position is invalid"):
            non_integral.start_pass(path, NonIntegralPosition(source))


def test_progress_rejects_extra_and_incomplete_passes(tmp_path: Path) -> None:
    path = tmp_path / "pass-count.pcap"
    _write_capture(path, [Ether() / IP() / TCP()])
    progress = CaptureProgress(path, 1)

    list(iter_udp_records(path, _progress=progress))
    progress.ensure_complete()

    with pytest.raises(CaptureInputError, match="unexpected extra pass"):
        list(iter_udp_records(path, _progress=progress))

    incomplete = CaptureProgress(path, 2)
    list(iter_udp_records(path, _progress=incomplete))
    with pytest.raises(CaptureInputError, match="did not complete"):
        incomplete.ensure_complete()
