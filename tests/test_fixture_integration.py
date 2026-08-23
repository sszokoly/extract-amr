"""Byte-exact integration tests against checked-in independent fixtures."""

import io
from pathlib import Path

import pytest

from extract_amr import api
from extract_amr.models import Codec, FlowKey, FlowSelector, PayloadMode

FIXTURES = Path(__file__).parent / "fixtures"
GOLDENS = FIXTURES / "golden"


@pytest.mark.parametrize(
    "selector,flow_key,codec,mode,golden_name",
    (
        (
            FlowSelector(src_port=4000, dst_port=5000),
            FlowKey("192.0.2.1", "192.0.2.2", 4000, 5000, 0x11111111, 96),
            Codec.AMR,
            PayloadMode.OCTET_ALIGNED,
            "directional_amr_oa.amr",
        ),
        (
            FlowSelector(src_port=5000, dst_port=4000),
            FlowKey("192.0.2.2", "192.0.2.1", 5000, 4000, 0x11111111, 96),
            Codec.AMR_WB,
            PayloadMode.BANDWIDTH_EFFICIENT,
            "directional_amrwb_be.awb",
        ),
    ),
)
def test_directional_pcap_matches_independent_golden(
    selector: FlowSelector,
    flow_key: FlowKey,
    codec: Codec,
    mode: PayloadMode,
    golden_name: str,
) -> None:
    output = io.BytesIO()

    report = api.extract_pcap(
        FIXTURES / "directional_modes.pcap",
        output,
        selector=selector,
    )

    assert output.getvalue() == (GOLDENS / golden_name).read_bytes()
    assert report.selected_flow.flow_key == flow_key
    assert report.selected_flow.codec is codec
    assert report.selected_flow.payload_mode is mode
    assert report.capture_pass_count == 2
    assert report.capture_packet_count == 2
    assert report.udp_packet_count == 1
    assert report.selected_rtp_packet_count == 1
    assert report.emitted_frame_count == 1
    assert report.malformed_packet_count == 0


def test_multi_ssrc_pcapng_matches_independent_goldens() -> None:
    first_flow = FlowKey(
        "198.51.100.10",
        "198.51.100.20",
        6000,
        7000,
        0x01020304,
        98,
    )
    second_flow = FlowKey(
        "198.51.100.10",
        "198.51.100.20",
        6000,
        7000,
        0xA0B0C0D0,
        98,
    )
    outputs = {first_flow: io.BytesIO(), second_flow: io.BytesIO()}

    reports = api.extract_flows(
        FIXTURES / "multi_ssrc_modes.pcapng",
        outputs,
        selector=FlowSelector(src_port=6000, dst_port=7000),
    )

    assert [report.selected_flow.flow_key for report in reports] == [first_flow, second_flow]
    assert (
        outputs[first_flow].getvalue() == (GOLDENS / "multi_ssrc_01020304_amr_be.amr").read_bytes()
    )
    assert (
        outputs[second_flow].getvalue()
        == (GOLDENS / "multi_ssrc_a0b0c0d0_amrwb_oa.awb").read_bytes()
    )
    assert reports[0].selected_flow.codec is Codec.AMR
    assert reports[0].selected_flow.payload_mode is PayloadMode.BANDWIDTH_EFFICIENT
    assert reports[0].bad_quality_frame_count == 1
    assert reports[1].selected_flow.codec is Codec.AMR_WB
    assert reports[1].selected_flow.payload_mode is PayloadMode.OCTET_ALIGNED
    assert reports[1].bad_quality_frame_count == 0
    assert all(report.capture_pass_count == 2 for report in reports)
    assert all(report.capture_packet_count == 2 for report in reports)
    assert all(report.udp_packet_count == 2 for report in reports)
    assert all(report.selected_rtp_packet_count == 1 for report in reports)
    assert all(report.emitted_frame_count == 1 for report in reports)
    assert all(report.duplicate_packet_count == 0 for report in reports)
    assert all(report.overlap_frame_count == 0 for report in reports)
