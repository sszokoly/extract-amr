"""Optional regression validation of known local captures."""

import hashlib
import io
import json
from collections import Counter
from pathlib import Path

import pytest

from extract_amr import api
from extract_amr.models import Codec, FlowKey, FlowSelector, PayloadMode, SelectedFlow

PROJECT_ROOT = Path(__file__).parent.parent
PRIVATE_CASES_PATH = Path(__file__).parent / "private" / "local_captures.json"


def _load_private_cases():
    if not PRIVATE_CASES_PATH.is_file():
        return ()
    document = json.loads(PRIVATE_CASES_PATH.read_text(encoding="utf-8"))
    return tuple(
        (
            case["name"],
            case["capture_sha256"],
            FlowKey(**case["flow_key"]),
            Codec(case["codec"]),
            case["frame_count"],
            {int(frame_type): count for frame_type, count in case["frame_types"].items()},
            case["gap_count"],
            case["output_size"],
            case["output_sha256"],
        )
        for case in document["cases"]
    )


LOCAL_CASES = _load_private_cases()


def _selector(key: FlowKey) -> FlowSelector:
    return FlowSelector(
        src_address=key.src_address,
        dst_address=key.dst_address,
        src_port=key.src_port,
        dst_port=key.dst_port,
        ssrc=key.ssrc,
        payload_type=key.payload_type,
    )


@pytest.mark.parametrize(
    ("name,capture_hash,flow_key,codec,frame_count,frame_types,gap_count,output_size,output_hash"),
    LOCAL_CASES,
)
def test_local_octet_aligned_capture_matches_known_reference(
    name: str,
    capture_hash: str,
    flow_key: FlowKey,
    codec: Codec,
    frame_count: int,
    frame_types: dict,
    gap_count: int,
    output_size: int,
    output_hash: str,
) -> None:
    capture = PROJECT_ROOT / "pcaps" / name
    if not capture.is_file():
        pytest.skip(f"optional local capture is unavailable: {capture}")
    assert hashlib.sha256(capture.read_bytes()).hexdigest() == capture_hash

    selection = SelectedFlow(
        candidate_id="known-local-reference",
        flow_key=flow_key,
        codec=codec,
        payload_mode=PayloadMode.OCTET_ALIGNED,
        first_packet_number=1,
    )
    observed_types = Counter(frame.frame_type for frame in api.iter_frames(capture, selection))
    output = io.BytesIO()
    report = api.extract_pcap(
        capture,
        output,
        selector=_selector(flow_key),
        codec=codec,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )
    output_bytes = output.getvalue()

    assert observed_types == frame_types
    assert report.capture_pass_count == 1
    assert report.capture_packet_count == frame_count
    assert report.selected_rtp_packet_count == frame_count
    assert report.emitted_frame_count == frame_count
    assert report.bad_quality_frame_count == 0
    assert report.malformed_packet_count == 0
    assert report.gap_count == gap_count
    assert len(output_bytes) == output_size
    assert hashlib.sha256(output_bytes).hexdigest() == output_hash
