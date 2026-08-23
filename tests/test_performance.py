"""Assertions over the recorded repeatable performance benchmark."""

import hashlib
import json
import math
import statistics
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
EXPECTED_THRESHOLDS = {
    "peak_ratio": 3.0,
    "peak_delta_bytes": 8 * 1024 * 1024,
    "current_delta_bytes": 1024 * 1024,
    "retained_delta_bytes": 512 * 1024,
    "successive_growth_factor": 2.0,
    "successive_growth_floor_bytes": 64 * 1024,
    "vm_hwm_delta_kib": 16 * 1024,
}
PACKET_COUNTS = {"small": 1000, "medium": 5000, "large": 20000}
EXPECTED_PAYLOAD_SHA256 = "47a39297b321bcb6a73a82a33f9c1f5f9bea0d32f370da836bcc87af8d0b39aa"
EXPECTED_OUTPUT_SHA256 = "96c602fb09a6e20fa952db37db83ee53b0018104bc6ef0f86549a9737bf34b4d"


def _source_sha256() -> str:
    digest = hashlib.sha256()
    paths = sorted((PROJECT_ROOT / "extract_amr").glob("*.py"))
    paths.extend(
        (
            PROJECT_ROOT / "pyproject.toml",
            PROJECT_ROOT / "benchmarks" / "task_9_4.py",
        ),
    )
    for path in paths:
        digest.update(str(path.relative_to(PROJECT_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _assert_extraction(measurement: dict, packet_count: int) -> None:
    extraction = measurement["extraction"]
    assert measurement["requested_packet_count"] == packet_count
    assert extraction == {
        "capture_pass_count": 1,
        "capture_packet_count": packet_count,
        "selected_rtp_packet_count": packet_count,
        "emitted_frame_count": packet_count,
        "malformed_packet_count": 0,
        "duplicate_packet_count": 0,
        "gap_count": 0,
        "reordered_packet_count": 0,
        "late_packet_count": 0,
        "packet_history_overflow_count": 0,
        "output_bytes": 6 + packet_count * 14,
    }


def _assert_successive_growth(memory: dict, field: str) -> None:
    small = memory["small"][field]
    medium = memory["medium"][field]
    large = memory["large"][field]
    first_delta = max(medium - small, 0)
    second_delta = max(large - medium, 0)
    allowed = max(
        EXPECTED_THRESHOLDS["successive_growth_floor_bytes"],
        first_delta * EXPECTED_THRESHOLDS["successive_growth_factor"],
    )
    recorded = memory["successive_growth"][field]
    assert recorded["first_delta_bytes"] == first_delta
    assert recorded["second_delta_bytes"] == second_delta
    assert recorded["allowed_second_delta_bytes"] == allowed
    assert second_delta <= allowed
    assert recorded["passed"] is True


@pytest.mark.performance
def test_recorded_backend_and_memory_benchmark_passes() -> None:
    result_path = PROJECT_ROOT / "benchmarks" / "results" / "task-9.4-python3.8-linux-x86_64.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    throughput = result["throughput"]
    memory = result["memory"]

    assert result["schema_version"] == 2
    assert result["source_sha256"] == _source_sha256()
    assert result["environment"]["python"].startswith("3.8.")
    assert result["environment"]["scapy"] == "2.5.0"
    assert result["environment"]["bitarray"] == "3.10.1"
    assert throughput["accelerated"]["backend"] == "bitarray"
    assert throughput["pure_python"]["backend"] == "python"
    assert throughput["parity"] is True
    assert throughput["accelerated"]["payload_sha256"] == EXPECTED_PAYLOAD_SHA256
    assert throughput["accelerated"]["output_sha256"] == EXPECTED_OUTPUT_SHA256
    assert (
        throughput["accelerated"]["payload_sha256"] == (throughput["pure_python"]["payload_sha256"])
    )
    assert (
        throughput["accelerated"]["output_sha256"] == (throughput["pure_python"]["output_sha256"])
    )
    for backend in (throughput["accelerated"], throughput["pure_python"]):
        assert len(backend["samples"]) == 5
        assert backend["iterations_per_sample"] == 3000
        assert backend["total_frames"] == 5 * 3000 * 4
        expected_rate = 3000 / statistics.median(backend["samples"])
        assert math.isclose(backend["median_payloads_per_second"], expected_rate)
    expected_ratio = (
        throughput["accelerated"]["median_payloads_per_second"]
        / throughput["pure_python"]["median_payloads_per_second"]
    )
    assert math.isclose(throughput["accelerated_to_python_ratio"], expected_ratio)
    assert math.isfinite(expected_ratio)

    assert memory["thresholds"] == EXPECTED_THRESHOLDS
    for name, packet_count in PACKET_COUNTS.items():
        _assert_extraction(memory[name], packet_count)
    peak_ratio = memory["large"]["peak_bytes"] / memory["small"]["peak_bytes"]
    peak_delta = memory["large"]["peak_bytes"] - memory["small"]["peak_bytes"]
    current_delta = (
        memory["large"]["current_bytes_before_collection"]
        - memory["small"]["current_bytes_before_collection"]
    )
    retained_delta = memory["large"]["retained_bytes"] - memory["small"]["retained_bytes"]
    assert math.isclose(memory["peak_ratio"], peak_ratio)
    assert memory["peak_delta_bytes"] == peak_delta
    assert memory["current_delta_bytes"] == current_delta
    assert memory["retained_delta_bytes"] == retained_delta
    assert peak_ratio <= EXPECTED_THRESHOLDS["peak_ratio"]
    assert peak_delta <= EXPECTED_THRESHOLDS["peak_delta_bytes"]
    assert current_delta <= EXPECTED_THRESHOLDS["current_delta_bytes"]
    assert retained_delta <= EXPECTED_THRESHOLDS["retained_delta_bytes"]
    for field in (
        "peak_bytes",
        "retained_bytes",
    ):
        _assert_successive_growth(memory, field)
    if memory["vm_hwm_delta_kib"] is not None:
        vm_delta = memory["large"]["vm_hwm_kib"] - memory["small"]["vm_hwm_kib"]
        assert memory["vm_hwm_delta_kib"] == vm_delta
        assert vm_delta <= EXPECTED_THRESHOLDS["vm_hwm_delta_kib"]
    assert memory["passed"] is True
    assert result["passed"] is True
