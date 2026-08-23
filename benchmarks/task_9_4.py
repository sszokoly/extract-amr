"""Compare bit backends and verify bounded streaming extraction memory."""

from __future__ import annotations

import argparse
import gc
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import statistics
import struct
import subprocess
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path
from typing import Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MEMORY_PAYLOAD = bytes.fromhex("f09555555555555555555555555500")
BASE_FRAME = bytes.fromhex(
    "02000000001402000000000a080045000037000300004011262ec633640ac6336414"
    "17701b580023000080620064000003e801020304"
    "f09555555555555555555555555500"
)
SMALL_PACKETS = 1000
MEDIUM_PACKETS = 5000
LARGE_PACKETS = 20000
THROUGHPUT_SAMPLES = 5
THROUGHPUT_ITERATIONS = 3000
THRESHOLDS = {
    "peak_ratio": 3.0,
    "peak_delta_bytes": 8 * 1024 * 1024,
    "current_delta_bytes": 1024 * 1024,
    "retained_delta_bytes": 512 * 1024,
    "successive_growth_factor": 2.0,
    "successive_growth_floor_bytes": 64 * 1024,
    "vm_hwm_delta_kib": 16 * 1024,
}


def _pack_bits(value: str) -> bytes:
    padded = value + "0" * ((-len(value)) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, "big")


def _throughput_payload() -> bytes:
    toc = "".join(("1" if index < 3 else "0") + "10001" for index in range(4))
    speech = "10" * (477 * 4 // 2)
    return _pack_bits("1111" + toc + speech)


THROUGHPUT_PAYLOAD = _throughput_payload()


class _NullWriter:
    def __init__(self) -> None:
        self.bytes_written = 0

    def write(self, data) -> int:
        length = len(data)
        self.bytes_written += length
        return length


def _throughput_worker() -> None:
    from extract_amr.bits import BIT_BACKEND
    from extract_amr.models import Codec, PayloadMode
    from extract_amr.rfc4867 import depacketize
    from extract_amr.storage import storage_bytes

    expected = storage_bytes(
        Codec.AMR_WB,
        depacketize(
            THROUGHPUT_PAYLOAD,
            Codec.AMR_WB,
            PayloadMode.BANDWIDTH_EFFICIENT,
        ),
    )
    for _ in range(500):
        depacketize(
            THROUGHPUT_PAYLOAD,
            Codec.AMR_WB,
            PayloadMode.BANDWIDTH_EFFICIENT,
        )
    durations = []
    frame_count = 0
    for _ in range(THROUGHPUT_SAMPLES):
        started = time.perf_counter()
        for _ in range(THROUGHPUT_ITERATIONS):
            frame_count += len(
                depacketize(
                    THROUGHPUT_PAYLOAD,
                    Codec.AMR_WB,
                    PayloadMode.BANDWIDTH_EFFICIENT,
                ),
            )
        durations.append(time.perf_counter() - started)
    median = statistics.median(durations)
    print(
        json.dumps(
            {
                "backend": BIT_BACKEND.name,
                "fallback_reason": BIT_BACKEND.fallback_reason,
                "payload_sha256": hashlib.sha256(THROUGHPUT_PAYLOAD).hexdigest(),
                "output_sha256": hashlib.sha256(expected).hexdigest(),
                "samples": durations,
                "iterations_per_sample": THROUGHPUT_ITERATIONS,
                "total_frames": frame_count,
                "median_payloads_per_second": THROUGHPUT_ITERATIONS / median,
            },
            sort_keys=True,
        ),
    )


def _vm_hwm_kib() -> Optional[int]:
    status = Path("/proc/self/status")
    if not status.is_file():
        return None
    for line in status.read_text(encoding="ascii").splitlines():
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return None


def _memory_worker(capture: Path, packet_count: int) -> None:
    from extract_amr import api
    from extract_amr.bits import BIT_BACKEND
    from extract_amr.models import Codec, FlowSelector, PayloadMode, ResourceLimits

    selector = FlowSelector(
        src_address="198.51.100.10",
        dst_address="198.51.100.20",
        src_port=6000,
        dst_port=7000,
        ssrc=0x01020304,
        payload_type=98,
    )
    sink = _NullWriter()
    gc.collect()
    tracemalloc.start()
    report = api.extract_pcap(
        capture,
        sink,
        selector=selector,
        codec=Codec.AMR,
        payload_mode=PayloadMode.BANDWIDTH_EFFICIENT,
        limits=ResourceLimits(),
    )
    current, peak = tracemalloc.get_traced_memory()
    expected_output_bytes = 6 + packet_count * 14
    observed = {
        "capture_pass_count": report.capture_pass_count,
        "capture_packet_count": report.capture_packet_count,
        "selected_rtp_packet_count": report.selected_rtp_packet_count,
        "emitted_frame_count": report.emitted_frame_count,
        "malformed_packet_count": report.malformed_packet_count,
        "duplicate_packet_count": report.duplicate_packet_count,
        "gap_count": report.gap_count,
        "reordered_packet_count": report.reordered_packet_count,
        "late_packet_count": report.late_packet_count,
        "packet_history_overflow_count": report.packet_history_overflow_count,
        "output_bytes": sink.bytes_written,
    }
    expected = {
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
        "output_bytes": expected_output_bytes,
    }
    if observed != expected:
        raise RuntimeError(f"memory fixture extraction mismatch: {observed!r}")
    del report
    gc.collect()
    retained, measured_peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print(
        json.dumps(
            {
                "backend": BIT_BACKEND.name,
                "requested_packet_count": packet_count,
                "extraction": observed,
                "current_bytes_before_collection": current,
                "retained_bytes": retained,
                "peak_bytes": max(peak, measured_peak),
                "vm_hwm_kib": _vm_hwm_kib(),
            },
            sort_keys=True,
        ),
    )


def _write_capture(path: Path, packet_count: int) -> None:
    from scapy.utils import RawPcapWriter

    writer = RawPcapWriter(str(path), linktype=1, sync=True)
    try:
        for index in range(packet_count):
            frame = bytearray(BASE_FRAME)
            struct.pack_into("!H", frame, 44, index & 0xFFFF)
            struct.pack_into("!I", frame, 46, index * 160)
            writer.write(bytes(frame))
    finally:
        writer.close()


def _run_worker(arguments, environment: Optional[Dict[str, str]] = None) -> dict:
    result = subprocess.run(
        [sys.executable, "-m", "benchmarks.task_9_4", *arguments],
        cwd=str(PROJECT_ROOT),
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=180,
    )
    return json.loads(result.stdout)


def _python_backend_environment(shadow: Path) -> Dict[str, str]:
    shadow.mkdir()
    (shadow / "bitarray.py").write_text(
        'raise ImportError("benchmark forced pure-Python backend")\n',
        encoding="ascii",
    )
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = str(shadow) + (os.pathsep + existing if existing else "")
    return environment


def _package_version(distribution: str) -> Optional[str]:
    try:
        return importlib.metadata.version(distribution)
    except importlib.metadata.PackageNotFoundError:
        return None


def _source_sha256() -> str:
    digest = hashlib.sha256()
    paths = sorted((PROJECT_ROOT / "extract_amr").glob("*.py"))
    paths.extend((PROJECT_ROOT / "pyproject.toml", Path(__file__)))
    for path in paths:
        digest.update(str(path.relative_to(PROJECT_ROOT)).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _successive_growth(small: dict, medium: dict, large: dict, field: str) -> dict:
    first_delta = max(medium[field] - small[field], 0)
    second_delta = max(large[field] - medium[field], 0)
    allowed = max(
        THRESHOLDS["successive_growth_floor_bytes"],
        first_delta * THRESHOLDS["successive_growth_factor"],
    )
    return {
        "first_delta_bytes": first_delta,
        "second_delta_bytes": second_delta,
        "allowed_second_delta_bytes": allowed,
        "passed": second_delta <= allowed,
    }


def _evaluate_memory(small: dict, medium: dict, large: dict) -> dict:
    peak_ratio = large["peak_bytes"] / max(small["peak_bytes"], 1)
    peak_delta = large["peak_bytes"] - small["peak_bytes"]
    current_delta = (
        large["current_bytes_before_collection"] - small["current_bytes_before_collection"]
    )
    retained_delta = large["retained_bytes"] - small["retained_bytes"]
    growth = {
        field: _successive_growth(small, medium, large, field)
        for field in (
            "peak_bytes",
            "retained_bytes",
        )
    }
    vm_delta = None
    if small["vm_hwm_kib"] is not None and large["vm_hwm_kib"] is not None:
        vm_delta = large["vm_hwm_kib"] - small["vm_hwm_kib"]
    passed = (
        peak_ratio <= THRESHOLDS["peak_ratio"]
        and peak_delta <= THRESHOLDS["peak_delta_bytes"]
        and current_delta <= THRESHOLDS["current_delta_bytes"]
        and retained_delta <= THRESHOLDS["retained_delta_bytes"]
        and all(item["passed"] for item in growth.values())
        and (vm_delta is None or vm_delta <= THRESHOLDS["vm_hwm_delta_kib"])
    )
    return {
        "small": small,
        "medium": medium,
        "large": large,
        "peak_ratio": peak_ratio,
        "peak_delta_bytes": peak_delta,
        "current_delta_bytes": current_delta,
        "retained_delta_bytes": retained_delta,
        "successive_growth": growth,
        "vm_hwm_delta_kib": vm_delta,
        "thresholds": THRESHOLDS,
        "passed": passed,
    }


def run_benchmark(output: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="extract-amr-benchmark-") as temporary:
        temporary_path = Path(temporary)
        pure_environment = _python_backend_environment(temporary_path / "backend-shadow")
        accelerated = _run_worker(["--throughput-worker"])
        pure_python = _run_worker(
            ["--throughput-worker"],
            environment=pure_environment,
        )
        if accelerated["backend"] != "bitarray":
            raise RuntimeError("install the performance extra to benchmark bitarray")
        if pure_python["backend"] != "python":
            raise RuntimeError("pure-Python benchmark worker did not select its backend")
        if accelerated["output_sha256"] != pure_python["output_sha256"]:
            raise RuntimeError("bit backends produced different storage bytes")

        small_capture = temporary_path / "small.pcap"
        medium_capture = temporary_path / "medium.pcap"
        large_capture = temporary_path / "large.pcap"
        _write_capture(small_capture, SMALL_PACKETS)
        _write_capture(medium_capture, MEDIUM_PACKETS)
        _write_capture(large_capture, LARGE_PACKETS)
        small_memory = _run_worker(
            ["--memory-worker", str(small_capture), str(SMALL_PACKETS)],
        )
        medium_memory = _run_worker(
            ["--memory-worker", str(medium_capture), str(MEDIUM_PACKETS)],
        )
        large_memory = _run_worker(
            ["--memory-worker", str(large_capture), str(LARGE_PACKETS)],
        )

    memory = _evaluate_memory(small_memory, medium_memory, large_memory)
    throughput = {
        "accelerated": accelerated,
        "pure_python": pure_python,
        "accelerated_to_python_ratio": (
            accelerated["median_payloads_per_second"] / pure_python["median_payloads_per_second"]
        ),
        "parity": accelerated["output_sha256"] == pure_python["output_sha256"],
    }
    result = {
        "schema_version": 2,
        "source_sha256": _source_sha256(),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "extract_amr": _package_version("extract-amr"),
            "scapy": _package_version("scapy"),
            "bitarray": _package_version("bitarray"),
        },
        "throughput": throughput,
        "memory": memory,
        "passed": throughput["parity"] and memory["passed"],
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--throughput-worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--memory-worker", nargs=2, metavar=("CAPTURE", "PACKETS"))
    arguments = parser.parse_args()
    if arguments.throughput_worker:
        _throughput_worker()
        return
    if arguments.memory_worker:
        _memory_worker(
            Path(arguments.memory_worker[0]),
            int(arguments.memory_worker[1]),
        )
        return
    if arguments.output is None:
        parser.error("--output is required")
    result = run_benchmark(arguments.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["passed"] or not math.isfinite(
        result["throughput"]["accelerated_to_python_ratio"],
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
