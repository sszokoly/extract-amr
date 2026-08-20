# extract-amr

`extract-amr` streams PCAP and PCAPNG files, identifies RTP-carried AMR or
AMR-WB media, and writes RFC 4867 single-channel storage streams. The package
provides a Click command-line interface and a reusable Python API.

## Installation

The base package requires Python 3.8 or later, Click, and Scapy:

```console
python -m pip install .
```

Install the optional bit-processing accelerator with:

```console
python -m pip install '.[performance]'
```

At import time, the package tries to initialize `bitarray`. If import or
initialization raises an ordinary exception, extraction continues with the
bundled pure-Python backend. The selected backend and a sanitized fallback
reason are available in extraction reports and CLI output. Both backends have
the same codec behavior; acceleration primarily affects bandwidth-efficient
payloads because octet-aligned payloads use direct byte operations.

## Supported Formats

The parser supports:

- Saved PCAP and PCAPNG captures readable by Scapy.
- Complete, non-fragmented IPv4 and IPv6 UDP datagrams.
- RTP version 2, including CSRC lists, header extensions, and padding.
- AMR-NB and AMR-WB.
- RFC 4867 octet-aligned and bandwidth-efficient payloads.
- Single-channel compound payloads without CRC, interleaving, or robust
  sorting.
- AMR speech frame types 0-7, SID type 8, and NO_DATA type 15.
- AMR-WB speech frame types 0-8, SID type 9, SPEECH_LOST type 14, and NO_DATA
  type 15.

Structurally valid RTCP and unrelated UDP traffic are excluded. A frame with
`Q=0` is valid media: it is preserved and counted as bad quality.

The following are explicit non-goals for this release:

- EVS, Iu-UP, multichannel RFC 4867, frame CRC, interleaving, and robust
  sorting.
- SIP/SDP parsing or dynamic-payload signaling interpretation.
- IP fragment reassembly, arbitrary tunnels, and live capture.
- AMR decoding, PCM/WAV output, resampling, and 3GPP multimedia containers.

The output is an AMR codec storage stream, not a `.3ga` container:

- AMR uses `.amr` and starts with `#!AMR\n`.
- AMR-WB uses `.awb` and starts with `#!AMR-WB\n`.

## Command Line

Inspect a capture:

```console
extract-amr inspect call.pcapng
```

Inspect only a directional UDP port pair:

```console
extract-amr inspect call.pcapng \
  --src-port 4000 \
  --dst-port 5000
```

Extract one automatically selected flow:

```console
extract-amr extract call.pcapng --output call.amr
```

Use a complete selection for deterministic one-pass extraction:

```console
extract-amr extract call.pcapng --output call.awb \
  --src-address 192.0.2.1 \
  --dst-address 192.0.2.2 \
  --src-port 4000 \
  --dst-port 5000 \
  --ssrc 42 \
  --payload-type 96 \
  --codec amr-wb \
  --mode octet-aligned
```

Extract every independently resolved flow matching a directional port filter:

```console
extract-amr extract call.pcapng \
  --src-port 4000 \
  --dst-port 5000 \
  --output-dir extracted
```

The module entry point is equivalent:

```console
python -m extract_amr inspect call.pcapng
```

### Options

Both commands accept:

```text
--src-address TEXT
--dst-address TEXT
--src-port INTEGER               1..65535
--dst-port INTEGER               1..65535
--ssrc INTEGER                   0..4294967295
--payload-type INTEGER           0..127
--codec [amr|amr-wb]
--mode [octet-aligned|bandwidth-efficient]
--max-candidates INTEGER         default: 1024
--max-samples-per-flow INTEGER   default: 64
--max-diagnostics INTEGER        1..100; default: 1
--reorder-window INTEGER         default: 64
--progress                       show byte progress and disable diagnostics
```

Extraction also accepts:

```text
-o, --output PATH
--output-dir DIRECTORY
--gap-policy [omit|no-data]         default: omit
--malformed-policy [skip|strict]    default: skip
```

Exactly one of `--output` and `--output-dir` is required. Automatic
single-flow extraction and a complete selector use `--output`. An incomplete
selector containing a source or destination port is an intentional multi-flow
filter and requires `--output-dir`, even if other fields narrow the result to
one flow.

The CLI stages output in the destination directory, flushes it, and replaces
final paths only after successful extraction. It removes staged files on
ordinary extraction failure and restores existing outputs when commit rollback
succeeds. If the filesystem also refuses restoration, the CLI reports that
failure and retains the original bytes in a hidden `.backup` file. Input and
output cannot refer to the same file, including through a hard link. A caller
using the stream-based Python API owns its own transaction behavior.

### Processing Progress

Enable progress during inspection or extraction with:

```console
extract-amr inspect call.pcapng --progress
extract-amr extract call.pcapng --output call.amr --progress
```

Progress is measured from bytes consumed in the capture container, not from a
packet pre-count. Inspection and completely explicit extraction therefore keep
one capture pass. Automatic and port-filtered extraction show one aggregate bar
covering their discovery and extraction passes, without adding a third pass.
Headers, PCAPNG metadata, filtered packets, and non-media packets all contribute
to completion.

The bar is written only to standard error when standard error is an interactive
terminal. If it is redirected, progress is silent and the normal report remains
on standard output. Exact progress requires an uncompressed regular file;
compressed captures, streams, FIFOs, devices, changing files, and inputs without
reliable byte positions are rejected before output staging. A failed operation
closes a partial bar without forcing it to 100 percent.

`--progress` cannot be combined with an explicitly supplied
`--max-diagnostics`, including `--max-diagnostics 1`. Progress mode retains no
individual diagnostics and displays neither diagnostic messages nor an omitted
diagnostic summary. Aggregate statistics such as malformed packet counts remain
in the final report. Without progress, the CLI continues to retain one
diagnostic by default.

### Multi-Flow Names

Port-filtered output names contain every directional flow field and a short
identity digest:

```text
src-{source-address}-{source-port}__dst-{destination-address}-{destination-port}__
pt-{payload-type}__ssrc-{eight-digit-hex}__{sha256-prefix}.{amr|awb}
```

The actual filename is one line. Runs of address characters other than ASCII
letters, digits, `.`, and `-` are replaced with `-`; leading and trailing `.`
or `-` are removed, and an empty result becomes `address`. The 12-character
digest is derived from the unsanitized source address and port, destination
address and port, payload type, and SSRC, preventing sanitized address
collisions.

## Selection Rules

A flow is directional and is identified by:

```text
(source address, destination address, source port, destination port,
 SSRC, RTP payload type)
```

Every supplied selector field is authoritative. The parser never substitutes
a different captured value.

1. A complete six-field flow selector with explicit codec and payload mode
   performs one streaming capture pass.
2. Any incomplete flow, codec, or mode selection performs one bounded
   discovery pass followed by at most one extraction pass. The input must be a
   reopenable path.
3. Discovery validates retained payloads against all supported codec/mode
   combinations. Payload length alone is not evidence.
4. Without a port filter, exactly one compatible flow and format must remain.
5. A directional port filter intentionally selects every matching full flow;
   codec and mode must resolve independently for each one.
6. Ambiguity fails with complete candidate selectors instead of guessing.
7. Exceeding the candidate limit prevents selection. Samples and diagnostics
   beyond their bounds are counted in the report.

For `inspect`, CLI `--codec` and `--mode` filter the displayed format list. The
Python `inspect_pcap` operation still returns complete retained evidence.

## Policies and Timeline

Each full flow has independent sequence, timestamp, duplicate, reordering,
gap, diagnostic, and statistics state. Frames are separated by 20 ms in the
media clock: 160 ticks for AMR and 320 ticks for AMR-WB.

Within the bounded reordering window, output is committed in media-time order.
Duplicate RTP packets are omitted. If multiple frames overlap one timestamp,
selection prefers good quality, then greater encoded bit length, then earliest
capture provenance. Frames arriving after their timestamp was committed are
reported and omitted.

Gap policies:

- `omit`: count inferred missing 20 ms intervals and emit nothing.
- `no-data`: insert codec-appropriate FT 15 entries for missing intervals.

No synthetic interval is inserted before the first observed frame.

Malformed-input policies:

- `skip`: record a bounded diagnostic, omit the complete invalid payload, and
  continue.
- `strict`: raise at an attributable malformed selected-flow RTP or RFC 4867
  payload.

Payload validation is atomic. A malformed later frame in a compound payload
cannot cause earlier frames from that payload to be serialized. Valid `Q=0`
frames are unaffected by the malformed-input policy.

## Python API

The high-level API is exported from `extract_amr`:

```python
from extract_amr import (
    Codec,
    FlowSelector,
    GapPolicy,
    MalformedPolicy,
    PayloadMode,
    ResourceLimits,
    extract_flows,
    extract_pcap,
    inspect_pcap,
    iter_frames,
    select_candidates,
)
```

### Inspection

```python
report = inspect_pcap(
    "call.pcapng",
    selector=FlowSelector(dst_port=5000),
    limits=ResourceLimits(max_candidates=128),
)
```

`inspect_pcap` performs one bounded-memory pass and returns an immutable
`InspectionReport` containing deterministic candidates, exact format evidence,
packet counts, diagnostics, and overflow counts. Paths and caller-owned binary
capture streams are accepted; caller-owned streams remain open.

### Single-Flow Extraction

```python
with open("call.amr", "wb") as output:
    report = extract_pcap(
        "call.pcapng",
        output,
        selector=FlowSelector(
            src_address="192.0.2.1",
            dst_address="192.0.2.2",
            src_port=4000,
            dst_port=5000,
            ssrc=42,
            payload_type=96,
        ),
        codec=Codec.AMR,
        payload_mode=PayloadMode.OCTET_ALIGNED,
    )
```

The output must be a caller-owned writable binary stream, not a path. The API
does not close capture or output streams and retries legal short writes. Stream
output is not transactional: a header and earlier valid frames may already be
present if a later packet fails under `strict` policy.

### Multi-Flow Extraction

`extract_flows` accepts either a mapping from `FlowKey` to distinct writable
binary streams or a factory called once for each resolved `SelectedFlow`:

```python
from contextlib import ExitStack


with ExitStack() as stack:

    def output_for(selection):
        extension = "amr" if selection.codec is Codec.AMR else "awb"
        return stack.enter_context(
            open(f"{selection.candidate_id}.{extension}", "wb"),
        )


    reports = extract_flows(
        "call.pcapng",
        output_for,
        selector=FlowSelector(src_port=4000, dst_port=5000),
    )
```

Every selected flow requires an independent stream. Reports are returned in
deterministic candidate order. Stream ownership, naming, and transactions
belong to the caller.

### Encoded Frames

`iter_frames(source, selection, ...)` streams ordered immutable `EncodedFrame`
records without requiring an AMR storage writer. Each record contains codec,
frame type, quality, exact bit length, MSB-first packed data, extended media
timestamp, and capture provenance.

Resolve a `SelectedFlow` through inspection before consuming frames:

```python
inspection = inspect_pcap("call.pcapng")
selection = select_candidates(inspection.discovery)[0]

for frame in iter_frames("call.pcapng", selection):
    consume(frame)
```

`depacketize(payload, codec, mode, ...)` is the lower-level payload boundary.
It validates one complete RFC 4867 payload atomically and returns its encoded
frames. Optional `Rfc4867Options` explicitly reject multichannel, CRC,
interleaving, and robust sorting configurations.

Reports identify the selected flow and format, bit backend and fallback reason,
capture passes and packet counts, emitted and bad-quality frames, duplicates,
gaps, inserted NO_DATA entries, reordered and late packets, overlaps,
malformed packets, bounded diagnostics, and overflow counters.

Structured exceptions under `extract_amr.errors` provide a stable `code`,
message, capture provenance, and details mapping.

## Playback and Conversion

Use an FFmpeg build containing the corresponding AMR decoder:

```console
ffplay -f amr extracted.amr
ffplay -f amr extracted.awb
```

Convert to mono PCM WAV:

```console
ffmpeg -f amr -i extracted.amr -c:a pcm_s16le extracted.wav
ffmpeg -f amr -i extracted.awb -c:a pcm_s16le extracted.wav
```

AMR-NB decodes at its native 8 kHz rate and AMR-WB at its native 16 kHz rate.
Resampling either source to 48 kHz does not add source quality.

## Future Decoder Boundary

Normalized encoded frames deliberately separate capture and timeline handling
from storage writing:

```text
PCAP/PCAPNG -> UDP -> RTP -> RFC 4867 -> ordered EncodedFrame iterator
                                             |-> AMR/AMR-WB storage now
                                             |-> decoder -> PCM -> WAV later
```

A future WAV exporter can consume `iter_frames` without changing capture, RTP,
selection, or timeline code. It should default to 8 kHz for AMR-NB and 16 kHz
for AMR-WB. Decoder integration and resampling remain separate future work.

## Development and Verification

Install all development dependencies:

```console
uv sync --all-extras
```

Run the suite and style checks:

```console
uv run pytest
uv run ruff check extract_amr tests benchmarks scripts
uv run ruff format --check extract_amr tests benchmarks scripts
```

Regenerate the independent fixture files:

```console
uv run python tests/fixtures/generate_fixtures.py
```

Run the backend and bounded-memory benchmark:

```console
uv run python -m benchmarks.task_9_4 \
  --output benchmarks/results/task-9.4-python3.8-linux-x86_64.json
uv run pytest -m performance tests/test_performance.py
```

Verify an isolated base installation without `bitarray`:

```console
uv run python scripts/verify_base_install.py \
  --output verification/base-install-python3.8.json
```

Python code follows PEP 8 where practical. Prefer lines no longer than 80
characters; Ruff enforces a hard maximum of 100 characters.

## Disclaimer

`extract_amr` is an independent tool and is not affiliated with, developed by,
endorsed by, or supported by any vendor. It is provided "as is," without
warranties of any kind, express or implied. Users are responsible for evaluating
its suitability and assume all risks associated with its use.
