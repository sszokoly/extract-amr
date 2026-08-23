# Performance verification

Install the development and optional performance dependencies, then run:

```console
uv run python -m benchmarks.task_9_4 \
  --output benchmarks/results/task-9.4-python3.8-linux-x86_64.json
```

The benchmark uses fresh subprocesses to compare bandwidth-efficient payload
throughput with `bitarray` and the bundled pure-Python backend. It records both
rates and byte parity but does not require acceleration to exceed a timing
threshold, because scheduler and platform noise would make that gate flaky.

Streaming memory is measured in separate processes while explicitly extracting
1,000, 5,000, and 20,000 packets to a byte-counting, non-retaining sink. The
result validates actual extraction counters and storage byte counts. It fails
if the 20x packet increase causes more than 3x traced peak memory, 8 MiB
additional peak memory, 1 MiB additional pre-collection memory, 512 KiB
additional retained memory, or 16 MiB additional Linux `VmHWM`. Successive
growth from the second to third workload is also bounded relative to growth
from the first to second workload, preventing small per-packet retention from
hiding under a fixed interpreter baseline.

Run the recorded-result assertions with:

```console
uv run pytest -m performance tests/test_performance.py
```
