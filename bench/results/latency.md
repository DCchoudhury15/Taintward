# Latency benchmark

Machine: 12th Gen Intel(R) Core(TM) i5-1235U, 12 logical CPUs, 15.3 GB RAM, Linux 7.0.0-38-generic, Python 3.12.3.

Packages: presidio-analyzer 2.2.364, spacy 3.8.16, en-core-web-sm 3.8.0, opentelemetry-sdk 1.44.0, ff3 1.0.3

## Cold init (median of 3 fresh processes)

| step | seconds |
|---|---:|
| import taintward.sdk.detect | 0.66 |
| build Presidio analyzer (loads spaCy model) | 0.26 |
| first detect_text call | 0.02 |
| **total** | **0.94** |

## Warm, per call

| size | operation | n | p50 ms | p95 ms | p99 ms | calls/s | KB/s |
|---|---|---:|---:|---:|---:|---:|---:|
| 100B | detect_mapping | 400 | 3.356 | 5.514 | 6.544 | 275.6 | 20.9 |
| 100B | detect_text | 400 | 5.615 | 7.801 | 9.221 | 170.8 | 17.1 |
| 100B | redact_payload | 400 | 2.562 | 3.066 | 4.086 | 375.8 | 28.6 |
| 100B | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 10930292.2 | 830702.2 |
| 100B | tool_wrapped | 400 | 2.834 | 4.050 | 5.756 | 329.8 | 25.1 |
| 100B | tool_wrapped_cached | 400 | 0.164 | 0.243 | 0.285 | 5701.6 | 433.3 |
| 1KB | detect_mapping | 400 | 5.556 | 6.294 | 8.823 | 176.9 | 195.3 |
| 1KB | detect_text | 400 | 15.175 | 18.766 | 28.141 | 63.8 | 63.8 |
| 1KB | redact_payload | 271 | 29.797 | 39.303 | 48.076 | 33.8 | 37.3 |
| 1KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 9644937.8 | 10648011.3 |
| 1KB | tool_wrapped | 400 | 8.377 | 9.710 | 11.644 | 119.6 | 132.0 |
| 1KB | tool_wrapped_cached | 400 | 0.813 | 1.181 | 1.453 | 1168.4 | 1289.9 |
| 10KB | detect_mapping | 245 | 32.038 | 40.758 | 46.732 | 30.6 | 308.5 |
| 10KB | detect_text | 59 | 128.171 | 176.979 | 181.786 | 7.3 | 73.0 |
| 10KB | redact_payload | 48 | 163.981 | 204.903 | 208.633 | 6.0 | 60.3 |
| 10KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 7417766.5 | 74667237.8 |
| 10KB | tool_wrapped | 197 | 38.339 | 50.615 | 61.006 | 24.6 | 248.0 |
| 10KB | tool_wrapped_cached | 400 | 4.298 | 5.381 | 6.127 | 217.7 | 2191.9 |
| 100KB | detect_mapping | 19 | 404.825 | 591.226 | 601.963 | 2.3 | 234.3 |
| 100KB | detect_text | 5 | 1628.898 | 1783.633 | 1805.344 | 0.6 | 61.7 |
| 100KB | redact_payload | 22 | 395.964 | 438.835 | 452.559 | 2.6 | 264.1 |
| 100KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 7178410.9 | 718745570.2 |
| 100KB | tool_wrapped | 23 | 354.758 | 411.102 | 432.235 | 2.8 | 281.4 |
| 100KB | tool_wrapped_cached | 146 | 50.547 | 91.804 | 98.265 | 18.1 | 1814.9 |

## Overhead of wrapping a tool with instrument_tool (p50)

| size | payload bytes | leaf values | wrapped p50 ms | unwrapped p50 ms | overhead ms |
|---|---:|---:|---:|---:|---:|
| 100B | 76 | 3 | 2.834 | 0.0001 | 2.834 |
| 1KB | 1104 | 44 | 8.377 | 0.0001 | 8.377 |
| 10KB | 10066 | 400 | 38.339 | 0.0001 | 38.339 |
| 100KB | 100126 | 3997 | 354.758 | 0.0001 | 354.757 |
