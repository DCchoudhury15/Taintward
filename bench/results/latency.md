# Latency benchmark

Machine: 12th Gen Intel(R) Core(TM) i5-1235U, 12 logical CPUs, 15.3 GB RAM, Linux 7.0.0-38-generic, Python 3.12.3.

Packages: presidio-analyzer 2.2.364, spacy 3.8.16, en-core-web-sm 3.8.0, opentelemetry-sdk 1.44.0, ff3 1.0.3

## Cold init (median of 3 fresh processes)

| step | seconds |
|---|---:|
| import sdk.detect | 0.96 |
| build Presidio analyzer (loads spaCy model) | 0.32 |
| first detect_text call | 0.14 |
| **total** | **1.43** |

## Warm, per call

| size | operation | n | p50 ms | p95 ms | p99 ms | calls/s | KB/s |
|---|---|---:|---:|---:|---:|---:|---:|
| 100B | detect_mapping | 400 | 8.182 | 9.180 | 9.944 | 118.8 | 9.0 |
| 100B | detect_text | 400 | 5.076 | 6.190 | 10.699 | 188.0 | 18.8 |
| 100B | redact_payload | 400 | 5.590 | 6.247 | 7.021 | 176.9 | 13.4 |
| 100B | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 11515401.8 | 875170.5 |
| 100B | tool_wrapped | 235 | 31.053 | 45.160 | 57.148 | 29.3 | 2.2 |
| 1KB | detect_mapping | 50 | 165.673 | 188.112 | 211.219 | 6.2 | 6.8 |
| 1KB | detect_text | 275 | 26.811 | 36.688 | 44.858 | 34.3 | 34.3 |
| 1KB | redact_payload | 78 | 100.705 | 112.272 | 121.760 | 9.7 | 10.8 |
| 1KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 10204017.8 | 11265235.7 |
| 1KB | tool_wrapped | 16 | 517.781 | 646.453 | 689.551 | 1.9 | 2.1 |
| 10KB | detect_mapping | 6 | 1353.818 | 1603.414 | 1623.767 | 0.7 | 7.4 |
| 10KB | detect_text | 21 | 418.640 | 471.528 | 477.222 | 2.5 | 25.0 |
| 10KB | redact_payload | 8 | 949.086 | 1233.053 | 1234.363 | 1.0 | 10.0 |
| 10KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 11490769.4 | 115666085.2 |
| 10KB | tool_wrapped | 3 | 4066.881 | 4165.702 | 4174.486 | 0.2 | 2.5 |
| 100KB | detect_mapping | 3 | 12165.580 | 12288.783 | 12299.734 | 0.1 | 8.3 |
| 100KB | detect_text | 3 | 13882.734 | 14048.458 | 14063.189 | 0.1 | 7.2 |
| 100KB | redact_payload | 3 | 10579.070 | 11754.972 | 11859.496 | 0.1 | 9.3 |
| 100KB | tool_unwrapped | 100000 | 0.000 | 0.000 | 0.000 | 11501962.4 | 1151645487.9 |
| 100KB | tool_wrapped | 3 | 43938.391 | 46898.943 | 47162.103 | 0.0 | 2.3 |

## Overhead of wrapping a tool with instrument_tool (p50)

| size | payload bytes | leaf values | wrapped p50 ms | unwrapped p50 ms | overhead ms |
|---|---:|---:|---:|---:|---:|
| 100B | 76 | 3 | 31.053 | 0.0001 | 31.053 |
| 1KB | 1104 | 44 | 517.781 | 0.0001 | 517.781 |
| 10KB | 10066 | 400 | 4066.881 | 0.0001 | 4066.881 |
| 100KB | 100126 | 3997 | 43938.391 | 0.0001 | 43938.391 |
