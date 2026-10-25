# SDK throughput (current)

2026-10-25 13:10:26, Python 3.12.3, 12 CPUs, 10 s per point, exporter: in-memory (dropped).

| payload | mode | workers | wrapped calls/s |
|---|---|---|---|
| clean | threads | 1 | 40 |
| clean | threads | 2 | 35 |
| clean | threads | 4 | 23 |
| clean | threads | 8 | 21 |
| clean | processes | 2 | 38 |
| clean | processes | 4 | 66 |
| leak | threads | 1 | 20 |
| leak | threads | 2 | 18 |
| leak | threads | 4 | 13 |
| leak | threads | 8 | 11 |
| leak | processes | 2 | 25 |
| leak | processes | 4 | 36 |
