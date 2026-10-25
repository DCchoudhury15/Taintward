# Gateway throughput (current)

2026-10-25 13:16:23, Python 3.12.3, 12 CPUs, 10 s per point. Upstream: taintward/gateway/examples/hr_server.py over stdio.

| mode | tool | gateway processes | concurrency | calls/s |
|---|---|---|---|---|
| stdio | clean | 1 | 1 | 22 |
| stdio | clean | 1 | 4 | 21 |
| stdio | sensitive | 1 | 1 | 28 |
| stdio | sensitive | 1 | 4 | 26 |
| http | clean | 1 | 1 | 25 |
| http | clean | 1 | 4 | 20 |
| http | clean | 1 | 8 | 17 |
| http | sensitive | 1 | 1 | 26 |
| http | sensitive | 1 | 4 | 25 |
| http | sensitive | 1 | 8 | 21 |
| http | clean | 2 | 1 | 25 |
| http | clean | 2 | 4 | 34 |
| http | clean | 2 | 8 | 28 |
| http | sensitive | 2 | 1 | 27 |
| http | sensitive | 2 | 4 | 39 |
| http | sensitive | 2 | 8 | 34 |
| http | clean | 4 | 1 | 24 |
| http | clean | 4 | 4 | 44 |
| http | clean | 4 | 8 | 40 |
| http | sensitive | 4 | 1 | 20 |
| http | sensitive | 4 | 4 | 44 |
| http | sensitive | 4 | 8 | 40 |
