# Collector throughput

Run: `IMAGE=taintward-collector:scale CPUS="1 2 4" DURATION=30 loadtest/collector/run.sh`
(4 telemetrygen v0.159.0 senders, 4 workers each, no rate limit). Raw rows:
[`collector-raw.tsv`](collector-raw.tsv).

Machine: 12th Gen Intel Core i5-1235U laptop (12 logical CPUs, 15 GB RAM),
Linux 7.0.0-38, Docker 29. The senders ran on the same machine, and other
work was running at the same time (load average 6 to 20), so treat the
numbers as rough. The collector container was limited with `--cpus`.

Pipeline: OTLP/gRPC receiver, memory_limiter, taint_policy (Rego), batch
(512), debug exporter at basic verbosity (a log line per batch, so the
backend is not what is measured).

| scenario | CPU limit | spans/s | CPU used (cores) | spans/s per used core | refused |
|---|---:|---:|---:|---:|---:|
| policy-violation | 1 | 3,931 | 0.99 | 3,970 | 0 |
| policy-violation | 2 | 6,794 | 1.74 | 3,900 | 0 |
| policy-violation | 4 | 9,211 | 2.48 | 3,710 | 0 |
| policy-clean | 1 | 17,282 | 0.99 | 17,460 | 0 |
| policy-clean | 2 | 25,299 | 1.45 | 17,450 | 0 |
| policy-clean | 4 | 30,212 | 1.88 | 16,070 | 0 |
| passthrough | 1 | 43,927 | 0.71 | about 62,000 | 0 |
| passthrough | 2 | 43,836 | 0.70 | about 62,000 | 0 |
| passthrough | 4 | 44,644 | 0.76 | about 59,000 | 0 |

What the scenarios are:

* **policy-violation**: every span is `taintward.sensitive=true`, destination
  `external`, jurisdiction `us`, and its result holds an SSN, an AWS key and
  an email. Rego fires both rules and the processor runs its redaction
  regexes over every string attribute. This is the worst case.
* **policy-clean**: spans are not sensitive and go to `internal`. Rego runs,
  nothing is redacted. Most spans of a normal agent look like this.
* **passthrough**: no taint_policy, same spans as policy-violation. The
  senders could not push more than about 44k spans/s, so the collector was
  never busy here: the per core figure is extrapolated from CPU use.

## What it says

* One core handles about **4k spans/s** when every span is a violation and
  about **17k spans/s** when spans are clean. A real mix sits in between.
* Throughput grows with cores: the processor has no lock, each request is
  handled in its own goroutine. Per core numbers stay flat from 1 to 4 CPUs.
  In the 2 and 4 CPU rows the collector did not use all of its CPUs because
  the senders, sharing the laptop, could not keep up.
* The Rego decision costs about 40 microseconds per span (17k/s vs about
  62k/s without it). Redaction and the fired rules on top cost about 195 microseconds per
  violating span: the Go side runs 5 regexes over every string attribute.
  That is the first thing to optimize if the policy tier ever needs fewer
  pods (one combined regex, or only scan the attributes that can carry
  payloads).
* No span was refused by memory_limiter in any run (1 GB container limit).

A single sender (one telemetrygen process, which only has one request in
flight) gave 3,881 / 4,600 / 4,641 spans/s for policy-violation at 1 / 2 / 4
CPUs: with one client the work is serial, so more CPUs do not help. Real
traffic from many agents is many parallel requests.
