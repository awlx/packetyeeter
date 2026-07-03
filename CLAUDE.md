# LLM Contributor Guide

This guide is for Claude, Copilot, and other LLM coding agents contributing to
PacketYeeter. It complements [`CONTRIBUTING.md`](CONTRIBUTING.md),
[`docs/operations.md`](docs/operations.md), and
[`docs/troubleshooting.md`](docs/troubleshooting.md). Follow the human
contributor docs first, then use this file for agent-specific guardrails.

## Project snapshot

PacketYeeter is a Linux/eBPF DDoS protection and traffic analysis system with a
split architecture:

- **Collector** (`cmd/collector`, `pkg/collector`) runs on protected Linux hosts,
  loads XDP/TC eBPF programs, enforces blocks, exposes metrics, runs HAProxy
  Peer/SPOE listeners, and streams signals to the analyzer.
- **Analyzer** (`cmd/analyzer`, `pkg/analyzer`) receives collector signals over
  gRPC, runs reputation, bot/crawler verification, JA4DB lookups, threat intel,
  AI/ML heuristics, and sends block commands back.
- **CLI/TUI/tools** include `yeetctl`, `yeetexplorer`, and `labeler`.
- **Proto API** lives in `api/proto/v1/packetyeeter.proto`; generated Go files
  are committed and must stay in sync with proto changes.
- **eBPF source** lives in `pkg/collector/ebpf/c/protector.bpf.c`; the compiled
  object `protector.bpf.o` is generated locally and ignored by git.

This repo can drop production traffic. Treat detection/enforcement changes as
safety-critical.

## Non-negotiable instructions

- Keep changes small, reviewable, and single-purpose.
- If an LLM agent substantially contributed to a commit, include an accurate
  `Co-authored-by` trailer for that agent according to the contribution
  platform's attribution conventions.
- Do **not** commit secrets, packet captures with real client data, GeoIP
  databases, ONNX models, compiled binaries, `.o` files, local dashboards, or
  private IP intelligence exports.
- Do **not** make enforcement stricter by default without documentation,
  tests, and dry-run/tuning guidance.
- Do **not** hide errors with broad catches or success-shaped fallbacks. Surface
  errors through existing logging/return patterns.
- Do **not** make Linux-only collector paths part of portable tests unless they
  are guarded by build tags or fakes.
- Do **not** rewrite public history, retarget branches, or merge PRs unless the
  human explicitly asks.

## Build and test workflow

Start with the portable checks unless you are on a Linux host with eBPF build
dependencies installed.

```bash
make deps
make portable-test
make analyzer
make yeetctl
```

On Linux with `clang`, `llvm`, `libbpf-dev`, and matching kernel headers:

```bash
make bpf
make collector
make test
```

Useful targeted commands:

```bash
go test ./pkg/analyzer/... ./pkg/ml/...
go test ./pkg/collector ./cmd/yeetctl
go test ./pkg/integration_test
```

If you change `api/proto/v1/packetyeeter.proto`, run `make proto` and commit the
updated generated files. If `buf` or protobuf plugins are missing, use
`make install-buf`.

If a validation command cannot run locally because the machine is not Linux or
does not have kernel/eBPF dependencies, say that plainly in the PR and run the
portable subset instead. Do not claim Linux collector validation from macOS.

## Architecture-sensitive areas

### Collector and eBPF

Collector changes need extra care because they affect kernel enforcement and
packet-path performance.

- Keep eBPF verifier constraints in mind: bounded loops, explicit packet bounds
  checks before access, no unbounded memory access, and small stack usage.
- Maintain IPv4 and IPv6 behavior together when changing maps, signals, blocks,
  or allowlist logic.
- Preserve safe lifecycle behavior: load, attach, start goroutines/listeners,
  stop listeners, close perf readers, detach/close maps/programs, then wait.
- Protect shared mutable Go state. Collector code has concurrent goroutines for
  map polling, perf events, analyzer streams, SPOE, management socket, metrics,
  and GC.
- Keep collector socket commands local-only and permission-conscious. Do not
  expose management operations over TCP without authentication/design review.
- Add tests with fakes where kernel privileges are not required. Avoid tests that
  need root unless clearly marked Linux/eBPF integration tests.

### Analyzer and detection

Detection changes should prefer safe, observable behavior over aggressive blocks.

- Preserve dry-run behavior. New detection paths must be visible in logs/metrics
  before they enforce.
- Blend or gate ML decisions with rule evidence. Avoid allowing a model output to
  erase strong deterministic signals without clear tests.
- Consider false positives first: crawlers, health checks, corporate proxies,
  CDNs, NAT gateways, VPNs, and monitoring systems can look unusual.
- Use timeouts and caching around network lookups such as DNS and threat intel.
  Detection workers must not block indefinitely on external services.
- Keep reputation forgiving and explainable: decay, expiry, score reasons, and
  allowlist feedback should be testable.
- When adding signals or categories, update metrics/docs and avoid unbounded
  high-cardinality labels by default.

### Operations and deployment

- Keep default listeners safe or clearly documented. Metrics and inspector
  endpoints should be bound or firewalled in production.
- Systemd hardening must not remove collector capabilities required for BPF,
  XDP/TC, perf events, raw networking, or memlock.
- Deployment docs should recommend staged rollout: analyzer dry-run, one
  collector canary, threshold/allowlist tuning, then wider enforcement.
- Downloaded third-party runtime artifacts in scripts should have version pins
  and checksum verification where practical.

## Documentation expectations

Update docs when changing any of these:

- CLI flags, environment/default files, or systemd units
- gRPC proto fields or service behavior
- Metrics names, labels, ports, or dashboard assumptions
- Management socket/`yeetctl` command behavior
- Detection thresholds, confidence decisions, warmup/dry-run behavior, or
  enforcement semantics
- Build, Docker, Makefile, CI, or deployment flow

Prefer concise operator-facing docs over internal implementation notes. Do not
create scratch planning markdown in the repository.

## PR checklist for LLM agents

Before opening or updating a PR:

1. Confirm the branch is based on the intended base branch.
2. Run `gofmt` on Go changes.
3. Run the narrowest relevant tests plus `make portable-test` when feasible.
4. Run `git diff --check`.
5. Check for secrets or accidental artifacts:

   ```bash
   git status --short
   git diff --cached --stat
   ```

6. Ensure generated protobuf files match `.proto` changes.
7. Summarize validation accurately, including any Linux/eBPF limitations.
8. Include accurate co-author attribution for substantial LLM-assisted commits
   according to the contribution platform's conventions.

## Common tasks

### Add or change a collector flag

Update all relevant surfaces:

- `cmd/collector/main.go`
- `collector.Config` and use sites
- `packetyeeter-collector.default`
- `packetyeeter-collector.service` if systemd should pass it
- README flag table and operations docs if operator-facing
- Tests for parsing/config behavior when practical

### Add or change an analyzer flag

Update:

- `cmd/analyzer/main.go`
- `analyzer.Config` and initialization
- `packetyeeter-analyzer.default`
- `packetyeeter-analyzer.service` if systemd should pass it
- README flag table and docs
- Tests for changed detection/config behavior

### Change proto messages or services

Update:

- `api/proto/v1/packetyeeter.proto`
- Generated Go files via `make proto`
- Collector/analyzer call sites
- Integration tests
- README/docs if behavior changes

### Add a metric

Update:

- `pkg/metrics/metrics.go`
- Any collector/analyzer emit sites
- `docs/observability.md`
- `grafana-dashboard.json` only if the dashboard should display it

Use labels carefully. High-cardinality labels should be disabled by default or
explicitly gated.

## When uncertain

If a change can block legitimate traffic, weaken security, expose management
surfaces, or require production tuning, stop and ask for human guidance. If a
local check is blocked by platform limitations, document the exact limitation and
run the closest portable validation.
