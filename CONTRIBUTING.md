# Contributing

Thanks for helping improve PacketYeeter. Keep changes focused, operationally safe, and easy to review.

## Development workflow

1. Fork and clone the repository.
2. Install Go 1.24+ and, for collector/eBPF work on Linux, `clang`, `llvm`, `libbpf-dev`, and matching `linux-headers`.
3. Download Go dependencies:

   ```bash
   make deps
   ```

4. Build the normal binaries:

   ```bash
   make
   make yeetctl
   ```

   The collector embeds `pkg/collector/ebpf/c/protector.bpf.o`; use `make bpf` or `make collector` on Linux to build it before collector tests or builds that need the eBPF object.

5. Run the portable test set before opening a PR:

   ```bash
   make portable-test
   ```

   On Linux hosts with eBPF build dependencies available, also run:

   ```bash
   make test
   ```

## Pull request expectations

- Keep PRs small and single-purpose.
- Update docs when changing flags, deployment behavior, metrics, systemd units, or operator workflows.
- For detection or blocking changes, describe the operational impact and include dry-run/tuning guidance.
- Do not commit generated binaries, local dashboards, secrets, packet captures with real client data, or private IP intelligence exports.
- Use `gofmt` on Go changes and keep generated protobuf updates in the same PR as the `.proto` change.

## LLM-assisted contributions

LLM coding agents should read [`CLAUDE.md`](CLAUDE.md) before making changes. It
contains repository-specific safety rules, validation expectations, and
architecture guidance for agent-generated contributions.

## Operational safety

PacketYeeter can drop traffic at XDP/TC. Test new detection and deployment changes in analyzer dry-run mode first, then roll out to a small set of collectors with conservative thresholds and allowlists for control-plane and trusted networks.

## Security issues

Do not open public issues for vulnerabilities. Follow [`SECURITY.md`](SECURITY.md) for private reporting.
