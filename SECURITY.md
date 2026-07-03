# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately using GitHub Security Advisories for this repository when available:

1. Open the repository on GitHub.
2. Go to **Security** > **Advisories**.
3. Select **Report a vulnerability**.

If private advisories are not available, avoid publishing exploit details in a public issue. Open a minimal public issue asking maintainers to enable or provide a private reporting channel, without including sensitive technical details.

## Scope

Relevant reports include:

- vulnerabilities that allow unintended traffic blocking, bypass, privilege escalation, or denial of service;
- unsafe defaults for eBPF/XDP/TC loading or systemd deployment;
- management socket or inspector exposure issues;
- dependency, build, or generated-artifact issues that affect released binaries.

## Handling expectations

Maintainers should acknowledge private reports, validate impact, prepare a fix, and coordinate disclosure timing with the reporter. Public disclosure should happen after affected users have a reasonable path to upgrade or mitigate.

## Operator security notes

- Treat the collector as privileged software: it loads eBPF programs, attaches XDP/TC hooks, and manages kernel maps.
- Keep the collector management socket local and permission-restricted.
- Bind metrics, inspector, pprof, and analyzer gRPC listeners only to trusted interfaces or protect them with network controls.
- Start new deployments in analyzer `-dry-run` mode and tune thresholds before enabling enforcement.
