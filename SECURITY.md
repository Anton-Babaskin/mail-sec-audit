# Security Policy

## Supported versions

Security fixes are handled on the default branch.

## Reporting a vulnerability

Please do not open a public issue for vulnerabilities that could expose users
or production mail servers.

Report security concerns by creating a private security advisory on GitHub, or
contact the maintainer directly through the profile listed in the README.

Please include:

- affected version or commit;
- operating system and mail stack, if relevant;
- a minimal reproduction or command line;
- impact and any known workaround.

## Project safety principles

- The audit mode must remain read-only by default.
- Destructive or configuration-changing actions must require explicit opt-in.
- Reports and logs may contain sensitive operational data and should not be
  committed.

