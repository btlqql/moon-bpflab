# Third-party test vectors

## uBPF

- Project: [iovisor/ubpf](https://github.com/iovisor/ubpf)
- Commit used: `8d2dd3580ab80f9b4a79a9d2fa2420aa38fc7521` (2026-10-16)
- License: Apache-2.0
- Use: selected assembly test vectors were translated into `Insn` constructors for differential tests. No uBPF source code is copied or linked.
- Vectors used: `tests/arsh.data`, `tests/arsh64.data`, `tests/early-exit.data`, `tests/ldxb-0offset.data`, `tests/ldxb-small-offset.data`, `tests/factorial.data`.
- Results and known divergences: `docs/ubpf-conformance.md`.

uBPF's own copyright and license remain with its authors. The MoonBpfLab repository is also Apache-2.0.
