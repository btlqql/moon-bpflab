// Differential tests against selected uBPF test vectors.
// Source: iovisor/ubpf commit 8d2dd3580ab80f9b4a79a9d2fa2420aa38fc7521,
// Apache-2.0. Only the assembly vectors were translated to Insn constructors;
// no uBPF source code is copied. See THIRD_PARTY.md and docs/ubpf-conformance.md.

///|
test "uBPF arsh32 vector" {
  let prog = [
    insn(0xb4, 0, 0, 0, 0xf8),
    insn(0x64, 0, 0, 0, 28),
    insn(0xc4, 0, 0, 0, 16),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(prog, [], 100).equal(0xffff8000UL))
}

///|
test "uBPF arsh64 vector" {
  let prog = [
    insn(0xb4, 0, 0, 0, 1),
    insn(0x67, 0, 0, 0, 63),
    insn(0xc7, 0, 0, 0, 55),
    insn(0xb4, 1, 0, 0, 5),
    insn(0xcf, 0, 1, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(prog, [], 100).equal(0xfffffffffffffff8UL))
}

///|
test "uBPF early exit vector" {
  let prog = [
    insn(0xb7, 0, 0, 0, 3),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [], 100).to_int(), 3)
}

///|
test "uBPF ldxb zero-offset vector" {
  let prog = [
    insn(0xb7, 0, 0, 0, 0),
    insn(0xbf, 2, 1, 0, 0),
    insn(0xbf, 7, 1, 0, 0),
    insn(0xbf, 8, 1, 0, 0),
    insn(0x07, 7, 0, 0, 1),
    insn(0x07, 8, 0, 0, 2),
    insn(0x71, 0, 2, 0, 0),
    insn(0x71, 7, 7, 0, 0),
    insn(0x71, 8, 8, 0, 0),
    insn(0x0f, 0, 7, 0, 0),
    insn(0x0f, 0, 8, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [1, 2, 3], 200).to_int(), 6)
}

///|
test "uBPF ldxb small-offset vector" {
  let input : Array[Int] = Array::new()
  for _ in 0..<144 {
    input.push(0)
  }
  input[8] = 2
  input[127] = 3
  let prog = [
    insn(0xbf, 2, 1, 0, 0),
    insn(0xbf, 8, 1, 0, 0),
    insn(0x71, 2, 2, 8, 0),
    insn(0x71, 8, 8, 127, 0),
    insn(0xbf, 0, 2, 0, 0),
    insn(0x0f, 0, 8, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, input, 200).to_int(), 5)
}

///|
test "uBPF factorial local-call vector" {
  let prog = [
    insn(0xb7, 1, 0, 0, 1),
    insn(0xb7, 2, 0, 0, 20),
    insn(0x85, 0, 1, 0, 1),
    insn(0x95, 0, 0, 0, 0),
    insn(0x2f, 1, 2, 0, 0),
    insn(0x17, 2, 0, 0, 1),
    insn(0x55, 2, 0, -3, 0),
    insn(0xbf, 0, 1, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(prog, [], 10000).equal(0x21c3677c82b40000UL))
}
