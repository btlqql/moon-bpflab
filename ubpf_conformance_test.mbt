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

///|
test "uBPF div/mod by zero vectors" {
  let div_zero = [
    insn(0xb4, 0, 0, 0, 1),
    insn(0x37, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(div_zero, [], 100).to_int(), 0)
  let mod_zero = [
    insn(0xb4, 0, 0, 0, 1),
    insn(0x94, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(mod_zero, [], 100).to_int(), 1)
}

///|
test "uBPF signed division vectors" {
  let sdiv = [
    insn(0x18, 0, 0, 0, 0),
    insn(0, 0, 0, 0, 1),
    insn(0x37, 0, 0, 1, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(sdiv, [], 100).equal(0x40000000UL))
  let sdiv_neg = [
    insn(0x18, 0, 0, 0, -13),
    insn(0, 0, 0, 0, -1),
    insn(0x37, 0, 0, 1, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(sdiv_neg, [], 100).equal(0xfffffffffffffffdUL))
  let sdiv_overflow = [
    insn(0x18, 0, 0, 0, 0),
    insn(0, 0, 0, 0, -2147483648),
    insn(0xb7, 1, 0, 0, -1),
    insn(0x3f, 0, 1, 1, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(sdiv_overflow, [], 100).equal(0x8000000000000000UL))
}

///|
test "uBPF signed modulo vectors" {
  let smod = [
    insn(0x18, 0, 0, 0, 5),
    insn(0, 0, 0, 0, 1),
    insn(0x97, 0, 0, 1, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(smod, [], 100).equal(0x1UL))
  let smod_neg = [
    insn(0x18, 0, 0, 0, -13),
    insn(0, 0, 0, 0, -1),
    insn(0x97, 0, 0, 1, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(smod_neg, [], 100).equal(0xffffffffffffffffUL))
}

///|
test "uBPF signed 32-bit division vector" {
  let prog = [
    insn(0xb4, 0, 0, 0, 15),
    insn(0x34, 0, 0, 1, 4),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [], 100).to_int(), 3)
  let overflow = [
    insn(0xb4, 0, 0, 0, -2147483648),
    insn(0x34, 0, 0, 1, -1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(overflow, [], 100).equal(0x80000000UL))
}

///|
test "uBPF sign-extending load vector" {
  let prog = [insn(0x81, 0, 1, 2, 0), insn(0x95, 0, 0, 0, 0)]
  let input : Array[Int] = [0xaa, 0xbb, 0x01, 0x00, 0x00, 0x80, 0xcc, 0xdd]
  assert_true(execute(prog, input, 100).equal(0xffffffff80000001UL))
}
