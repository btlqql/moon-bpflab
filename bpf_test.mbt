// Feasibility checks for the BPF interpreter prototype.

fn program_mov_ret(value : Int) -> Array[Insn] {
  [insn(0xb7, 0, 0, 0, value), insn(0x95, 0, 0, 0, 0)]
}

///|
test "returns the value in r0" {
  assert_eq(execute(program_mov_ret(42), [], 100).to_int(), 42)
  assert_eq(run_default(program_mov_ret(-7), []).to_int(), -7)
}

///|
test "64-bit addition wraps instead of saturating" {
  let prog = [
    insn(0xb7, 0, 0, 0, -1),
    insn(0x07, 0, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [], 100).to_int(), 0)
}

///|
test "32-bit ops zero-extend and wrap at 32 bits" {
  let zero_extend = [
    insn(0xb7, 0, 0, 0, -1),
    insn(0xb4, 0, 0, 0, -1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(zero_extend, [], 100).equal(0xffffffffUL))
  let wrap32 = [
    insn(0xb4, 0, 0, 0, -1),
    insn(0x04, 0, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(wrap32, [], 100).to_int(), 0)
  let widen = [
    insn(0xb4, 0, 0, 0, -1),
    insn(0x07, 0, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(widen, [], 100).equal(0x100000000UL))
}

///|
test "signed and unsigned jumps disagree on the same bits" {
  let signed = [
    insn(0xb7, 0, 0, 0, 0),
    insn(0xb7, 1, 0, 0, -1),
    insn(0x65, 1, 0, 2, 0),
    insn(0xb7, 0, 0, 0, 3),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 7),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(signed, [], 100).to_int(), 3)
  let unsigned = [
    insn(0xb7, 0, 0, 0, 0),
    insn(0xb7, 1, 0, 0, -1),
    insn(0x25, 1, 0, 2, 0),
    insn(0xb7, 0, 0, 0, 3),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 7),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(unsigned, [], 100).to_int(), 7)
}

///|
test "loads are little-endian and obey bounds" {
  let input : Array[Int] = [1, 2, 3, 4]
  let one_byte = [insn(0x71, 0, 1, 3, 0), insn(0x95, 0, 0, 0, 0)]
  assert_eq(execute(one_byte, input, 100).to_int(), 4)
  let eight_bytes = [insn(0x79, 0, 1, 0, 0), insn(0x95, 0, 0, 0, 0)]
  let rejected = try {
    ignore(execute(eight_bytes, input, 100))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
  let out_of_range = [insn(0x71, 0, 1, 100, 0), insn(0x95, 0, 0, 0, 0)]
  let rejected2 = try {
    ignore(execute(out_of_range, input, 100))
    false
  } catch {
    _ => true
  }
  assert_true(rejected2)
}

///|
test "stack stores round-trip and input is read-only" {
  let stack = [
    insn(0x7a, 10, 0, -8, 0x11223344),
    insn(0x79, 0, 10, -8, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(stack, [], 100).equal(0x11223344UL))
  let write_input = [
    insn(0x72, 1, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  let rejected = try {
    ignore(execute(write_input, [0, 0, 0, 0], 100))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "div/mod by zero follow the eBPF interpreter semantics" {
  let div_zero = [
    insn(0xb7, 0, 0, 0, 7),
    insn(0x37, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(div_zero, [], 100).to_int(), 0)
  let mod_zero = [
    insn(0xb7, 0, 0, 0, 7),
    insn(0x97, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(mod_zero, [], 100).to_int(), 7)
  let signed_div = [
    insn(0xb7, 0, 0, 0, -7),
    insn(0x37, 0, 0, 1, 2),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(signed_div, [], 100).to_int(), -3)
  let signed_mod = [
    insn(0xb7, 0, 0, 0, -7),
    insn(0x97, 0, 0, 1, 2),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(signed_mod, [], 100).to_int(), -1)
  let bad_helper = [insn(0x85, 0, 0, 0, 99), insn(0x95, 0, 0, 0, 0)]
  let rejected = try {
    ignore(execute(bad_helper, [], 100))
    false
  } catch {
    _ => true
  }
  assert_true(rejected)
}

///|
test "helper 1 sums a byte range" {
  let prog = [
    insn(0xb7, 1, 0, 0, 0x10000),
    insn(0xb7, 2, 0, 0, 4),
    insn(0x85, 0, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [1, 2, 3, 4], 100).to_int(), 10)
}

///|
test "step budget, frame pointer and bad jumps are rejected" {
  let loop_prog = [insn(0x05, 0, 0, -1, 0)]
  let budget = try {
    ignore(execute(loop_prog, [], 50))
    false
  } catch {
    _ => true
  }
  assert_true(budget)
  let write_r10 = [insn(0xb7, 10, 0, 0, 0), insn(0x95, 0, 0, 0, 0)]
  let frame = try {
    ignore(execute(write_r10, [], 100))
    false
  } catch {
    _ => true
  }
  assert_true(frame)
  let bad_jump = [insn(0x05, 0, 0, 100, 0), insn(0x95, 0, 0, 0, 0)]
  let jump = try {
    ignore(execute(bad_jump, [], 100))
    false
  } catch {
    _ => true
  }
  assert_true(jump)
  let unknown = [insn(0xff, 0, 0, 0, 0), insn(0x95, 0, 0, 0, 0)]
  let opcode = try {
    ignore(execute(unknown, [], 100))
    false
  } catch {
    _ => true
  }
  assert_true(opcode)
}
