// Core checks for the extended BPF tool.

fn hex_bytes(text : String) -> Array[Int] raise Failure {
  let out : Array[Int] = Array::new()
  let mut high = -1
  for i in 0..<text.length() {
    let c = text[i].to_int()
    let value = if c >= 48 && c <= 57 {
      Some(c - 48)
    } else if c >= 65 && c <= 70 {
      Some(c - 55)
    } else if c >= 97 && c <= 102 {
      Some(c - 87)
    } else {
      None
    }
    match value {
      Some(v) =>
        if high < 0 {
          high = v
        } else {
          out.push((high << 4) | v)
          high = -1
        }
      None => {
        if c != 32 && c != 9 && c != 10 && c != 13 {
          fail("invalid hex in test")
        }
      }
    }
  }
  if high >= 0 {
    fail("odd hex in test")
  }
  out
}

///|
test "disassembler covers ALU, memory, jumps and calls" {
  let prog = [
    insn(0xb7, 0, 0, 0, 42),
    insn(0x07, 0, 0, 0, 1),
    insn(0x79, 2, 10, -8, 0),
    insn(0x7a, 10, 0, -8, 7),
    insn(0x25, 0, 0, 2, 10),
    insn(0x85, 0, 0, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  let lines = disassemble(prog)
  assert_eq(lines[0], "mov64 r0, 42")
  assert_eq(lines[1], "add64 r0, 1")
  assert_eq(lines[2], "ldxdw r2, [r10-8]")
  assert_eq(lines[3], "stdw [r10-8], 7")
  assert_eq(lines[4], "jgt r0, 10, +2")
  assert_eq(lines[5], "call helper 1")
  assert_eq(lines[6], "exit")
}

///|
test "step, snapshot and breakpoints expose machine state" {
  let prog = [
    insn(0xb7, 0, 0, 0, 1),
    insn(0xb7, 0, 0, 0, 2),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [])
  assert_eq(machine.snapshot().pc, 0)
  machine.set_breakpoint(2)
  match machine.run_until_break() {
    BreakpointHit(pc) => assert_eq(pc, 2)
    _ => fail("expected a breakpoint")
  }
  assert_eq(machine.snapshot().pc, 2)
  match machine.step() {
    Halted(value) => assert_eq(value.to_int(), 2)
    _ => fail("the exit instruction should halt")
  }
  assert_eq(machine.snapshot().regs[0].to_int(), 2)
  assert_eq(machine.run().to_int(), 2)
}

///|
test "local subprogram call returns to the caller" {
  let prog = [
    insn(0xb7, 0, 0, 0, 1),
    insn(0x85, 0, 1, 1, 1),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 7),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(Machine::new_default(prog, []).run().to_int(), 7)
}

///|
test "runaway local calls hit the call-depth limit" {
  let prog = [insn(0x85, 0, 1, -1, 0)]
  let failed = try {
    ignore(Machine::new_default(prog, []).run())
    false
  } catch {
    _ => true
  }
  assert_true(failed)
}

///|
test "array map update and lookup round-trip" {
  let prog = [
    insn(0xb7, 1, 0, 0, 0),
    insn(0xb7, 2, 0, 0, 0x10000),
    insn(0xb7, 3, 0, 0, 0x10001),
    insn(0xb7, 4, 0, 0, 0),
    insn(0x85, 0, 0, 0, 3),
    insn(0xb7, 1, 0, 0, 0),
    insn(0xb7, 2, 0, 0, 0x10000),
    insn(0x85, 0, 0, 0, 2),
    insn(0x61, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [1, 42, 0, 0, 0])
  ignore(machine.add_array_map(1, 4, 4))
  assert_eq(machine.run().to_int(), 42)
}

///|
test "array map delete removes the key" {
  let prog = [
    insn(0xb7, 1, 0, 0, 0),
    insn(0xb7, 2, 0, 0, 0x10000),
    insn(0xb7, 3, 0, 0, 0x10001),
    insn(0xb7, 4, 0, 0, 0),
    insn(0x85, 0, 0, 0, 3),
    insn(0xb7, 1, 0, 0, 0),
    insn(0xb7, 2, 0, 0, 0x10000),
    insn(0x85, 0, 0, 0, 4),
    insn(0xb7, 1, 0, 0, 0),
    insn(0xb7, 2, 0, 0, 0x10000),
    insn(0x85, 0, 0, 0, 2),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [1, 42, 0, 0, 0])
  ignore(machine.add_array_map(1, 4, 4))
  assert_eq(machine.run().to_int(), 0)
}

///|
test "minimal ELF loads a .text section" {
  let elf_hex = "7F454C460201010000000000000000000200F7000100000000000000000000000000000000000000680000000000000000000000400000000000400003000200B70000002A00000095000000000000002E74657874002E7368737472746162000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000060000000000000000000000000000004000000000000000100000000000000000000000000000000800000000000000000000000000000006000000030000000000000000000000000000000000000050000000000000001000000000000000000000000000000008000000000000000000000000000000"
  let image = load_elf(hex_bytes(elf_hex))
  assert_eq(image.entry, 0)
  assert_eq(image.text.length(), 2)
  let lines = disassemble(image.text)
  assert_eq(lines[0], "mov64 r0, 42")
  assert_eq(lines[1], "exit")
}

///|
test "raw bytecode decoding and bad ELF rejection" {
  let raw = hex_bytes("b70000002a0000009500000000000000")
  let program = decode_instructions(raw)
  assert_eq(program.length(), 2)
  assert_eq(program[0].imm, 42)
  let bad = try {
    ignore(load_elf(hex_bytes("00010203")))
    false
  } catch {
    _ => true
  }
  assert_true(bad)
}

///|
test "conditional breakpoint waits for a register value" {
  let prog = [
    insn(0xb7, 0, 0, 0, 0),
    insn(0x07, 0, 0, 0, 1),
    insn(0xa5, 0, 0, -2, 3),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [])
  machine.set_conditional_breakpoint(2, 0, 2UL)
  match machine.run_until_break() {
    BreakpointHit(pc) => assert_eq(pc, 2)
    _ => fail("conditional breakpoint should fire")
  }
  assert_eq(machine.snapshot().regs[0].to_int(), 2)
}

///|
test "coverage counts executed instructions" {
  let prog = [
    insn(0x07, 0, 0, 0, 1),
    insn(0xa5, 0, 0, -2, 3),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [])
  ignore(machine.run())
  assert_eq(machine.execution_count(0), 3)
  assert_eq(machine.execution_count(1), 3)
  assert_eq(machine.execution_count(2), 1)
}

///|
test "bounded run stops after the requested steps" {
  let prog = [
    insn(0xb7, 0, 0, 0, 1),
    insn(0xb7, 0, 0, 0, 2),
    insn(0x95, 0, 0, 0, 0),
  ]
  let machine = Machine::new_default(prog, [])
  match machine.run_n(1) {
    Continue => assert_eq(machine.snapshot().pc, 1)
    _ => fail("first step should continue")
  }
  match machine.run_n(1) {
    Continue => assert_eq(machine.snapshot().pc, 2)
    _ => fail("second step should continue")
  }
  match machine.run_n(5) {
    Halted(value) => assert_eq(value.to_int(), 2)
    _ => fail("third step should halt")
  }
}

///|
test "disassembly annotates jump and local-call targets" {
  let prog = [
    insn(0xb7, 0, 0, 0, 0),
    insn(0x25, 0, 0, 2, 0),
    insn(0x05, 0, 0, 1, 0),
    insn(0x95, 0, 0, 0, 0),
    insn(0x85, 0, 1, 0, 1),
    insn(0x95, 0, 0, 0, 0),
  ]
  let lines = disassemble_with_targets(prog)
  assert_true(lines[1].contains("-> 4"))
  assert_true(lines[2].contains("-> 4"))
  assert_true(lines[4].contains("-> 6"))
}

///|
test "ELF loader exposes section names and sizes" {
  let elf_hex = "7F454C460201010000000000000000000200F7000100000000000000000000000000000000000000680000000000000000000000400000000000400003000200B70000002A00000095000000000000002E74657874002E7368737472746162000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000060000000000000000000000000000004000000000000000100000000000000000000000000000000800000000000000000000000000000006000000030000000000000000000000000000000000000050000000000000001000000000000000000000000000000008000000000000000000000000000000"
  let image = load_elf(hex_bytes(elf_hex))
  assert_true(image.sections.length() >= 2)
  let mut found_text = false
  for section in image.sections {
    if section.name == ".text" {
      found_text = true
      assert_eq(section.size, 16)
    }
  }
  assert_true(found_text)
}

///|
test "JMP32 compares low 32 bits with unsigned and signed semantics" {
  let unsigned = [
    insn(0xb4, 0, 0, 0, -1),
    insn(0xb7, 1, 0, 0, 0),
    insn(0x2e, 0, 1, 2, 0),
    insn(0xb7, 0, 0, 0, 3),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 7),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(unsigned, [], 100).to_int(), 7)
  let signed = [
    insn(0xb4, 0, 0, 0, -1),
    insn(0xb7, 1, 0, 0, 0),
    insn(0x6e, 0, 1, 2, 0),
    insn(0xb7, 0, 0, 0, 3),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 0, 0, 0, 7),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(signed, [], 100).to_int(), 3)
  let ja32 = [insn(0x06, 0, 0, 1, 0), insn(0xb7, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0)]
  assert_eq(execute(ja32, [], 100).to_int(), 0)
}

///|
test "endianness instructions truncate and byte-swap" {
  let be16 = [insn(0xb7, 0, 0, 0, 0x1122), insn(0xdc, 0, 0, 0, 16), insn(0x95, 0, 0, 0, 0)]
  assert_eq(execute(be16, [], 100).to_int(), 0x2211)
  let le32 = [insn(0xb7, 0, 0, 0, 0x12345678), insn(0xd4, 0, 0, 0, 32), insn(0x95, 0, 0, 0, 0)]
  assert_eq(execute(le32, [], 100).to_int(), 0x12345678)
  let le16 = [insn(0xb7, 0, 0, 0, 0x12345678), insn(0xd4, 0, 0, 0, 16), insn(0x95, 0, 0, 0, 0)]
  assert_eq(execute(le16, [], 100).to_int(), 0x5678)
  let bswap = [
    insn(0x18, 0, 0, 0, 0x55667788),
    insn(0, 0, 0, 0, 0x11223344),
    insn(0xd7, 0, 0, 0, 0),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_true(execute(bswap, [], 100).equal(0x8877665544332211UL))
}

///|
test "sign-extending loads match MEMSX semantics" {
  let word = [insn(0x81, 0, 1, 2, 0), insn(0x95, 0, 0, 0, 0)]
  let input : Array[Int] = [0xaa, 0xbb, 0x01, 0x00, 0x00, 0x80, 0xcc, 0xdd]
  assert_true(execute(word, input, 100).equal(0xffffffff80000001UL))
  let byte = [insn(0x91, 0, 1, 0, 0), insn(0x95, 0, 0, 0, 0)]
  assert_true(execute(byte, [0x80], 100).equal(0xffffffffffffff80UL))
  let half = [insn(0x89, 0, 1, 0, 0), insn(0x95, 0, 0, 0, 0)]
  assert_true(execute(half, [0x00, 0x80], 100).equal(0xffffffffffff8000UL))
}

///|
test "local calls preserve r6-r9" {
  let prog = [
    insn(0xb7, 6, 0, 0, 5),
    insn(0x85, 0, 1, 0, 2),
    insn(0xbf, 0, 6, 0, 0),
    insn(0x95, 0, 0, 0, 0),
    insn(0xb7, 6, 0, 0, 9),
    insn(0x95, 0, 0, 0, 0),
  ]
  assert_eq(execute(prog, [], 100).to_int(), 5)
}
