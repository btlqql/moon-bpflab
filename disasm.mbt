// Text disassembly for the supported instruction subset.

fn signed(value : Int) -> String {
  if value >= 0 {
    "+" + value.to_string()
  } else {
    value.to_string()
  }
}

fn reg(index : Int) -> String {
  "r" + index.to_string()
}

fn alu_name(base : Int) -> String {
  if base == 0x07 {
    "add"
  } else if base == 0x17 {
    "sub"
  } else if base == 0x27 {
    "mul"
  } else if base == 0x37 {
    "div"
  } else if base == 0x47 {
    "or"
  } else if base == 0x57 {
    "and"
  } else if base == 0x67 {
    "lsh"
  } else if base == 0x77 {
    "rsh"
  } else if base == 0x87 {
    "neg"
  } else if base == 0x97 {
    "mod"
  } else if base == 0xa7 {
    "xor"
  } else if base == 0xb7 {
    "mov"
  } else if base == 0xc7 {
    "arsh"
  } else {
    "alu"
  }
}

fn is_alu64(base : Int) -> Bool {
  base == 0x07 || base == 0x17 || base == 0x27 || base == 0x37 ||
  base == 0x47 || base == 0x57 || base == 0x67 || base == 0x77 ||
  base == 0x87 || base == 0x97 || base == 0xa7 || base == 0xb7 || base == 0xc7
}

fn is_alu32(base : Int) -> Bool {
  base == 0x04 || base == 0x14 || base == 0x24 || base == 0x34 ||
  base == 0x44 || base == 0x54 || base == 0x64 || base == 0x74 ||
  base == 0x84 || base == 0x94 || base == 0xa4 || base == 0xb4 || base == 0xc4
}

fn jump_name(base : Int) -> String {
  if base == 0x15 {
    "jeq"
  } else if base == 0x25 {
    "jgt"
  } else if base == 0x35 {
    "jge"
  } else if base == 0x45 {
    "jset"
  } else if base == 0x55 {
    "jne"
  } else if base == 0x65 {
    "jsgt"
  } else if base == 0x75 {
    "jsge"
  } else if base == 0xa5 {
    "jlt"
  } else if base == 0xb5 {
    "jle"
  } else if base == 0xc5 {
    "jslt"
  } else if base == 0xd5 {
    "jsle"
  } else {
    "jmp"
  }
}

fn load_name(op : Int) -> String {
  if op == 0x61 {
    "ldxw"
  } else if op == 0x69 {
    "ldxh"
  } else if op == 0x71 {
    "ldxb"
  } else {
    "ldxdw"
  }
}

fn store_name(op : Int) -> String {
  if op == 0x63 {
    "stxw"
  } else if op == 0x6b {
    "stxh"
  } else if op == 0x73 {
    "stxb"
  } else {
    "stxdw"
  }
}

fn store_imm_name(op : Int) -> String {
  if op == 0x62 {
    "stw"
  } else if op == 0x6a {
    "sth"
  } else if op == 0x72 {
    "stb"
  } else {
    "stdw"
  }
}

pub fn disassemble_one(ins : Insn) -> String {
  let op = ins.op
  let base = op & 0xf7
  if is_alu64(base) || is_alu32(base) {
    let suffix = if is_alu64(base) { "64" } else { "32" }
    let name = alu_name(base) + suffix
    if base == 0x87 || base == 0x84 {
      name + " " + reg(ins.dst)
    } else if (op & 0x08) != 0 {
      name + " " + reg(ins.dst) + ", " + reg(ins.src)
    } else {
      name + " " + reg(ins.dst) + ", " + ins.imm.to_string()
    }
  } else if op == 0x61 || op == 0x69 || op == 0x71 || op == 0x79 {
    load_name(op) + " " + reg(ins.dst) + ", [" + reg(ins.src) +
    signed(ins.off) + "]"
  } else if op == 0x63 || op == 0x6b || op == 0x73 || op == 0x7b {
    store_name(op) + " [" + reg(ins.dst) + signed(ins.off) + "], " +
    reg(ins.src)
  } else if op == 0x62 || op == 0x6a || op == 0x72 || op == 0x7a {
    store_imm_name(op) + " [" + reg(ins.dst) + signed(ins.off) + "], " +
    ins.imm.to_string()
  } else if op == 0x05 {
    "ja " + signed(ins.off)
  } else if op == 0x15 || op == 0x1d || op == 0x25 || op == 0x2d ||
    op == 0x35 || op == 0x3d || op == 0x45 || op == 0x4d ||
    op == 0x55 || op == 0x5d || op == 0x65 || op == 0x6d ||
    op == 0x75 || op == 0x7d || op == 0xa5 || op == 0xad ||
    op == 0xb5 || op == 0xbd || op == 0xc5 || op == 0xcd ||
    op == 0xd5 || op == 0xdd {
    let source = if (op & 0x08) != 0 {
      reg(ins.src)
    } else {
      ins.imm.to_string()
    }
    jump_name(base) + " " + reg(ins.dst) + ", " + source + ", " +
    signed(ins.off)
  } else if op == 0x85 {
    if ins.src == 1 {
      "call " + signed(ins.imm)
    } else {
      "call helper " + ins.imm.to_string()
    }
  } else if op == 0x95 {
    "exit"
  } else if op == 0x18 {
    "lddw " + reg(ins.dst) + ", 0x" + ins.imm.to_string()
  } else {
    ".insn op=0x" + op.to_string() + " dst=" + ins.dst.to_string() + " src=" +
    ins.src.to_string() + " off=" + ins.off.to_string() + " imm=" +
    ins.imm.to_string()
  }
}

pub fn disassemble(program : Array[Insn]) -> Array[String] {
  let out : Array[String] = Array::new()
  let mut i = 0
  while i < program.length() {
    let ins = program[i]
    if ins.op == 0x18 && i + 1 < program.length() {
      let value = (ins.imm.to_int64().reinterpret_as_uint64()).land(
        0xffffffffUL,
      ).lor(
        (program[i + 1].imm.to_int64().reinterpret_as_uint64()).land(
          0xffffffffUL,
        ).shl(32),
      )
      out.push("lddw " + reg(ins.dst) + ", 0x" + value.to_string(radix=16))
      i = i + 2
    } else {
      out.push(disassemble_one(ins))
      i = i + 1
    }
  }
  out
}

fn is_conditional_jump(op : Int) -> Bool {
  op == 0x15 || op == 0x1d || op == 0x25 || op == 0x2d ||
  op == 0x35 || op == 0x3d || op == 0x45 || op == 0x4d ||
  op == 0x55 || op == 0x5d || op == 0x65 || op == 0x6d ||
  op == 0x75 || op == 0x7d || op == 0xa5 || op == 0xad ||
  op == 0xb5 || op == 0xbd || op == 0xc5 || op == 0xcd ||
  op == 0xd5 || op == 0xdd
}

pub fn disassemble_with_targets(program : Array[Insn]) -> Array[String] {
  let out : Array[String] = Array::new()
  let mut i = 0
  while i < program.length() {
    let ins = program[i]
    if ins.op == 0x18 && i + 1 < program.length() {
      let value = (ins.imm.to_int64().reinterpret_as_uint64()).land(
        0xffffffffUL,
      ).lor(
        (program[i + 1].imm.to_int64().reinterpret_as_uint64()).land(
          0xffffffffUL,
        ).shl(32),
      )
      out.push("lddw " + reg(ins.dst) + ", 0x" + value.to_string(radix=16))
      i = i + 2
    } else {
      let mut line = disassemble_one(ins)
      if ins.op == 0x05 || is_conditional_jump(ins.op) {
        line = line + " -> " + (i + 1 + ins.off).to_string()
      } else if ins.op == 0x85 && ins.src == 1 {
        line = line + " -> " + (i + 1 + ins.imm).to_string()
      }
      out.push(line)
      i = i + 1
    }
  }
  out
}
