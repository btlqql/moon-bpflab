// Feasibility prototype: a user-space BPF interpreter with explicit bounds.
// Scope: a documented instruction subset, 64-bit register semantics, byte-addressed
// input/stack memory, one helper, step budget. Not a kernel verifier or JIT.

pub(all) struct Insn {
  op : Int
  dst : Int
  src : Int
  off : Int
  imm : Int
}

pub(all) suberror BpfError {
  UnknownOpcode(Int)
  DivisionByZero
  InvalidRegister(Int)
  InvalidProgram(Int)
  MemoryAccess(UInt64, Int)
  WriteToReadOnly(UInt64)
  StepBudgetExceeded
  UnknownHelper(Int)
}

const INPUT_BASE : UInt64 = 0x10000UL
const STACK_BASE : UInt64 = 0x20000UL
const STACK_SIZE : Int = 512
const HELPER_SUM : Int = 1

pub fn insn(op : Int, dst : Int, src : Int, off : Int, imm : Int) -> Insn {
  { op, dst, src, off, imm }
}

fn imm_u64(imm : Int) -> UInt64 {
  imm.to_int64().to_uint64()
}

fn low32(x : UInt64) -> UInt64 {
  x.land(0xffffffffUL)
}

fn sign_extend_low32(x : UInt64) -> UInt64 {
  // Shift the low 32 bits into the high half, arithmetic-shift back.
  x.shl(32).reinterpret_as_int64().shr(32).reinterpret_as_uint64()
}

pub(all) struct Vm {
  regs : Array[UInt64]
  input : Array[Int]
  stack : Array[Int]
  mut steps : Int
  max_steps : Int
}

pub fn Vm::new(input : Array[Int], max_steps : Int) -> Vm {
  let regs : Array[UInt64] = Array::new()
  for _ in 0..<11 {
    regs.push(0UL)
  }
  regs[1] = INPUT_BASE
  regs[10] = STACK_BASE.add(STACK_SIZE.to_uint64())
  let stack : Array[Int] = Array::new()
  for _ in 0..<STACK_SIZE {
    stack.push(0)
  }
  { regs, input, stack, steps: 0, max_steps }
}

fn in_range(addr : UInt64, base : UInt64, len : Int, size : Int) -> Bool {
  addr >= base && addr.add(size.to_uint64()) <= base.add(len.to_uint64())
}

fn load_from(bytes : Array[Int], offset : Int, size : Int) -> UInt64 {
  let mut value = 0UL
  for i in 0..<size {
    value = value.lor(bytes[offset + i].to_uint64().shl(8 * i))
  }
  value
}

fn store_to(bytes : Array[Int], offset : Int, size : Int, value : UInt64) -> Unit {
  for i in 0..<size {
    bytes[offset + i] = value.shr(8 * i).land(0xffUL).to_int()
  }
}

pub fn Vm::load(self : Vm, addr : UInt64, size : Int) -> UInt64 raise BpfError {
  if in_range(addr, INPUT_BASE, self.input.length(), size) {
    return load_from(self.input, addr.sub(INPUT_BASE).to_int(), size)
  }
  if in_range(addr, STACK_BASE, self.stack.length(), size) {
    return load_from(self.stack, addr.sub(STACK_BASE).to_int(), size)
  }
  raise MemoryAccess(addr, size)
}

pub fn Vm::store(
  self : Vm,
  addr : UInt64,
  size : Int,
  value : UInt64,
) -> Unit raise BpfError {
  if in_range(addr, INPUT_BASE, self.input.length(), size) {
    raise WriteToReadOnly(addr)
  }
  if in_range(addr, STACK_BASE, self.stack.length(), size) {
    store_to(self.stack, addr.sub(STACK_BASE).to_int(), size, value)
    return
  }
  raise MemoryAccess(addr, size)
}

fn alu64(op : Int, dst : UInt64, src : UInt64) -> UInt64 raise BpfError {
  if op == 0x07 {
    dst.add(src)
  } else if op == 0x17 {
    dst.sub(src)
  } else if op == 0x27 {
    dst.mul(src)
  } else if op == 0x37 {
    if src.equal(0UL) {
      raise DivisionByZero
    }
    dst.div(src)
  } else if op == 0x47 {
    dst.lor(src)
  } else if op == 0x57 {
    dst.land(src)
  } else if op == 0x67 {
    dst.shl(src.to_int() & 63)
  } else if op == 0x77 {
    dst.shr(src.to_int() & 63)
  } else if op == 0x87 {
    let zero : UInt64 = 0UL
    zero.sub(dst)
  } else if op == 0x97 {
    if src.equal(0UL) {
      raise DivisionByZero
    }
    dst.mod(src)
  } else if op == 0xa7 {
    dst.lxor(src)
  } else if op == 0xb7 {
    src
  } else if op == 0xc7 {
    dst.reinterpret_as_int64().shr(src.to_int() & 63).reinterpret_as_uint64()
  } else {
    raise UnknownOpcode(op)
  }
}

fn alu32(op : Int, dst : UInt64, src : UInt64) -> UInt64 raise BpfError {
  let d = low32(dst)
  let s = low32(src)
  if op == 0x04 {
    low32(d.add(s))
  } else if op == 0x14 {
    low32(d.sub(s))
  } else if op == 0x24 {
    low32(d.mul(s))
  } else if op == 0x34 {
    if s.equal(0UL) {
      raise DivisionByZero
    }
    low32(d.div(s))
  } else if op == 0x44 {
    low32(d.lor(s))
  } else if op == 0x54 {
    low32(d.land(s))
  } else if op == 0x64 {
    low32(d.shl(s.to_int() & 31))
  } else if op == 0x74 {
    low32(d.shr(s.to_int() & 31))
  } else if op == 0x84 {
    let zero : UInt64 = 0UL
    low32(zero.sub(d))
  } else if op == 0x94 {
    if s.equal(0UL) {
      raise DivisionByZero
    }
    low32(d.mod(s))
  } else if op == 0xa4 {
    low32(d.lxor(s))
  } else if op == 0xb4 {
    s
  } else if op == 0xc4 {
    low32(sign_extend_low32(d).reinterpret_as_int64().shr(s.to_int() & 31).reinterpret_as_uint64())
  } else {
    raise UnknownOpcode(op)
  }
}

fn check_reg(reg : Int) -> Unit raise BpfError {
  if reg < 0 || reg > 10 {
    raise InvalidRegister(reg)
  }
}

fn check_dst(reg : Int) -> Unit raise BpfError {
  check_reg(reg)
  if reg == 10 {
    raise InvalidRegister(reg)
  }
}

fn jump_taken(op : Int, dst : UInt64, src : UInt64) -> Bool {
  if op == 0x15 {
    dst.equal(src)
  } else if op == 0x1d {
    dst.equal(src)
  } else if op == 0x25 {
    dst > src
  } else if op == 0x2d {
    dst > src
  } else if op == 0x35 {
    dst >= src
  } else if op == 0x3d {
    dst >= src
  } else if op == 0x45 {
    !dst.land(src).equal(0UL)
  } else if op == 0x4d {
    !dst.land(src).equal(0UL)
  } else if op == 0x55 {
    !dst.equal(src)
  } else if op == 0x5d {
    !dst.equal(src)
  } else if op == 0x65 {
    dst.reinterpret_as_int64() > src.reinterpret_as_int64()
  } else if op == 0x6d {
    dst.reinterpret_as_int64() > src.reinterpret_as_int64()
  } else if op == 0x75 {
    dst.reinterpret_as_int64() >= src.reinterpret_as_int64()
  } else if op == 0x7d {
    dst.reinterpret_as_int64() >= src.reinterpret_as_int64()
  } else if op == 0xa5 {
    dst < src
  } else if op == 0xad {
    dst < src
  } else if op == 0xb5 {
    dst <= src
  } else if op == 0xbd {
    dst <= src
  } else if op == 0xc5 {
    dst.reinterpret_as_int64() < src.reinterpret_as_int64()
  } else if op == 0xcd {
    dst.reinterpret_as_int64() < src.reinterpret_as_int64()
  } else if op == 0xd5 {
    dst.reinterpret_as_int64() <= src.reinterpret_as_int64()
  } else if op == 0xdd {
    dst.reinterpret_as_int64() <= src.reinterpret_as_int64()
  } else {
    false
  }
}

fn helper_sum(vm : Vm, ptr : UInt64, len : Int) -> UInt64 raise BpfError {
  let mut total = 0UL
  for i in 0..<len {
    total = total.add(vm.load(ptr.add(i.to_uint64()), 1))
  }
  total
}

pub fn execute(
  program : Array[Insn],
  input : Array[Int],
  max_steps : Int,
) -> UInt64 raise BpfError {
  let vm = Vm::new(input, max_steps)
  let mut pc = 0
  while pc < program.length() {
    vm.steps = vm.steps + 1
    if vm.steps > vm.max_steps {
      raise StepBudgetExceeded
    }
    let ins = program[pc]
    let op = ins.op
    let mut next_pc = pc + 1
    // ALU64 register forms have the 0x08 source bit set.
    if op == 0x07 || op == 0x0f || op == 0x17 || op == 0x1f ||
      op == 0x27 || op == 0x2f || op == 0x37 || op == 0x3f ||
      op == 0x47 || op == 0x4f || op == 0x57 || op == 0x5f ||
      op == 0x67 || op == 0x6f || op == 0x77 || op == 0x7f ||
      op == 0x87 || op == 0x97 || op == 0x9f || op == 0xa7 ||
      op == 0xaf || op == 0xb7 || op == 0xbf || op == 0xc7 || op == 0xcf {
      check_dst(ins.dst)
      let src = if (op & 0x08) != 0 {
        check_reg(ins.src)
        vm.regs[ins.src]
      } else {
        imm_u64(ins.imm)
      }
      vm.regs[ins.dst] = alu64(op & 0xf7, vm.regs[ins.dst], src)
    } else if op == 0x04 || op == 0x0c || op == 0x14 || op == 0x1c ||
      op == 0x24 || op == 0x2c || op == 0x34 || op == 0x3c ||
      op == 0x44 || op == 0x4c || op == 0x54 || op == 0x5c ||
      op == 0x64 || op == 0x6c || op == 0x74 || op == 0x7c ||
      op == 0x84 || op == 0x94 || op == 0x9c || op == 0xa4 ||
      op == 0xac || op == 0xb4 || op == 0xbc || op == 0xc4 || op == 0xcc {
      check_dst(ins.dst)
      let src = if (op & 0x08) != 0 {
        check_reg(ins.src)
        vm.regs[ins.src]
      } else {
        imm_u64(ins.imm)
      }
      vm.regs[ins.dst] = alu32(op & 0xf7, vm.regs[ins.dst], src)
    } else if op == 0x61 || op == 0x69 || op == 0x71 || op == 0x79 {
      check_dst(ins.dst)
      check_reg(ins.src)
      let size = if op == 0x61 {
        4
      } else if op == 0x69 {
        2
      } else if op == 0x71 {
        1
      } else {
        8
      }
      let addr = vm.regs[ins.src].add(imm_u64(ins.off))
      vm.regs[ins.dst] = vm.load(addr, size)
    } else if op == 0x63 || op == 0x6b || op == 0x73 || op == 0x7b {
      check_reg(ins.dst)
      check_reg(ins.src)
      let size = if op == 0x63 {
        4
      } else if op == 0x6b {
        2
      } else if op == 0x73 {
        1
      } else {
        8
      }
      let addr = vm.regs[ins.dst].add(imm_u64(ins.off))
      vm.store(addr, size, vm.regs[ins.src])
    } else if op == 0x62 || op == 0x6a || op == 0x72 || op == 0x7a {
      check_reg(ins.dst)
      let size = if op == 0x62 {
        4
      } else if op == 0x6a {
        2
      } else if op == 0x72 {
        1
      } else {
        8
      }
      let addr = vm.regs[ins.dst].add(imm_u64(ins.off))
      vm.store(addr, size, imm_u64(ins.imm))
    } else if op == 0x05 {
      next_pc = pc + 1 + ins.off
    } else if op == 0x15 || op == 0x1d || op == 0x25 || op == 0x2d ||
      op == 0x35 || op == 0x3d || op == 0x45 || op == 0x4d ||
      op == 0x55 || op == 0x5d || op == 0x65 || op == 0x6d ||
      op == 0x75 || op == 0x7d || op == 0xa5 || op == 0xad ||
      op == 0xb5 || op == 0xbd || op == 0xc5 || op == 0xcd ||
      op == 0xd5 || op == 0xdd {
      check_reg(ins.dst)
      let src = if (op & 0x08) != 0 {
        check_reg(ins.src)
        vm.regs[ins.src]
      } else {
        imm_u64(ins.imm)
      }
      if jump_taken(op, vm.regs[ins.dst], src) {
        next_pc = pc + 1 + ins.off
      }
    } else if op == 0x85 {
      if ins.imm == HELPER_SUM {
        check_reg(1)
        check_reg(2)
        let len = vm.regs[2].to_int()
        if len < 0 || len > 1048576 {
          raise MemoryAccess(vm.regs[1], len)
        }
        vm.regs[0] = helper_sum(vm, vm.regs[1], len)
      } else {
        raise UnknownHelper(ins.imm)
      }
    } else if op == 0x95 {
      return vm.regs[0]
    } else if op == 0x18 {
      check_dst(ins.dst)
      if pc + 1 >= program.length() {
        raise InvalidProgram(pc)
      }
      let hi = program[pc + 1].imm
      vm.regs[ins.dst] = low32(imm_u64(ins.imm)).lor(
        low32(imm_u64(hi)).shl(32),
      )
      next_pc = pc + 2
    } else {
      raise UnknownOpcode(op)
    }
    if next_pc < 0 || next_pc > program.length() {
      raise InvalidProgram(next_pc)
    }
    pc = next_pc
  }
  raise InvalidProgram(pc)
}

pub fn run_default(program : Array[Insn], input : Array[Int]) -> UInt64 raise BpfError {
  execute(program, input, 10000)
}
