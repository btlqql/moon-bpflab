// Single-step execution, breakpoints and map-aware helper dispatch.

pub(all) enum StepResult {
  Continue
  Halted(UInt64)
  BreakpointHit(Int)
}

pub(all) struct Snapshot {
  pc : Int
  steps : Int
  halted : Bool
  retval : UInt64
  regs : Array[UInt64]
}

pub(all) struct ConditionalBreak {
  pc : Int
  reg : Int
  value : UInt64
}

pub(all) struct Machine {
  program : Array[Insn]
  vm : Vm
  mut pc : Int
  mut steps : Int
  max_steps : Int
  mut halted : Bool
  mut retval : UInt64
  breakpoints : Array[Int]
  conditions : Array[ConditionalBreak]
  call_stack : Array[Int]
  executed : Array[Int]
  max_call_depth : Int
}

pub fn Machine::new(
  program : Array[Insn],
  input : Array[Int],
  max_steps : Int,
) -> Machine {
  {
    program,
    vm: Vm::new(input, max_steps),
    pc: 0,
    steps: 0,
    max_steps,
    halted: false,
    retval: 0UL,
    breakpoints: Array::new(),
    conditions: Array::new(),
    call_stack: Array::new(),
    executed: Array::new(),
    max_call_depth: 8,
  }
}

pub fn Machine::new_default(
  program : Array[Insn],
  input : Array[Int],
) -> Machine {
  Machine::new(program, input, 10000)
}

pub fn Machine::add_array_map(
  self : Machine,
  key_size : Int,
  value_size : Int,
  max_entries : Int,
) -> Int raise BpfError {
  self.vm.add_array_map(key_size, value_size, max_entries)
}

pub fn Machine::set_breakpoint(self : Machine, pc : Int) -> Unit {
  for existing in self.breakpoints {
    if existing == pc {
      return
    }
  }
  self.breakpoints.push(pc)
}

pub fn Machine::clear_breakpoints(self : Machine) -> Unit {
  while self.breakpoints.length() > 0 {
    ignore(self.breakpoints.pop())
  }
  while self.conditions.length() > 0 {
    ignore(self.conditions.pop())
  }
}

pub fn Machine::set_conditional_breakpoint(
  self : Machine,
  pc : Int,
  reg : Int,
  value : UInt64,
) -> Unit raise BpfError {
  check_reg(reg)
  self.conditions.push({ pc, reg, value })
}

fn is_breakpoint(self : Machine, pc : Int) -> Bool {
  for existing in self.breakpoints {
    if existing == pc {
      return true
    }
  }
  for condition in self.conditions {
    if condition.pc == pc && self.vm.regs[condition.reg].equal(condition.value) {
      return true
    }
  }
  false
}

pub fn Machine::snapshot(self : Machine) -> Snapshot {
  let regs : Array[UInt64] = Array::new()
  for value in self.vm.regs {
    regs.push(value)
  }
  {
    pc: self.pc,
    steps: self.steps,
    halted: self.halted,
    retval: self.retval,
    regs,
  }
}

pub fn Machine::coverage(self : Machine) -> Array[Int] {
  let out : Array[Int] = Array::new()
  for value in self.executed {
    out.push(value)
  }
  out
}

pub fn Machine::execution_count(self : Machine, pc : Int) -> Int {
  if pc < 0 || pc >= self.executed.length() {
    0
  } else {
    self.executed[pc]
  }
}

fn step_once(
  program : Array[Insn],
  vm : Vm,
  pc : Int,
  call_stack : Array[Int],
  max_call_depth : Int,
) -> (Int, UInt64?) raise BpfError {
  let ins = program[pc]
  let op = ins.op
  let mut next_pc = pc + 1
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
    vm.regs[ins.dst] = alu64(
      op & 0xf7, vm.regs[ins.dst], src, ins.off == 1,
    )
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
    vm.regs[ins.dst] = alu32(
      op & 0xf7, vm.regs[ins.dst], src, ins.off == 1,
    )
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
  } else if op == 0x06 {
    next_pc = pc + 1 + ins.off
  } else if is_jmp32(op) {
    check_reg(ins.dst)
    let src = if (op & 0x08) != 0 {
      check_reg(ins.src)
      vm.regs[ins.src]
    } else {
      imm_u64(ins.imm)
    }
    if jump_taken32(op, vm.regs[ins.dst], src) {
      next_pc = pc + 1 + ins.off
    }
  } else if op == 0x85 {
    if ins.src == 1 {
      if call_stack.length() >= max_call_depth {
        raise CallDepthExceeded
      }
      call_stack.push(pc + 1)
      next_pc = pc + 1 + ins.imm
    } else if ins.src != 0 {
      raise UnsupportedCallMode(ins.src)
    } else if ins.imm == HELPER_SUM {
      check_reg(1)
      check_reg(2)
      let len = vm.regs[2].to_int()
      if len < 0 || len > 1048576 {
        raise MemoryAccess(vm.regs[1], len)
      }
      vm.regs[0] = helper_sum(vm, vm.regs[1], len)
    } else if ins.imm == HELPER_MAP_LOOKUP {
      check_reg(1)
      check_reg(2)
      vm.regs[0] = helper_map_lookup(
        vm, vm.regs[1].to_int(), vm.regs[2],
      )
    } else if ins.imm == HELPER_MAP_UPDATE {
      check_reg(1)
      check_reg(2)
      check_reg(3)
      check_reg(4)
      vm.regs[0] = helper_map_update(
        vm, vm.regs[1].to_int(), vm.regs[2], vm.regs[3], vm.regs[4].to_int(),
      )
    } else if ins.imm == HELPER_MAP_DELETE {
      check_reg(1)
      check_reg(2)
      vm.regs[0] = helper_map_delete(
        vm, vm.regs[1].to_int(), vm.regs[2],
      )
    } else {
      raise UnknownHelper(ins.imm)
    }
  } else if op == 0x95 {
    if call_stack.length() > 0 {
      let ret = match call_stack.pop() {
        Some(value) => value
        None => pc + 1
      }
      return (ret, None)
    }
    return (pc, Some(vm.regs[0]))
  } else if op == 0x18 {
    check_dst(ins.dst)
    if ins.src != 0 {
      raise UnsupportedMapFd
    }
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
  (next_pc, None)
}

pub fn Machine::step(self : Machine) -> StepResult raise BpfError {
  if self.halted {
    return Halted(self.retval)
  }
  if self.pc < 0 || self.pc >= self.program.length() {
    raise InvalidProgram(self.pc)
  }
  self.steps = self.steps + 1
  if self.steps > self.max_steps {
    raise StepBudgetExceeded
  }
  while self.executed.length() <= self.pc {
    self.executed.push(0)
  }
  self.executed[self.pc] = self.executed[self.pc] + 1
  let (next, halt) = step_once(
    self.program, self.vm, self.pc, self.call_stack, self.max_call_depth,
  )
  self.pc = next
  match halt {
    Some(value) => {
      self.halted = true
      self.retval = value
      Halted(value)
    }
    None => Continue
  }
}

pub fn Machine::run(self : Machine) -> UInt64 raise BpfError {
  let mut done = false
  let mut result = 0UL
  while !done {
    match self.step() {
      Halted(value) => {
        result = value
        done = true
      }
      Continue => ()
      BreakpointHit(_) => ()
    }
  }
  result
}

pub fn Machine::run_n(self : Machine, limit : Int) -> StepResult raise BpfError {
  let mut count = 0
  while count < limit && !self.halted {
    ignore(self.step())
    count = count + 1
  }
  if self.halted {
    Halted(self.retval)
  } else {
    Continue
  }
}

pub fn Machine::run_until_break(self : Machine) -> StepResult raise BpfError {
  let mut done = false
  let mut result = BreakpointHit(self.pc)
  while !done {
    if !self.halted && self.is_breakpoint(self.pc) {
      result = BreakpointHit(self.pc)
      done = true
    } else {
      match self.step() {
        Halted(value) => {
          result = Halted(value)
          done = true
        }
        Continue => ()
        BreakpointHit(pc) => {
          result = BreakpointHit(pc)
          done = true
        }
      }
    }
  }
  result
}
