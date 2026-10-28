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
  CallDepthExceeded
  UnsupportedCallMode(Int)
  UnsupportedMapFd
  UnknownMap(Int)
  MapFull(Int)
  MapKeyError(Int)
}

const INPUT_BASE : UInt64 = 0x10000UL
const STACK_BASE : UInt64 = 0x20000UL
const STACK_SIZE : Int = 512
const MAP_BASE : UInt64 = 0x30000UL
const MAP_SCRATCH_SIZE : Int = 1024
const HELPER_SUM : Int = 1
const HELPER_MAP_LOOKUP : Int = 2
const HELPER_MAP_UPDATE : Int = 3
const HELPER_MAP_DELETE : Int = 4

pub fn insn(op : Int, dst : Int, src : Int, off : Int, imm : Int) -> Insn {
  { op, dst, src, off, imm }
}

fn imm_u64(imm : Int) -> UInt64 {
  imm.to_int64().to_uint64()
}

fn low32(x : UInt64) -> UInt64 {
  x.land(0xffffffffUL)
}

fn sign_extend_n(x : UInt64, bits : Int) -> UInt64 {
  let shift = 64 - bits
  x.shl(shift).reinterpret_as_int64().shr(shift).reinterpret_as_uint64()
}

fn sign_extend_low32(x : UInt64) -> UInt64 {
  // Shift the low 32 bits into the high half, arithmetic-shift back.
  x.shl(32).reinterpret_as_int64().shr(32).reinterpret_as_uint64()
}

fn bswap64(x : UInt64) -> UInt64 {
  x.shl(56).land(0xff00000000000000UL).lor(
    x.shl(40).land(0x00ff000000000000UL),
  ).lor(
    x.shl(24).land(0x0000ff0000000000UL),
  ).lor(
    x.shl(8).land(0x000000ff00000000UL),
  ).lor(
    x.shr(8).land(0x00000000ff000000UL),
  ).lor(
    x.shr(24).land(0x0000000000ff0000UL),
  ).lor(
    x.shr(40).land(0x000000000000ff00UL),
  ).lor(x.shr(56))
}

fn bswap16(x : UInt64) -> UInt64 {
  low32(x).land(0xffffUL).shl(8).lor(low32(x).land(0xffffUL).shr(8)).land(0xffffUL)
}

fn bswap32(x : UInt64) -> UInt64 {
  low32(x).shl(24).land(0xff000000UL).lor(
    low32(x).shl(8).land(0x00ff0000UL),
  ).lor(
    low32(x).shr(8).land(0x0000ff00UL),
  ).lor(low32(x).shr(24).land(0x000000ffUL))
}

fn endian_op(op : Int, value : UInt64, width : Int) -> UInt64 {
  if op == 0xd4 {
    // Little-endian conversion on a little-endian value is truncation.
    if width == 16 {
      low32(value).land(0xffffUL)
    } else if width == 32 {
      low32(value)
    } else {
      value
    }
  } else if op == 0xdc {
    if width == 16 {
      bswap16(value)
    } else if width == 32 {
      bswap32(value)
    } else {
      bswap64(value)
    }
  } else {
    bswap64(value)
  }
}

pub(all) struct ArrayMap {
  key_size : Int
  value_size : Int
  max_entries : Int
  mut keys : Array[Array[Int]]
  mut values : Array[Array[Int]]
}

pub(all) struct Vm {
  regs : Array[UInt64]
  input : Array[Int]
  stack : Array[Int]
  maps : Array[ArrayMap]
  map_scratch : Array[Int]
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
  let maps : Array[ArrayMap] = Array::new()
  let map_scratch : Array[Int] = Array::new()
  for _ in 0..<MAP_SCRATCH_SIZE {
    map_scratch.push(0)
  }
  { regs, input, stack, maps, map_scratch, steps: 0, max_steps }
}

pub fn Vm::add_array_map(
  self : Vm,
  key_size : Int,
  value_size : Int,
  max_entries : Int,
) -> Int raise BpfError {
  if key_size <= 0 || value_size <= 0 || max_entries <= 0 {
    raise MapKeyError(0)
  }
  if value_size > MAP_SCRATCH_SIZE {
    raise MapFull(value_size)
  }
  let keys : Array[Array[Int]] = Array::new()
  let values : Array[Array[Int]] = Array::new()
  self.maps.push({ key_size, value_size, max_entries, keys, values })
  self.maps.length() - 1
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
  if in_range(addr, MAP_BASE, self.map_scratch.length(), size) {
    return load_from(self.map_scratch, addr.sub(MAP_BASE).to_int(), size)
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
  if in_range(addr, MAP_BASE, self.map_scratch.length(), size) {
    store_to(self.map_scratch, addr.sub(MAP_BASE).to_int(), size, value)
    return
  }
  raise MemoryAccess(addr, size)
}

let int64_min : Int64 = 0x8000000000000000L
let int32_min : Int64 = -2147483648L

fn div64(dst : UInt64, src : UInt64, signed_op : Bool) -> UInt64 {
  if src.equal(0UL) {
    0UL
  } else if signed_op {
    let a = dst.reinterpret_as_int64()
    let b = src.reinterpret_as_int64()
    if a.equal(int64_min) && b.equal(-1L) {
      dst
    } else {
      (a / b).reinterpret_as_uint64()
    }
  } else {
    dst.div(src)
  }
}

fn mod64(dst : UInt64, src : UInt64, signed_op : Bool) -> UInt64 {
  if src.equal(0UL) {
    dst
  } else if signed_op {
    let a = dst.reinterpret_as_int64()
    let b = src.reinterpret_as_int64()
    if a.equal(int64_min) && b.equal(-1L) {
      0UL
    } else {
      (a % b).reinterpret_as_uint64()
    }
  } else {
    dst.mod(src)
  }
}

fn div32(dst : UInt64, src : UInt64, signed_op : Bool) -> UInt64 {
  let d = low32(dst)
  let s = low32(src)
  if s.equal(0UL) {
    0UL
  } else if signed_op {
    let a = sign_extend_low32(d).reinterpret_as_int64()
    let b = sign_extend_low32(s).reinterpret_as_int64()
    if a.equal(int32_min) && b.equal(-1L) {
      low32(0x80000000UL)
    } else {
      low32((a / b).reinterpret_as_uint64())
    }
  } else {
    low32(d.div(s))
  }
}

fn mod32(dst : UInt64, src : UInt64, signed_op : Bool) -> UInt64 {
  let d = low32(dst)
  let s = low32(src)
  if s.equal(0UL) {
    d
  } else if signed_op {
    let a = sign_extend_low32(d).reinterpret_as_int64()
    let b = sign_extend_low32(s).reinterpret_as_int64()
    if a.equal(int32_min) && b.equal(-1L) {
      0UL
    } else {
      low32((a % b).reinterpret_as_uint64())
    }
  } else {
    low32(d.mod(s))
  }
}

fn alu64(
  op : Int,
  dst : UInt64,
  src : UInt64,
  signed_op : Bool,
) -> UInt64 raise BpfError {
  if op == 0x07 {
    dst.add(src)
  } else if op == 0x17 {
    dst.sub(src)
  } else if op == 0x27 {
    dst.mul(src)
  } else if op == 0x37 {
    div64(dst, src, signed_op)
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
    mod64(dst, src, signed_op)
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

fn alu32(
  op : Int,
  dst : UInt64,
  src : UInt64,
  signed_op : Bool,
) -> UInt64 raise BpfError {
  let d = low32(dst)
  let s = low32(src)
  if op == 0x04 {
    low32(d.add(s))
  } else if op == 0x14 {
    low32(d.sub(s))
  } else if op == 0x24 {
    low32(d.mul(s))
  } else if op == 0x34 {
    div32(dst, src, signed_op)
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
    mod32(dst, src, signed_op)
  } else if op == 0xa4 {
    low32(d.lxor(s))
  } else if op == 0xb4 {
    s
  } else if op == 0xc4 {
    low32(
      sign_extend_low32(d).reinterpret_as_int64().shr(s.to_int() & 31).reinterpret_as_uint64(),
    )
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

fn is_jmp32(op : Int) -> Bool {
  op == 0x06 || op == 0x16 || op == 0x1e || op == 0x26 || op == 0x2e ||
  op == 0x36 || op == 0x3e || op == 0x46 || op == 0x4e || op == 0x56 ||
  op == 0x5e || op == 0x66 || op == 0x6e || op == 0x76 || op == 0x7e ||
  op == 0xa6 || op == 0xae || op == 0xb6 || op == 0xbe || op == 0xc6 ||
  op == 0xce || op == 0xd6 || op == 0xde
}

fn jump_taken32(op : Int, dst : UInt64, src : UInt64) -> Bool {
  let d = low32(dst)
  let s = low32(src)
  if op == 0x16 || op == 0x1e {
    d.equal(s)
  } else if op == 0x26 || op == 0x2e {
    d > s
  } else if op == 0x36 || op == 0x3e {
    d >= s
  } else if op == 0x46 || op == 0x4e {
    !d.land(s).equal(0UL)
  } else if op == 0x56 || op == 0x5e {
    !d.equal(s)
  } else if op == 0x66 || op == 0x6e {
    sign_extend_low32(d).reinterpret_as_int64() >
      sign_extend_low32(s).reinterpret_as_int64()
  } else if op == 0x76 || op == 0x7e {
    sign_extend_low32(d).reinterpret_as_int64() >=
      sign_extend_low32(s).reinterpret_as_int64()
  } else if op == 0xa6 || op == 0xae {
    d < s
  } else if op == 0xb6 || op == 0xbe {
    d <= s
  } else if op == 0xc6 || op == 0xce {
    sign_extend_low32(d).reinterpret_as_int64() <
      sign_extend_low32(s).reinterpret_as_int64()
  } else if op == 0xd6 || op == 0xde {
    sign_extend_low32(d).reinterpret_as_int64() <=
      sign_extend_low32(s).reinterpret_as_int64()
  } else {
    false
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

fn read_mem(vm : Vm, addr : UInt64, size : Int) -> Array[Int] raise BpfError {
  let out : Array[Int] = Array::new()
  for i in 0..<size {
    out.push(vm.load(addr.add(i.to_uint64()), 1).to_int())
  }
  out
}

fn bytes_equal(a : Array[Int], b : Array[Int]) -> Bool {
  if a.length() != b.length() {
    return false
  }
  for i in 0..<a.length() {
    if a[i] != b[i] {
      return false
    }
  }
  true
}

fn map_index(vm : Vm, index : Int) -> ArrayMap raise BpfError {
  if index < 0 || index >= vm.maps.length() {
    raise UnknownMap(index)
  }
  vm.maps[index]
}

fn find_key(map : ArrayMap, key : Array[Int]) -> Int {
  for i in 0..<map.keys.length() {
    if bytes_equal(map.keys[i], key) {
      return i
    }
  }
  -1
}

fn helper_map_lookup(vm : Vm, index : Int, key_ptr : UInt64) -> UInt64 raise BpfError {
  let map = map_index(vm, index)
  let key = read_mem(vm, key_ptr, map.key_size)
  let slot = find_key(map, key)
  if slot < 0 {
    0UL
  } else {
    let value = map.values[slot]
    for i in 0..<value.length() {
      vm.map_scratch[i] = value[i]
    }
    MAP_BASE
  }
}

fn helper_map_update(
  vm : Vm,
  index : Int,
  key_ptr : UInt64,
  value_ptr : UInt64,
  flags : Int,
) -> UInt64 raise BpfError {
  let map = map_index(vm, index)
  let key = read_mem(vm, key_ptr, map.key_size)
  let value = read_mem(vm, value_ptr, map.value_size)
  let slot = find_key(map, key)
  if slot >= 0 {
    if flags == 1 {
      raise MapKeyError(flags)
    }
    map.values[slot] = value
  } else {
    if flags == 2 {
      raise MapKeyError(flags)
    }
    if map.keys.length() >= map.max_entries {
      raise MapFull(index)
    }
    map.keys.push(key)
    map.values.push(value)
  }
  0UL
}

fn helper_map_delete(vm : Vm, index : Int, key_ptr : UInt64) -> UInt64 raise BpfError {
  let map = map_index(vm, index)
  let key = read_mem(vm, key_ptr, map.key_size)
  let slot = find_key(map, key)
  if slot < 0 {
    raise MapKeyError(index)
  }
  for i in slot..<(map.keys.length() - 1) {
    map.keys[i] = map.keys[i + 1]
    map.values[i] = map.values[i + 1]
  }
  ignore(map.keys.pop())
  ignore(map.values.pop())
  0UL
}

pub fn execute(
  program : Array[Insn],
  input : Array[Int],
  max_steps : Int,
) -> UInt64 raise BpfError {
  Machine::new(program, input, max_steps).run()
}

pub fn run_default(program : Array[Insn], input : Array[Int]) -> UInt64 raise BpfError {
  execute(program, input, 10000)
}
