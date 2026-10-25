// Minimal ELF64 little-endian loader for BPF instruction sections.

pub(all) suberror ElfError {
  NotElf
  UnsupportedClass
  UnsupportedEndian
  UnsupportedMachine(Int)
  Truncated
  BadSection
  NoText
}

pub(all) struct ElfSymbol {
  name : String
  value : Int
  size : Int
  info : Int
}

pub(all) struct ElfSection {
  name : String
  typ : Int
  flags : Int
  offset : Int
  size : Int
}

pub(all) struct ElfImage {
  entry : Int
  text : Array[Insn]
  symbols : Array[ElfSymbol]
  sections : Array[ElfSection]
}

fn u8(bytes : Array[Int], off : Int) -> Int raise ElfError {
  if off < 0 || off >= bytes.length() {
    raise Truncated
  }
  bytes[off]
}

fn u16le(bytes : Array[Int], off : Int) -> Int raise ElfError {
  u8(bytes, off) | (u8(bytes, off + 1) << 8)
}

fn u32le(bytes : Array[Int], off : Int) -> Int64 raise ElfError {
  let mut value : Int64 = 0L
  for i in 0..<4 {
    value = value | (u8(bytes, off + i).to_int64() << (8 * i))
  }
  value
}

fn u64le(bytes : Array[Int], off : Int) -> Int64 raise ElfError {
  let low = u32le(bytes, off).land(0xffffffffL)
  let high = u32le(bytes, off + 4).land(0xffffffffL)
  low | (high << 32)
}

fn i32le(bytes : Array[Int], off : Int) -> Int raise ElfError {
  u32le(bytes, off).to_int()
}

fn i16le(bytes : Array[Int], off : Int) -> Int raise ElfError {
  let value = u16le(bytes, off)
  if value >= 0x8000 {
    value - 0x10000
  } else {
    value
  }
}

pub fn is_elf(bytes : Array[Int]) -> Bool {
  bytes.length() >= 4 && bytes[0] == 0x7f && bytes[1] == 0x45 &&
  bytes[2] == 0x4c && bytes[3] == 0x46
}

pub fn decode_instructions(bytes : Array[Int]) -> Array[Insn] raise ElfError {
  if bytes.length() % 8 != 0 {
    raise BadSection
  }
  let out : Array[Insn] = Array::new()
  let mut pos = 0
  while pos < bytes.length() {
    let op = bytes[pos]
    let regs = bytes[pos + 1]
    let dst = regs & 0x0f
    let src = (regs >> 4) & 0x0f
    let off = i16le(bytes, pos + 2)
    let imm = i32le(bytes, pos + 4)
    out.push({ op, dst, src, off, imm })
    pos = pos + 8
  }
  out
}

struct Section {
  name_off : Int
  typ : Int
  flags : Int
  offset : Int
  size : Int
}

fn section_at(
  bytes : Array[Int],
  shoff : Int,
  index : Int,
  shentsize : Int,
) -> Section raise ElfError {
  let base = shoff + index * shentsize
  if base + 64 > bytes.length() {
    raise Truncated
  }
  {
    name_off: u32le(bytes, base).to_int(),
    typ: u32le(bytes, base + 4).to_int(),
    flags: u64le(bytes, base + 8).to_int(),
    offset: u64le(bytes, base + 24).to_int(),
    size: u64le(bytes, base + 32).to_int(),
  }
}

fn section_name(strtab : Array[Int], offset : Int) -> String {
  let out = StringBuilder()
  let mut i = offset
  while i >= 0 && i < strtab.length() && strtab[i] != 0 {
    out.write_char(Char::from_int(strtab[i]))
    i = i + 1
  }
  out.to_string()
}

fn slice(bytes : Array[Int], start : Int, size : Int) -> Array[Int] raise ElfError {
  if start < 0 || size < 0 || start + size > bytes.length() {
    raise Truncated
  }
  let out : Array[Int] = Array::new()
  for i in 0..<size {
    out.push(bytes[start + i])
  }
  out
}

pub fn load_elf(bytes : Array[Int]) -> ElfImage raise ElfError {
  if !is_elf(bytes) {
    raise NotElf
  }
  if u8(bytes, 4) != 2 {
    raise UnsupportedClass
  }
  if u8(bytes, 5) != 1 {
    raise UnsupportedEndian
  }
  let machine = u16le(bytes, 18)
  if machine != 247 {
    raise UnsupportedMachine(machine)
  }
  let entry = u64le(bytes, 24).to_int()
  let shoff = u64le(bytes, 40).to_int()
  let shentsize = u16le(bytes, 58)
  let shnum = u16le(bytes, 60)
  let shstrndx = u16le(bytes, 62)
  if shentsize < 64 || shnum == 0 || shstrndx >= shnum {
    raise BadSection
  }
  if shoff + shnum * shentsize > bytes.length() {
    raise Truncated
  }
  let shstr = section_at(bytes, shoff, shstrndx, shentsize)
  let strtab = slice(bytes, shstr.offset, shstr.size)
  let mut text_bytes : Array[Int]? = None
  let mut symtab : Section? = None
  let mut symstr : Section? = None
  let sections : Array[ElfSection] = Array::new()
  for i in 0..<shnum {
    let section = section_at(bytes, shoff, i, shentsize)
    let name = section_name(strtab, section.name_off)
    if name.length() > 0 && section.typ != 0 {
      sections.push({
        name,
        typ: section.typ,
        flags: section.flags,
        offset: section.offset,
        size: section.size,
      })
    }
    if name == ".text" {
      text_bytes = Some(slice(bytes, section.offset, section.size))
    } else if name == ".symtab" {
      symtab = Some(section)
    } else if name == ".strtab" {
      symstr = Some(section)
    }
  }
  let text = match text_bytes {
    Some(raw) => decode_instructions(raw)
    None => raise NoText
  }
  let symbols : Array[ElfSymbol] = Array::new()
  match (symtab, symstr) {
    (Some(table), Some(names)) => {
      let names_bytes = slice(bytes, names.offset, names.size)
      let count = table.size / 24
      for i in 0..<count {
        let base = table.offset + i * 24
        if base + 24 <= bytes.length() {
          let name_off = u32le(bytes, base).to_int()
          let name = section_name(names_bytes, name_off)
          if name.length() > 0 {
            symbols.push({
              name,
              value: u64le(bytes, base + 8).to_int(),
              size: u64le(bytes, base + 16).to_int(),
              info: u8(bytes, base + 4),
            })
          }
        }
      }
    }
    _ => ()
  }
  { entry, text, symbols, sections }
}
