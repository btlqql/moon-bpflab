// Node is used only for file IO. All decoding and execution runs in MoonBit.

extern "js" fn read_hex(path : String) -> String? =
  #| (path) => {
  #|   try {
  #|     const fs = process.getBuiltinModule('node:fs');
  #|     const buffer = fs.readFileSync(path);
  #|     if (buffer.length > 4194304) return undefined;
  #|     return buffer.toString('hex');
  #|   } catch { return undefined; }
  #| }

extern "js" fn stderr(text : String) -> Unit =
  #| (text) => { process.stderr.write(text + '\n'); }

extern "js" fn exit_code(code : Int) -> Unit =
  #| (code) => { process.exitCode = code; }

fn usage() -> Unit {
  println(
    "MoonBpfLab 0.1.0\n" +
    "Usage:\n" +
    "  bpflab disasm <file>                 disassemble raw BPF or ELF .text\n" +
    "  bpflab run <file> [input-hex] [--trace]\n" +
    "                                        execute and print r0\n" +
    "  bpflab elf <file>                    print ELF entry, text size and symbols\n" +
    "Inputs are offline files; no kernel verifier or bus is involved.",
  )
}

fn hex_byte(text : String) -> Array[Int]? {
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
        if c != 32 && c != 9 && c != 10 && c != 13 && c != 44 && c != 58 {
          return None
        }
      }
    }
  }
  if high >= 0 {
    None
  } else {
    Some(out)
  }
}

fn load_file(path : String) -> Array[Int]? {
  match read_hex(path) {
    Some(text) => hex_byte(text)
    None => None
  }
}

fn load_program(bytes : Array[Int]) -> Array[@bpf.Insn]? {
  try {
    if @bpf.is_elf(bytes) {
      Some(@bpf.load_elf(bytes).text)
    } else {
      Some(@bpf.decode_instructions(bytes))
    }
  } catch {
    _ => None
  }
}

fn dec_parse(text : String) -> Int? {
  if text.length() == 0 {
    return None
  }
  let mut value = 0
  for i in 0..<text.length() {
    let c = text[i].to_int()
    if c < 48 || c > 57 {
      return None
    }
    value = value * 10 + (c - 48)
  }
  Some(value)
}

fn parse_u64(text : String) -> UInt64? {
  let body = if text.has_prefix("0x") || text.has_prefix("0X") {
    text.substring(start=2)
  } else {
    text
  }
  match hex_byte(body) {
    Some(bytes) =>
      if bytes.length() == 0 || bytes.length() > 8 {
        None
      } else {
        let mut value = 0UL
        for b in bytes {
          value = value.shl(8).lor(b.to_uint64())
        }
        Some(value)
      }
    None => None
  }
}

fn run() -> Unit {
  let args = @env.args()
  if args.length() < 3 {
    usage()
    return
  }
  let command = args[2]
  if command == "help" || command == "--help" {
    usage()
  } else if command == "disasm" && args.length() == 4 {
    match load_file(args[3]) {
      Some(bytes) =>
        match load_program(bytes) {
          Some(program) => {
            let lines = @bpf.disassemble_with_targets(program)
            for i in 0..<lines.length() {
              println(i.to_string() + ": " + lines[i])
            }
          }
          None => {
            stderr("ERROR: file is neither raw BPF nor a supported ELF")
            exit_code(1)
          }
        }
      None => {
        stderr("ERROR: cannot read file")
        exit_code(2)
      }
    }
  } else if command == "run" && args.length() >= 4 {
    let mut input : Array[Int] = []
    let mut trace = false
    let mut show_coverage = false
    let mut break_pc = -1
    let mut has_condition = false
    let mut condition_pc = -1
    let mut condition_reg = -1
    let mut condition_value = 0UL
    let mut i = 4
    while i < args.length() {
      if args[i] == "--trace" {
        trace = true
        i = i + 1
      } else if args[i] == "--coverage" {
        show_coverage = true
        i = i + 1
      } else if args[i] == "--break" && i + 1 < args.length() {
        match dec_parse(args[i + 1]) {
          Some(value) => break_pc = value
          None => {
            stderr("ERROR: --break expects a decimal pc")
            exit_code(2)
            return
          }
        }
        i = i + 2
      } else if args[i] == "--when" && i + 1 < args.length() {
        let parts = args[i + 1].split(":").to_array()
        if parts.length() != 3 {
          stderr("ERROR: --when expects pc:reg:hex-value")
          exit_code(2)
          return
        }
        let pc = match dec_parse(parts[0].to_string()) {
          Some(value) => value
          None => {
            stderr("ERROR: invalid --when pc")
            exit_code(2)
            return
          }
        }
        let reg = match dec_parse(parts[1].to_string()) {
          Some(value) => value
          None => {
            stderr("ERROR: invalid --when register")
            exit_code(2)
            return
          }
        }
        let value = match parse_u64(parts[2].to_string()) {
          Some(v) => v
          None => {
            stderr("ERROR: invalid --when value")
            exit_code(2)
            return
          }
        }
        has_condition = true
        condition_pc = pc
        condition_reg = reg
        condition_value = value
        i = i + 2
      } else {
        match hex_byte(args[i]) {
          Some(bytes) => input = bytes
          None => {
            stderr("ERROR: input must be a hex string")
            exit_code(2)
            return
          }
        }
        i = i + 1
      }
    }
    match load_file(args[3]) {
      Some(bytes) =>
        match load_program(bytes) {
          Some(program) => {
            let machine = @bpf.Machine::new_default(program, input)
            if break_pc >= 0 {
              machine.set_breakpoint(break_pc)
            }
            if has_condition {
              let configured = try {
                machine.set_conditional_breakpoint(
                  condition_pc, condition_reg, condition_value,
                )
                true
              } catch {
                _ => false
              }
              if !configured {
                stderr("ERROR: invalid conditional breakpoint")
                exit_code(1)
                return
              }
            }
            if break_pc >= 0 || has_condition {
              let outcome = try {
                Some(machine.run_until_break())
              } catch {
                _ => {
                  stderr("ERROR: execution failed")
                  exit_code(1)
                  None
                }
              }
              match outcome {
                Some(result) =>
                  match result {
                    @bpf.BreakpointHit(pc) => {
                      let snap = machine.snapshot()
                      println("breakpoint pc=" + pc.to_string())
                      println("r0=0x" + snap.regs[0].to_string(radix=16))
                    }
                    @bpf.Halted(value) =>
                      println(
                        "r0=0x" + value.to_string(radix=16) + " (" +
                        value.to_string() + ")",
                      )
                    @bpf.Continue => ()
                  }
                None => ()
              }
              return
            }
            if trace {
              let mut done = false
              while !done {
                let snap = machine.snapshot()
                if snap.halted {
                  done = true
                } else if snap.pc >= 0 && snap.pc < program.length() {
                  println(
                    "pc=" + snap.pc.to_string() + " " +
                    @bpf.disassemble_one(program[snap.pc]) + " r0=" +
                    snap.regs[0].to_string(radix=16),
                  )
                  let outcome = try {
                    Some(machine.step())
                  } catch {
                    _ => {
                      stderr("ERROR: execution failed")
                      exit_code(1)
                      None
                    }
                  }
                  match outcome {
                    Some(result) =>
                      match result {
                        @bpf.Continue => ()
                        @bpf.Halted(_) => done = true
                        @bpf.BreakpointHit(pc) => {
                          println("breakpoint " + pc.to_string())
                          done = true
                        }
                      }
                    None => done = true
                  }
                } else {
                  done = true
                }
              }
            }
            try {
              let result = machine.run()
              println("r0=0x" + result.to_string(radix=16) + " (" + result.to_string() + ")")
              if show_coverage {
                let counts = machine.coverage()
                for pc in 0..<counts.length() {
                  if counts[pc] > 0 {
                    println("coverage pc=" + pc.to_string() + " count=" + counts[pc].to_string())
                  }
                }
              }
            } catch {
              err => {
                stderr("ERROR: execution or ELF decode failed")
                exit_code(1)
              }
            }
          }
          None => {
            stderr("ERROR: file is neither raw BPF nor a supported ELF")
            exit_code(1)
          }
        }
      None => {
        stderr("ERROR: cannot read file")
        exit_code(2)
      }
    }
  } else if command == "elf" && args.length() == 4 {
    match load_file(args[3]) {
      Some(bytes) =>
        try {
          let image = @bpf.load_elf(bytes)
          println("entry=" + image.entry.to_string())
          println("text_instructions=" + image.text.length().to_string())
          for section in image.sections {
            println(
              "section " + section.name + " type=" + section.typ.to_string() +
              " size=" + section.size.to_string() + " offset=" +
              section.offset.to_string(),
            )
          }
          for symbol in image.symbols {
            println(
              "symbol " + symbol.name + " value=" + symbol.value.to_string() +
              " size=" + symbol.size.to_string(),
            )
          }
        } catch {
          err => {
            stderr("ERROR: execution or ELF decode failed")
            exit_code(1)
          }
        }
      None => {
        stderr("ERROR: cannot read file")
        exit_code(2)
      }
    }
  } else {
    usage()
    exit_code(2)
  }
}

///|
fn main {
  run()
}
