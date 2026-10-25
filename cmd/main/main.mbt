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
    for i in 4..<args.length() {
      if args[i] == "--trace" {
        trace = true
      } else {
        match hex_byte(args[i]) {
          Some(bytes) => input = bytes
          None => {
            stderr("ERROR: input must be a hex string")
            exit_code(2)
            return
          }
        }
      }
    }
    match load_file(args[3]) {
      Some(bytes) =>
        match load_program(bytes) {
          Some(program) => {
            let machine = @bpf.Machine::new_default(program, input)
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
