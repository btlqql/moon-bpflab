# MoonBpfLab

用户态 BPF 执行与调试工具：加载原始字节码或 ELF `.text`，反汇编、单步、设断点、查看寄存器与内存，并执行受限指令集。

- 仓库：https://github.com/btlqql/moon-bpflab
- 版本：0.1.2
- 许可证：Apache-2.0

## 为什么单独做这一层

MoonCakes 上已有 [hevienz/moonbit_libbpf](https://mooncakes.io/docs/hevienz/moonbit_libbpf)，它把 libbpf 绑定给 MoonBit，调用的是内核/宿主能力。MoonBpfLab 的方向相反：**在 MoonBit 内解释并调试指令**，不把执行转发给 C 库或内核。

2026-10-24 在 MoonCakes 搜索 `bpf` 只找到 libbpf 绑定和沙箱规划器，未发现用户态 BPF 虚拟机/调试器。搜索未命中不等于绝对不存在，私有实现和不同命名仍是盲区。

## 功能

- **指令执行**：ALU32/ALU64、JMP/JMP32、LDX（含符号扩展 MEMSX）、STX/ST、END/BSWAP、LD_IMM64、CALL、EXIT。
- **64 位语义**：位模式运算、32 位结果零扩展、算术/逻辑右移、有符号与无符号比较；除零返回 0、模零保留被除数，有符号 div/mod 按 RFC 9669。
- **内存模型**：只读输入区、可写栈区、map 值暂存区；越界访问拒绝。
- **调试器**：`Machine::step()`、断点、条件断点（寄存器等于指定值）、`run_until_break()`、寄存器快照、指令覆盖计数；CLI 暴露 `--break` 与 `--when`。
- **子程序调用**：`call` 带返回栈、调用深度上限，并保存/恢复 r6–r9；超限拒绝。
- **Array map**：lookup/update/delete helper，键值大小与容量检查。
- **ELF64 子集**：读取 little-endian ELF、`.text`、`.symtab`/`.strtab`，只接受 `EM_BPF`。
- **反汇编**：文本输出 ALU、内存、跳转、helper 调用和 64 位立即数，并标注跳转/调用目标。

## 标准兼容终点

目标是覆盖 eBPF ISA v1.0 的核心指令语义（ALU/ALU64、JMP/JMP32、LDX 含 MEMSX、STX/ST、END/BSWAP、LDDW、CALL、EXIT），参照 RFC 9669 与 uBPF 解释器。矩阵、输入输出案例和明确排除项见 [docs/isa-compatibility.md](docs/isa-compatibility.md)。

不在终点内：atomics、legacy packet load、map fd 伪指令、verifier、BTF、CO-RE、重定位、JIT。

## 快速开始

要求 MoonBit 工具链（本版本在 `moon 0.1.20260904` 验证）。CLI 以 JS 为目标，文件读取只使用 Node 内置模块。

```bash
moon test
moon run cmd/main --target js -- disasm examples/minimal.elf
moon run cmd/main --target js -- run examples/minimal.elf
moon run cmd/main --target js -- run examples/minimal.elf --trace
```

输出：

```text
0: mov64 r0, 42
1: exit
r0=0x2a (42)
```

## CLI

```text
bpflab disasm <file>                 disassemble with jump/call targets
bpflab run <file> [input-hex] [--trace]
                                      execute and print r0
bpflab elf <file>                    print entry, sections and symbols
```

`run` 的第二个参数是可选的十六进制输入，作为只读输入区；`--trace` 每步打印 pc、反汇编和 r0；`--break` 在指定 pc 停止；`--when` 在“pc 处且寄存器等于指定值”时停止；`--coverage` 输出每条指令的执行次数。

## 支持的指令

| 类别 | 指令 |
|---|---|
| ALU64 | add, sub, mul, div, or, and, lsh, rsh, neg, mod, xor, mov, arsh |
| ALU32 | 同上，结果零扩展到 64 位 |
| 跳转 | ja, jeq, jgt, jge, jset, jne, jsgt, jsge, jlt, jle, jslt, jsle |
| 内存 | ldxb/h/w/dw, stxb/h/w/dw, stb/h/w/dw |
| 其他 | lddw, call (helper 与本地子程序), exit |

helper 1 对输入/栈逐字节求和；helper 2/3/4 是 array map 的 lookup/update/delete。

## 测试

`moon test` 共 38 项：

- r0 返回、64 位溢出、32 位零扩展/回绕、有符号与无符号跳转分歧。
- 小端加载、输入只读、栈往返、越界拒绝。
- 除零/模零与有符号 div/mod、JMP32 有符号/无符号比较、END/BSWAP、符号扩展加载、r6–r9 调用保存。
- helper 求和。
- 反汇编 ALU/内存/跳转/helper；跳转与本地调用带目标地址。
- 单步、快照、断点、条件断点、指令覆盖计数、有界运行。
- 本地子程序调用、调用深度上限与 callee-saved 寄存器。
- array map update/lookup/delete。
- 最小 ELF 加载、原始字节码解码、坏 ELF 拒绝。
- uBPF 差分向量：arsh、early-exit、ldxb、factorial、div/mod 零、sdiv/smod、sdiv32、ldxsw 等一致；见 [docs/ubpf-conformance.md](docs/ubpf-conformance.md)。

GitHub Actions 在 wasm、wasm-gc、js、native 四个后端执行 check/build/test。

## 外部对照

- 已对 [iovisor/ubpf](https://github.com/iovisor/ubpf) 提交 `8d2dd35` 的多组向量做差分，包含除零、有符号 div/mod、MEMSX；结果见 [docs/ubpf-conformance.md](docs/ubpf-conformance.md)。
- 标准兼容终点与矩阵见 [docs/isa-compatibility.md](docs/isa-compatibility.md)。
- uBPF 测试向量来源与许可证见 [THIRD_PARTY.md](THIRD_PARTY.md)。
- 未运行 uBPF 本体：本机没有 C 编译器、Docker、WSL 发行版或 Rust 工具链。

## 明确不做

- 不是内核 verifier：不实现完整类型跟踪、有界循环证明、map 类型兼容矩阵或内核 helper 全集。
- 不实现 CO-RE、BTF、重定位、JIT、atomics、legacy packet load、map fd 伪指令，也不做完整内核栈帧校验。
- 只加载 ELF64 little-endian 的 `.text` 子集，不处理程序头、动态段、多段代码或伪 map fd。
- 不提供生产级隔离；执行器只用于离线工具和测试，不应用于运行不可信生产代码。
- array map 是固定容量模型，不含 hash map、per-CPU map、ring buffer 或并发语义。

## 后续

优先补：更多 ELF 段与重定位、BTF 子集、hash map、更多 helper、条件断点表达式、指令级 trace 导出、atomics/legacy 指令的明确拒绝测试。每项都要有真实编译产物和失败样例，再谈发布。
