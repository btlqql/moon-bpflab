# eBPF ISA 兼容终点（2026-10-25）

本项目不再以“只支持一个指令子集”为终点。明确目标是：

> **覆盖 eBPF ISA v1.0 的核心指令语义**，以 RFC 9669（BPF Instruction Set Architecture）和 [iovisor/ubpf](https://github.com/iovisor/ubpf) 提交 `8d2dd3580ab80f9b4a79a9d2fa2420aa38fc7521` 的解释器行为为参照；对每条纳入范围的指令给出输入、执行和输出证据。

## 兼容矩阵

| 类别 | 指令 | 状态 |
|---|---|---|
| ALU / ALU64 | add、sub、mul、div、or、and、lsh、rsh、neg、mod、xor、mov、arsh | 已实现 |
| 有符号 div/mod | `off == 1` 的 sdiv/smod（含 INT_MIN / -1 溢出与除零） | 已实现 |
| 除零/模零 | div 除零结果为 0；mod 除零保留被除数 | 已实现，与 uBPF/RFC 9669 一致 |
| JMP | ja、jeq、jgt、jge、jset、jne、jsgt、jsge、jlt、jle、jslt、jsle | 已实现 |
| JMP32 | ja32 与全部 32 位条件跳转（低位比较，含有符号/无符号） | 已实现 |
| LDX | ldxb/h/w/dw | 已实现 |
| LDX MEMSX | ldxsb、ldxsh、ldxsw（符号扩展加载） | 已实现 |
| STX / ST | stxb/h/w/dw、stb/h/w/dw | 已实现 |
| END | le16/32/64、be16/32/64、bswap | 已实现 |
| LD_IMM64 | lddw（`src == 0`） | 已实现 |
| CALL | helper 调用；本地子程序调用，r6–r9 保存/恢复、返回栈、深度上限 | 已实现 |
| EXIT | 顶层返回 r0；子程序返回到调用点 | 已实现 |

## 输入输出案例

| 输入 | 期望输出 | 依据 |
|---|---|---|
| `mov32 r0, 1; div r0, 0; exit` | `0` | uBPF `div64-by-zero-imm.data`；RFC 9669 |
| `mov32 r0, 1; mod32 r0, 0; exit` | `1` | uBPF `mod-by-zero-imm.data`；RFC 9669 |
| `lddw r0, 0xfffffffffffffff3; sdiv r0, 4; exit` | `0xfffffffffffffffd`（-3） | uBPF `sdiv64-neg.data` |
| `lddw r0, 0x8000000000000000; mov r1, -1; sdiv r0, r1; exit` | `0x8000000000000000` | uBPF `sdiv64-overflow.data` |
| `lddw r0, 0x100000005; smod r0, 4; exit` | `1` | uBPF `smod64.data` |
| `lddw r0, 0xfffffffffffffff3; smod r0, 4; exit` | `0xffffffffffffffff`（-1） | uBPF `smod64-neg.data` |
| `mov32 r0, 15; sdiv32 r0, 4; exit` | `3` | uBPF `sdiv32.data` |
| `mov32 r0, 0x80000000; sdiv32 r0, -1; exit` | `0x80000000` | uBPF `sdiv32-overflow.data` |
| `ldxsw r0, [r1+2]; exit`，输入 `aa bb 01 00 00 80 cc dd` | `0xffffffff80000001` | uBPF `ldxsw.data` |
| `mov32 r0, -1; jgt32 r0, 0` | 跳转（无符号） | 本项目测试 |
| `mov32 r0, -1; jsgt32 r0, 0` | 不跳转（有符号） | 本项目测试 |
| `mov r0, 0x1122; be16 r0; exit` | `0x2211` | 本项目测试 |
| `mov r0, 0x12345678; le16 r0; exit` | `0x5678` | 本项目测试 |
| 调用子程序并让子程序改写 r6，调用方读 r6 | 恢复为调用前的值 | 本项目测试 |

## 验证

- `moon test` 共 38 项，覆盖上述输入输出、错误路径、调试器和 ELF。
- uBPF 差分：原始 6 组向量 + div/mod 零、sdiv/smod、sdiv32、ldxsw 等新增向量，结果见 [ubpf-conformance.md](ubpf-conformance.md)。
- GitHub Actions 四后端通过。

## 不在兼容终点内

- atomics、legacy packet load（`BPF_LD_ABS/IND`）、map fd 伪指令、BPF-to-BPF 的完整内核栈帧校验。
- verifier、BTF、CO-RE、重定位、JIT。
- 内核 helper 全集与生产级隔离。

这些是明确排除项，不是隐藏差异；申报书与 README 同步声明。
