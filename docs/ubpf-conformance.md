# uBPF 差分对照（2026-10-25）

参考实现：[iovisor/ubpf](https://github.com/iovisor/ubpf)，提交 `8d2dd3580ab80f9b4a79a9d2fa2420aa38fc7521`，Apache-2.0。只取测试向量中的汇编语义，翻译成 MoonBpfLab 的 `Insn`，未复制源码。兼容终点见 [isa-compatibility.md](isa-compatibility.md)。

## 通过的向量

| uBPF 用例 | 语义 | uBPF 期望 | MoonBpfLab |
|---|---|---|---|
| `arsh.data` | 32 位算术右移 | `0xffff8000` | 一致 |
| `arsh64.data` | 64 位算术右移 + 寄存器移位 | `0xfffffffffffffff8` | 一致 |
| `early-exit.data` | 首条 `exit` 后停止 | `0x3` | 一致 |
| `ldxb-0offset.data` | 单字节加载 + 指针算术 | `0x6` | 一致 |
| `ldxb-small-offset.data` | 正偏移单字节加载 | `0x5` | 一致 |
| `factorial.data` | 本地子程序调用 + 循环 | `0x21c3677c82b40000` | 一致 |
| `div64-by-zero-imm.data` | 64 位除零返回 0 | `0x0` | 一致 |
| `mod-by-zero-imm.data` | 32 位模零保留被除数 | `0x1` | 一致 |
| `sdiv64.data` | 有符号 64 位除法 | `0x40000000` | 一致 |
| `sdiv64-neg.data` | 负数除法向零截断 | `0xfffffffffffffffd` | 一致 |
| `sdiv64-overflow.data` | INT64_MIN / -1 | `0x8000000000000000` | 一致 |
| `smod64.data` | 有符号 64 位取模 | `0x1` | 一致 |
| `smod64-neg.data` | 负数取模符号随被除数 | `0xffffffffffffffff` | 一致 |
| `sdiv32.data` | 有符号 32 位除法 | `0x3` | 一致 |
| `sdiv32-overflow.data` | INT32_MIN / -1 | `0x80000000` | 一致 |
| `ldxsw.data` | 有符号 32 位加载 | `0xffffffff80000001` | 一致 |

另外有项目自测覆盖 JMP32 有符号/无符号比较、JA32、LE/BE 端序、bswap 和 r6–r9 调用保存。

## 与 uBPF 的剩余差异

| 用例 | 说明 |
|---|---|
| `mul-loop.data` | 依赖真实 ctx 指针低 32 位；本测试输入基址固定为 `0x10000`，循环次数不同。不是语义差异，是测试环境差异，未纳入。 |

原先记录的“除零行为不同”“未实现 ldxsw”“未实现 END/JMP32”已经消除：这些语义现在按 RFC 9669 / uBPF 实现并有测试。

## 未覆盖

- 未运行 uBPF 本体：本机没有 C 编译器、Docker、WSL 发行版或 Rust 工具链。
- 未覆盖 atomics、legacy packet load、map fd 伪指令、BTF/CO-RE、ELF 重定位、JIT。
- 只选能映射到当前兼容终点的向量，不是完整 conformance suite。

## 复现

```bash
moon test
```

测试文件：`ubpf_conformance_test.mbt`、`machine_test.mbt`。
