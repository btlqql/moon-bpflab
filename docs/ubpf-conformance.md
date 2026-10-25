# uBPF 差分对照（2026-10-24）

参考实现：[iovisor/ubpf](https://github.com/iovisor/ubpf)，提交 `8d2dd3580ab80f9b4a79a9d2fa2420aa38fc7521`，Apache-2.0。只取测试向量中的汇编语义，翻译成 MoonBpfLab 的 `Insn`，未复制源码。

## 通过的向量

| uBPF 用例 | 语义 | uBPF 期望 | MoonBpfLab 结果 |
|---|---|---|---|
| `arsh.data` | 32 位算术右移 | `0xffff8000` | 一致 |
| `arsh64.data` | 64 位算术右移 + 寄存器移位 | `0xfffffffffffffff8` | 一致 |
| `early-exit.data` | 首条 `exit` 后停止 | `0x3` | 一致 |
| `ldxb-0offset.data` | 单字节加载 + 指针算术 | `0x6` | 一致 |
| `ldxb-small-offset.data` | 正偏移单字节加载 | `0x5` | 一致 |
| `factorial.data` | 本地子程序调用 + 循环 | `0x21c3677c82b40000` | 一致 |

这些用例覆盖 ALU32/ALU64 移位、提前退出、内存加载、本地 call/return 和循环跳转。

## 已知不一致（不计入通过）

| 用例 | uBPF 行为 | MoonBpfLab 行为 | 说明 |
|---|---|---|---|
| `div64-by-zero-imm.data` | 返回 0 | 抛 `DivisionByZero` | BPF 规范把除零留作未定义；本项目选择显式拒绝，避免静默结果 |
| `mod-by-zero-imm.data` | 返回被除数 | 抛 `DivisionByZero` | 同上 |
| `ldxsw.data` | 有符号 16 位加载并符号扩展 | 未实现 `ldxsw` | 支持矩阵中明确不包含符号扩展加载 |
| `mul-loop.data` | 依赖真实 ctx 指针低 32 位 | 输入基址固定为 `0x10000`，循环次数不同 | 不是语义差异，是测试环境差异，未纳入 |

## 未覆盖

- 未运行 uBPF 本体：本机没有 C 编译器、Docker、WSL 发行版或 Rust 工具链。
- 未覆盖 uBPF 的 JIT、helpers、maps、BTF/CO-RE、ELF 重定位和扩展调用约定。
- 只选了 6 个能映射到当前指令子集的向量；不是完整 conformance suite。

## 复现

```bash
moon test -f "uBPF"
```

测试文件：`ubpf_conformance_test.mbt`。
