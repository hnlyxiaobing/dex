# hnlyxiaobing/dex

把 DEX 字节解析成六表结构、指令序列、注解与交叉引用，输出可读清单与 smali 风格反汇编。

## 安装

```bash
moon add hnlyxiaobing/dex
```

## 最小可用示例

```moonbit nocheck
// 已 `moon add hnlyxiaobing/dex` 后，包名为 dex
fn analyze(dex_bytes : Bytes) -> Unit {
  let dex = @dex.parse(dex_bytes)?
  println("string count: \(dex.strings().length())")
  println("class count: \(dex.classes().length())")
  let ok = @dex.signature_ok(dex_bytes)?
  println("signature ok: \(ok)")
}
```

## 能力概览

- **六表解析**：header / string / type / proto / field / method / class_def，含索引越界与长度校验
- **指令解码**：`code_item` 全 opcode 序列与结构化操作数（含 DEX 038+ 指令组）
- **反汇编**：`disasm` 输出 smali 风格文本
- **注解与静态值**：`annotations_index` / `static_values` / `encoded_array`
- **交叉引用**：`build_xref` 九种 kind 的调用点与字段访问点双向索引
- **完整性校验**：`signature_ok` 校验 DEX header 的 SHA-1 signature（仅格式完整性，非 APK 签名验签）

公开 API 以 `pkg.generated.mbti` 为准；索引入口包括 `parse` / `disasm` / `build_xref` / `signature_ok` / `annotations_index` 等。

## 命令行（可选）

本模块附带 `cmd/main` 二进制（默认 `preferred_target = wasm`，可切 native 运行）：

```bash
moon run cmd/main --target native -- dump <apk|dex> [--view summary|norm|xref] [--json]
moon run cmd/main --target native -- disasm <apk|dex> [--method <ref>]
```

APK 输入条目 CRC-32 不符或解压失败时整体拒绝（fail-closed），无部分输出，退出码 1。

## 依赖与许可

零第三方依赖；`preferred_target = "wasm"`；Apache-2.0。
