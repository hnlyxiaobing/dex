// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "hnlyxiaobing/dex"

version = "0.1.0"

readme = "README.mbt.md"

repository = "https://github.com/hnlyxiaobing/dex"

license = "Apache-2.0"

keywords = [
  "dex",
  "android",
  "parser",
  "disassembly",
  "smali",
  "reverse-engineering",
]

preferred_target = "wasm"

description = "把 DEX 字节解析成六表结构、指令序列、注解与交叉引用，输出可读清单与 smali 风格反汇编。"
