///|
/// dex-cli：DEX 反汇编/清单 CLI（hnlyxiaobing/dex 公开 API 驱动）。
/// 契约：退出码 0=成功 / 1=解析或IO错误 / 2=用法错误；
/// 默认记录行输出（norm 口径与 dexdump 规范化黄金一致，见 tests/ASSETS.md §2），
/// `--json` 机器可读。APK 容器条目读取使用 moonbitlang/core/archive/zip（零跨模块依赖）。

///|
let tool_name = "dex-cli"

///|
/// 帮助文本（stdout，exit 0）。
fn usage_text() -> String {
  join_lines([
    "\{tool_name} —— DEX 清单/反汇编工具（hnlyxiaobing/dex 公开 API 驱动）",
    "",
    "用法:",
    "  \{tool_name} dump <apk|dex> [--view summary|norm|xref] [--entry <name>] [--json]",
    "      summary（默认）：HDR|k|v + 每类 CLZ|desc、CLSM|desc|super|source|0xflags、",
    "      FLD|cls|name|type|0xflags、MTH|cls|name|proto|0xflags，",
    "      ANN|target|visibility|type|elements（注解，已接线）、SVC|cls|i|value（静态初值，已接线）",
    "      norm：黄金规范化口径（HDR+STR+CLZ/MTH+OPS 全方法 opcode 序列），",
    "      与 dexdump 规范化黄金逐行一致（口径见 tests/ASSETS.md §2）",
    "      xref：调用点/字段访问点索引（XREF|<caller>|<offset>|<kind>|<target>，",
    "      kind=call-virtual|call-super|call-direct|call-static|call-interface|",
    "      field-read-static|field-write-static|field-read-instance|field-write-instance）",
    "  \{tool_name} disasm <apk|dex> [--method <ref>] [--entry <name>] [--json]",
    "      全方法 smali 风格反汇编（MREF|ref|cls|name|proto + .class/.method/指令块，",
    "      操作数常量/字段/方法均解析为名字）；--method 只反汇编指定 method_ref",
    "  \{tool_name} --help",
    "",
    "输入: .apk（ZIP 容器，自动收集 classes*.dex，多 dex 自然支持）或原始 .dex（按魔数判别）。",
    "      APK 输入下每个 dex 段以 DEX|<条目名> 标记开头；--entry 可指定单个 dex 条目。",
    "输出: 默认人类可读记录行；--json 输出单行 JSON（stdout）；错误信息一律走 stderr。",
    "退出码: 0=成功 1=解析或IO错误 2=用法错误",
  ])
}

///|
/// 读取输入文件；路径为空或不可读时返回 `ok=false`（退出码 1 由调用方返回）。
async fn read_input(path : String) -> (Bytes, Bool) {
  if path == "" {
    return (b"", false)
  }
  if !@fs.exists(path) {
    eprintln("error: 无法读取文件：\{path}")
    return (b"", false)
  }
  (@fs.read_binary(path), true)
}

///|
/// 输入是否为 ZIP/APK 容器（本地头魔数 PK）。
fn is_zip_container(data : Bytes) -> Bool {
  data.length() >= 2 && data[0].to_int() == 0x50 && data[1].to_int() == 0x4B
}

///|
/// 输入是否为原始 DEX（魔数 "dex\n"）。
fn is_dex_file(data : Bytes) -> Bool {
  data.length() >= 4 &&
  data[0].to_int() == 0x64 &&
  data[1].to_int() == 0x65 &&
  data[2].to_int() == 0x78 &&
  data[3].to_int() == 0x0A
}

///|
/// 条目名是否为 dex（classes.dex / classes2.dex / classesN.dex）。
fn is_dex_name(name : String) -> Bool {
  if !name.has_prefix("classes") || !name.has_suffix(".dex") {
    return false
  }
  let mid = name[7:name.length() - 4].to_owned()
  if mid == "" {
    return true
  }
  for c in mid.iter() {
    let v = c.to_int()
    if v < 48 || v > 57 {
      return false
    }
  }
  true
}

///|
/// 数字串 -> 自然数（--method 解析；不做外部依赖）。
fn parse_nat(s : String) -> Int32? {
  if s == "" {
    return None
  }
  let mut n = 0
  for c in s.iter() {
    let v = c.to_int()
    if v < 48 || v > 57 {
      return None
    }
    n = n * 10 + (v - 48)
    if n > 100000000 {
      return None
    }
  }
  Some(n)
}

///|
/// 从 APK 容器收集 dex 条目（按条目名字典序；宽松 ZIP 读取器，见 zipmin.mbt）；
/// 找不到时报错返回空表。
fn zip_dex_entries(
  data : Bytes,
  only : String?,
) -> Array[(String, Bytes)] raise {
  let ents = zip_min_entries(data)
  let names : Array[String] = []
  for e in ents {
    match only {
      Some(v) => if e.name == v { names.push(e.name) }
      None => if is_dex_name(e.name) { names.push(e.name) }
    }
  }
  // 字典序插入排序（确定性输出；不依赖外部库）
  let mut i = 1
  while i < names.length() {
    let key = names[i]
    let mut j = i - 1
    while j >= 0 && names[j] > key {
      names[j + 1] = names[j]
      j = j - 1
    }
    names[j + 1] = key
    i = i + 1
  }
  let out : Array[(String, Bytes)] = []
  for n in names {
    for e in ents {
      if e.name == n {
        out.push((n, zip_min_extract(data, e)))
      }
    }
  }
  if only is Some(v) && out.is_empty() {
    eprintln("error: APK 中找不到 dex 条目：\{v}")
  }
  if only is None && out.is_empty() {
    eprintln("error: APK 中没有 classes*.dex 条目")
  }
  out
}

///|
/// 读取一个 dex 段的 JSON 基础片段（header + classes 含 annotations/static_values）。
fn json_dump_section(
  name : String,
  data : Bytes,
  d : @dex.DexFile,
) -> String raise {
  let parts : Array[String] = []
  parts.push("{\"name\":\{json_escape(name)},\"header\":{")
  parts.push("\"magic\":\{json_escape(magic_str(d.version))},")
  parts.push("\"checksum\":\{json_escape(hex8(d.checksum))},")
  parts.push("\"signature\":\{json_escape(sig_short(d.signature))},")
  parts.push("\"file_size\":\{d.file_size},")
  parts.push("\"header_size\":\{d.header_size},")
  parts.push("\"string_ids_size\":\{d.strings.length()},")
  parts.push("\"type_ids_size\":\{d.type_descriptors.length()},")
  parts.push("\"proto_ids_size\":\{d.protos.length()},")
  parts.push("\"field_ids_size\":\{d.fields.length()},")
  parts.push("\"method_ids_size\":\{d.methods.length()},")
  parts.push("\"class_defs_size\":\{d.classes.length()}")
  parts.push("},\"classes\":[")
  let mut first = true
  for ci in 0..<d.classes.length() {
    let c = d.classes[ci]
    if !first {
      parts.push(",")
    }
    first = false
    let super_desc = match c.superclass_index {
      Some(i) => d.type_descriptors[i]
      None => ""
    }
    parts.push(
      "{\"descriptor\":\{json_escape(c.type_descriptor)},\"super\":\{json_escape(super_desc)},\"source\":\{json_escape(opt_str(c.source_file))},\"access\":\{json_escape("0x" + hex_min(c.access_flags, 4))},\"fields\":[",
    )
    let mut f2 = true
    for f in c.static_fields {
      if !f2 {
        parts.push(",")
      }
      f2 = false
      parts.push(
        "{\"name\":\{json_escape(d.strings[f.name_index])},\"type\":\{json_escape(d.type_descriptors[f.type_index])},\"access\":\{json_escape("0x" + hex_min(f.access_flags, 4))}}",
      )
    }
    for f in c.instance_fields {
      if !f2 {
        parts.push(",")
      }
      f2 = false
      parts.push(
        "{\"name\":\{json_escape(d.strings[f.name_index])},\"type\":\{json_escape(d.type_descriptors[f.type_index])},\"access\":\{json_escape("0x" + hex_min(f.access_flags, 4))}}",
      )
    }
    parts.push("],\"methods\":[")
    let mut m2 = true
    for m in c.direct_methods {
      if !m2 {
        parts.push(",")
      }
      m2 = false
      parts.push(
        "{\"name\":\{json_escape(d.strings[m.name_index])},\"proto\":\{json_escape(proto_str(d.protos[m.proto_index]))},\"access\":\{json_escape("0x" + hex_min(m.access_flags, 4))}}",
      )
    }
    for m in c.virtual_methods {
      if !m2 {
        parts.push(",")
      }
      m2 = false
      parts.push(
        "{\"name\":\{json_escape(d.strings[m.name_index])},\"proto\":\{json_escape(proto_str(d.protos[m.proto_index]))},\"access\":\{json_escape("0x" + hex_min(m.access_flags, 4))}}",
      )
    }
    parts.push("],\"annotations\":")
    parts.push(json_ann_array(data, d, ci))
    parts.push(",\"static_values\":")
    parts.push(json_svc_array(data, ci))
    parts.push("}")
  }
  parts.push("]}")
  str_join(parts)
}

///|
/// 反汇编一个 dex 段的 JSON 片段。
fn json_disasm_section(
  name : String,
  d : @dex.DexFile,
  only_ref : Int32?,
) -> String raise {
  let parts : Array[String] = []
  parts.push("{\"name\":\{json_escape(name)},\"methods\":[")
  let mut first = true
  let mut mref = 0
  while mref < d.methods.length() {
    let m = d.methods[mref]
    let take = match only_ref {
      Some(r) => r == mref
      None => true
    }
    match m.code {
      Some(_) =>
        if take {
          if !first {
            parts.push(",")
          }
          first = false
          let cls = d.type_descriptors[m.class_index]
          let nm = d.strings[m.name_index]
          let proto = proto_str(d.protos[m.proto_index])
          parts.push(
            "{\"ref\":\{mref},\"class\":\{json_escape(cls)},\"name\":\{json_escape(nm)},\"proto\":\{json_escape(proto)},\"disasm\":\{json_escape(@dex.disasm(d, mref))}}",
          )
        }
      None => ()
    }
    mref = mref + 1
  }
  parts.push("]}")
  str_join(parts)
}

///|
/// xref 视图的 JSON 片段：`{"name":…,"sites":[…]}`；
/// 每站点 `{"method_ref":N,"offset":N,"kind":"<label>","target_ref":N}`
/// （`--json` 口径）；站点序与 XREF| 记录行同序。
fn json_xref_section(
  name : String,
  d : @dex.DexFile,
  xi : @dex.XrefIndex,
) -> String raise @dex.DexError {
  let parts : Array[String] = []
  parts.push("{\"name\":\{json_escape(name)},\"sites\":[")
  let mut first = true
  for s in xref_sites_ordered(d, xi) {
    if !first {
      parts.push(",")
    }
    first = false
    parts.push(
      "{\"method_ref\":\{s.method_ref},\"offset\":\{s.offset},\"kind\":\{json_escape(xref_kind_label(s.kind))},\"target_ref\":\{s.target_ref}}",
    )
  }
  parts.push("]}")
  str_join(parts)
}

///|
/// `dump` 子命令。
async fn cmd_dump(rest : ArrayView[String]) -> Int32 {
  let mut in_path = ""
  let mut view = "summary"
  let mut entry : String? = None
  let mut json = false
  for xs = rest {
    match xs {
      ["--json", .. r] => {
        json = true
        continue r
      }
      ["--view", v, .. r] => {
        view = v
        continue r
      }
      ["--entry", v, .. r] => {
        entry = Some(v)
        continue r
      }
      ["--help", ..] => {
        println(usage_text())
        return 0
      }
      ["-h", ..] => {
        println(usage_text())
        return 0
      }
      [p, .. r] => {
        if p.has_prefix("-") {
          eprintln("error: 未知选项：\{p}")
          eprintln(
            "用法: \{tool_name} dump <apk|dex> [--view summary|norm|xref] [--entry <name>] [--json]",
          )
          return 2
        }
        if in_path != "" {
          eprintln("error: 多余的位置参数：\{p}")
          return 2
        }
        in_path = p
        continue r
      }
      [] => break
    }
  }
  if in_path == "" {
    eprintln("error: dump 需要 <apk|dex> 参数")
    eprintln(
      "用法: \{tool_name} dump <apk|dex> [--view summary|norm|xref] [--entry <name>] [--json]",
    )
    return 2
  }
  if view != "summary" && view != "norm" && view != "xref" {
    eprintln("error: --view 取值应为 summary / norm / xref：\{view}")
    return 2
  }
  let (data, ok) = read_input(in_path)
  if !ok {
    return 1
  }
  let sections : Array[(String, Bytes)] = []
  if is_zip_container(data) {
    for s in zip_dex_entries(data, entry) {
      sections.push(s)
    }
    if sections.is_empty() {
      return 1
    }
  } else if is_dex_file(data) {
    if entry is Some(_) {
      eprintln("error: --entry 仅对 APK（ZIP 容器）输入有效")
      return 2
    }
    sections.push((in_path, data))
  } else {
    eprintln(
      "error: 无法识别的输入（既不是 APK/ZIP 也不是 DEX）：\{in_path}",
    )
    return 1
  }
  if json {
    let parts : Array[String] = []
    parts.push(
      "{\"tool\":\"\{tool_name}\",\"file\":\{json_escape(in_path)},\"view\":\{json_escape(view)},\"dexes\":[",
    )
    let mut first = true
    for s in sections {
      if !first {
        parts.push(",")
      }
      first = false
      let d = @dex.parse(s.1)
      if view == "xref" {
        parts.push(json_xref_section(s.0, d, @dex.build_xref(d)))
      } else {
        parts.push(json_dump_section(s.0, s.1, d))
      }
    }
    parts.push("]}")
    println(str_join(parts))
  } else {
    for s in sections {
      let d = @dex.parse(s.1)
      if is_zip_container(data) {
        println("DEX|\{s.0}")
      }
      let lines = if view == "norm" {
        norm_lines(d)
      } else if view == "xref" {
        xref_lines(d, @dex.build_xref(d))
      } else {
        summary_lines(s.1, d)
      }
      for l in lines {
        println(l)
      }
    }
  }
  0
}

///|
/// `disasm` 子命令。
async fn cmd_disasm(rest : ArrayView[String]) -> Int32 {
  let mut in_path = ""
  let mut entry : String? = None
  let mut method_ref : Int32? = None
  let mut json = false
  for xs = rest {
    match xs {
      ["--json", .. r] => {
        json = true
        continue r
      }
      ["--entry", v, .. r] => {
        entry = Some(v)
        continue r
      }
      ["--method", v, .. r] => {
        match parse_nat(v) {
          Some(n) => method_ref = Some(n)
          None => {
            eprintln("error: --method 需要非负整数 method_ref：\{v}")
            return 2
          }
        }
        continue r
      }
      ["--help", ..] => {
        println(usage_text())
        return 0
      }
      ["-h", ..] => {
        println(usage_text())
        return 0
      }
      [p, .. r] => {
        if p.has_prefix("-") {
          eprintln("error: 未知选项：\{p}")
          eprintln(
            "用法: \{tool_name} disasm <apk|dex> [--method <ref>] [--entry <name>] [--json]",
          )
          return 2
        }
        if in_path != "" {
          eprintln("error: 多余的位置参数：\{p}")
          return 2
        }
        in_path = p
        continue r
      }
      [] => break
    }
  }
  if in_path == "" {
    eprintln("error: disasm 需要 <apk|dex> 参数")
    eprintln(
      "用法: \{tool_name} disasm <apk|dex> [--method <ref>] [--entry <name>] [--json]",
    )
    return 2
  }
  let (data, ok) = read_input(in_path)
  if !ok {
    return 1
  }
  let sections : Array[(String, Bytes)] = []
  if is_zip_container(data) {
    for s in zip_dex_entries(data, entry) {
      sections.push(s)
    }
    if sections.is_empty() {
      return 1
    }
  } else if is_dex_file(data) {
    if entry is Some(_) {
      eprintln("error: --entry 仅对 APK（ZIP 容器）输入有效")
      return 2
    }
    sections.push((in_path, data))
  } else {
    eprintln(
      "error: 无法识别的输入（既不是 APK/ZIP 也不是 DEX）：\{in_path}",
    )
    return 1
  }
  if json {
    let parts : Array[String] = []
    parts.push(
      "{\"tool\":\"\{tool_name}\",\"file\":\{json_escape(in_path)},\"dexes\":[",
    )
    let mut first = true
    for s in sections {
      if !first {
        parts.push(",")
      }
      first = false
      parts.push(json_disasm_section(s.0, @dex.parse(s.1), method_ref))
    }
    parts.push("]}")
    println(str_join(parts))
  } else {
    for s in sections {
      let d = @dex.parse(s.1)
      if is_zip_container(data) {
        println("DEX|\{s.0}")
      }
      let mut mref = 0
      while mref < d.methods.length() {
        let m = d.methods[mref]
        let take = match method_ref {
          Some(r) => r == mref
          None => true
        }
        match m.code {
          Some(_) =>
            if take {
              println(
                "MREF|\{mref}|\{d.type_descriptors[m.class_index]}|\{d.strings[m.name_index]}|\{proto_str(d.protos[m.proto_index])}",
              )
              println(@dex.disasm(d, mref))
            }
          None => ()
        }
        mref = mref + 1
      }
    }
  }
  0
}

///|
/// 运行入口：返回进程退出码；库抛出的解析错误统一按“解析错误”返回 1。
async fn run(args : Array[String]) -> Int32 {
  if args.length() <= 1 {
    eprintln("error: 缺少子命令（dump / disasm）")
    eprintln("运行 \{tool_name} --help 查看用法")
    return 2
  }
  let sub = args[1]
  let rest = args[2:]
  if sub == "dump" {
    cmd_dump(rest) catch {
      e => {
        eprintln("error: \{e}")
        1
      }
    }
  } else if sub == "disasm" {
    cmd_disasm(rest) catch {
      e => {
        eprintln("error: \{e}")
        1
      }
    }
  } else if sub == "--help" || sub == "-h" || sub == "help" {
    println(usage_text())
    0
  } else {
    eprintln("error: 未知子命令：\{sub}")
    eprintln("运行 \{tool_name} --help 查看用法")
    2
  }
}

///|
async fn main {
  let code = run(@env.args())
  if code != 0 {
    @env.exit(code)
  }
}
