///|
/// WP-3 dex-cli 视图渲染：summary / norm（文本记录行与 --json 两种形态）。
/// norm 记录行口径与 fixtures/golden/dex/*.dexparse.norm.txt 一致
/// （HDR 子集 + STR + CLZ + MTH + OPS 全方法 opcode 序列）；summary 在同口径上
/// 扩展 CLSM（类元数据）/ FLD（字段）与 ANN/SVC（WP-2 注解/静态初值，已接线）。

///|
/// HDR 记录行（golden 口径 11 键）。
fn hdr_lines(d : @dex.DexFile) -> Array[String] {
  let out : Array[String] = []
  out.push("HDR|magic|\{magic_str(d.version)}")
  out.push("HDR|checksum|\{hex8(d.checksum)}")
  out.push("HDR|signature|\{sig_short(d.signature)}")
  out.push("HDR|file_size|\{d.file_size}")
  out.push("HDR|header_size|\{d.header_size}")
  out.push("HDR|string_ids_size|\{d.strings.length()}")
  out.push("HDR|type_ids_size|\{d.type_descriptors.length()}")
  out.push("HDR|proto_ids_size|\{d.protos.length()}")
  out.push("HDR|field_ids_size|\{d.fields.length()}")
  out.push("HDR|method_ids_size|\{d.methods.length()}")
  out.push("HDR|class_defs_size|\{d.classes.length()}")
  out
}

///|
/// 全方法 opcode 序列渲染（golden dexparse 口径，WP-4 2026-11-07）：
/// `OPS|<class>|<name>|<proto>|<n>|<m0> <m1> ...`；code-less 方法 n=0 空序列。
fn ops_line(
  cls : String,
  name : String,
  proto : String,
  code : @dex.CodeItem?,
) -> String {
  let mut s = ""
  let mut n = 0
  match code {
    Some(c) => {
      let mut first = true
      for i in c.insns {
        if first {
          first = false
        } else {
          s = s + " "
        }
        s = s + i.mnemonic
        n = n + 1
      }
    }
    None => ()
  }
  "OPS|\{cls}|\{name}|\{proto}|\{n}|\{s}"
}

///|
/// norm 视图记录行（golden dexparse 口径：HDR + STR + CLZ/MTH + OPS 全方法序列）。
fn norm_lines(d : @dex.DexFile) -> Array[String] {
  let out : Array[String] = []
  for l in hdr_lines(d) {
    out.push(l)
  }
  let mut i = 0
  while i < d.strings.length() {
    out.push("STR|\{i}|\{d.strings[i]}")
    i = i + 1
  }
  for c in d.classes {
    out.push("CLZ|\{c.type_descriptor}")
    for m in c.direct_methods {
      out.push(
        "MTH|\{c.type_descriptor}|\{d.strings[m.name_index]}|\{proto_str(d.protos[m.proto_index])}|0x\{hex_min(m.access_flags, 4)}",
      )
    }
    for m in c.virtual_methods {
      out.push(
        "MTH|\{c.type_descriptor}|\{d.strings[m.name_index]}|\{proto_str(d.protos[m.proto_index])}|0x\{hex_min(m.access_flags, 4)}",
      )
    }
  }
  // OPS：全方法 opcode 序列（golden-diff 同口径）：类序 -> direct -> virtual。
  for c in d.classes {
    for m in c.direct_methods {
      out.push(
        ops_line(
          c.type_descriptor,
          d.strings[m.name_index],
          proto_str(d.protos[m.proto_index]),
          m.code,
        ),
      )
    }
    for m in c.virtual_methods {
      out.push(
        ops_line(
          c.type_descriptor,
          d.strings[m.name_index],
          proto_str(d.protos[m.proto_index]),
          m.code,
        ),
      )
    }
  }
  out
}

///|
/// 注解可见性渲染（稳定小写标识）。
fn vis_name(v : @dex.AnnotationVisibility) -> String {
  match v {
    VisibilityBuild => "build"
    VisibilityRuntime => "runtime"
    VisibilitySystem => "system"
  }
}

///|
/// EncodedValue 文本渲染（常量可见；名字为 WP-2 解析好的 smali 风格）：
/// 数值十进制、char 可打印 ASCII `'c'` 否则 `U+XXXX`、字符串带引号转义、
/// 类型/字段/方法/枚举原样（Lcls;… / Lcls;->name:type / Lcls;->name(…)…）、
/// 数组 `[v,…]` 递归、注解 `Ltype;{name=value;…}` 递归。
fn enc_text(v : @dex.EncodedValue) -> String {
  match v {
    ValueByte(x) => "\{x}"
    ValueShort(x) => "\{x}"
    ValueChar(x) =>
      if x >= 0x20 && x <= 0x7E {
        "'" + x.unsafe_to_char().to_string() + "'"
      } else {
        "U+" + json_hex4(x)
      }
    ValueInt(x) => "\{x}"
    ValueLong(x) => "\{x}"
    ValueFloat(x) => "\{x}"
    ValueDouble(x) => "\{x}"
    ValueString(s) => json_escape(s)
    ValueType(s) => s
    ValueField(s) => s
    ValueMethod(s) => s
    ValueEnum(s) => s
    ValueArray(items) => {
      let mut s = "["
      let mut first = true
      for it in items {
        if first {
          first = false
        } else {
          s = s + ","
        }
        s = s + enc_text(it)
      }
      s + "]"
    }
    ValueAnnotation(a) => {
      let mut s = a.type_descriptor + "{"
      let mut first = true
      for e in a.elements {
        if first {
          first = false
        } else {
          s = s + ";"
        }
        s = s + e.name + "=" + enc_text(e.value)
      }
      s + "}"
    }
    ValueNull => "null"
    ValueBoolean(b) => if b { "true" } else { "false" }
  }
}

///|
/// 注解元素串：`name=value;name=value`（无元素为空串）。
fn ann_elements_text(elements : Array[@dex.AnnotationElement]) -> String {
  let mut s = ""
  let mut first = true
  for e in elements {
    if first {
      first = false
    } else {
      s = s + ";"
    }
    s = s + e.name + "=" + enc_text(e.value)
  }
  s
}

///|
/// [已接线 · WP-2 注解] 类注解摘要（annotations_directory_item）。
/// `data` 为原始 DEX 字节（WP-2 API 首参）；`class_index` 为 class_defs 表位置。
/// 记录：`ANN|<target>|<visibility>|<type>|<elements>`；
/// target：类=描述符；字段/方法=smali 引用（Lcls;->name:type / Lcls;->name(params)ret）；
/// 形参=方法引用 + `#p<序号>`；visibility=build|runtime|system。
fn ann_lines(
  data : Bytes,
  d : @dex.DexFile,
  class_index : Int32,
) -> Array[String] raise @dex.DexError {
  let out : Array[String] = []
  match @dex.class_annotations(data, class_index) {
    None => ()
    Some(dir) => {
      let cls = d.classes[class_index].type_descriptor
      for a in dir.class_annotations.annotations {
        out.push(
          "ANN|\{cls}|\{vis_name(a.visibility)}|\{a.annotation.type_descriptor}|\{ann_elements_text(a.annotation.elements)}",
        )
      }
      for fa in dir.field_annotations {
        let target = @dex.field_ref_name(d, fa.field_index)
        for a in fa.annotations.annotations {
          out.push(
            "ANN|\{target}|\{vis_name(a.visibility)}|\{a.annotation.type_descriptor}|\{ann_elements_text(a.annotation.elements)}",
          )
        }
      }
      for ma in dir.method_annotations {
        let target = @dex.method_ref_name(d, ma.method_index)
        for a in ma.annotations.annotations {
          out.push(
            "ANN|\{target}|\{vis_name(a.visibility)}|\{a.annotation.type_descriptor}|\{ann_elements_text(a.annotation.elements)}",
          )
        }
      }
      for pa in dir.parameter_annotations {
        let base = @dex.method_ref_name(d, pa.method_index)
        let mut pi = 0
        for ps in pa.parameters {
          let target = base + "#p\{pi}"
          for a in ps.annotations {
            out.push(
              "ANN|\{target}|\{vis_name(a.visibility)}|\{a.annotation.type_descriptor}|\{ann_elements_text(a.annotation.elements)}",
            )
          }
          pi = pi + 1
        }
      }
    }
  }
  out
}

///|
/// [已接线 · WP-2 静态初值] class_def 的 encoded_array static_values 摘要。
/// `data` 为原始 DEX 字节；`class_index` 为 class_defs 表位置；
/// `static_values` 返回静态字段前缀省略编码（空数组=无初值）。
/// 记录：`SVC|<cls>|<i>|<value>`；i 为该类静态字段序号（与 FLD 记录顺序对应）。
fn svc_lines(
  data : Bytes,
  d : @dex.DexFile,
  class_index : Int32,
) -> Array[String] raise @dex.DexError {
  let out : Array[String] = []
  let vals = @dex.static_values(data, class_index)
  let mut i = 0
  for v in vals {
    out.push(
      "SVC|\{d.classes[class_index].type_descriptor}|\{i}|\{enc_text(v)}",
    )
    i = i + 1
  }
  out
}

///|
/// summary 视图记录行：HDR + 每类 CLSM / FLD / MTH + ANN/SVC（WP-2 已接线）。
fn summary_lines(
  data : Bytes,
  d : @dex.DexFile,
) -> Array[String] raise @dex.DexError {
  let out : Array[String] = []
  for l in hdr_lines(d) {
    out.push(l)
  }
  for ci in 0..<d.classes.length() {
    let c = d.classes[ci]
    let super_desc = match c.superclass_index {
      Some(i) => d.type_descriptors[i]
      None => ""
    }
    out.push("CLZ|\{c.type_descriptor}")
    out.push(
      "CLSM|\{c.type_descriptor}|\{super_desc}|\{opt_str(c.source_file)}|0x\{hex_min(c.access_flags, 4)}",
    )
    for f in c.static_fields {
      out.push(
        "FLD|\{c.type_descriptor}|\{d.strings[f.name_index]}|\{d.type_descriptors[f.type_index]}|0x\{hex_min(f.access_flags, 4)}",
      )
    }
    for f in c.instance_fields {
      out.push(
        "FLD|\{c.type_descriptor}|\{d.strings[f.name_index]}|\{d.type_descriptors[f.type_index]}|0x\{hex_min(f.access_flags, 4)}",
      )
    }
    for m in c.direct_methods {
      out.push(
        "MTH|\{c.type_descriptor}|\{d.strings[m.name_index]}|\{proto_str(d.protos[m.proto_index])}|0x\{hex_min(m.access_flags, 4)}",
      )
    }
    for m in c.virtual_methods {
      out.push(
        "MTH|\{c.type_descriptor}|\{d.strings[m.name_index]}|\{proto_str(d.protos[m.proto_index])}|0x\{hex_min(m.access_flags, 4)}",
      )
    }
    for l in ann_lines(data, d, ci) {
      out.push(l)
    }
    for l in svc_lines(data, d, ci) {
      out.push(l)
    }
  }
  out
}

///|
/// --json：单个注解对象片段。
fn json_ann_item(a : @dex.Annotation) -> String {
  let parts : Array[String] = []
  parts.push(
    "{\"visibility\":\{json_escape(vis_name(a.visibility))},\"type\":\{json_escape(a.annotation.type_descriptor)},\"elements\":[",
  )
  let mut first = true
  for e in a.annotation.elements {
    if !first {
      parts.push(",")
    }
    first = false
    parts.push(
      "{\"name\":\{json_escape(e.name)},\"value\":\{json_escape(enc_text(e.value))}}",
    )
  }
  parts.push("]}")
  str_join(parts)
}

///|
/// --json：注解数组片段（口径与 ANN| 记录一致）。
fn json_ann_array(
  data : Bytes,
  d : @dex.DexFile,
  class_index : Int32,
) -> String raise @dex.DexError {
  let parts : Array[String] = []
  parts.push("[")
  let mut first = true
  match @dex.class_annotations(data, class_index) {
    None => ()
    Some(dir) => {
      let cls = d.classes[class_index].type_descriptor
      for a in dir.class_annotations.annotations {
        if !first {
          parts.push(",")
        }
        first = false
        parts.push(
          "{\"target\":\{json_escape(cls)},\"annotation\":\{json_ann_item(a)}}",
        )
      }
      for fa in dir.field_annotations {
        let target = @dex.field_ref_name(d, fa.field_index)
        for a in fa.annotations.annotations {
          if !first {
            parts.push(",")
          }
          first = false
          parts.push(
            "{\"target\":\{json_escape(target)},\"annotation\":\{json_ann_item(a)}}",
          )
        }
      }
      for ma in dir.method_annotations {
        let target = @dex.method_ref_name(d, ma.method_index)
        for a in ma.annotations.annotations {
          if !first {
            parts.push(",")
          }
          first = false
          parts.push(
            "{\"target\":\{json_escape(target)},\"annotation\":\{json_ann_item(a)}}",
          )
        }
      }
      for pa in dir.parameter_annotations {
        let base = @dex.method_ref_name(d, pa.method_index)
        let mut pi = 0
        for ps in pa.parameters {
          let target = base + "#p\{pi}"
          for a in ps.annotations {
            if !first {
              parts.push(",")
            }
            first = false
            parts.push(
              "{\"target\":\{json_escape(target)},\"annotation\":\{json_ann_item(a)}}",
            )
          }
          pi = pi + 1
        }
      }
    }
  }
  parts.push("]")
  str_join(parts)
}

///|
/// --json：静态初值数组片段（口径与 SVC| 记录一致）。
fn json_svc_array(
  data : Bytes,
  class_index : Int32,
) -> String raise @dex.DexError {
  let parts : Array[String] = []
  parts.push("[")
  let vals = @dex.static_values(data, class_index)
  let mut first = true
  let mut i = 0
  for v in vals {
    if !first {
      parts.push(",")
    }
    first = false
    parts.push("{\"index\":\{i},\"value\":\{json_escape(enc_text(v))}}")
    i = i + 1
  }
  parts.push("]")
  str_join(parts)
}

///|
/// [已接线 · WP-2 xref] 站点目标名：Field* → field_ref_name；
/// Call* → method_ref_name（wp2-contract §5 接线形态逐字口径）。
fn xref_target_name(
  d : @dex.DexFile,
  s : @dex.XrefSite,
) -> String raise @dex.DexError {
  match s.kind {
    XrefFieldReadStatic
    | XrefFieldWriteStatic
    | XrefFieldReadInstance
    | XrefFieldWriteInstance => @dex.field_ref_name(d, s.target_ref)
    _ => @dex.method_ref_name(d, s.target_ref)
  }
}

///|
/// [已接线 · WP-2 xref] 黄金序站点收集（wp2-contract §4 排序承诺）：
/// caller 序 = MTH/OPS 同序（class_def 序 → direct_methods → virtual_methods，
/// 经 method_ref_of 桥接）× caller 内 offset 升序（sites_in 冻结排序）。
fn xref_sites_ordered(
  d : @dex.DexFile,
  xi : @dex.XrefIndex,
) -> Array[@dex.XrefSite] raise @dex.DexError {
  let out : Array[@dex.XrefSite] = []
  for c in d.classes {
    for m in c.direct_methods {
      match @dex.method_ref_of(d, m) {
        None => ()
        Some(mref) =>
          for s in xi.sites_in(mref) {
            out.push(s)
          }
      }
    }
    for m in c.virtual_methods {
      match @dex.method_ref_of(d, m) {
        None => ()
        Some(mref) =>
          for s in xi.sites_in(mref) {
            out.push(s)
          }
      }
    }
  }
  out
}

///|
/// [已接线 · WP-2 xref] xref 视图记录行（wp2-contract §4/§5 黄金口径）：
/// `XREF|<caller_ref>|<offset>|<kind>|<target_ref>`；
/// caller_ref/target_ref 复用 method_ref_name/field_ref_name 渲染，
/// offset 为十进制 code-unit 偏移；无访问点 = 空数组（0 行）。
fn xref_lines(
  d : @dex.DexFile,
  xi : @dex.XrefIndex,
) -> Array[String] raise @dex.DexError {
  let out : Array[String] = []
  for s in xref_sites_ordered(d, xi) {
    out.push(
      "XREF|\{@dex.method_ref_name(d, s.method_ref)}|\{s.offset}|\{xref_kind_label(s.kind)}|\{xref_target_name(d, s)}",
    )
  }
  out
}
