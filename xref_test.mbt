// xref P1 单元/语义测试。
//
// 覆盖（五类，仅单元/语义；黄金比对测试归 fixtures_test.mbt，
// 本文件不做黄金比对、不使用 `golden dex xref` 用例名）：
// 1) 不变量：Σ callers == Σ callees == invoke 指令总数；Σ field_sites ==
//    iget/iput/sget/sput 指令总数；每条 site 的 (method_ref, offset) 处指令
//    opcode 族与 kind 一致；sites() 与各查询汇总一致。
// 2) kind 分类：invoke 五族（含 /range、interface）+ 四类字段访问全覆盖，
//    归一按 opcode 数值域（边界位 0x52/0x58、0x59/0x5f、0x60/0x66、0x67/0x6d
//    与 0x6e–0x72、0x74–0x78 全族钉死）。
// 3) 边界：abstract/native/外部方法口径、越界 InvalidIndex、payload 伪指令
//    不产 site、排序稳定（含 method_sites ≡ callers、重复构建稳定）。
// 4) 盲区口径：0xFA–0xFF 畸形样本维持 parse 抛 InvalidInstruction（钉死）。
// 5) 不读 golden 文件。
//
// 程序化 fixture 仅做单元语义（合成 dex 不冒充真实格式兼容；真实样本
// 逐行核对归 fixtures_test.mbt 黄金用例）。sem_b_* 字节构造与 sem_check* 断言复用
// dex_sem_annotations_test.mbt 的共享辅助（黑盒测试同一命名空间）。
// kind 标签表为测试侧镜像（黄金口径固定标签表），不进库公开面。

///|
/// 测试侧 kind 标签（镜像黄金口径固定标签表；库内不加 label 方法）。
fn xref_kind_tag(k : @dex.XrefKind) -> String {
  match k {
    @dex.XrefKind::XrefCallVirtual => "call-virtual"
    @dex.XrefKind::XrefCallSuper => "call-super"
    @dex.XrefKind::XrefCallDirect => "call-direct"
    @dex.XrefKind::XrefCallStatic => "call-static"
    @dex.XrefKind::XrefCallInterface => "call-interface"
    @dex.XrefKind::XrefFieldReadStatic => "field-read-static"
    @dex.XrefKind::XrefFieldWriteStatic => "field-write-static"
    @dex.XrefKind::XrefFieldReadInstance => "field-read-instance"
    @dex.XrefKind::XrefFieldWriteInstance => "field-write-instance"
  }
}

///|
/// 助记符前缀 → kind 标签（独立 oracle，与实现的 opcode 数值域分类交叉验证）。
fn xref_mn_kind(mn : String) -> String {
  if mn.has_prefix("invoke-virtual") {
    "call-virtual"
  } else if mn.has_prefix("invoke-super") {
    "call-super"
  } else if mn.has_prefix("invoke-direct") {
    "call-direct"
  } else if mn.has_prefix("invoke-static") {
    "call-static"
  } else if mn.has_prefix("invoke-interface") {
    "call-interface"
  } else if mn.has_prefix("iget") {
    "field-read-instance"
  } else if mn.has_prefix("iput") {
    "field-write-instance"
  } else if mn.has_prefix("sget") {
    "field-read-static"
  } else if mn.has_prefix("sput") {
    "field-write-static"
  } else {
    "none"
  }
}

///|
/// site → `method_ref:offset:target_ref:kind` 文本键（可读断言用）。
fn xref_key(s : @dex.XrefSite) -> String {
  s.method_ref.to_string() +
  ":" +
  s.offset.to_string() +
  ":" +
  s.target_ref.to_string() +
  ":" +
  xref_kind_tag(s.kind)
}

///|
/// site 序列 → 文本键序列。
fn xref_keys(arr : Array[@dex.XrefSite]) -> Array[String] {
  let out : Array[String] = []
  for s in arr {
    out.push(xref_key(s))
  }
  out
}

///|
/// 按 (method_ref, offset) 取回解码指令（不变量交叉验证用）。
fn xref_insn_at(
  dex : @dex.DexFile,
  method_ref : Int32,
  offset : Int32,
) -> @dex.Instruction? {
  match dex.methods[method_ref].code {
    None => None
    Some(c) => {
      let mut found : @dex.Instruction? = None
      for insn in c.insns {
        if insn.offset == offset {
          found = Some(insn)
        }
      }
      found
    }
  }
}

///|
/// 判断 site 是否在序列中（四字段一致）。
fn xref_has(arr : Array[@dex.XrefSite], s : @dex.XrefSite) -> Bool {
  for t in arr {
    if t.method_ref == s.method_ref &&
      t.offset == s.offset &&
      t.target_ref == s.target_ref &&
      xref_kind_tag(t.kind) == xref_kind_tag(s.kind) {
      return true
    }
  }
  false
}

///|
/// 程序化 fixture：xref 语义微型 DEX（单类 LTest; + 外部 LExt;/LIface;/Object 引用）。
/// 字符串 19 / 类型 6 / 原型 2 / 字段 4 / 方法 7 / 类 1。
/// method_ids：0=LTest;->m()V（全指令流） 1=LTest;->n(I)V（小流）
/// 2=LTest;->abs()V（abstract，code_off=0） 3=LTest;->nat()V（native，code_off=0）
/// 4=LExt;->foo()V（外部） 5=Ljava/lang/Object;-><init>()V（外部）
/// 6=LIface;->bar()V（外部）。
/// field_ids：0=LTest;->f:I 1=LTest;->g:I 2=LTest;->s:I 3=LTest;->t:I。
/// m 指令流覆盖：invoke 五族 + 五族 /range（0x6e–0x72/0x74–0x78）、
/// 字段访问全四族含域边界位（0x52/0x54/0x58、0x59/0x5e/0x5f、
/// 0x60/0x62/0x66、0x67/0x6c/0x6d）、aget/aput（不算字段）、
/// const-string（不产 site）、packed-switch + packed-switch-payload（不产 site）、
/// return-void。访问点合计：m 22（10 调用 + 12 字段）、n 3（2 调用 + 1 字段）。
fn xref_build_dex() -> Bytes {
  let strings = [
    "LTest;", "Ljava/lang/Object;", "V", "I", "LExt;", "LIface;", "m", "n", "abs",
    "nat", "foo", "<init>", "bar", "f", "g", "s", "t", "x", "VI",
  ]
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    sem_b_u8(arr, 0)
  }
  // magic "dex\n035\0"
  sem_b_patch_u32(arr, 0x00, 0x0a786564)
  sem_b_patch_u32(arr, 0x04, 0x00353330)
  for i in 0..<20 {
    arr[0x0C + i] = (0x22).to_byte()
  }
  sem_b_patch_u32(arr, 0x24, 0x70) // header_size
  sem_b_patch_u32(arr, 0x28, 0x12345678) // endian_tag
  // 六表：19 string / 6 type / 2 proto / 4 field / 7 method / 1 class
  sem_b_patch_u32(arr, 0x38, 19)
  sem_b_patch_u32(arr, 0x3C, 0x70)
  let type_ids_off = 0x70 + 19 * 4
  sem_b_patch_u32(arr, 0x40, 6)
  sem_b_patch_u32(arr, 0x44, type_ids_off)
  let proto_ids_off = type_ids_off + 6 * 4
  sem_b_patch_u32(arr, 0x48, 2)
  sem_b_patch_u32(arr, 0x4C, proto_ids_off)
  let field_ids_off = proto_ids_off + 2 * 12
  sem_b_patch_u32(arr, 0x50, 4)
  sem_b_patch_u32(arr, 0x54, field_ids_off)
  let method_ids_off = field_ids_off + 4 * 8
  sem_b_patch_u32(arr, 0x58, 7)
  sem_b_patch_u32(arr, 0x5C, method_ids_off)
  let class_defs_off = method_ids_off + 7 * 8
  sem_b_patch_u32(arr, 0x60, 1)
  sem_b_patch_u32(arr, 0x64, class_defs_off)
  // string_ids 占位（稍后补丁）
  for _ in 0..<19 {
    sem_b_u32(arr, 0)
  }
  // type_ids：类型 0..5 → 字符串 0..5（LTest;/Object;/V/I/LExt;/LIface;）
  for i in 0..<6 {
    sem_b_u32(arr, i)
  }
  // proto_ids：0=()V 1=(I)V
  sem_b_u32(arr, 2) // shorty "V"
  sem_b_u32(arr, 2) // return V
  sem_b_u32(arr, 0) // 无参数
  sem_b_u32(arr, 18) // shorty "VI"
  sem_b_u32(arr, 2) // return V
  sem_b_u32(arr, 0) // parameters_off 稍后补丁
  // field_ids：0=f 1=g 2=s 3=t（均 LTest;:I）
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 3)
  sem_b_u32(arr, 13)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 3)
  sem_b_u32(arr, 14)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 3)
  sem_b_u32(arr, 15)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 3)
  sem_b_u32(arr, 16)
  // method_ids：0=m 1=n 2=abs 3=nat 4=LExt;->foo()V 5=Object;-><init>()V 6=LIface;->bar()V
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 6)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 1)
  sem_b_u32(arr, 7)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 8)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 9)
  sem_b_u16(arr, 4)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 10)
  sem_b_u16(arr, 1)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 11)
  sem_b_u16(arr, 5)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 12)
  // class_defs：0=LTest;（1 个类）
  sem_b_u32(arr, 0) // class_idx
  sem_b_u32(arr, 1) // public
  sem_b_u32(arr, 1) // superclass Ljava/lang/Object;
  sem_b_u32(arr, 0) // interfaces_off
  sem_b_u32(arr, -1) // source_file_idx = NONE
  sem_b_u32(arr, 0) // annotations_off
  sem_b_u32(arr, 0) // class_data_off 稍后补丁
  sem_b_u32(arr, 0) // static_values_off
  // type_list（proto1 参数 I）
  let tl_off = arr.length()
  sem_b_u32(arr, 1)
  sem_b_u16(arr, 3)
  sem_b_u16(arr, 0)
  sem_b_patch_u32(arr, proto_ids_off + 20, tl_off)
  // string data
  for i in 0..<19 {
    let s_off = arr.length()
    sem_b_patch_u32(arr, 0x70 + i * 4, s_off)
    sem_b_str_item(arr, strings[i])
  }
  sem_b_align4(arr)
  // code_item m（70 code units：22 访问点 + aget/aput/const-string/switch/payload）
  let code_m_off = arr.length()
  sem_b_u16(arr, 4) // registers_size
  sem_b_u16(arr, 0) // ins_size
  sem_b_u16(arr, 2) // outs_size
  sem_b_u16(arr, 0) // tries_size
  sem_b_u32(arr, 0) // debug_info_off
  sem_b_u32(arr, 70) // insns_size
  let words_m = [
    // invoke 五族（0x6e–0x72）
    0x206e, 0x0001, 0x0010, // [0] invoke-virtual {v0,v1}, method@1
     0x106f, 0x0005, 0x0000, // [3] invoke-super {v0}, method@5
     0x1070, 0x0000, 0x0000, // [6] invoke-direct {v0}, method@0
     0x0071, 0x0004, 0x0000, // [9] invoke-static {}, method@4
     0x1072, 0x0006, 0x0000, // [12] invoke-interface {v0}, method@6
    // invoke 五族 /range（0x74–0x78，同 kind）
     0x0274, 0x0001, 0x0001, // [15] invoke-virtual/range {v1..v2}, method@1
     0x0175, 0x0005, 0x0000, // [18] invoke-super/range {v0}, method@5
     0x0176, 0x0000, 0x0000, // [21] invoke-direct/range {v0}, method@0
     0x0177, 0x0004, 0x0000, // [24] invoke-static/range {v0}, method@4
     0x0178, 0x0006, 0x0000, // [27] invoke-interface/range {v0}, method@6
    // 读实例字段 0x52–0x58（含域边界位）
     0x1052, 0x0000, // [30] iget v0, v1, field@0
     0x1054, 0x0001, // [32] iget-object v0, v1, field@1
     0x1058, 0x0001, // [34] iget-short v0, v1, field@1
    // 写实例字段 0x59–0x5f（含域边界位）
     0x1059, 0x0000, // [36] iput v0, v1, field@0
     0x105e, 0x0001, // [38] iput-char v0, v1, field@1
     0x105f, 0x0001, // [40] iput-short v0, v1, field@1
    // 读静态字段 0x60–0x66（含域边界位）
     0x0060, 0x0002, // [42] sget v0, field@2
     0x0062, 0x0003, // [44] sget-object v0, field@3
     0x0066, 0x0002, // [46] sget-short v0, field@2
    // 写静态字段 0x67–0x6d（含域边界位）
     0x0067, 0x0002, // [48] sput v0, field@2
     0x006c, 0x0003, // [50] sput-char v0, field@3
     0x006d, 0x0003, // [52] sput-short v0, field@3
    // aget/aput：数组元素访问不算字段访问
     0x0044, 0x0201, // [54] aget v0, v1, v2
     0x004b, 0x0201, // [56] aput v0, v1, v2
    // const-string：常量池引用不产 site
     0x001a, 0x0011, // [58] const-string v0, string@17
    // packed-switch + payload：payload 伪指令不产 site
     0x002b, 0x0003, 0x0000, // [60] packed-switch v0, +3
     0x0100, 0x0001, 0x0000, 0x0000, 0x0002, 0x0000, // [63] packed-switch-payload
     0x000e, // [69] return-void
  ]
  for w in words_m {
    sem_b_u16(arr, w)
  }
  // code_item n（9 code units：2 调用 + 1 字段访问）
  let code_n_off = arr.length()
  sem_b_u16(arr, 2) // registers_size
  sem_b_u16(arr, 1) // ins_size
  sem_b_u16(arr, 1) // outs_size
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 0)
  sem_b_u32(arr, 9) // insns_size
  let words_n = [
    0x0071, 0x0002, 0x0000, // [0] invoke-static {}, method@2（abs）
     0x0177, 0x0004, 0x0000, // [3] invoke-static/range {v0}, method@4（foo）
     0x0060, 0x0002, // [6] sget v0, field@2
     0x000e, // [8] return-void
  ]
  for w in words_n {
    sem_b_u16(arr, w)
  }
  sem_b_align4(arr)
  // class_data：static=[s,t] instance=[f,g] direct=[m] virtual=[n,abs,nat]
  let class_data_off = arr.length()
  sem_b_uleb(arr, 2) // static_fields_size
  sem_b_uleb(arr, 2) // instance_fields_size
  sem_b_uleb(arr, 1) // direct_methods_size
  sem_b_uleb(arr, 3) // virtual_methods_size
  sem_b_uleb(arr, 2) // s = field@2
  sem_b_uleb(arr, 8) // static
  sem_b_uleb(arr, 1) // t = field@3
  sem_b_uleb(arr, 8)
  sem_b_uleb(arr, 0) // f = field@0
  sem_b_uleb(arr, 1) // instance
  sem_b_uleb(arr, 1) // g = field@1
  sem_b_uleb(arr, 1)
  sem_b_uleb(arr, 0) // m = method@0
  sem_b_uleb(arr, 1)
  sem_b_uleb(arr, code_m_off)
  sem_b_uleb(arr, 1) // n = method@1（分段首条目 diff 即绝对索引）
  sem_b_uleb(arr, 1)
  sem_b_uleb(arr, code_n_off)
  sem_b_uleb(arr, 1) // abs = method@2
  sem_b_uleb(arr, 0x400) // abstract
  sem_b_uleb(arr, 0) // code_off=0
  sem_b_uleb(arr, 1) // nat = method@3
  sem_b_uleb(arr, 0x100) // native
  sem_b_uleb(arr, 0) // code_off=0
  // 补丁：class_data_off / file_size / checksum
  sem_b_patch_u32(arr, class_defs_off + 24, class_data_off)
  sem_b_patch_u32(arr, 0x20, arr.length())
  sem_b_fix_checksum(arr)
  Bytes::from_array(arr)
}

///|
/// 盲区样本：单类单方法，code_item 只含一条低字节为 `op` 的畸形指令。
/// 用于钉死 0xFA–0xFF（MethodHandle 体系）在解析层即被拒绝的口径。
fn xref_bad_opcode_dex(op : Int32) -> Bytes {
  let names = ["LBad;", "Ljava/lang/Object;", "V", "m"]
  let arr : Array[Byte] = []
  for _ in 0..<0x70 {
    sem_b_u8(arr, 0)
  }
  sem_b_patch_u32(arr, 0x00, 0x0a786564)
  sem_b_patch_u32(arr, 0x04, 0x00353330)
  for i in 0..<20 {
    arr[0x0C + i] = (0x22).to_byte()
  }
  sem_b_patch_u32(arr, 0x24, 0x70)
  sem_b_patch_u32(arr, 0x28, 0x12345678)
  // 六表：4 string / 3 type / 1 proto / 0 field / 1 method / 1 class
  sem_b_patch_u32(arr, 0x38, 4)
  sem_b_patch_u32(arr, 0x3C, 0x70)
  let type_ids_off = 0x70 + 4 * 4
  sem_b_patch_u32(arr, 0x40, 3)
  sem_b_patch_u32(arr, 0x44, type_ids_off)
  let proto_ids_off = type_ids_off + 3 * 4
  sem_b_patch_u32(arr, 0x48, 1)
  sem_b_patch_u32(arr, 0x4C, proto_ids_off)
  sem_b_patch_u32(arr, 0x50, 0) // field_ids_size=0
  sem_b_patch_u32(arr, 0x54, 0)
  let method_ids_off = proto_ids_off + 1 * 12
  sem_b_patch_u32(arr, 0x58, 1)
  sem_b_patch_u32(arr, 0x5C, method_ids_off)
  let class_defs_off = method_ids_off + 1 * 8
  sem_b_patch_u32(arr, 0x60, 1)
  sem_b_patch_u32(arr, 0x64, class_defs_off)
  for _ in 0..<4 {
    sem_b_u32(arr, 0)
  }
  // type_ids：0=LBad; 1=Ljava/lang/Object; 2=V
  sem_b_u32(arr, 0)
  sem_b_u32(arr, 1)
  sem_b_u32(arr, 2)
  // proto_ids：0=()V
  sem_b_u32(arr, 2)
  sem_b_u32(arr, 2)
  sem_b_u32(arr, 0)
  // method_ids：0=LBad;->m()V
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 3)
  // class_defs：0=LBad;
  sem_b_u32(arr, 0)
  sem_b_u32(arr, 1)
  sem_b_u32(arr, 1)
  sem_b_u32(arr, 0)
  sem_b_u32(arr, -1)
  sem_b_u32(arr, 0)
  sem_b_u32(arr, 0) // class_data_off 稍后补丁
  sem_b_u32(arr, 0)
  // string data
  for i in 0..<4 {
    let s_off = arr.length()
    sem_b_patch_u32(arr, 0x70 + i * 4, s_off)
    sem_b_str_item(arr, names[i])
  }
  sem_b_align4(arr)
  // code_item m：单条畸形指令（低字节 = op）
  let code_off = arr.length()
  sem_b_u16(arr, 1) // registers_size
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u16(arr, 0)
  sem_b_u32(arr, 0)
  sem_b_u32(arr, 1) // insns_size
  sem_b_u16(arr, op)
  sem_b_align4(arr)
  // class_data：direct=[m]
  let class_data_off = arr.length()
  sem_b_uleb(arr, 0)
  sem_b_uleb(arr, 0)
  sem_b_uleb(arr, 1)
  sem_b_uleb(arr, 0)
  sem_b_uleb(arr, 0) // m = method@0
  sem_b_uleb(arr, 1)
  sem_b_uleb(arr, code_off)
  sem_b_patch_u32(arr, class_defs_off + 24, class_data_off)
  sem_b_patch_u32(arr, 0x20, arr.length())
  sem_b_fix_checksum(arr)
  Bytes::from_array(arr)
}

///|
/// 不变量：Σ callers == Σ callees == invoke 指令总数；Σ field_sites ==
/// iget/iput/sget/sput 指令总数；每条 site 的 (method_ref, offset) 处指令
/// opcode 族与 kind 一致；sites() 与各查询汇总一致。
/// 计数 oracle 走类迭代 + `method_ref_of` 桥接（独立于 build_xref 的
/// method_ids 扫描），分类 oracle 用助记符前缀（独立于 opcode 数值域）。
test "xref: 不变量——计数恒等式与 kind/opcode 族一致" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  let mut inv = 0
  let mut fld = 0
  for c in dex.classes() {
    for m in c.direct_methods {
      match m.code {
        None => ()
        Some(code) =>
          for insn in code.insns {
            let mn = insn.mnemonic
            if mn.has_prefix("invoke") {
              inv = inv + 1
            } else if mn.has_prefix("iget") ||
              mn.has_prefix("iput") ||
              mn.has_prefix("sget") ||
              mn.has_prefix("sput") {
              fld = fld + 1
            }
          }
      }
    }
    for m in c.virtual_methods {
      match m.code {
        None => ()
        Some(code) =>
          for insn in code.insns {
            let mn = insn.mnemonic
            if mn.has_prefix("invoke") {
              inv = inv + 1
            } else if mn.has_prefix("iget") ||
              mn.has_prefix("iput") ||
              mn.has_prefix("sget") ||
              mn.has_prefix("sput") {
              fld = fld + 1
            }
          }
      }
    }
  }
  sem_check_eq(inv, 12, msg="oracle：invoke 指令总数")
  sem_check_eq(fld, 13, msg="oracle：iget/iput/sget/sput 总数")
  let mut sum_callers = 0
  let mut sum_callees = 0
  let mut sum_in = 0
  for mi in 0..<dex.methods.length() {
    sum_callers = sum_callers + xi.callers(mi).length()
    sum_callees = sum_callees + xi.callees(mi).length()
    sum_in = sum_in + xi.sites_in(mi).length()
  }
  let mut sum_fields = 0
  for fi in 0..<dex.fields.length() {
    sum_fields = sum_fields + xi.field_sites(fi).length()
  }
  sem_check_eq(sum_callers, inv, msg="Σ callers == invoke 指令总数")
  sem_check_eq(sum_callees, inv, msg="Σ callees == invoke 指令总数")
  sem_check_eq(
    sum_fields,
    fld,
    msg="Σ field_sites == 字段访问指令总数",
  )
  sem_check_eq(
    xi.sites().length(),
    inv + fld,
    msg="sites() == 调用点+字段点",
  )
  sem_check_eq(sum_in, xi.sites().length(), msg="Σ sites_in == sites()")
  sem_check_eq(
    sum_callers + sum_fields,
    xi.sites().length(),
    msg="目标侧查询汇总 == sites()",
  )
  // 每条 site 的 (method_ref, offset) 处指令 opcode 族与 kind 一致，
  // 且在调用方侧/目标侧两个方向都能查到
  for s in xi.sites() {
    match xref_insn_at(dex, s.method_ref, s.offset) {
      None => fail("site 的 (method_ref, offset) 处应有指令")
      Some(ins) =>
        sem_check_eq(
          xref_kind_tag(s.kind),
          xref_mn_kind(ins.mnemonic),
          msg="kind 与指令 opcode 族一致",
        )
    }
    sem_check(xref_has(xi.sites_in(s.method_ref), s), msg="sites_in 可查到")
    match s.kind {
      @dex.XrefKind::XrefFieldReadStatic
      | @dex.XrefKind::XrefFieldWriteStatic
      | @dex.XrefKind::XrefFieldReadInstance
      | @dex.XrefKind::XrefFieldWriteInstance =>
        sem_check(
          xref_has(xi.field_sites(s.target_ref), s),
          msg="field_sites 可查到",
        )
      _ =>
        sem_check(
          xref_has(xi.callers(s.target_ref), s),
          msg="callers 可查到",
        )
    }
  }
}

///|
/// kind 分类（调用）：invoke 五族（含 interface）+ /range 与非 /range 同 kind，
/// 按 opcode 数值域 0x6e–0x72 / 0x74–0x78 归一。
test "xref: kind 分类——invoke 五族 + /range 同 kind" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  let got : Array[String] = []
  for s in xi.sites_in(0) {
    let tag = xref_kind_tag(s.kind)
    if tag.has_prefix("call-") {
      got.push(
        s.offset.to_string() + ":" + tag + ":" + s.target_ref.to_string(),
      )
    }
  }
  sem_check_eq(
    got,
    [
      "0:call-virtual:1", "3:call-super:5", "6:call-direct:0", "9:call-static:4",
      "12:call-interface:6", "15:call-virtual:1", "18:call-super:5", "21:call-direct:0",
      "24:call-static:4", "27:call-interface:6",
    ],
    msg="五族 × {非 /range, /range} 同 kind",
  )
  // 目标侧反查互证：每个调用目标的 callers 集合
  sem_check_eq(
    xref_keys(xi.callers(1)),
    ["0:0:1:call-virtual", "0:15:1:call-virtual"],
    msg="callers(n)——两种形式同 kind",
  )
  sem_check_eq(
    xref_keys(xi.callers(6)),
    ["0:12:6:call-interface", "0:27:6:call-interface"],
    msg="callers(bar)——interface 两形式",
  )
}

///|
/// kind 分类（字段）：四类字段访问按 opcode 数值域归一（边界位钉死），
/// aget/aput 不算字段访问、const-string 等引用不产 site。
test "xref: kind 分类——四类字段访问按 opcode 数值域归一" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  let got : Array[String] = []
  for s in xi.sites_in(0) {
    let tag = xref_kind_tag(s.kind)
    if tag.has_prefix("field-") {
      got.push(
        s.offset.to_string() + ":" + tag + ":" + s.target_ref.to_string(),
      )
    }
  }
  sem_check_eq(
    got,
    [
      "30:field-read-instance:0", "32:field-read-instance:1", "34:field-read-instance:1",
      "36:field-write-instance:0", "38:field-write-instance:1", "40:field-write-instance:1",
      "42:field-read-static:2", "44:field-read-static:3", "46:field-read-static:2",
      "48:field-write-static:2", "50:field-write-static:3", "52:field-write-static:3",
    ],
    msg="0x52/0x58、0x59/0x5f、0x60/0x66、0x67/0x6d 域边界归一",
  )
  // m 内 22 个访问点（10 调用 + 12 字段）：aget/aput/const-string/
  // packed-switch/payload/return-void 均不产 site
  sem_check_eq(
    xi.sites_in(0).length(),
    22,
    msg="仅 invoke+字段访问产 site",
  )
  // 目标侧反查互证
  sem_check_eq(
    xref_keys(xi.field_sites(0)),
    ["0:30:0:field-read-instance", "0:36:0:field-write-instance"],
    msg="field_sites(f)",
  )
  sem_check_eq(
    xref_keys(xi.field_sites(1)),
    [
      "0:32:1:field-read-instance", "0:34:1:field-read-instance", "0:38:1:field-write-instance",
      "0:40:1:field-write-instance",
    ],
    msg="field_sites(g)",
  )
}

///|
/// 边界：abstract/native（code==None）与外部方法口径——callees/sites_in 空、
/// callers 正常；外部方法照常计 callers。
test "xref: 边界——abstract/native/外部方法口径" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  // fixture 口径核对：abs/nat/外部方法 code==None
  sem_check(dex.methods[2].code is None, msg="abs 应无 code")
  sem_check(dex.methods[3].code is None, msg="nat 应无 code")
  sem_check(dex.methods[4].code is None, msg="外部 foo 应无 code")
  // abstract/native：callees/sites_in 空
  sem_check_eq(xi.callees(2).length(), 0, msg="abstract callees 空")
  sem_check_eq(xi.sites_in(2).length(), 0, msg="abstract sites_in 空")
  sem_check_eq(xi.callees(3).length(), 0, msg="native callees 空")
  sem_check_eq(xi.sites_in(3).length(), 0, msg="native sites_in 空")
  // abstract 被调用照常计 callers
  sem_check_eq(
    xref_keys(xi.callers(2)),
    ["1:0:2:call-static"],
    msg="abstract callers 正常",
  )
  // native 未被调用 → 空数组
  sem_check_eq(xi.callers(3).length(), 0, msg="未被调用 → 空数组")
  // 外部方法照常计 callers，且自身无 site
  sem_check_eq(
    xref_keys(xi.callers(4)),
    ["0:9:4:call-static", "0:24:4:call-static", "1:3:4:call-static"],
    msg="外部方法照常计 callers",
  )
  sem_check_eq(xi.callees(4).length(), 0, msg="外部方法 callees 空")
  sem_check_eq(xi.sites_in(4).length(), 0, msg="外部方法 sites_in 空")
  sem_check_eq(xi.callers(5).length(), 2, msg="外部 Object;-><init> callers")
  sem_check_eq(
    xi.sites_in(5).length(),
    0,
    msg="外部 Object;-><init> sites_in 空",
  )
}

///|
/// 边界：越界查询抛 InvalidIndex（MethodId|FieldId, ref），与 DexFile::code 同口径；
/// 界内边界位合法。
test "xref: 边界——越界查询抛 InvalidIndex" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  let mut got1 = false
  ignore(xi.callers(-1)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::MethodId, msg="callers(-1) MethodId")
      sem_check_eq(idx, -1)
      got1 = true
    }
    _ => ()
  }
  sem_check(got1, msg="callers(-1) 应抛 InvalidIndex")
  let mut got2 = false
  ignore(xi.callers(7)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::MethodId)
      sem_check_eq(idx, 7, msg="== methods.length()")
      got2 = true
    }
    _ => ()
  }
  sem_check(got2, msg="callers(7) 应抛 InvalidIndex")
  let mut got3 = false
  ignore(xi.sites_in(7)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::MethodId)
      sem_check_eq(idx, 7)
      got3 = true
    }
    _ => ()
  }
  sem_check(got3, msg="sites_in(7) 应抛 InvalidIndex")
  let mut got4 = false
  ignore(xi.field_sites(-1)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::FieldId, msg="field_sites(-1) FieldId")
      sem_check_eq(idx, -1)
      got4 = true
    }
    _ => ()
  }
  sem_check(got4, msg="field_sites(-1) 应抛 InvalidIndex")
  let mut got5 = false
  ignore(xi.field_sites(4)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::FieldId)
      sem_check_eq(idx, 4, msg="== fields.length()")
      got5 = true
    }
    _ => ()
  }
  sem_check(got5, msg="field_sites(4) 应抛 InvalidIndex")
  // 界内边界位合法
  sem_check_eq(xi.callers(6).length(), 2, msg="最大合法 method_ref")
  sem_check_eq(xi.field_sites(3).length(), 3, msg="最大合法 field_ref")
}

///|
/// 边界：payload 伪指令不产 site；排序稳定（callers/field_sites 的
/// caller 升序+offset 升序、callees/sites_in 的 offset 升序、sites() 全局序）；
/// method_sites ≡ callers（同序同内容）；重复构建结果稳定。
test "xref: 边界——payload 不产 site 与排序稳定" {
  let dex = @dex.parse(xref_build_dex())
  let xi = @dex.build_xref(dex)
  // payload（m 的 packed-switch-payload，offset 63）不产 site
  let mut at_payload = false
  for s in xi.sites() {
    if s.method_ref == 0 && s.offset == 63 {
      at_payload = true
    }
  }
  sem_check(!at_payload, msg="payload 伪指令不产 site")
  // callers：caller 的 method_ref 升序、同 caller 内 offset 升序（跨 caller）
  sem_check_eq(
    xref_keys(xi.callers(4)),
    ["0:9:4:call-static", "0:24:4:call-static", "1:3:4:call-static"],
    msg="callers(foo) caller 升序+offset 升序",
  )
  // 自递归调用同 caller 内 offset 升序
  sem_check_eq(
    xref_keys(xi.callers(0)),
    ["0:6:0:call-direct", "0:21:0:call-direct"],
    msg="callers(m) 自递归 offset 升序",
  )
  // callees：offset 升序
  sem_check_eq(
    xref_keys(xi.callees(0)),
    [
      "0:0:1:call-virtual", "0:3:5:call-super", "0:6:0:call-direct", "0:9:4:call-static",
      "0:12:6:call-interface", "0:15:1:call-virtual", "0:18:5:call-super", "0:21:0:call-direct",
      "0:24:4:call-static", "0:27:6:call-interface",
    ],
    msg="callees(m) offset 升序",
  )
  // sites_in：offset 升序（含字段点）
  sem_check_eq(
    xref_keys(xi.sites_in(1)),
    ["1:0:2:call-static", "1:3:4:call-static", "1:6:2:field-read-static"],
    msg="sites_in(n) offset 升序",
  )
  // field_sites：caller 升序、同 caller 内 offset 升序（跨 caller）
  sem_check_eq(
    xref_keys(xi.field_sites(2)),
    [
      "0:42:2:field-read-static", "0:46:2:field-read-static", "0:48:2:field-write-static",
      "1:6:2:field-read-static",
    ],
    msg="field_sites(s) caller 升序+offset 升序",
  )
  // sites() 全局：method_ref 升序、offset 升序
  let all = xi.sites()
  for i in 1..<all.length() {
    let p = all[i - 1]
    let q = all[i]
    sem_check(
      p.method_ref < q.method_ref ||
      (p.method_ref == q.method_ref && p.offset <= q.offset),
      msg="sites() (method_ref, offset) 升序",
    )
  }
  // method_sites ≡ callers（同序同内容），全部 method_ref 逐一核对
  for mi in 0..<dex.methods.length() {
    sem_check_eq(
      xref_keys(xi.method_sites(mi)),
      xref_keys(xi.callers(mi)),
      msg="method_sites ≡ callers",
    )
  }
  // 重复构建稳定（同输入同序）
  let xi2 = @dex.build_xref(dex)
  sem_check_eq(
    xref_keys(xi2.sites()),
    xref_keys(all),
    msg="重复构建结果稳定",
  )
}

///|
/// R4 口径更新：0xFA–0xFF（MethodHandle 体系）已纳入指令表，parse 不再以
/// `InvalidInstruction` 拒绝它们（旧「盲区钉死」用例随 R4 实现翻转）。
/// 本用例守住「不再误报 InvalidInstruction(op)」；0xE3–0xF9 仍为未定义。
test "xref: 0xFA–0xFF 已纳入指令表（不再报 InvalidInstruction）" {
  for op in [0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff] {
    let data = xref_bad_opcode_dex(op)
    let mut invalid_insn = false
    try ignore(@dex.parse(data)) catch {
      @dex.DexError::InvalidInstruction(_, code) =>
        if code == op {
          invalid_insn = true
        }
      _ => ()
    } noraise {
      _ => ()
    }
    sem_check(
      !invalid_insn,
      msg="opcode " +
        op.to_string() +
        " 已纳入表，不应报 InvalidInstruction",
    )
  }
}

///|
/// method_ref_of：(class_index, name_index, proto_index) 三元组反查表索引
/// （含 direct/virtual/外部条目自反查与未命中 None）。
test "xref: method_ref_of 三元组反查" {
  let dex = @dex.parse(xref_build_dex())
  let c = dex.classes()[0]
  // 类遍历序 → method_ids 索引（黄金 MTH/OPS 桥接口径）
  sem_check_eq(@dex.method_ref_of(dex, c.direct_methods[0]), Some(0), msg="m")
  sem_check_eq(@dex.method_ref_of(dex, c.virtual_methods[0]), Some(1), msg="n")
  sem_check_eq(
    @dex.method_ref_of(dex, c.virtual_methods[1]),
    Some(2),
    msg="abs",
  )
  sem_check_eq(
    @dex.method_ref_of(dex, c.virtual_methods[2]),
    Some(3),
    msg="nat",
  )
  // 外部条目：三元组一致即命中自身索引
  sem_check_eq(
    @dex.method_ref_of(dex, dex.methods[4]),
    Some(4),
    msg="foo 自反查",
  )
  // 未命中 → None
  let bogus = @dex.MethodDef::{
    class_index: 99,
    name_index: 99,
    proto_index: 99,
    access_flags: 0U,
    code_off: 0,
    code: None,
  }
  sem_check(
    @dex.method_ref_of(dex, bogus) is None,
    msg="三元组未命中 → None",
  )
}
