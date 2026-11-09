///|
/// DEX 调用点 / 字段访问点索引（xref P1；公开签名冻结 2026-11-08）。
///
/// 职责：把单个 dex 内的 invoke-*（调用点）与 iget/iput/sget/sput
/// （字段访问点）指令收敛为 `XrefSite`，提供目标侧（callers/method_sites/
/// field_sites）与调用方侧（callees/sites_in）双向查询及全量 `sites()`。
/// 方法/字段身份一律用 method_ids / field_ids 表索引（Int32），与
/// `DexFile::code` 的 `MethodHandle`、`instruction_operands` 的 `index` 同口径；
/// 名字渲染复用 `method_ref_name` / `field_ref_name`，不新增渲染函数。
/// 逐 dex 构建，不跨 dex 合并（MultiDexNotMerged 口径维持）。
///
/// kind 归一按 opcode 数值域（勿按助记符）：
/// 0x6e–0x72 / 0x74–0x78 两域内按位次为 CallVirtual/CallSuper/CallDirect/
/// CallStatic/CallInterface（/range 与非 /range 同 kind）；
/// 0x52–0x58 FieldReadInstance、0x59–0x5f FieldWriteInstance、
/// 0x60–0x66 FieldReadStatic、0x67–0x6d FieldWriteStatic。
/// payload 伪指令（IndexNone）不产 site；aget/aput 不算字段访问；
/// 注解/静态初值的 ValueField/ValueMethod 引用不入 P1 索引。
///
/// 盲区（P1 不覆盖，如实声明）：反射；MethodHandle 体系（0xFA–0xFF 解析层
/// 即拒 `InvalidInstruction`——含此类指令的 code_item 在 parse 时已失败，
/// xref 不可见，测试钉死该口径）；invoke-custom / invoke-polymorphic
/// （0x73/0x79/0x7A 本库指令表未定义，同样解析层即拒）；JNI RegisterNatives /
/// 动态代理 / 运行时织入；跨 dex 调用图；虚分派展开（非目标）；
/// 注解 / encoded_array / catch_type 引用。
///
/// 复杂度：`build_xref` = O(M+I) 一次线性扫描（M=method_ids 条目数、
/// I=指令总数，`instruction_operands` 重解码），O(S) 空间（S=访问点数），
/// 无全局可变状态；查询为 O(S) 线性过滤，返回新数组。
/// 错误：构建仅传播 `InvalidInstruction`（签名保守带 raise）；
/// 查询越界抛 `InvalidIndex(MethodId|FieldId, ref)`，与 `DexFile::code` 一致。

///|
/// 访问点类别：五族调用 + 四类字段访问（构造器顺序即冻结顺序）。
pub(all) enum XrefKind {
  XrefCallVirtual
  XrefCallSuper
  XrefCallDirect
  XrefCallStatic
  XrefCallInterface
  XrefFieldReadStatic
  XrefFieldWriteStatic
  XrefFieldReadInstance
  XrefFieldWriteInstance
}

///|
/// 单个访问点（冻结布局）。
pub(all) struct XrefSite {
  method_ref : Int32 // 所在（调用方）方法的 method_ids 索引
  offset : Int32 // code_item 内 code-unit 偏移（与 Instruction::offset 同口径）
  target_ref : Int32 // Call* → method_ids 索引；Field* → field_ids 索引
  kind : XrefKind
}

///|
/// 逐 dex 的访问点索引（不透明 `pub struct`、私有字段；逐 dex，不跨 dex 合并）。
/// 构建后视为只读；各查询返回新数组，`sites()` 返回副本。
pub struct XrefIndex {
  all_sites : Array[XrefSite]
  method_count : Int32
  field_count : Int32
}

///|
/// opcode 数值域 → `XrefKind`（按数值域归一，勿按助记符）：
/// 0x6e–0x72 / 0x74–0x78 两域内按位次映射五族调用（/range 同 kind）；
/// 0x52–0x58 / 0x59–0x5f / 0x60–0x66 / 0x67–0x6d 四域各归一为一类字段访问。
/// 其余 opcode（含 aget/aput、payload 伪指令、盲区 0xFA–0xFF）返回 `None`。
fn xref_kind_of_opcode(op : Int32) -> XrefKind? {
  if (op >= 0x6e && op <= 0x72) || (op >= 0x74 && op <= 0x78) {
    // 两域 0x6e–0x72 / 0x74–0x78 内按位次：Virtual/Super/Direct/Static/Interface
    let base = if op <= 0x72 { 0x6e } else { 0x74 }
    match op - base {
      0 => Some(XrefKind::XrefCallVirtual)
      1 => Some(XrefKind::XrefCallSuper)
      2 => Some(XrefKind::XrefCallDirect)
      3 => Some(XrefKind::XrefCallStatic)
      _ => Some(XrefKind::XrefCallInterface)
    }
  } else if op >= 0x52 && op <= 0x58 {
    Some(XrefKind::XrefFieldReadInstance)
  } else if op >= 0x59 && op <= 0x5f {
    Some(XrefKind::XrefFieldWriteInstance)
  } else if op >= 0x60 && op <= 0x66 {
    Some(XrefKind::XrefFieldReadStatic)
  } else if op >= 0x67 && op <= 0x6d {
    Some(XrefKind::XrefFieldWriteStatic)
  } else {
    None
  }
}

///|
/// 是否调用类 kind（Call* 五族）。
fn xref_is_call(k : XrefKind) -> Bool {
  match k {
    XrefCallVirtual
    | XrefCallSuper
    | XrefCallDirect
    | XrefCallStatic
    | XrefCallInterface => true
    _ => false
  }
}

///|
/// 是否字段访问类 kind（Field* 四类）。
fn xref_is_field(k : XrefKind) -> Bool {
  match k {
    XrefFieldReadStatic
    | XrefFieldWriteStatic
    | XrefFieldReadInstance
    | XrefFieldWriteInstance => true
    _ => false
  }
}

///|
/// 构建单 dex 的访问点索引：对 method_ids 表（`DexFile::methods`，parse 已回填
/// code/flags）一次线性扫描，`instruction_operands` 重解码每个操作数引用。
///
/// - 参数：`dex` 为 `parse` 输出；方法身份用 method_ids 索引（Int32）。
/// - 返回：`XrefIndex`，sites 按 (method_ref 升序, offset 升序) 排列（构建序即该序）。
/// - 语义：仅 invoke-* 与 iget/iput/sget/sput 产 site；payload 伪指令、
///   aget/aput、const-string/const-class/类型引用、注解/静态初值的
///   ValueField/ValueMethod 均不产 site；abstract/native 与外部方法
///   （code==None）无自身 site，调用它们的点照常计。
/// - 错误：仅传播 `InvalidInstruction`（签名保守带 raise）。
pub fn build_xref(dex : DexFile) -> XrefIndex raise DexError {
  let sites : Array[XrefSite] = []
  let ms = dex.methods
  for i in 0..<ms.length() {
    match ms[i].code {
      None => ()
      Some(code) =>
        for insn in code.insns {
          match xref_kind_of_opcode(insn.opcode) {
            None => ()
            Some(kind) => {
              let ops = instruction_operands(insn)
              // kind 族与 IndexKind 一致才记录（parse 产物恒一致；
              // payload/空视图为 IndexNone，不产 site）
              let consistent = if xref_is_call(kind) {
                ops.index_kind is IndexKind::IndexMethod
              } else {
                ops.index_kind is IndexKind::IndexField
              }
              if consistent {
                sites.push(XrefSite::{
                  method_ref: i,
                  offset: insn.offset,
                  target_ref: ops.index,
                  kind,
                })
              }
            }
          }
        }
    }
  }
  XrefIndex::{
    all_sites: sites,
    method_count: ms.length(),
    field_count: dex.fields.length(),
  }
}

///|
/// (class_index, name_index, proto_index) 三元组反查 method_ids 索引
/// （DEX 规范三元组唯一）。用于把 class_def 遍历序（direct_methods +
/// virtual_methods）的 `MethodDef` 桥接为表索引身份；未命中返回 `None`。
/// O(M) 线性查找，无 raise。
pub fn method_ref_of(dex : DexFile, m : MethodDef) -> Int32? {
  for i in 0..<dex.methods.length() {
    let e = dex.methods[i]
    if e.class_index == m.class_index &&
      e.name_index == m.name_index &&
      e.proto_index == m.proto_index {
      return Some(i)
    }
  }
  None
}

///|
/// 目标侧查询：谁调用了 `method_ref`（Call* 点、target_ref == method_ref）。
/// 排序（冻结）：caller 的 method_ref 升序、同 caller 内 offset 升序。
/// `method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`；空结果=空数组。
pub fn XrefIndex::callers(
  self : XrefIndex,
  method_ref : Int32,
) -> Array[XrefSite] raise DexError {
  if method_ref < 0 || method_ref >= self.method_count {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  let out : Array[XrefSite] = []
  for s in self.all_sites {
    if xref_is_call(s.kind) && s.target_ref == method_ref {
      out.push(s)
    }
  }
  out
}

///|
/// 调用方侧查询：`method_ref` 发出的调用点（Call* 点、method_ref == 入参）。
/// 排序（冻结）：offset 升序。abstract/native 与外部方法（code==None）
/// 返回空数组。`method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`；
/// 空结果=空数组。
pub fn XrefIndex::callees(
  self : XrefIndex,
  method_ref : Int32,
) -> Array[XrefSite] raise DexError {
  if method_ref < 0 || method_ref >= self.method_count {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  let out : Array[XrefSite] = []
  for s in self.all_sites {
    if s.method_ref == method_ref && xref_is_call(s.kind) {
      out.push(s)
    }
  }
  out
}

///|
/// 目标侧查询：与 `callers` 等价（同序同内容），口径对称显式（契约 §0 ⑤）。
/// 排序（冻结）：caller 的 method_ref 升序、同 caller 内 offset 升序。
/// `method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`。
pub fn XrefIndex::method_sites(
  self : XrefIndex,
  method_ref : Int32,
) -> Array[XrefSite] raise DexError {
  self.callers(method_ref)
}

///|
/// 调用方侧查询：`method_ref` 方法体内的全部访问点（Call* + Field*）。
/// 排序（冻结）：offset 升序。abstract/native 与外部方法（code==None）
/// 返回空数组。`method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`；
/// 空结果=空数组。
pub fn XrefIndex::sites_in(
  self : XrefIndex,
  method_ref : Int32,
) -> Array[XrefSite] raise DexError {
  if method_ref < 0 || method_ref >= self.method_count {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  let out : Array[XrefSite] = []
  for s in self.all_sites {
    if s.method_ref == method_ref {
      out.push(s)
    }
  }
  out
}

///|
/// 目标侧查询：对 `field_ref` 的字段访问点（Field* 点、target_ref == field_ref）。
/// 排序（冻结）：caller 的 method_ref 升序、同 caller 内 offset 升序。
/// `field_ref` 越界抛 `InvalidIndex(FieldId, field_ref)`；空结果=空数组。
pub fn XrefIndex::field_sites(
  self : XrefIndex,
  field_ref : Int32,
) -> Array[XrefSite] raise DexError {
  if field_ref < 0 || field_ref >= self.field_count {
    raise DexError::InvalidIndex(TableKind::FieldId, field_ref)
  }
  let out : Array[XrefSite] = []
  for s in self.all_sites {
    if xref_is_field(s.kind) && s.target_ref == field_ref {
      out.push(s)
    }
  }
  out
}

///|
/// 全量访问点（副本）。排序（冻结）：method_ref 升序、offset 升序。
pub fn XrefIndex::sites(self : XrefIndex) -> Array[XrefSite] {
  let out : Array[XrefSite] = []
  for s in self.all_sites {
    out.push(s)
  }
  out
}
