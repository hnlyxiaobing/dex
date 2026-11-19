///|
/// DEX 扩展调用点索引——覆盖 0xFA–0xFD（W7，选项 A）。
///
/// `build_xref`（P1）仅覆盖 invoke-* 0x6e–0x78 族（五族调用）与字段访问
/// 0x52–0x6d。invoke-polymorphic{,/range}（0xFA/0xFB）与 invoke-custom{,/range}
/// （0xFC/0xFD）虽为方法调用且操作数引用了 method_ids / call_site_ids 表，
/// 但其 kind 语义不同于既有五族调用——重复利用 XrefKind 会失真。
/// 本文件提供独立的扩展索引 `build_xref_ext`，不修改 `build_xref` 输出
/// （P5 防火墙律）。
///
/// 非目标：0xFE（const-method-handle）/ 0xFF（const-method-type）为常量族，
/// 无调用目标，不产 site。
///
/// kind 映射（按 opcode 数值域）：
///   0xFA → XrefExtInvokePolymorphic
///   0xFB → XrefExtInvokePolymorphicRange
///   0xFC → XrefExtInvokeCustom
///   0xFD → XrefExtInvokeCustomRange
///
/// 复杂性：`build_xref_ext` = O(M+I) 一次线性扫描（M=method_ids、I=指令总数），
/// 与 `build_xref` 同构。构建仅传播 `InvalidInstruction`（签名保守带 raise）。
/// 查询越界抛 `InvalidIndex`，与 P1 一致。

///|
/// 扩展调用点类别（0xFA–0xFF invoke-polymorphic / invoke-custom 体系）。
pub(all) enum XrefKindExt {
  XrefExtInvokePolymorphic // 0xFA
  XrefExtInvokePolymorphicRange // 0xFB
  XrefExtInvokeCustom // 0xFC
  XrefExtInvokeCustomRange // 0xFD
}

///|
/// 扩展调用点 site（结构与 XrefSite 对齐，kind 使用扩展枚举）。
pub(all) struct XrefSiteExt {
  method_ref : Int32 // 所在（调用方）方法的 method_ids 索引
  offset : Int32 // code_item 内 code-unit 偏移
  target_ref : Int32 // 0xFA/0xFB: method_idx；0xFC/0xFD: call_site_idx
  kind : XrefKindExt
}

///|
/// 逐 dex 的扩展访问点索引（不透明 pub struct，与 XrefIndex 同构）。
/// 构建后只读。
pub struct XrefIndexExt {
  all_sites : Array[XrefSiteExt]
  method_count : Int32
  call_site_count : Int32
}

///|
/// opcode 数值域 → `XrefKindExt`。
/// 0xFA–0xFD 四指令；其余返回 `None`。
fn xref_ext_kind_of_opcode(op : Int32) -> XrefKindExt? {
  match op {
    0xfa => Some(XrefExtInvokePolymorphic)
    0xfb => Some(XrefExtInvokePolymorphicRange)
    0xfc => Some(XrefExtInvokeCustom)
    0xfd => Some(XrefExtInvokeCustomRange)
    _ => None
  }
}

///|
/// 构建扩展调用点索引。O(M+I) 一次线性扫描。
/// - 仅 0xFA–0xFD 产 site（0xFE/0xFF const 族无调用目标），
///   且 instruction_operands 必须返回 IndexMethod（0xFA/0xFB）
///   或 IndexCallSite（0xFC/0xFD），否则 skip（防御）。
/// - site 排序（冻结）：method_ref 升序 × offset 升序，
///   与 `build_xref` 同契约。
pub fn build_xref_ext(dex : DexFile) -> XrefIndexExt raise DexError {
  let sites : Array[XrefSiteExt] = []
  let ms = dex.methods
  for i in 0..<ms.length() {
    match ms[i].code {
      None => ()
      Some(code) =>
        for insn in code.insns {
          match xref_ext_kind_of_opcode(insn.opcode) {
            None => ()
            Some(kind) => {
              let ops = instruction_operands(insn)
              // 防御：kind 与 IndexKind 一致才记录
              let consistent = match kind {
                XrefExtInvokePolymorphic | XrefExtInvokePolymorphicRange =>
                  ops.index_kind is IndexKind::IndexMethod
                XrefExtInvokeCustom | XrefExtInvokeCustomRange =>
                  ops.index_kind is IndexKind::IndexCallSite
              }
              if consistent {
                sites.push(XrefSiteExt::{
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
  XrefIndexExt::{
    all_sites: sites,
    method_count: ms.length(),
    call_site_count: dex.call_sites.length(),
  }
}

///|
/// 全量 site 副本（冻结排序：method_ref 升序 × offset 升序）。
pub fn XrefIndexExt::sites(self : XrefIndexExt) -> Array[XrefSiteExt] {
  self.all_sites
}

///|
/// 调用方侧查询：`method_ref` 发出的扩展调用点。
/// `method_ref` 越界抛 `InvalidIndex(MethodId, method_ref)`。
pub fn XrefIndexExt::callees(
  self : XrefIndexExt,
  method_ref : Int32,
) -> Array[XrefSiteExt] raise DexError {
  if method_ref < 0 || method_ref >= self.method_count {
    raise DexError::InvalidIndex(TableKind::MethodId, method_ref)
  }
  let out : Array[XrefSiteExt] = []
  for s in self.all_sites {
    if s.method_ref == method_ref {
      out.push(s)
    }
  }
  out
}

///|
/// 目标侧查询：谁通过 0xFA–0xFD 族调用了 `target_ref`。
/// 排序（冻结）：caller 的 method_ref 升序、同 caller 内 offset 升序。
/// `target_ref` 越界（method_count 或 call_site_count）抛
/// `InvalidIndex(MethodId|CallSiteId, target_ref)`。
pub fn XrefIndexExt::callers(
  self : XrefIndexExt,
  target_ref : Int32,
) -> Array[XrefSiteExt] raise DexError {
  if target_ref < 0 {
    raise DexError::InvalidIndex(TableKind::MethodId, target_ref)
  }
  let out : Array[XrefSiteExt] = []
  for s in self.all_sites {
    if s.target_ref == target_ref {
      // 仅记录 method / call_site 两类引用
      match s.kind {
        XrefExtInvokePolymorphic | XrefExtInvokePolymorphicRange => {
          if target_ref >= self.method_count {
            raise DexError::InvalidIndex(TableKind::MethodId, target_ref)
          }
          out.push(s)
        }
        XrefExtInvokeCustom | XrefExtInvokeCustomRange => {
          if target_ref >= self.call_site_count {
            raise DexError::InvalidIndex(TableKind::CallSiteId, target_ref)
          }
          out.push(s)
        }
      }
    }
  }
  out
}
