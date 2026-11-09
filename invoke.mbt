///|
/// DEX 038+ 指令组支撑表：method_handles_item / call_site_id_item 解析、
/// MethodHandle kind 标注与可读符号名渲染（invoke-custom / invoke-polymorphic /
/// const-method-handle / const-method-type 指令组的名字解析数据源）。
/// 规范依据：AOSP dex-format 的 method_handle_item / call_site_id_item 章节；
/// kind 码表与 AOSP libdexfile `DexFile::MethodHandleType` 逐一核对
/// （0x00–0x03 引用 field_ids，0x04–0x08 引用 method_ids），渲染标签与
/// dexdump 35.0.0 `Method handle #N: type :` 行同词。
/// 两张表只在 map_list 中出现（header 无专用字段）：type 0x0007 = call_site_id_item、
/// 0x0008 = method_handle_item；map_item.unused 与 method_handle_item.unused
/// 为保留位（res0），必须为 0，非法值报 `DexError` 不 panic。

///|
/// method_handle_item.method_handle_type：MethodHandle 句柄类型（Dex 038+ 标注）。
/// 0x00–0x03 为字段读写句柄（field_or_method_index 是 field_ids 索引），
/// 0x04–0x08 为方法调用句柄（field_or_method_index 是 method_ids 索引）。
pub(all) enum MethodHandleKind {
  StaticPut // 0x00 静态字段写
  StaticGet // 0x01 静态字段读
  InstancePut // 0x02 实例字段写
  InstanceGet // 0x03 实例字段读
  InvokeStatic // 0x04 静态方法调用
  InvokeInstance // 0x05 实例方法调用（非 <init>）
  InvokeConstructor // 0x06 构造器调用
  InvokeDirect // 0x07 direct/special 方法调用
  InvokeInterface // 0x08 接口方法调用
}

///|
/// method_handle_item 结构化解析结果。
/// - `handle_type`：句柄类型（见 `MethodHandleKind`）。
/// - `field_or_method_index`：按 kind 语义解释——字段句柄（`is_field_ref`）为
///   field_ids 表索引，方法句柄（`is_method_ref`）为 method_ids 表索引。
pub(all) struct MethodHandleItem {
  handle_type : MethodHandleKind
  field_or_method_index : Int32
}

///|
/// 字段句柄（0x00–0x03）判定：索引语义为 field_ids 表索引。
pub fn MethodHandleItem::is_field_ref(self : MethodHandleItem) -> Bool {
  match self.handle_type {
    StaticPut | StaticGet | InstancePut | InstanceGet => true
    _ => false
  }
}

///|
/// 方法句柄（0x04–0x08）判定：索引语义为 method_ids 表索引。
pub fn MethodHandleItem::is_method_ref(self : MethodHandleItem) -> Bool {
  !self.is_field_ref()
}

///|
/// call_site_id_item → call_site_item（encoded_array）的解析结果。
/// - `call_site_off`：call_site_item 的文件内偏移（call_site_id_item 原值）。
/// - `values`：call_site_item 的 encoded_array 值序列；DEX 规范布局为
///   [bootstrap MethodHandle, 链接名 String, 链接类型 MethodType, 静态参数…]，
///   其中 MethodHandle/MethodType 为 DEX 038+ 新增 encoded_value 类型。
pub(all) struct CallSiteItem {
  call_site_off : Int32
  values : Array[EncodedValue]
}

///|
/// MethodHandle kind → dexdump 同词标签（golden 差分口径，见 tests/ASSETS.md）。
fn handle_kind_label(k : MethodHandleKind) -> String {
  match k {
    StaticPut => "put-static"
    StaticGet => "get-static"
    InstancePut => "put-instance"
    InstanceGet => "get-instance"
    InvokeStatic => "invoke-static"
    InvokeInstance => "invoke-instance"
    InvokeConstructor => "invoke-constructor"
    InvokeDirect => "invoke-direct"
    InvokeInterface => "invoke-interface"
  }
}

///|
/// 数值 kind → 枚举（0x00–0x08）；超范围返回 `None`（调用方报 `DexError`）。
fn handle_kind_of(t : Int32) -> MethodHandleKind? {
  match t {
    0 => Some(StaticPut)
    1 => Some(StaticGet)
    2 => Some(InstancePut)
    3 => Some(InstanceGet)
    4 => Some(InvokeStatic)
    5 => Some(InvokeInstance)
    6 => Some(InvokeConstructor)
    7 => Some(InvokeDirect)
    8 => Some(InvokeInterface)
    _ => None
  }
}

///|
/// proto → `(参数串)返回类型`（与 method_ref_name 的签名段同构）。
fn fmt_proto_sig(p : ProtoId) -> String {
  "(" + join_str(p.parameters, "") + ")" + p.return_type
}

///|
/// DexFile → 解析上下文（供 DexFile 视图的名字解析复用既有渲染器）。
fn ctx_of(dex : DexFile) -> Ctx {
  Ctx::{
    strings: dex.strings,
    types: dex.type_descriptors,
    protos: dex.protos,
    fields: dex.fields,
    methods: dex.methods,
    handles: dex.handles,
    call_sites: dex.call_sites,
  }
}

///|
/// method_handle@ 引用解析为可读符号名（DexFile 视图）：
/// `<kind 标签> <目标>`；越界抛 `InvalidIndex(MethodHandle, index)`。
pub fn method_handle_name(
  dex : DexFile,
  index : Int32,
) -> String raise DexError {
  fmt_method_handle_ref(ctx_of(dex), index)
}

///|
/// call_site@ 引用解析为可读符号名（DexFile 视图）：
/// `call_site@N{bsm=…, name=…, type=…, args=[…]}`；越界抛 `InvalidIndex(CallSiteId, index)`。
pub fn call_site_name(dex : DexFile, index : Int32) -> String raise DexError {
  fmt_call_site_ref(ctx_of(dex), index)
}

///|
/// proto@ 引用解析为 `(参数串)返回类型`（DexFile 视图：const-method-type /
/// invoke-polymorphic 的 proto 操作数）；越界抛 `InvalidIndex(ProtoId, index)`。
pub fn proto_name(dex : DexFile, index : Int32) -> String raise DexError {
  if index < 0 || index >= dex.protos.length() {
    raise DexError::InvalidIndex(TableKind::ProtoId, index)
  }
  fmt_proto_sig(dex.protos[index])
}

///|
/// method_handle@ 引用解析为 `<kind 标签> <目标>`：
/// 字段句柄 `put-static Lcls;->name:type`、方法句柄 `invoke-static Lcls;->name(params)ret`
/// （目标渲染与 fmt_field_ref / fmt_method_ref 一致）。
fn fmt_method_handle_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.handles.length() {
    raise DexError::InvalidIndex(TableKind::MethodHandle, idx)
  }
  let h = ctx.handles[idx]
  let target = if h.is_field_ref() {
    fmt_field_ref(ctx, h.field_or_method_index)
  } else {
    fmt_method_ref(ctx, h.field_or_method_index)
  }
  handle_kind_label(h.handle_type) + " " + target
}

///|
/// 单个 encoded_value 的确定性文本渲染（call_site 参数等场景）。
fn fmt_encoded_value(v : EncodedValue) -> String {
  match v {
    ValueByte(x) | ValueShort(x) | ValueChar(x) | ValueInt(x) => fmt_sint(x)
    ValueLong(x) => x.to_string()
    ValueFloat(x) => x.to_string()
    ValueDouble(x) => x.to_string()
    ValueString(s) => s.escape(quote=true)
    ValueType(s)
    | ValueField(s)
    | ValueMethod(s)
    | ValueEnum(s)
    | ValueMethodType(s)
    | ValueMethodHandle(s) => s
    ValueNull => "null"
    ValueBoolean(b) => b.to_string()
    ValueArray(items) =>
      "[" + join_str(items.map(fmt_encoded_value), ", ") + "]"
    ValueAnnotation(a) => "@" + a.type_descriptor
  }
}

///|
/// call_site@ 引用解析为 `call_site@N{…}`：
/// 规范布局（[bsm, name, type, 静态参数…]）渲染为
/// `bsm=<bootstrap 句柄>, name="…", type=(…)…, args=[…]`；
/// 非规范形状退化为位置渲染 `v0, v1, …`（宽容不拒）。
fn fmt_call_site_ref(ctx : Ctx, idx : Int32) -> String raise DexError {
  if idx < 0 || idx >= ctx.call_sites.length() {
    raise DexError::InvalidIndex(TableKind::CallSiteId, idx)
  }
  let cs = ctx.call_sites[idx]
  let vs = cs.values
  let body = if vs.length() >= 3 &&
    vs[0] is ValueMethodHandle(_) &&
    vs[1] is ValueString(_) &&
    vs[2] is ValueMethodType(_) {
    let args : Array[String] = []
    let mut i = 3
    while i < vs.length() {
      args.push(fmt_encoded_value(vs[i]))
      i = i + 1
    }
    "bsm=" +
    fmt_encoded_value(vs[0]) +
    ", name=" +
    fmt_encoded_value(vs[1]) +
    ", type=" +
    fmt_encoded_value(vs[2]) +
    ", args=[" +
    join_str(args, ", ") +
    "]"
  } else {
    let parts : Array[String] = []
    let mut i = 0
    while i < vs.length() {
      parts.push("v" + i.to_string() + "=" + fmt_encoded_value(vs[i]))
      i = i + 1
    }
    join_str(parts, ", ")
  }
  "call_site@" + idx.to_string() + "{" + body + "}"
}

///|
/// 解析 method_handles_item（map_list type 0x0008）：
/// size×{u16 method_handle_type; u16 unused; u32 field_or_method_id}。
/// 校验（全部报 `DexError` 不 panic）：表位置/条目越界 → `BadTableOffset(MethodHandle, …)`；
/// unused（res0）非 0 或 kind 超范围 → `BadTableOffset(MethodHandle, …)`；
/// field/method 索引越界 → `InvalidIndex(FieldId|MethodId, …)`。
fn parse_method_handles(
  data : Bytes,
  map_off : Int32,
  field_count : Int32,
  method_count : Int32,
) -> Array[MethodHandleItem] raise DexError {
  let file_size = data.length()
  let out : Array[MethodHandleItem] = []
  if map_off == 0 {
    return out
  }
  let mut i = 0
  let count = read_u32(data, map_off)
  while i < count {
    let p = map_off + 4 + i * 12
    let ty = read_u16(data, p)
    let unused = read_u16(data, p + 2)
    let size = read_u32(data, p + 4)
    let off = read_u32(data, p + 8)
    if unused != 0 {
      raise DexError::BadTableOffset(TableKind::MapList, p)
    }
    if ty == 0x0008 {
      check_table(file_size, off, size, 8, TableKind::MethodHandle)
      for k in 0..<size {
        let base = off + k * 8
        let raw_kind = read_u16(data, base)
        let item_unused = read_u16(data, base + 2)
        let ref_idx = read_u32(data, base + 4)
        if item_unused != 0 {
          raise DexError::BadTableOffset(TableKind::MethodHandle, base)
        }
        match handle_kind_of(raw_kind) {
          None => raise DexError::BadTableOffset(TableKind::MethodHandle, base)
          Some(handle_type) => {
            if raw_kind <= 3 {
              if ref_idx < 0 || ref_idx >= field_count {
                raise DexError::InvalidIndex(TableKind::FieldId, ref_idx)
              }
            } else if ref_idx < 0 || ref_idx >= method_count {
              raise DexError::InvalidIndex(TableKind::MethodId, ref_idx)
            }
            out.push(MethodHandleItem::{
              handle_type,
              field_or_method_index: ref_idx,
            })
          }
        }
      }
    }
    i = i + 1
  }
  out
}

///|
/// 解析 call_site_id_item（map_list type 0x0007）：size×u32 call_site_off，
/// 每项指向 call_site_item（encoded_array，解码为 `CallSiteItem::values`）。
/// 校验：表位置/偏移越界 → `BadTableOffset(CallSiteId, …)`；
/// encoded_array 结构损坏复用既有构造（`BadTableOffset`/`UnexpectedEof`/`InvalidIndex`）。
fn parse_call_sites(
  data : Bytes,
  map_off : Int32,
  ctx : Ctx,
) -> Array[CallSiteItem] raise DexError {
  let file_size = data.length()
  let out : Array[CallSiteItem] = []
  if map_off == 0 {
    return out
  }
  let mut i = 0
  let count = read_u32(data, map_off)
  while i < count {
    let p = map_off + 4 + i * 12
    let ty = read_u16(data, p)
    let size = read_u32(data, p + 4)
    let off = read_u32(data, p + 8)
    if ty == 0x0007 {
      check_table(file_size, off, size, 4, TableKind::CallSiteId)
      for k in 0..<size {
        let call_site_off = read_u32(data, off + k * 4)
        if call_site_off < 0x70 || call_site_off >= file_size {
          raise DexError::BadTableOffset(TableKind::CallSiteId, call_site_off)
        }
        let (values, _) = decode_array_body(ctx, data, call_site_off)
        out.push(CallSiteItem::{ call_site_off, values, })
      }
    }
    i = i + 1
  }
  out
}

///|
/// 解析 method_handles_item 表（公开入口，自含：第一参数为原始 DEX 字节）。
///
/// - 返回：表内全部句柄（表序）；035 及无该表的 DEX 返回空数组。
/// - 错误：头部/表校验同 `parse`；kind 超范围或 res0 非 0 抛
///   `BadTableOffset(MethodHandle, …)`，索引越界抛 `InvalidIndex(FieldId|MethodId, …)`。
/// - 线程：纯函数，无全局状态，可并发。
pub fn method_handles(data : Bytes) -> Array[MethodHandleItem] raise DexError {
  let ctx = read_ctx(data)
  ctx.handles
}

///|
/// 解析 call_site_id_item 表（公开入口，自含：第一参数为原始 DEX 字节）。
///
/// - 返回：表内全部 call_site（表序，`values` 为已解码 encoded_array）；
///   无该表的 DEX 返回空数组。
/// - 错误：同 `method_handles`；call_site_off 越界抛 `BadTableOffset(CallSiteId, …)`。
/// - 线程：纯函数，无全局状态，可并发。
pub fn call_sites(data : Bytes) -> Array[CallSiteItem] raise DexError {
  let ctx = read_ctx(data)
  ctx.call_sites
}

///|
/// method_handle@ 引用解析为可读符号名（`method_handles` 表项渲染）：
/// `<kind 标签> <目标>`，如 `invoke-static Lcls;->m(II)I`、`put-static Lcls;->f:I`。
/// `index` 为 method_handles 表索引（与 `Instruction` 操作数 `method_handle@` 同口径）；
/// 越界抛 `InvalidIndex(MethodHandle, index)`。
pub fn method_handle_ref_name(
  data : Bytes,
  index : Int32,
) -> String raise DexError {
  let ctx = read_ctx(data)
  fmt_method_handle_ref(ctx, index)
}

///|
/// call_site@ 引用解析为可读符号名（invoke-custom 的关联标注）：
/// `call_site@N{bsm=…, name=…, type=…, args=[…]}`（见 `CallSiteItem::values` 布局）。
/// `index` 为 call_site_ids 表索引；越界抛 `InvalidIndex(CallSiteId, index)`。
pub fn call_site_ref_name(data : Bytes, index : Int32) -> String raise DexError {
  let ctx = read_ctx(data)
  fmt_call_site_ref(ctx, index)
}
