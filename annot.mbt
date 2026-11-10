///|
/// 注解目录（annotation_directory_item）与静态初值（static_values_off → encoded_array）
/// 的公开入口。全部入口自含：调用方传原始 DEX 字节 `data`（所有权归调用方，不缓存）
/// 与 class_defs 表位置；内部复用 `read_ctx`（与 `parse` 相同的头部校验 + 六表读取），
/// 不解码 class_def / code_item，因此比 `parse` 轻量。
/// 批量遍历全类时请用 `annotations_index(data)` 建一次索引再复用查询方法：
/// 单次查询入口每次都会重建一次六表，对 N 个类逐类调用即 O(N × 表规模)，
/// 在真实规模 DEX 上会退化为分钟级；CLI 的 summary / --json 已接线索引。
/// 多 dex 组合维持 `MultiDexNotMerged` 语义：本文件只处理单个 DEX 字节流。

///|
/// 读取 class_defs[class_index] 的 annotations_off（+20）与 static_values_off（+28）。
/// `class_index` 为 class_defs 表位置（与 `DexFile::methods` 参数同义）；
/// 越界抛 `InvalidIndex(ClassDef, ...)`，表损坏抛 `BadTableOffset`。
fn class_aux_offs(
  data : Bytes,
  class_index : Int32,
) -> (Int32, Int32) raise DexError {
  let file_size = data.length()
  let class_defs_size = read_u32(data, 0x60)
  let class_defs_off = read_u32(data, 0x64)
  if class_index < 0 || class_index >= class_defs_size {
    raise DexError::InvalidIndex(TableKind::ClassDef, class_index)
  }
  let base = class_defs_off + class_index * 32
  if base < 0x70 || base + 32 > file_size {
    raise DexError::BadTableOffset(TableKind::ClassDef, class_defs_off)
  }
  let annotations_off = read_u32(data, base + 20)
  let static_values_off = read_u32(data, base + 28)
  for off in [annotations_off, static_values_off] {
    if off != 0 && (off < 0x70 || off >= file_size) {
      raise DexError::BadTableOffset(TableKind::ClassDef, off)
    }
  }
  (annotations_off, static_values_off)
}

///|
/// 注解 / 静态初值索引（加法性新增，2026-11-09）：一次 `read_ctx` 建立解析上下文，
/// 之后按 class_defs 位置 O(1) 局部解码，避免批量查询时逐类重建六张表。
///
/// - 构建：`annotations_index(data)` 执行与 `parse` 相同的头部校验与六表读取；
/// - 查询：`AnnotationsIndex::class_annotations` / `::static_values` 与同名全局
///   入口语义逐字一致（含 `InvalidIndex(ClassDef, ...)`、`BadTableOffset` 等错误）；
/// - 复杂度：构建 O(表规模) 一次，每次查询只解码该类自身的注解目录 / encoded_array；
/// - 逐 dex 使用，不缓存、不跨 dex 合并（`MultiDexNotMerged` 口径维持）；
/// - 不透明 `pub struct`、私有字段，构建后视为只读；纯函数，无全局状态，可并发。
/// - 实现注记：`Ctx` 为包内私有类型，公开结构不得直接依赖它；此处平铺保存其
///   公开类型的表字段，查询时在包内重组 `Ctx`（只搬表引用，不复制表内容）。
pub struct AnnotationsIndex {
  data : Bytes
  strings : Array[String]
  types : Array[String]
  protos : Array[ProtoId]
  fields : Array[FieldDef]
  methods : Array[MethodDef]
  handles : Array[MethodHandleItem]
  call_sites : Array[CallSiteItem]
}

///|
/// 查询时重组包内解析上下文（只搬表引用，O(1)，不复制表内容）。
fn AnnotationsIndex::ctx(self : AnnotationsIndex) -> Ctx {
  Ctx::{
    strings: self.strings,
    types: self.types,
    protos: self.protos,
    fields: self.fields,
    methods: self.methods,
    handles: self.handles,
    call_sites: self.call_sites,
  }
}

///|
/// 为单份 DEX 字节建立注解索引（一次全表读取 + 头部校验）。
/// 批量遍历所有类时只调用一次，再复用两个查询方法。
pub fn annotations_index(data : Bytes) -> AnnotationsIndex raise DexError {
  let ctx = read_ctx(data)
  AnnotationsIndex::{
    data,
    strings: ctx.strings,
    types: ctx.types,
    protos: ctx.protos,
    fields: ctx.fields,
    methods: ctx.methods,
    handles: ctx.handles,
    call_sites: ctx.call_sites,
  }
}

///|
/// 索引视图：解析指定类的注解目录；`annotations_off == 0` 直接返回 `None`，
/// 不重复解码任何索引表。错误同全局 `class_annotations`。
pub fn AnnotationsIndex::class_annotations(
  self : AnnotationsIndex,
  class_index : Int32,
) -> AnnotationsDirectory? raise DexError {
  let (annotations_off, _) = class_aux_offs(self.data, class_index)
  if annotations_off == 0 {
    None
  } else {
    Some(
      decode_annotations_directory_body(self.ctx(), self.data, annotations_off),
    )
  }
}

///|
/// 索引视图：解析指定类的静态字段初值；`static_values_off == 0` 返回空数组。
/// 错误同全局 `static_values`。
pub fn AnnotationsIndex::static_values(
  self : AnnotationsIndex,
  class_index : Int32,
) -> Array[EncodedValue] raise DexError {
  let (_, static_values_off) = class_aux_offs(self.data, class_index)
  if static_values_off == 0 {
    return []
  }
  let (values, _) = decode_array_body(self.ctx(), self.data, static_values_off)
  values
}

///|
/// 解码 annotation_directory_item 主体：
/// u32 class_annotations_off + 3×u32 size + 12 字节条目×(fields + methods + params)。
fn decode_annotations_directory_body(
  ctx : Ctx,
  data : Bytes,
  off : Int32,
) -> AnnotationsDirectory raise DexError {
  need_bytes(data, off, 16)
  let class_annotations_off = read_u32(data, off)
  let fields_size = read_u32(data, off + 4)
  let methods_size = read_u32(data, off + 8)
  let params_size = read_u32(data, off + 12)
  for size in [fields_size, methods_size, params_size] {
    if size < 0 || size > (data.length() - off - 16) / 12 {
      raise DexError::BadTableOffset(TableKind::ClassDef, off)
    }
  }
  let class_annotations = if class_annotations_off == 0 {
    AnnotationSet::{ annotations: [], }
  } else {
    decode_annotation_set_body(ctx, data, class_annotations_off)
  }
  let field_annotations : Array[FieldAnnotations] = []
  let mut pos = off + 16
  for _ in 0..<fields_size {
    let field_index = read_u32(data, pos)
    let set_off = read_u32(data, pos + 4)
    pos = pos + 8
    if field_index < 0 || field_index >= ctx.fields.length() {
      raise DexError::InvalidIndex(TableKind::FieldId, field_index)
    }
    let annotations = if set_off == 0 {
      AnnotationSet::{ annotations: [], }
    } else {
      decode_annotation_set_body(ctx, data, set_off)
    }
    field_annotations.push(FieldAnnotations::{ field_index, annotations, })
  }
  let method_annotations : Array[MethodAnnotations] = []
  for _ in 0..<methods_size {
    let method_index = read_u32(data, pos)
    let set_off = read_u32(data, pos + 4)
    pos = pos + 8
    if method_index < 0 || method_index >= ctx.methods.length() {
      raise DexError::InvalidIndex(TableKind::MethodId, method_index)
    }
    let annotations = if set_off == 0 {
      AnnotationSet::{ annotations: [], }
    } else {
      decode_annotation_set_body(ctx, data, set_off)
    }
    method_annotations.push(MethodAnnotations::{ method_index, annotations, })
  }
  let parameter_annotations : Array[ParameterAnnotations] = []
  for _ in 0..<params_size {
    let method_index = read_u32(data, pos)
    let ref_list_off = read_u32(data, pos + 4)
    pos = pos + 8
    if method_index < 0 || method_index >= ctx.methods.length() {
      raise DexError::InvalidIndex(TableKind::MethodId, method_index)
    }
    // annotation_set_ref_list：u32 size + u32 set_off×size（0 = 该参数无注解）
    need_bytes(data, ref_list_off, 4)
    let count = read_u32(data, ref_list_off)
    if count < 0 || count > (data.length() - ref_list_off - 4) / 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, ref_list_off)
    }
    let parameters : Array[AnnotationSet] = []
    for j in 0..<count {
      let set_off = read_u32(data, ref_list_off + 4 + j * 4)
      if set_off == 0 {
        parameters.push(AnnotationSet::{ annotations: [], })
      } else {
        parameters.push(decode_annotation_set_body(ctx, data, set_off))
      }
    }
    parameter_annotations.push(ParameterAnnotations::{
      method_index,
      parameters,
    })
  }
  AnnotationsDirectory::{
    class_annotations,
    field_annotations,
    method_annotations,
    parameter_annotations,
  }
}

///|
/// 解析指定类的注解目录（annotation_directory_item）。
///
/// - 参数：`data` 为完整单 DEX 字节（调用方持有所有权）；`class_index` 为
///   class_defs 表位置（与 `DexFile::methods` 的 `class_index` 同义）。
/// - 返回：`Some(AnnotationsDirectory)`（class/field/method/parameter 四类）；
///   `annotations_off == 0` 时返回 `None`。
/// - 错误：头部/表校验同 `parse`（`BadMagic`/`UnsupportedVersion`/`BadTableOffset`…）；
///   `class_index` 越界抛 `InvalidIndex(ClassDef, ...)`；注解结构损坏抛
///   `BadTableOffset(ClassDef, 偏移)` 或 `UnexpectedEof`。
/// - 线程：纯函数，无全局状态，可并发。
/// - 批量：遍历全类请用 `annotations_index(data)` 建一次索引再复用查询方法，
///   单次入口每次都会重建六表（等价实现见索引视图）。
/// - 非目标：不做注解语义解释（如 InnerClass 语义还原）、不做多 dex 合并。
pub fn class_annotations(
  data : Bytes,
  class_index : Int32,
) -> AnnotationsDirectory? raise DexError {
  let index = annotations_index(data)
  index.class_annotations(class_index)
}

///|
/// 解码指定偏移处的 annotation_set_item。`off` 为文件内偏移（0x70 起）。
/// 错误同 `class_annotations`。
pub fn annotation_set(
  data : Bytes,
  off : Int32,
) -> AnnotationSet raise DexError {
  let ctx = read_ctx(data)
  if off < 0x70 || off >= data.length() {
    raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
  decode_annotation_set_body(ctx, data, off)
}

///|
/// 解码指定偏移处的 annotation_item（u8 visibility + encoded_annotation）。
/// 错误同 `class_annotations`。
pub fn annotation_item(data : Bytes, off : Int32) -> Annotation raise DexError {
  let ctx = read_ctx(data)
  if off < 0x70 || off >= data.length() {
    raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
  decode_annotation_item_body(ctx, data, off)
}

///|
/// 解码指定偏移处的 encoded_array（uleb128 size + encoded_value×size）。
/// 注解默认值（AnnotationDefault）、静态初值等场景的通用入口。
/// 错误同 `class_annotations`。
pub fn encoded_array(
  data : Bytes,
  off : Int32,
) -> Array[EncodedValue] raise DexError {
  let ctx = read_ctx(data)
  if off < 0x70 || off >= data.length() {
    raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
  let (values, _) = decode_array_body(ctx, data, off)
  values
}

///|
/// 解析指定类的静态字段初值（class_def.static_values_off → encoded_array）。
/// 加密字符串入口：静态常量字符串/整型初值在此展开为结构化常量值。
///
/// - 返回：与 `ClassDef::static_fields` **前缀**一一对应的值数组；
///   DEX 只编码非默认值的前缀，尾部默认值被省略（返回数组长度 ≤ static_fields 长度）。
///   `static_values_off == 0` 时返回空数组。
/// - 错误：同 `class_annotations`。
/// - 批量：同 `class_annotations`，遍历全类请用 `annotations_index(data)`。
pub fn static_values(
  data : Bytes,
  class_index : Int32,
) -> Array[EncodedValue] raise DexError {
  let index = annotations_index(data)
  index.static_values(class_index)
}
