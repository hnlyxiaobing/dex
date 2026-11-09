///|
/// DEX 注解与 encoded_value 语义解码：encoded_value 全 16 种 value_type、
/// encoded_array、encoded_annotation、annotation_item / annotation_set_item。
/// 规范依据：AOSP dex-format 的 annotation_directory_item / annotation_set_item /
/// annotation_item / encoded_annotation / encoded_value / encoded_array 章节。
/// 布局实证（2026-11-07）：javac 21 + d8（build-tools 35.0.0）生成样本与
/// tvshell-debug / motionshell 真实 classes.dex 的 `dexdump -d -a` 输出逐值核对：
/// - format 字节 = (value_arg << 5) | value_type，value_arg = 字节数 - 1；
/// - 整型右对齐符号/零扩展（最小宽度），float/double **左对齐**、低位补零
///   （dex 格式原文 "zero-extended to the right"，实测 3.5f 存 `60 40` 两字节）；
/// - value_type 码表：byte=0x00 short=0x02 char=0x03 int=0x04 long=0x06
///   float=0x10 double=0x11 string=0x17 type=0x18 field=0x19 method=0x1a
///   enum=0x1b array=0x1c annotation=0x1d null=0x1e boolean=0x1f。

///|
/// annotation_item.visibility：0=BUILD（编译期可见）、1=RUNTIME、2=SYSTEM（VM 注解）。
pub(all) enum AnnotationVisibility {
  VisibilityBuild
  VisibilityRuntime
  VisibilitySystem
}

///|
/// encoded_value 全 16 种 value_type 的结构化解码结果。
/// 引用类值（string/type/field/method/enum）在解码时按表解析为名字
/// （字段/方法/枚举沿用 smali 风格 `Lcls;->name:type` / `Lcls;->name(sig)ret`）；
/// 整型/字符为扩展后的数值；float/double 为 IEEE-754 位模式还原值。
pub(all) enum EncodedValue {
  ValueByte(Int32)
  ValueShort(Int32)
  ValueChar(Int32)
  ValueInt(Int32)
  ValueLong(Int64)
  ValueFloat(Float)
  ValueDouble(Double)
  ValueString(String)
  ValueType(String)
  ValueField(String)
  ValueMethod(String)
  ValueEnum(String)
  /// DEX 038+：VALUE_METHOD_TYPE（proto 引用，`(params)ret` 文本）
  ValueMethodType(String)
  /// DEX 038+：VALUE_METHOD_HANDLE（method_handles 表引用，`<kind> <target>` 文本）
  ValueMethodHandle(String)
  ValueArray(Array[EncodedValue])
  ValueAnnotation(EncodedAnnotation)
  ValueNull
  ValueBoolean(Bool)
}

///|
/// 注解元素：元素名（name_idx 已解析）与值。
pub(all) struct AnnotationElement {
  name : String
  value : EncodedValue
}

///|
/// encoded_annotation：注解类型描述符 + 元素序列（保持文件内顺序，
/// 合法 DEX 中按元素名升序）。
pub(all) struct EncodedAnnotation {
  type_descriptor : String
  elements : Array[AnnotationElement]
}

///|
/// annotation_item：可见性 + encoded_annotation。
pub(all) struct Annotation {
  visibility : AnnotationVisibility
  annotation : EncodedAnnotation
}

///|
/// annotation_set_item：一个成员的注解集合（合法 DEX 中按类型描述符升序）。
pub(all) struct AnnotationSet {
  annotations : Array[Annotation]
}

///|
/// 字段注解目录项（annotation_directory_item.field_annotations）。
pub(all) struct FieldAnnotations {
  field_index : Int32
  annotations : AnnotationSet
}

///|
/// 方法注解目录项（annotation_directory_item.method_annotations）。
pub(all) struct MethodAnnotations {
  method_index : Int32
  annotations : AnnotationSet
}

///|
/// 方法参数注解目录项（annotation_directory_item.parameter_annotations →
/// annotation_set_ref_list）。`parameters` 与形参一一对应，空 `AnnotationSet`
/// 表示该参数无注解（ref 列表中偏移为 0）。
pub(all) struct ParameterAnnotations {
  method_index : Int32
  parameters : Array[AnnotationSet]
}

///|
/// annotation_directory_item 解码结果：class / field / method / parameter
/// 四类注解目录。字段/方法索引为 field_ids / method_ids 表索引。
pub(all) struct AnnotationsDirectory {
  class_annotations : AnnotationSet
  field_annotations : Array[FieldAnnotations]
  method_annotations : Array[MethodAnnotations]
  parameter_annotations : Array[ParameterAnnotations]
}

///|
/// 读取 n 字节小端无符号值（零扩展到 Int64），n ∈ 1..8。
fn read_sized_le(data : Bytes, pos : Int32, n : Int32) -> Int64 {
  let mut v = 0L
  let mut i = n - 1
  while i >= 0 {
    v = (v << 8) | (byte_at(data, pos + i).to_int64() & 0xffL)
    i = i - 1
  }
  v
}

///|
/// 读取 n 字节小端值并符号扩展到 Int64（整型最小宽度编码的还原）。
fn read_sized_signed(data : Bytes, pos : Int32, n : Int32) -> Int64 {
  let raw = read_sized_le(data, pos, n)
  let bits = n * 8
  if bits >= 64 {
    raw
  } else {
    let sign_bit = 1L << (bits - 1)
    if (raw & sign_bit) != 0L {
      raw | (-1L << bits)
    } else {
      raw
    }
  }
}

///|
/// float 32 位模式还原：payload 为高 n 字节、低位补零（左对齐）。
fn read_float_bits(data : Bytes, pos : Int32, n : Int32) -> Int32 {
  (read_sized_le(data, pos, n) << ((4 - n) * 8)).to_int()
}

///|
/// double 64 位模式还原：payload 为高 n 字节、低位补零（左对齐）。
fn read_double_bits(data : Bytes, pos : Int32, n : Int32) -> Int64 {
  read_sized_le(data, pos, n) << ((8 - n) * 8)
}

///|
/// 校验 `data[pos..pos+n]` 仍在界内，否则抛 `UnexpectedEof`。
fn need_bytes(data : Bytes, pos : Int32, n : Int32) -> Unit raise DexError {
  if pos < 0 || n < 0 || pos + n > data.length() {
    raise DexError::UnexpectedEof(pos)
  }
}

///|
/// 校验 unsigned 索引（Int32 位模式）落在 [0, size) 内，返回 Int32。
fn check_index(
  kind : TableKind,
  idx_raw : Int64,
  size : Int32,
) -> Int32 raise DexError {
  if idx_raw < 0L || idx_raw >= size.to_int64() {
    raise DexError::InvalidIndex(kind, idx_raw.to_int())
  }
  idx_raw.to_int()
}

///|
/// 读 uleb128；截断/溢出抛 `BadTableOffset(ClassDef, off)`。
fn uleb_ann(data : Bytes, off : Int32) -> (Int32, Int32) raise DexError {
  match try_uleb128(data, off) {
    Some(r) => r
    None => raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
}

///|
/// 解码 encoded_array 主体（uleb128 size + value×size），返回 (值列表, 结束偏移)。
fn decode_array_body(
  ctx : Ctx,
  data : Bytes,
  pos : Int32,
) -> (Array[EncodedValue], Int32) raise DexError {
  let (size, p0) = uleb_ann(data, pos)
  if size < 0 || size > data.length() {
    raise DexError::BadTableOffset(TableKind::ClassDef, pos)
  }
  let mut p = p0
  let out : Array[EncodedValue] = []
  for _ in 0..<size {
    let (v, np) = decode_value(ctx, data, p)
    out.push(v)
    p = np
  }
  (out, p)
}

///|
/// 解码 encoded_annotation 主体（uleb128 type_idx + uleb128 size + 元素），
/// 返回 (注解, 结束偏移)。
fn decode_encoded_annotation_body(
  ctx : Ctx,
  data : Bytes,
  pos : Int32,
) -> (EncodedAnnotation, Int32) raise DexError {
  let (type_raw, p1) = uleb_ann(data, pos)
  let type_idx = check_index(
    TableKind::TypeId,
    type_raw.to_int64(),
    ctx.types.length(),
  )
  let (count, p2) = uleb_ann(data, p1)
  let mut p = p2
  if count < 0 || count > data.length() {
    raise DexError::BadTableOffset(TableKind::ClassDef, pos)
  }
  let elements : Array[AnnotationElement] = []
  for _ in 0..<count {
    let (name_raw, pa) = uleb_ann(data, p)
    let name_idx = check_index(
      TableKind::StringId,
      name_raw.to_int64(),
      ctx.strings.length(),
    )
    let (value, pb) = decode_value(ctx, data, pa)
    elements.push(AnnotationElement::{ name: ctx.strings[name_idx], value, })
    p = pb
  }
  (EncodedAnnotation::{ type_descriptor: ctx.types[type_idx], elements, }, p)
}

///|
/// 解码单个 encoded_value：format 字节 (value_arg << 5) | value_type + payload。
/// 返回 (值, 下一偏移)。未定义 value_type 抛 `BadTableOffset`，索引越界抛 `InvalidIndex`。
fn decode_value(
  ctx : Ctx,
  data : Bytes,
  pos : Int32,
) -> (EncodedValue, Int32) raise DexError {
  need_bytes(data, pos, 1)
  let fmt = byte_at(data, pos)
  let vtype = fmt & 0x1f
  let size = (fmt >> 5) + 1
  if vtype == 0x00 {
    // VALUE_BYTE：1 字节符号扩展
    need_bytes(data, pos + 1, 1)
    (ValueByte(read_sized_signed(data, pos + 1, 1).to_int()), pos + 2)
  } else if vtype == 0x02 {
    // VALUE_SHORT：右对齐符号扩展（1..2 字节）
    if size > 2 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (
      ValueShort(read_sized_signed(data, pos + 1, size).to_int()),
      pos + 1 + size,
    )
  } else if vtype == 0x03 {
    // VALUE_CHAR：右对齐零扩展（1..2 字节）
    if size > 2 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (ValueChar(read_sized_le(data, pos + 1, size).to_int()), pos + 1 + size)
  } else if vtype == 0x04 {
    // VALUE_INT：右对齐符号扩展（1..4 字节）
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (ValueInt(read_sized_signed(data, pos + 1, size).to_int()), pos + 1 + size)
  } else if vtype == 0x06 {
    // VALUE_LONG：右对齐符号扩展（1..8 字节）
    if size > 8 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (ValueLong(read_sized_signed(data, pos + 1, size)), pos + 1 + size)
  } else if vtype == 0x10 {
    // VALUE_FLOAT：左对齐、低位补零（1..4 字节）
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (
      ValueFloat(
        Float::reinterpret_from_int(read_float_bits(data, pos + 1, size)),
      ),
      pos + 1 + size,
    )
  } else if vtype == 0x11 {
    // VALUE_DOUBLE：左对齐、低位补零（1..8 字节）
    if size > 8 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    (
      ValueDouble(read_double_bits(data, pos + 1, size).reinterpret_as_double()),
      pos + 1 + size,
    )
  } else if vtype == 0x15 {
    // VALUE_METHOD_TYPE（DEX 038+，仅 call_site 上下文合法）：proto 引用
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::ProtoId,
      read_sized_le(data, pos + 1, size),
      ctx.protos.length(),
    )
    (ValueMethodType(fmt_proto_sig(ctx.protos[idx])), pos + 1 + size)
  } else if vtype == 0x16 {
    // VALUE_METHOD_HANDLE（DEX 038+）：method_handles 表引用
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::MethodHandle,
      read_sized_le(data, pos + 1, size),
      ctx.handles.length(),
    )
    (ValueMethodHandle(fmt_method_handle_ref(ctx, idx)), pos + 1 + size)
  } else if vtype == 0x17 {
    // VALUE_STRING：字符串池索引（1..4 字节零扩展）
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::StringId,
      read_sized_le(data, pos + 1, size),
      ctx.strings.length(),
    )
    (ValueString(ctx.strings[idx]), pos + 1 + size)
  } else if vtype == 0x18 {
    // VALUE_TYPE：类型索引
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::TypeId,
      read_sized_le(data, pos + 1, size),
      ctx.types.length(),
    )
    (ValueType(ctx.types[idx]), pos + 1 + size)
  } else if vtype == 0x19 {
    // VALUE_FIELD：字段引用
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::FieldId,
      read_sized_le(data, pos + 1, size),
      ctx.fields.length(),
    )
    (ValueField(fmt_field_ref(ctx, idx)), pos + 1 + size)
  } else if vtype == 0x1a {
    // VALUE_METHOD：方法引用
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::MethodId,
      read_sized_le(data, pos + 1, size),
      ctx.methods.length(),
    )
    (ValueMethod(fmt_method_ref(ctx, idx)), pos + 1 + size)
  } else if vtype == 0x1b {
    // VALUE_ENUM：枚举常量（字段引用）
    if size > 4 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    need_bytes(data, pos + 1, size)
    let idx = check_index(
      TableKind::FieldId,
      read_sized_le(data, pos + 1, size),
      ctx.fields.length(),
    )
    (ValueEnum(fmt_field_ref(ctx, idx)), pos + 1 + size)
  } else if vtype == 0x1c {
    // VALUE_ARRAY：内嵌 encoded_array
    if fmt >> 5 != 0 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    let (arr, endp) = decode_array_body(ctx, data, pos + 1)
    (ValueArray(arr), endp)
  } else if vtype == 0x1d {
    // VALUE_ANNOTATION：内嵌 encoded_annotation（无可见性字节）
    if fmt >> 5 != 0 {
      raise DexError::BadTableOffset(TableKind::ClassDef, pos)
    }
    let (ann, endp) = decode_encoded_annotation_body(ctx, data, pos + 1)
    (ValueAnnotation(ann), endp)
  } else if vtype == 0x1e {
    // VALUE_NULL
    (ValueNull, pos + 1)
  } else if vtype == 0x1f {
    // VALUE_BOOLEAN：值 = value_arg & 1，无 payload
    (ValueBoolean(((fmt >> 5) & 1) == 1), pos + 1)
  } else {
    // 0x01/0x05/0x07-0x0f/0x12-0x14 为保留码（0x15/0x16 已在上面单独处理）
    raise DexError::BadTableOffset(TableKind::ClassDef, pos)
  }
}

///|
/// 解码 annotation_item（u8 visibility + encoded_annotation）。
fn decode_annotation_item_body(
  ctx : Ctx,
  data : Bytes,
  off : Int32,
) -> Annotation raise DexError {
  need_bytes(data, off, 1)
  let vis = byte_at(data, off)
  let visibility = if vis == 0 {
    VisibilityBuild
  } else if vis == 1 {
    VisibilityRuntime
  } else if vis == 2 {
    VisibilitySystem
  } else {
    raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
  let (ann, _) = decode_encoded_annotation_body(ctx, data, off + 1)
  Annotation::{ visibility, annotation: ann, }
}

///|
/// 解码 annotation_set_item（u32 size + u32 offset×size）。
fn decode_annotation_set_body(
  ctx : Ctx,
  data : Bytes,
  off : Int32,
) -> AnnotationSet raise DexError {
  need_bytes(data, off, 4)
  let size = read_u32(data, off)
  if size < 0 || size > (data.length() - off - 4) / 4 {
    raise DexError::BadTableOffset(TableKind::ClassDef, off)
  }
  let annotations : Array[Annotation] = []
  for i in 0..<size {
    let item_off = read_u32(data, off + 4 + i * 4)
    if item_off < 0x70 || item_off >= data.length() {
      raise DexError::BadTableOffset(TableKind::ClassDef, item_off)
    }
    annotations.push(decode_annotation_item_body(ctx, data, item_off))
  }
  AnnotationSet::{ annotations, }
}
