///|
/// fill-array-data-payload 元素展开视图（W6）。
///
/// 既有 `decode_payload` 对三种 payload 伪指令只输出 width/size（B10），
/// 本文件把 fill-array-data-payload 的数据元素展开为逐元素字节切片，
/// 不做端序转换（A1 寻址忠实：元素按原始小端字节序给出，解释权留给下游）。
/// 不改既有 `Instruction` 语义（P4/P5 防火墙律）。
///
/// fill-array-data-payload 布局（AOSP dex-format）：
///   u16 ident（必须 0x0300）｜ u16 element_width ｜ u32 size ｜ size*width 字节数据
/// `code_off` 为 code_item 偏移，`u` 为 payload 相对 code_item insns 区起点的
/// code unit 偏移（与 `decode_payload` 同坐标系，`foff = code_off + 16 + u*2`）。
///
/// 校验（复用 decode_payload 溢出/截断口径，fail-closed）：
///   ident ≠ 0x0300 → `BadCodeItem(code_off, "not a fill-array-data-payload")`
///   size 为负 / 越界 / width=0 且 size>0 → `BadCodeItem(code_off, …)`
///   数据区截断 → `BadCodeItem(code_off, "truncated fill-array-data-payload")`

///|
/// fill-array-data-payload 的结构化视图：`element_width` 与逐元素原始字节。
pub(all) struct ArrayPayloadView {
  element_width : Int32
  elements : Array[Bytes]
}

///|
/// 返回 `data` 中以 `(code_off, u)` 定位的 fill-array-data-payload 的元素视图。
///
/// - `code_off`：code_item 偏移；`u`：payload 相对 insns 区的 code unit 偏移。
/// - 返回：`element_width` 与 `elements`（每元素 width 字节小端原始序）。
/// - 校验：任何越界 / 非 0x0300 ident / size 溢出 → `BadCodeItem(code_off, …)`，不 panic。
pub fn array_payload_view(
  data : Bytes,
  code_off : Int32,
  u : Int32,
) -> ArrayPayloadView raise DexError {
  let file_size = data.length()
  let foff = code_off + 16 + u * 2
  if code_off < 0x70 || foff < 0 || foff + 8 > file_size {
    raise DexError::BadCodeItem(code_off, "truncated fill-array-data-payload")
  }
  let ident = read_u16(data, foff)
  if ident != 0x0300 {
    raise DexError::BadCodeItem(code_off, "not a fill-array-data-payload")
  }
  let width = read_u16(data, foff + 2)
  let size = read_u32(data, foff + 4)
  // 与 decode_payload 同口径：size 溢出 fail-closed。
  if size < 0 || (width != 0 && size > 0x3fffffff / width) {
    raise DexError::BadCodeItem(code_off, "fill-array-data size overflow")
  }
  let data_bytes = size * width
  let available = file_size - foff - 8
  if width == 0 && size > 0 {
    raise DexError::BadCodeItem(
      code_off, "fill-array-data invalid element width 0",
    )
  }
  if data_bytes > available {
    raise DexError::BadCodeItem(code_off, "truncated fill-array-data-payload")
  }
  let elements : Array[Bytes] = []
  for i in 0..<size {
    elements.push(slice_bytes(data, foff + 8 + i * width, width))
  }
  ArrayPayloadView::{ element_width: width, elements, }
}
