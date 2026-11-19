///|
/// map_list 结构化视图（W4）。
///
/// DEX header 无专用字段定位 map_list，唯一入口是 header 偏移 52（`map_off`）。
/// 本文件把 map_list 从原始字节（`parse_dex.map_list`）升级为逐项的
/// `MapItem` 视图；不改既有 raw API 语义（P4/P5 防火墙律）。
///
/// map_item 布局（AOSP dex-format，12 字节/项）：
///   u16 type_code ｜ u16 unused（必须为 0）｜ u32 size（本类型项数）｜ u32 offset（文件偏移）
/// type_code 保留原始 u16 值（0x0000 header … 0x0008 method_handle），
/// 不塞入冻结枚举 `TableKind`（0x0007 call_site / 0x0008 method_handle 超出其变体域）。
///
/// 错误映射（复用既有 9 变体，文档注明约定）：
///   map_off 越界 / count 截断 → `UnexpectedEof(map_off)`（与 parse.mbt 既有口径一致）
///   unused 非 0 / size 为负 / offset 越界 → `BadTableOffset(MapList, 项位置)`
/// map_off = 0 返回空数组（map_list 可选，合法）。

///|
/// 单条 map_item 的结构化视图。
pub(all) struct MapItem {
  type_code : Int32
  size : Int32
  offset : Int32
}

///|
/// 返回 `data` 中 map_list 的结构化视图。
///
/// - 参数：完整 DEX 字节（与 `parse` 同源）。
/// - 返回：按 map_list 表序的 `MapItem` 数组；`map_off = 0` 返回空数组。
/// - 校验：header 偏移 52 读取 `map_off`；越界/截断抛 `UnexpectedEof`；
///   `unused` 非 0、`size` 为负、`offset` 越界抛 `BadTableOffset(MapList, …)`。
pub fn map_items(data : Bytes) -> Array[MapItem] raise DexError {
  let file_size = data.length()
  if file_size < 0x70 {
    raise DexError::UnexpectedEof(file_size)
  }
  let map_off = read_u32(data, 52)
  if map_off == 0 {
    return []
  }
  if map_off < 0x70 || map_off + 4 > file_size {
    raise DexError::UnexpectedEof(map_off)
  }
  let count = read_u32(data, map_off)
  if count < 0 || count > (file_size - map_off - 4) / 12 {
    raise DexError::UnexpectedEof(map_off)
  }
  let out : Array[MapItem] = []
  let mut i = 0
  while i < count {
    let p = map_off + 4 + i * 12
    let unused = read_u16(data, p + 2)
    let size = read_u32(data, p + 4)
    let offset = read_u32(data, p + 8)
    if unused != 0 {
      raise DexError::BadTableOffset(TableKind::MapList, p)
    }
    if size < 0 {
      raise DexError::BadTableOffset(TableKind::MapList, p)
    }
    if offset < 0 || offset >= file_size {
      raise DexError::BadTableOffset(TableKind::MapList, p)
    }
    out.push(MapItem::{ type_code: read_u16(data, p), size, offset, })
    i = i + 1
  }
  out
}
