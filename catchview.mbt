///|
/// encoded_catch_handler_list 多类型展开视图（W8）。
///
/// 既有 `parse_code_item` 对每个 try_item 只记录 handler 的 `first_type`（B7 深度限制），
/// 本文件把整个 handler list 展开为逐 handler 的 type_addr_pairs + catch-all 标记。
/// 不改既有 `CodeItem` / `TryItem` 冻结 struct 与 first_type 口径（P4/P5 防火墙律）。
///
/// 布局（AOSP dex-format）：
///   encoded_catch_handler_list：uleb128 size（handler 数），随后每个 handler：
///     sleb128 类型对数量（size > 0 无 catch-all；size <= 0 表示 |size| 个对 + 1 个 catch-all）
///     |size| 个 (uleb128 type_idx, uleb128 addr)
///     若 size <= 0：uleb128 catch_all_addr
/// `list_off` 为 encoded_catch_handler_list 的字节偏移（即 uleb 计数的起始）。
///
/// 越界 / 截断 / 坏 uleb/sleb → 复用 `BadCodeItem(code_off, …)`，不 panic。

///|
/// 单个 encoded_catch_handler 的多类型展开视图。
pub(all) struct CatchHandlerView {
  pairs : Array[(Int32, Int32)] // (type_idx, handler code unit 偏移)
  catch_all_offset : Int32? // sleb128 size<=0 时的 catch-all 偏移
}

///|
/// 解析 `data` 偏移 `list_off` 处的 encoded_catch_handler_list，返回逐 handler 视图。
///
/// - `list_off`：handler list 的字节偏移（uleb128 计数起点）。
/// - 返回：`Array[CatchHandlerView]`，每项含 `pairs`（全量 type_addr_pairs）与
///   `catch_all_offset`（size<=0 时为 `Some(addr)`，否则 `None`）。
/// - 校验：越界 / 坏 uleb/sleb → `BadCodeItem(code_off, …)`，不 panic。
pub fn catch_handlers(
  data : Bytes,
  list_off : Int32,
) -> Array[CatchHandlerView] raise DexError {
  let (count, hp) = uleb_code(data, list_off, list_off)
  let out : Array[CatchHandlerView] = []
  let mut hpos = hp
  for _ in 0..<count {
    let (size, p1) = sleb_code(data, hpos, list_off)
    hpos = p1
    let pairs : Array[(Int32, Int32)] = []
    let mut n = size
    if n < 0 {
      n = 0 - n
    }
    for _ in 0..<n {
      let (type_idx, pa) = uleb_code(data, hpos, list_off)
      let (addr, pb) = uleb_code(data, pa, list_off)
      pairs.push((type_idx, addr))
      hpos = pb
    }
    let mut catch_all : Int32? = None
    if size <= 0 {
      let (addr, pc) = uleb_code(data, hpos, list_off)
      catch_all = Some(addr)
      hpos = pc
    }
    out.push(CatchHandlerView::{ pairs, catch_all_offset: catch_all, })
  }
  out
}
