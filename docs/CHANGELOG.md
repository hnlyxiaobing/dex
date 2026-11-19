# dex · 变更记录（CHANGELOG.md）

> 本文件登记影响公开面 / 行为 / 证据链的变更。加法性 API 变更必须在此留一条，且与
> `pkg.generated.mbti` 快照在同一次提交。条目按时间倒序。

## 2026-11-19 · W9：hiddenapi 文档声明（选项 A，零 API）

- 裁决：hiddenapi 位（access_flags 高 16 位）属 ART 内部约定，非 DEX 格式规范（§9 判据界外），
  选项 A 通过——README 非目标节新增明确声明："本库不解释、不映射、不声明枚举"。
- 零公开 API 变更，`pkg.generated.mbti` 无 diff。既有 `access_flags` 原始输出口径不变。

## 2026-11-19 · W8：catch handler 多类型展开视图（新增公开 API）

- 新增 `catchview.mbt`：补齐 B7 深度限制——encoded_catch_handler_list 全量
  type_addr_pairs 展开。布局（AOSP dex-format）：uleb128 count + 每 handler
  sleb128 类型对数量（size>0 无 catch-all；size<=0 为 |size| 对 + 1 个 catch-all）、
  |size| 个 (uleb type_idx, uleb addr)、size<=0 时末尾 uleb catch_all_addr。
  不改既有 `CodeItem` / `TryItem` 冻结 struct 与 first_type 口径（P4/P5 防火墙律）。
- **公开 API（纯加法）**：`pub(all) struct CatchHandlerView { pairs : Array[(Int32, Int32)];
  catch_all_offset : Int32? }` 与 `pub fn catch_handlers(Bytes, Int32) ->
  Array[CatchHandlerView] raise DexError`。`pkg.generated.mbti` **+2 处（1 fn + 1 struct），
  0 删改**。`list_off` 为 handler list 的字节偏移（uleb 计数起点）。
- 错误映射（复用 BadCodeItem）：越界 / 坏 uleb/sleb → `BadCodeItem(list_off, …)`，
  与 parse 的 catch handler 解析共用同一 helper（`uleb_code` / `sleb_code`）。
- 新增 5 个测试（125 → 130）：T-W8-1 多类型 handler 全量展开黄金、T-W8-2 catch-all
  Some/None 正确、T-W8-3 恒等式 I5（pairs[0].0 == 旧 catch_type_index）、T-W8-4 P5
  防火墙（parse 旧通道输出不变）、DoD 全前缀截断扫描无 panic。
- 五门禁全绿（`moon test` 130/130）；3 个既有 `#skip` 保持原样。

## 2026-11-19 · W4：map_list 结构化视图（新增公开 API）

- 新增 `maplist.mbt`：把 map_list 从原始字节（`parse_dex.map_list`）升级为逐项 `MapItem`
  视图，不改既有 raw API 语义（P4/P5 防火墙律）。map_item 布局 `u16 type_code｜u16 unused｜
  u32 size｜u32 offset`（AOSP dex-format，12 字节/项）。
- **公开 API（纯加法）**：`pub(all) struct MapItem { type_code : Int32; size : Int32;
  offset : Int32 }` 与 `pub fn map_items(Bytes) -> Array[MapItem] raise DexError`。
  `pkg.generated.mbti` **+2 处（1 fn + 1 struct），0 删改**。type_code 保留原始 u16 值
  （0x0000 header … 0x0008 method_handle），不塞入冻结枚举 `TableKind`。
- 错误映射（复用既有 9 变体，文档注明）：输入 < 0x70 字节 / `map_off` 越界 / count 截断 →
  `UnexpectedEof`（与 parse.mbt 既有口径一致）；`unused` 非 0 / size 为负 / offset 越界 →
  `BadTableOffset(MapList, …)`。`map_off = 0` 返回空数组（map_list 可选）。
- 新增 6 个测试（109 → 115）：T-W4-1 黄金逐项一致（含 0x0007/0x0008 type 原样保留）、
  T-W4-4 map_off=0 → 空数组、T-W4-3 三错误路径（map_off 越界 / count 截断 / unused 非 0）、
  DoD 全前缀截断扫描无 panic（该扫描**实测捕获**并修复了短输入读越界 panic）。
- 五门禁全绿（`moon test` 115/115）；3 个既有 `#skip` 保持原样。

## 2026-11-19 · W6：fill-array-data 元素展开视图（新增公开 API）

- 新增 `payloadview.mbt`：补齐 B10 剩余缺口——fill-array-data-payload 数据元素结构化切片。
  布局 `u16 ident(0x0300)｜u16 element_width｜u32 size｜size*width 字节数据`（AOSP dex-format）。
  坐标与 `decode_payload` 同系（`foff = code_off + 16 + u*2`，`u` 为 payload 相对 insns 区
  的 code unit 偏移）。不改 `decode_payload` 既有 operands 渲染口径（norm 黄金不动，P5）。
- **公开 API（纯加法）**：`pub(all) struct ArrayPayloadView { element_width : Int32;
  elements : Array[Bytes] }` 与 `pub fn array_payload_view(Bytes, Int32, Int32) ->
  ArrayPayloadView raise DexError`。`pkg.generated.mbti` **+2 处（1 fn + 1 struct），0 删改**。
- elements 为原始小端字节切片，不做端序转换（A1 寻址忠实）；奇数总字节对齐 pad 字节不产生
  元素（Σ 元素宽 == size*width 恒等式）。
- 错误映射（复用 BadCodeItem）：非 0x0300 ident / size 溢出（同 decode_payload 口径）/
  width=0 且 size>0 / 数据区截断 → `BadCodeItem(code_off, …)`，无 panic。
- 新增 10 个测试（115 → 125）：T-W6-1 width 1/2/4/8 元素切片黄金、T-W6-2 奇数 pad +
  视图长度恒等式、T-W6-3 size 溢出/ident 非 0x0300/width=0/截断四错误路径、DoD 全前缀
  截断扫描无 panic。
- 五门禁全绿（`moon test` 125/125）；3 个既有 `#skip` 保持原样。

## 2026-11-19 · W3：zipmin 条目 CRC-32 校验 + CLI 收集 fail-closed

- `cmd/main/zipmin.mbt`：新增私有 table-driven CRC-32（IEEE 802.3，反射多项式 `0xEDB88320`，
  初值/终值 `0xFFFFFFFF`，`UInt` 运算，模块级 256 项查表，确定性），core 的 crc32 在 internal
  包不可用故自研。读取条目时比对 CRC：中央目录偏移 `+16`、本地头偏移 `+14`。
- 判定语义：CRC 一致 → 正常返回；CRC 不符 / Deflate 解压失败 / 中央目录与本地头 CRC 非零且
  互相矛盾 → 该条目判失败；任一被选中的 dex 条目失败 → **整体 fail-closed**——`zip_dex_entries`
  返回空表（无部分输出）、stderr 明确诊断（如 `error: APK 条目 CRC 校验失败：<name>`），
  走既有 `main` 失败路径（退出码 1）。
- 现有能力不回退：Store(0)/Deflate(8)、aapt2 风格 local extra 1~3 字节裸填充原样跳过；
  ZIP64 继续显式拒绝（csize/usize `0xFFFFFFFF`、EOCD 计数 `0xFFFF`），口径不变。
- **公开 API 0 变化**：`pkg.generated.mbti` / `cmd/main/pkg.generated.mbti` 快照 0 行增删；
  不改 `parse` / `signature_ok`。
- 新增 6 个测试（103 → 109，白色盒 `cmd/main/zipmin_wbtest.mbt`，合成 ZIP 程序化构造，不引入
  二进制 fixture）：CRC-32 已知向量（`123456789`→`0xCBF43926`）、T-W3-1 Store/Deflate 双形态、
  T-W3-2 Deflate 压缩体损坏失败不 panic、T-W3-3 坏一条 dex 整体拒绝无部分输出、
  T-W3-4 local extra 1~3 字节 padding 回归、T-W3-5 ZIP64 标记显式拒绝。
- 五门禁全绿；3 个既有 `#skip` 保持原样。

## 2026-11-19 · W2 加固：SHA-1 字节提取补齐 `& 0xFFU` 掩码

- `sha1.mbt` 中 16 个消息字的字节→`UInt32` 提取，四个通道统一补齐 `& 0xFFU` 掩码，
  与 `parse.mbt` 的 `read_u32u` 模式对齐；确保无符号语义——即便 `Byte::to_int()` 在
  某后端发生符号扩展也不污染高位（当前 wasm/native 均零扩展，行为不变，属防御性加固）。
- 新增回归测试 1 个（102 → 103）：`[0xDE,0xAD,0xBE,0xEF]` 循环消息（每字节 ≥0x80）
  在 4 / 55 / 56 / 72 字节下与 OS 原生 SHA-1 一致，覆盖单字、单块、块边界、多块四条
  路径，锁定最后一字节（无移位、直接 OR）的无符号掩码语义。wasm 与 native 双后端通过。
- 公开 API 与 `pkg.generated.mbti` 快照 0 行增删（纯内部修改）；五门禁全绿。

## 2026-11-19 · W2：SHA-1 signature 校验值化（新增公开 API）

- 新增 `sha1.mbt`：纯 MoonBit SHA-1（RFC 3174，64 字节分块、大端位长，`UInt` 无符号语义，
  wasm/native 一致），仅供格式完整性校验。
- **公开 API（纯加法）**：`pub fn signature_ok(Bytes) -> Bool raise DexError`——计算
  `bytes[32..]` 的 SHA-1 并与 header[12..32) 的 signature 比对；不足 32 字节抛
  `UnexpectedEof(32)`，其余值化返回。`pkg.generated.mbti` **+1 行，0 删改**。
- 防火墙不变式：`signature_ok` 不在 `parse` 路径调用，`parse` 语义与输出逐字节不变
  （T-W2-5 实测）。
- 新增 6 个测试（96 → 102）：真实 fixture 全通过（4 个）、RFC 3174 已知向量
  （空串 / `abc` / 56B 跨块）、signature 单 bit 翻转、body 翻转 + adler32 重算后
  `parse` 成功而签名为 false、`len<32` 错误路径、防火墙恒等式。
- 说明：SHA-1 仅作格式完整性校验，「通过」不等于来源可信（不承担 APK 签名验签）。

## 2026-11-19 · 文档基线建立（W1）与工具链漂移修复

**五门禁基线（本机实测）**：`moon check --deny-warn` / `moon build` / `moon test` /
`moon fmt --check` / `moon info` 后快照 diff 全绿。`moon test`：**96 passed / 0 failed**；
另有 3 个 `#skip` 用例（不计入通过数）。

- 新增 `tests/ASSETS.md`：登记 6 个文件类样本与 1 个内嵌样本的来源、SHA-256、字节数、
  生成命令与 `dexdump` 规范化口径（`encoded_value` 全 18 种）。
- 新增 `docs/DECISIONS.md`：迁移 D3（`class_data_item` 索引分段复位缺陷，2026-11-07）。
- 消除文档漂移：`xref.mbt` / `semval.mbt` / `cmd/main/main.mbt` / `cmd/main/zipmin.mbt` /
  `tools/bench-dex.ps1` / `fixtures_malformed_test.mbt` 的过期能力描述与跨仓库引用；
  `FIXTURE-*` 标记与示例路径统一为仓库内相对路径，`GOLDEN-*` 标记去掉历史模块前缀。
- `README.md` 公开 API 索引补齐 `pub suberror DexError`、`to_repr`、`pub type MethodHandle`、
  `pub trait Disassembler`、`pub struct AnnotationsIndex` / `XrefIndex`，与
  `pkg.generated.mbti` 逐条一致。
- CI 文案修正：Gate 5 的 API 变更提示指向 `docs/CHANGELOG.md`；删除已不存在的
  `pkg.generated.mbti.r1` 表述。
- 工具链漂移修复（不改变行为，公开 API 快照 0 行增删）：`Bytes::new(0)` →
  `Bytes::make(0, b'\x00')`（`parse.mbt` 两处）；`@flate.inflate_exact(max_output=)` →
  `max_output_bytes=`（`cmd/main/zipmin.mbt`）。
