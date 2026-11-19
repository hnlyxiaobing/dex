# dex · 变更记录（CHANGELOG.md）

> 本文件登记影响公开面 / 行为 / 证据链的变更。加法性 API 变更必须在此留一条，且与
> `pkg.generated.mbti` 快照在同一次提交。条目按时间倒序。

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
