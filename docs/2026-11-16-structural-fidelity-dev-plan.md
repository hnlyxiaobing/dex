# dex 结构忠实与可信缺口开发文档

> 建立：2026-11-16 ｜ 状态：W1/W2/W3/W4 已交付（W4：2026-11-19）｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-16-test-system-design.md](2026-11-16-test-system-design.md)（验收测试 ID `T-W*-*` 出自该文档）
> 本文所有「现状」结论均为 2026-11-16 对本仓库源码的实测核对，非转述历史文档。
> 五门禁当日实测：`moon check --deny-warn` ✓ / `moon build` ✓ / `moon test` 96/96 ✓（99 条声明 − 3 条 `#skip`）/ `moon fmt --check` ✓ / `moon info` + `git diff --exit-code` 零差异 ✓。W1/W2/W3 落地后（2026-11-19）`moon test` 为 109/109（另 3 条 `#skip`）。W4 落地后（2026-11-19）`moon test` 为 114/114（另 3 条 `#skip`）。

## 0. 现状基线（实测核对，开发前必读）

### 0.1 已实现事实与真缺口（B1–B18）

| # | 事实 | 证据位置 |
|---|---|---|
| B1 | header 校验接受 DEX 035–041；adler32 checksum 不符 fail-closed 抛 `BadMagic("checksum mismatch …")`；ZIP 魔数 / size 字段小于文件长 → `MultiDexNotMerged` | parse.mbt `validate_header`（L692–766）；dex_test.mbt L593–683 |
| B2 | **SHA-1 signature 仅存储与渲染，从不校验**（真缺口） | parse.mbt `validate_header` 只校验 adler32；cmd/main/util.mbt `sig_short` 仅渲染 |
| B3 | 指令表已含 0xFA–0xFF 六条（invoke-polymorphic{,/range}、invoke-custom{,/range}、const-method-handle、const-method-type），解析层不再拒绝；测试钉死新口径 | instr.mbt `opcode_info` L307–312；xref_test.mbt L809 `test "xref: 0xFA–0xFF 已纳入指令表（不再报 InvalidInstruction）"` |
| B4 | **xref 不覆盖 0xFA–0xFD**：`xref_kind_of_opcode` 仅映射 0x52–0x78 域，其余返回 None 不产 site（真缺口；0xFE/0xFF 为 const 族无调用目标） | xref.mbt L67–71 及 `xref_kind_of_opcode` 全函数 |
| B5 | EncodedValue 共 **18 个变体**（含 0x15 MethodType、0x16 MethodHandle）；float/double 左对齐补零、整型右对齐符号扩展；保留 value_type 抛 `BadTableOffset(ClassDef, pos)` | semval.mbt 全文；pkg.generated.mbti `pub(all) enum EncodedValue`；dex_sem_annotations_test.mbt L1074–1077 |
| B6 | class_data 的 field_idx/method_idx uleb128 diff 在 static/instance、direct/virtual 分段处复位（2026-11-07 缺陷已修复并有回归用例） | parse.mbt `parse_class_data` L625/L654；fixtures_test.mbt L267 起 |
| B7 | try/catch handler 采用双偏移约定匹配（entry_start−list_off 与 entry_start−hp 两 key）；**catch_type 仅取 first_type，多类型 handler 不展开**（深度限制） | parse.mbt `parse_code_item` |
| B8 | **debug_info 仅长度校验后保留原始字节，未展开状态机**（真缺口）；流截断抛 `BadDebugInfo` | parse.mbt debug 流校验；dex_test.mbt L781–796 |
| B9 | **map_list 仅原始字节，无结构化视图**（真缺口）；method_handles/call_sites 已经 map_list type 0x0008/0x0007 定位，res0 非 0 抛 `BadTableOffset` | parse.mbt map 处理；invoke.mbt `parse_method_handles`/`parse_call_sites` |
| B10 | 三种 payload 伪指令均已识别：packed/sparse-switch 的 keys/targets **已全量展开**为 operands；**fill-array-data 仅 width/size，数据元素不展开**（真缺口，raw 字节保留）；size 溢出 fail-closed | instr.mbt `decode_payload` L586–658 |
| B11 | DexError 共 **9 个变体**（冻结）：UnexpectedEof / BadMagic / UnsupportedVersion / BadTableOffset / InvalidIndex / InvalidInstruction / BadCodeItem / BadDebugInfo / MultiDexNotMerged；checksum mismatch 复用 BadMagic 是既有语义 quirk，不得改动 | pkg.generated.mbti；dex_test.mbt L608–623 |
| B12 | class_def access_flags 以原始值输出，**hiddenapi 位未解码**（灰区，见 §9） | parse.mbt class_def 解析；render.mbt CLZ 记录行 |
| B13 | AnnotationsIndex 一次 read_ctx + O(1) 逐类查询；合成 4000 类 DEX 上旧逐类重建实现约 17s → 修复后约 0.06s；bench 阈值 summary<5000ms / norm<10000ms | annot.mbt；tools/bench-dex.ps1 L9–12、L56–59 |
| B14 | CLI 契约：退出码 0/1/2；记录行 HDR\|/STR\|/CLZ\|/CLSM\|/FLD\|/MTH\|/ANN\|/SVC\|/OPS\|/XREF\|/MREF\|/DEX\|；`--view summary|norm|xref`、`--json`、`--entry`（仅 APK 有效否则 2）、`--method` | cmd/main/main.mbt、render.mbt 全文 |
| B15 | zipmin 宽松 ZIP 读取器：容忍 aapt2 对齐裸填充 extra；Store/Deflate；**CRC-32 校验已实现（W3，IEEE 802.3 自研查表），ZIP64 仍不支持**（csize/usize `0xFFFFFFFF`、EOCD 计数 `0xFFFF` 显式拒绝）；inflate_exact 带 max_output 上界（usize 否则 1GiB） | cmd/main/zipmin.mbt 头注释与实现 |
| B16 | 3 条 `#skip` 显式存在：phone-1.6.0 第三方样本未提取、L3 真机差分、DEX 无 chunk 概念对应用例；99 条 test 声明 − 3 = 96 执行，与 moon test 实测一致 | fixtures_test.mbt / fixtures_malformed_test.mbt `#skip`；2026-11-16 实测 |
| B17 | 零第三方依赖：库仅 moonbitlang/core；CLI 另用 core/compress/flate（core 内包，非第三方）；CI 钉死 moon 0.1.20261104 / moonc v0.10.20+65efd5b93 / core 0.10.20+65efd5b93，版本断言 fail-closed | moon.mod；cmd/main/moon.pkg；.github/workflows/ci.yml |
| B18 | 公开 API 面含 `pub type MethodHandle = Int32` 与 `pub trait Disassembler { fn disasm(Self, Int32) -> String raise DexError }`；XrefIndex/AnnotationsIndex 为不透明 pub struct | pkg.generated.mbti（343 行，git 跟踪在列） |

### 0.2 文档/注释漂移（B19–B27，W1 清理对象）

| # | 漂移 | 证据位置 |
|---|---|---|
| B19 | `tests/ASSETS.md` 被 ≥12 处注释/帮助文本引用，**文件不存在**（tests/ 下无该文件，git 未跟踪） | invoke.mbt L66、invoke_test.mbt L7、cmd/main/util.mbt L4、cmd/main/render.mbt L3/L480、cmd/main/main.mbt L4/L22、dex_sem_annotations_test.mbt L9–10、fixtures_test.mbt L3–4 等、fixtures_malformed_test.mbt L3/L204 |
| B20 | `docs/DECISIONS.md D3` 被引用，**docs/ 为空目录**（「README 成为唯一说明文档」决议后遗留悬空引用） | fixtures_test.mbt L9/L267、fixtures_malformed_test.mbt L156；git ls-files 证实 docs/ 无跟踪文件 |
| B21 | ci.yml Gate5 错误文案要求把 API 变更记入 `docs/API.md`（**不存在**）；注释提及 `pkg.generated.mbti.r1`（**已删除**） | .github/workflows/ci.yml L16、L122 |
| B22 | xref.mbt 头注释声称「0xFA–0xFF 解析层即拒 InvalidInstruction」**已过时**，与 B3 直接矛盾（测试已钉死新口径）；真实盲区是 B4（xref 层不产 site） | xref.mbt L20–22 vs instr.mbt L307–312、xref_test.mbt L809 |
| B23 | semval.mbt 两处称「全 16 种 value_type」，**实为 18 变体**（0x15/0x16 已实现）；申报书同误 | semval.mbt L2、L24 vs pkg.generated.mbti EncodedValue |
| B24 | main.mbt 头注释称 APK 条目读取用 `moonbitlang/core/archive/zip`，**不实**：实际为自研 zipmin + core/compress/flate | cmd/main/main.mbt L5 vs cmd/main/moon.pkg、zipmin.mbt |
| B25 | README API 索引漏列 `pub type MethodHandle` 与 `pub trait Disassembler` | README.md API 节 vs pkg.generated.mbti |
| B26 | 申报书「后续：DEX 039–041」**版本接受已实现**（B1）；「13 条有效提交」实测 14 条；hiddenapi/容器语义仍未实现 | docs 申报口径 vs parse.mbt `validate_header`；git rev-list 实测 |
| B27 | 跨工作区引用违反模块自包含：zipmin.mbt 头注释提 axml-cli、bench-dex.ps1 注释引工作区根 ci.yml 行号、fixtures_malformed_test.mbt 引 axml 模块文件 | cmd/main/zipmin.mbt L2；tools/bench-dex.ps1 L4；fixtures_malformed_test.mbt |

**对历史口径的修正**（显式承认先前结论被推翻）：
1. 「0xFA–0xFF 在解析层即拒」——**被推翻**：指令表已收录六条新指令，解析成功；真实缺口收窄为 xref 层不产 site（B3/B4/B22）。
2. 「EncodedValue 16 种」——**被推翻**：18 变体，MethodType/MethodHandle 已实现（B5/B23）。
3. 「DEX 039–041 属后续工作」——**被推翻**：版本接受已实现并有测试；后续仅余 hiddenapi 等语义层（B1/B26）。
4. 「switch payload 未展开」类猜测——**核实为已展开**：packed/sparse-switch 的 keys/targets 全量渲染；仅 fill-array-data 数据元素未展开（B10）。
5. 「文档引用的 ASSETS.md/DECISIONS.md/API.md 存在」——**被推翻**：三者均不存在（B19–B21）。

## 1. 硬约束（每个工作包都必须满足）

1. **API 冻结**：pkg.generated.mbti（根 + cmd/main 两份）为冻结基线，只允许纯加法（新 pub fn / 新 struct / 新 enum / 新 trait）。禁止给既有 pub(all) struct 加字段；禁止新增 DexError 变体（破坏性变更须 ADR + 用户裁决 + CHANGELOG + 主版本四件例外）；校验失败用值字段（Bool/状态）表达，解析失败复用既有 9 变体。**冻结枚举清单**（加变体即破坏下游穷举匹配，一律禁止）：DexVersion、TableKind、IndexKind、XrefKind、MethodHandleKind、EncodedValue、AnnotationVisibility、DexError。语义变更走新函数新类型防火墙，旧 API 语义永不改变。
2. **加法三件套**：快照随源码同提交且 diff 纯加法 + CHANGELOG 登记 + CI 快照门禁绿。
3. **依赖不动**：零第三方依赖（B17）。core/compress/flate 为一次性解压接口 → 容器路径用理论上界预检（inflate_exact max_output）替代流式限额；不得为 SHA-1/CRC-32 引入第三方密码库，纯 MoonBit 自实现。
4. **许可红线**：第三方 APK/.dex 不入库；真实差分只允许「仓库外本地路径 + SHA-256 登记 + 显式 SKIPPED」；入库测试资产用确定性生成器自产（tools/gen-large-dex.py 模式）。
5. **五门禁全绿才可合入**；`#skip`/SKIPPED 不得写成通过（现有 3 条 #skip 见 B16，保持显式）。
6. **边界不变量**（非目标，语义防火墙）：不做 Java 反编译、不做数据流/语义分析、不做 Multi-DEX 合并（`MultiDexNotMerged` 显式拒绝口径不变）、不做 OAT/VDEX、不做 DEX 写回/patch、不做反射/MethodHandle 运行时目标/JNI RegisterNatives/动态代理推断。新工作包不得把下游语义结论塞进本库输出。
7. **文档自包含**：本仓库 docs/ 与注释不得引用、链接或假定可访问工作区其他目录；跨库事务只声明归属（B27 清理）。

## 2. 工作包总览

| 包 | 名称 | 优先级 | 规模 | API 影响 | 对应缺口(B#) |
|---|---|---|---|---|---|
| W1 | 文档/注释漂移清理 + 悬空引用实存化 | P0 | S | 无 | B19–B27 |
| W2 | SHA-1 signature 校验值化 | P1 | M | 加法：`signature_ok` | B2 |
| W3 | zipmin CRC-32 校验值化（CLI 层） | P1 | S | 无（cmd 内部） | B15 |
| W4 | map_list 结构化视图 | P2 | M | 加法：MapItem + `map_items` | B9 |
| W5 | debug_info 状态机展开视图 | P2 | L | 加法：DebugEvent/DebugInfoView + `debug_info_view` | B8 |
| W6 | fill-array-data 元素展开视图 | P2 | S | 加法：ArrayPayloadView + `array_payload_view` | B10 |
| W7 | xref 扩展索引覆盖 0xFA–0xFD「须裁决」 | P3 | M | 加法：XrefKindExt/XrefSiteExt/XrefIndexExt + `build_xref_ext` | B4 |
| W8 | catch handler 多类型展开视图 | P3 | S | 加法：CatchHandlerView + `catch_handlers` | B7 |
| W9 | hiddenapi flags 位语义「须裁决」 | P3 | S | 裁决后定；降级方案零 API | B12 |
| W10 | Multi-DEX 合并「须裁决」 | P3 | XL | 建议维持非目标，零 API | B1/B11 |

## 3. 工作包详细设计

### W1 文档/注释漂移清理 + 悬空引用实存化（P0/S）

**目标**：消除 B19–B27 全部漂移，使注释/帮助文本/CI 文案引用的每个文件实存、每处口径与代码一致。
**非目标**：不改任何解析/渲染行为；不动 mbti；不删既有测试。
**新增 API（mbti 草案，纯加法）**：无（纯文档包，快照 diff 必须为零）。
**实现要点**：
- 新建 `tests/ASSETS.md`：登记入库 fixture 清单（来源=受控自建 javac/d8 构建链、SHA-256、用途）；§2 写 dexdump 规范化黄金口径（记录行格式、排序、渲染约定），使 ≥12 处既有引用实存化（比逐处改注释风险更低）。黄金值仍内嵌测试常量，ASSETS.md 只登记口径与哈希。
- 新建 `docs/DECISIONS.md`：迁移 D3（class_data diff 分段复位缺陷修复记录，2026-11-07），保留原日期与结论；后续裁决（W7/W9/W10）也落此文件。
- 新建 `docs/CHANGELOG.md`：初始登记本文建立与五门禁基线（96/96，2026-11-16）。
- 修 xref.mbt L20–22 头注释：改为「0xFA–0xFF 已纳入指令表可解析；本索引（P1）不覆盖 0xFA–0xFD 的调用引用，0xFE/0xFF 为 const 族无调用目标」；同步 L69 注释。
- 修 semval.mbt L2/L24：「16 种」→「18 种（含 MethodType/MethodHandle）」。
- 修 cmd/main/main.mbt L5：改为「APK 容器条目读取使用自研宽松 ZIP 读取器 zipmin（core/compress/flate 解压，零跨模块依赖）」。
- README API 索引补 `pub type MethodHandle = Int32` 与 `pub trait Disassembler`（与 moon info 快照逐条核对，禁手编 mbti）。
- ci.yml L122 错误文案 `docs/API.md` → `docs/CHANGELOG.md`；L16 注释删去已不存在的 `pkg.generated.mbti.r1` 表述。
- 自包含清理：zipmin.mbt L2 头注释去掉 axml-cli 字样（改「dex-cli 宽松 ZIP 读取器」）；bench-dex.ps1 L4 工作区根 ci.yml 行号引用改为把裁决理由完整内联（「不增设机械第 6 道门禁」结论本身保留）；fixtures_malformed_test.mbt 跨模块文件引用改为归属声明（「同构语料另见 axml 仓库，非本仓库依赖」）。
**验收**：T-W1-1（引用实存性扫描：注释/帮助文本/CI 文案中出现的仓库内路径全部 Test-Path 通过）；T-W1-2（五门禁全绿且两份快照 diff=0）；T-W1-3（README API 索引与 pkg.generated.mbti 逐条一致，含 MethodHandle/Disassembler）。

### W2 SHA-1 signature 校验值化（P1/M）

**目标**：补齐 B2 完整性缺口——header[12..32] 的 SHA-1 应等于 bytes[32..file_size] 的摘要；以值化 Bool 暴露，不触碰 parse 语义。
**非目标**：不改 `parse`/`validate_header` 行为（checksum mismatch 仍抛 BadMagic，signature 不符**不**使 parse 失败——防火墙）；不做 APK 签名验签（v1/v2/v3 属容器层，非本库职责）；不新增错误变体。
**新增 API（mbti 草案，纯加法）**：

```text
/// 计算 bytes[32..] 的 SHA-1 并与 header signature 比对。
/// 输入不足 32 字节抛 UnexpectedEof；其余一律值化返回 Bool。
pub fn signature_ok(Bytes) -> Bool raise DexError
```

**实现要点**：新文件 `sha1.mbt`（库内私有 fn）：纯 MoonBit SHA-1（RFC 3174 口径，~120 行，UInt32 循环左移/分块压缩；wasm/native 均用无符号语义，避免 Int32 溢出 UB 差异）。`signature_ok` 先做长度预检（<32 → UnexpectedEof(32)），再比对 20 字节。**不**在 parse 路径调用（性能与语义双隔离）；CLI 后续如需暴露，走新增记录行/JSON 字段的加法路径，另行登记。SHA-1 在此仅作格式完整性校验（非安全签名），文档明示「通过 ≠ 来源可信」。
**验收**：T-W2-1（合法 fixture → true）；T-W2-2（signature 区单 bit 翻转 → false）；T-W2-3（body 单 bit 翻转 → false，且 adler32 同步重算后 parse 仍成功——证明双通道独立）；T-W2-4（len<32 → UnexpectedEof；截断扫描无 panic）；T-W2-5（防火墙恒等式：任意语料上 parse 结果与基线逐字节一致）；T-W2-6（快照 diff 纯加法 + 双目标 signature_ok 输出一致）。

### W3 zipmin CRC-32 校验值化（P1/S，CLI 层）

**目标**：补齐 B15 容器完整性缺口：解压/读取条目后比对 local header/central directory 的 CRC-32。
**非目标**：不支持 ZIP64（维持明示拒绝）；不改库 API（zipmin 是 cmd/main 内部 fn，非 pub）；不引入第三方压缩库。
**新增 API（mbti 草案，纯加法）**：无（cmd/main 内部 struct 可自由演进，不受库冻结约束；CLI 对外契约仅退出码语义增强）。
**实现要点**：zipmin.mbt 增私有 `crc32(Bytes) -> UInt32`（表驱动，256 项常量表或运行时生成）；条目读取结果内部 struct 加 `crc_ok : Bool` 值字段；CLI 在 CRC 不符时走既有失败路径（stderr 诊断 + 退出码 1），**写盘/输出前整体拒绝**。CHANGELOG 登记行为增强：「以前静默放行的损坏条目现在拒绝」——这是 fail-closed 修复而非契约破坏（退出码集合 0/1/2 不变）。aapt2 裸填充 extra 容忍逻辑不得回退（回归用例守住）。
**验收**：T-W3-1（Store 条目 CRC 正确 → 正常输出）；T-W3-2（Deflate 条目 CRC 正确 → 正常输出）；T-W3-3（CRC 字段单 bit 翻转 → 退出码 1 + 无部分输出）；T-W3-4（aapt2 对齐填充 APK 回归仍可读）；T-W3-5（ZIP64 仍显式拒绝，口径不变）。

### W4 map_list 结构化视图（P2/M）

**目标**：补齐 B9——把 map_list 从原始字节升级为新类型的结构化视图。
**非目标**：不改既有 map 原始字节 API；不把 map type code 塞进冻结枚举 TableKind（0x0007 call_site_id、0x0008 method_handle 等超出其变体域）。
**新增 API（mbti 草案，纯加法）**：

```text
pub(all) struct MapItem {
  type_code : Int32   // 原始 u16 值（0x0000 header … 0x0008 method_handle）
  size : Int32
  offset : Int32
}
/// map_off=0 时返回空数组（合法：map_list 可选）。
pub fn map_items(Bytes) -> Array[MapItem] raise DexError
```

**实现要点**：新文件 `maplist.mbt`；复用既有 read_ctx/uleb 读取；type_code 保留原始 Int32（附文档常量表，不加枚举）；size/offset 越界抛 `BadTableOffset`（复用既有变体，TableKind 取最接近语义者并在文档注明映射约定）；截断抛 UnexpectedEof。与 invoke.mbt 的 0x0007/0x0008 定位逻辑共享私有读取助手但不改其行为。
**验收**：T-W4-1（合成 DEX map_items 与 dexdump map list 黄金逐项一致）；T-W4-2（0x0007/0x0008 type code 原样保留）；T-W4-3（map_off 越界/截断 → 声明的错误变体，无 panic）；T-W4-4（map_off=0 → 空数组）；T-W4-5（快照 diff 纯加法）。

### W5 debug_info 状态机展开视图（P2/L）

**目标**：补齐 B8——按 DEX 规范 debug_info_item 状态机展开行号/局部变量事件。
**非目标**：不改既有「原始字节保留」API 与 `BadDebugInfo` 触发口径；不做源码级映射推断（下游语义）。
**新增 API（mbti 草案，纯加法）**：

```text
pub(all) enum DebugEvent {
  AdvancePc(Int32)
  AdvanceLine(Int32)
  StartLocal(Int32, String, String)      // reg, name, type
  StartLocalExtended(Int32, String, String, String)
  EndLocal(Int32)
  RestartLocal(Int32)
  SetPrologueEnd
  SetEpilogueBegin
  SetFile(String)
  SpecialOpcode(Int32)                    // 0x00–0x09 原始值兜底
}
pub(all) struct DebugInfoView {
  line_start : Int32
  parameter_names : Array[String?]        // NO_INDEX → None
  events : Array[DebugEvent]
}
pub fn debug_info_view(Bytes, Int32) -> DebugInfoView raise DexError
```

**实现要点**：新文件 `debugview.mbt`；新枚举 DebugEvent 是**新增**类型（冻结清单不含它，合法）；状态机严格按规范：first 0x00 DBG_END_SEQUENCE、0x01 ADVANCE_PC(uleb)、0x02 ADVANCE_LINE(sleb)、0x03–0x05 START_LOCAL 族、0x06 END_LOCAL、0x07 RESTART_LOCAL、0x08 SET_PROLOGUE_END、0x09 SET_EPILOGUE_BEGIN、0x0A SET_FILE、0x0C–0xFF special opcode（line/address 双增量公式）；0x0B 保留 → 抛 BadDebugInfo。名字/类型经 string 表解析（MUTF-8），越界抛 InvalidIndex(String, …)。事件流长度上界 = 输入字节数（每事件至少耗 1 字节），天然防死循环。与既有长度校验共存：旧 API 仍只验长度，新函数独立展开。
**验收**：T-W5-1（受控 javac/d8 fixture 行号序列与 dexdump -d 黄金一致）；T-W5-2（parameter_names 含 NO_INDEX → None）；T-W5-3（special opcode 公式边界：line_base/line_range 极值）；T-W5-4（保留 opcode 0x0B / 坏 uleb128 → BadDebugInfo）；T-W5-5（截断扫描：debug 流全前缀无 panic）；T-W5-6（恒等式：view.line_start == code_item 关联 debug 流头；旧 raw API 输出逐字节不变）；T-W5-7（快照 diff 纯加法 + 双目标一致）。

### W6 fill-array-data 元素展开视图（P2/S）

**目标**：补齐 B10 剩余缺口——数组 payload 数据元素的结构化切片。
**非目标**：不改 `decode_payload` 既有 operands 渲染口径（norm 黄金不动）；不解释元素语义（仅按 width 切字节）。
**新增 API（mbti 草案，纯加法）**：

```text
pub(all) struct ArrayPayloadView {
  element_width : Int32
  elements : Array[Bytes]   // 每元素 width 字节，小端原始序
}
/// (code_off, payload 的 code unit 偏移)；非 0x0300 ident 抛 BadCodeItem。
pub fn array_payload_view(Bytes, Int32, Int32) -> ArrayPayloadView raise DexError
```

**实现要点**：新文件 `payloadview.mbt`；复用 decode_payload 的溢出/截断校验口径（size>0x3fffffff/width → BadCodeItem；奇数字节末尾补零对齐）；elements 为原始字节切片不做端序转换（A1 寻址忠实）。
**验收**：T-W6-1（width 1/2/4/8 元素切片黄金）；T-W6-2（奇数总字节 → 末元素按规范处理，raw 与视图长度恒等式）；T-W6-3（size 溢出/截断 → BadCodeItem，无 panic）；T-W6-4（快照 diff 纯加法）。

### W7 xref 扩展索引覆盖 0xFA–0xFD「须裁决」（P3/M）

**目标**：补齐 B4——invoke-polymorphic{,/range}（0xFA/0xFB）与 invoke-custom{,/range}（0xFC/0xFD）的引用 site。
**非目标**：不改 `build_xref` 输出（冻结排序与 site 集合逐字节不变——防火墙）；不给冻结枚举 XrefKind 加变体；不推断 MethodHandle 运行时目标（已声明非目标）。
**裁决点**：新 kind 口径。选项 A（推荐）：新枚举 XrefKindExt 四变体（XrefExtInvokePolymorphic / XrefExtInvokePolymorphicRange / XrefExtInvokeCustom / XrefExtInvokeCustomRange），invoke-custom 的 target 记 call_site_id 原始索引（结构事实，不解析 bootstrap）；选项 B：归入既有 XrefCallVirtual 等（语义失真，不推荐）；选项 C：维持盲区声明（零成本降级）。
**新增 API（mbti 草案，纯加法，按选项 A）**：

```text
pub(all) enum XrefKindExt {
  XrefExtInvokePolymorphic
  XrefExtInvokePolymorphicRange
  XrefExtInvokeCustom
  XrefExtInvokeCustomRange
}
pub(all) struct XrefSiteExt {
  method_ref : Int32
  offset : Int32
  target_ref : Int32      // 0xFA/0xFB: method_idx；0xFC/0xFD: call_site_idx
  kind : XrefKindExt
}
pub struct XrefIndexExt        // 不透明，与 XrefIndex 同构
pub fn build_xref_ext(Bytes) -> XrefIndexExt raise DexError
pub fn XrefIndexExt::sites(Self) -> Array[XrefSiteExt]
```

**实现要点**：新文件 `xref_ext.mbt`；线性扫描 O(M+I) 与既有同构；排序契约 method_ref 升序 × offset 升序；仅 0xFA–0xFD 产 site（0xFE/0xFF const 族无调用语义，不产）。旧索引可组合使用（文档给出合并示例，库内不做合并 API 以免语义耦合）。
**验收**：T-W7-1（0xFA–0xFD 各产正确 kind/target 的 site，黄金断言）；T-W7-2（防火墙：任意语料上 build_xref 输出与基线逐字节一致）；T-W7-3（0xFE/0xFF 不产 site）；T-W7-4（排序契约 + 双目标一致）；T-W7-5（快照 diff 纯加法）。

### W8 catch handler 多类型展开视图（P3/S）

**目标**：补齐 B7 深度限制——encoded_catch_handler_list 全量 type_addr_pairs 展开。
**非目标**：不改既有 CodeItem/try-catch 冻结 struct 与 first_type 口径；不改双偏移约定匹配逻辑。
**新增 API（mbti 草案，纯加法）**：

```text
pub(all) struct CatchHandlerView {
  pairs : Array[(Int32, Int32)]   // (type_idx, handler code unit 偏移)
  catch_all_offset : Int32?       // sleb128 size<=0 时的 catch-all
}
pub fn catch_handlers(Bytes, Int32) -> Array[CatchHandlerView] raise DexError
```

**实现要点**：新文件 `catchview.mbt`；按规范 sleb128 size（负值 = |size| 个 type pair + catch-all）；与 parse_code_item 共享私有读取助手；越界/截断复用 BadCodeItem。
**验收**：T-W8-1（多类型 handler 全量展开黄金）；T-W8-2（catch-all 标记 Some/None 正确）；T-W8-3（与旧 first_type 口径恒等式：pairs[0].0 == 旧 catch_type_index）；T-W8-4（旧 API 输出不变 + 快照纯加法）。

### W9 hiddenapi flags 位语义「须裁决」（P3/S）

**目标**：处置 B12 灰区。hiddenapi 位（access_flags 高 16 位）是 **ART 内部约定而非 DEX 格式规范**，按 §9 判据属界外。
**裁决点**：选项 A（推荐，降级方案）：零 API，仅在 README/ASSETS.md 文档化「access_flags 为原始值，高位含 ART hiddenapi 约定，本库不解释」；选项 B：若用户裁决纳入，仅加位掩码常量新函数 `pub fn hiddenapi_bits(Int32) -> Int32`（纯位运算，无枚举无变体），语义解释仍留给下游。
**非目标**：不做 hiddenapi 名单匹配/豁免推断（下游语义，永不做）。
**验收**：T-W9-1（选项 A：文档声明与 README 非目标节一致，引用实存）；T-W9-2（选项 B：掩码常量与 ART 文档核对 [需联网核实]，旧 access_flags 输出不变）。

### W10 Multi-DEX 合并「须裁决」（P3/XL）

**目标**：处置「多 DEX 怎么办」的长期问题。当前 `MultiDexNotMerged` 显式拒绝是**已声明非目标**（B1/B11），不是缺陷。
**裁决点**：选项 A（推荐）：维持非目标，README 强化归属声明（合并属下游工具职责，本库保证单 DEX 事实忠实）；选项 B：若裁决纳入，属 XL 大工程（跨 DEX string/type/method 索引重映射 + 冻结 API 无法承载 → 必须全新类型族），须先出独立 ADR 拆里程碑，本文不预设计。
**非目标**：任何情况下不改 `MultiDexNotMerged` 触发口径。
**验收**：T-W10-1（选项 A：ZIP 魔数/尾随拼接语料仍抛 MultiDexNotMerged，既有 dex_test.mbt L660–683 用例保持绿）。

## 4. 里程碑与合入顺序

```text
M0（第1日）   W1 零风险文档/漂移清理（快照 diff=0）
M1            W2 SHA-1 值化 → W3 CRC-32 值化（安全缺口，各自独立提交）
M2            W4 map_list → W6 array payload → W8 catch 多类型（高价值低成本）
M3            W5 debug_info 状态机（结构纵深，规模 L 单独里程碑）
M4（裁决后）  W7 xref 扩展（选项 A 裁决后）；W9/W10 按裁决执行降级或立项
```

排序判据：先零风险文档、再安全缺口、再高价值低成本、最后须裁决/安全敏感大工程；每包独立提交、独立过五门禁；W2/W3 的 fail-closed 增强必须在 CHANGELOG 显式登记行为变化。

## 5. 簿记与变更管理

- docs/CHANGELOG.md（W1 创建）：每包登记「日期/工作包/新增 pub 声明/快照 diff 结论/测试增量/行为增强说明」；
- README API 索引随 moon info 快照同步（禁手编 mbti）；W1 补齐 B25 漏项后建立逐条核对惯例；
- docs/DECISIONS.md（W1 创建）：W7/W9/W10 裁决记录落此，含选项、理由、日期；
- 破坏性需求（如给 XrefKind 加变体）一律走四件例外流程：ADR + 用户裁决 + CHANGELOG + 主版本。

## 6. 完成定义（DoD，逐包勾选）

- [ ] 新增 API 与 mbti 草案一致（偏差回写本文）
- [ ] 快照 diff 纯加法（W1/W9A/W10A 为零），CHANGELOG 已登记
- [ ] T-W*-* 验收全绿；#skip 显式标注原因（3 条既有 #skip 不得转绿冒充）
- [ ] 五门禁全绿；CLI 记录行/退出码契约零意外漂移（W3 增强须登记）
- [ ] 畸形语料无 panic（新增解析路径全部进截断扫描）
- [ ] 零新第三方依赖；零许可不明二进制入库
- [ ] README 能力/非目标同步；本文状态行更新「已交付+日期」

## 7. 风险登记

| 风险 | 等级 | 缓解 |
|---|---|---|
| SHA-1 自实现在 wasm/native 的无符号语义差异 | 中 | 全程 UInt32 + 双目标差分项（T-W2-6）；RFC 3174 标准向量黄金 |
| W3 CRC 拒绝使既有「损坏但可解压」样本从绿转红 | 中 | 属 fail-closed 修复；CHANGELOG 显式登记；回归语料确认仅损坏样本受影响 |
| W5 状态机 special opcode 公式实现错误 | 中 | dexdump -d 黄金差分（T-W5-1）+ 边界值矩阵 + 截断扫描 |
| W7 新 kind 口径裁决拖延 | 低 | 降级选项 C（维持盲区声明）零成本；旧索引防火墙保证不阻塞其他包 |
| 新函数复用既有错误变体造成语义混淆（如 BadTableOffset 承载 map 错误） | 低 | 文档注明映射约定；错误消息字符串带上下文；簿记逐变体核对 |
| bench 阈值在共享 CI 机型 flaky | 低 | 维持第六道可选门禁定位（本地/显式调用），不挂五门禁链路 |
| 文档再次滞后于代码 | 中 | W1 建立引用实存性扫描（T-W1-1）进 L5 元契约；每包 DoD 强制 README 同步 |

## 8. 业界对标（P2 摘要，2026-11-16 调研）

**渠道与限定**：mooncakes registry 搜索当日不可用（如实记录，未穷举）；「MoonBit 语言 + 单 DEX 纯值化解析 + 反汇编/xref 组合语义，截至 2026-11-16，经公开 web 渠道未见同类库」——该结论受此限定，不冒充已穷举。易变事实（版本/维护状态）一律 [需联网核实]。

**能力清单 F#**（行）：F1 header 校验｜F2 六表解析｜F3 class_data｜F4 指令解码｜F5 反汇编渲染｜F6 xref｜F7 encoded_value｜F8 注解体系｜F9 MethodHandle/call_site｜F10 debug_info/try-catch｜F11 map_list｜F12 值化错误体系｜F13 CLI｜F14 wasm/native 双目标。

| F# | 本模块（B# 实测） | dexlib2 (google-smali) | androguard dex-parser | LIEF | Rust dex crate | dexdump (AOSP) |
|---|---|---|---|---|---|---|
| F1 | ✓ 035–041 + adler32 fail-closed；SHA-1 未校验(B1/B2) | ✓ 读写全版本 [需联网核实] | ✓ 结构解析 [需联网核实] | ✓ header [已知常识，官方教程] | ✓ [需联网核实] | ✓ 全量 dump [已知常识] |
| F2 | ✓ 六表 + MUTF-8(B1) | ✓ | ✓ | ✓ 类/方法枚举 [已知常识] | ✓ | ✓ |
| F3 | ✓ diff 分段复位(B6) | ✓ | ✓ [需联网核实] | 部分 [需联网核实] | ✓ [需联网核实] | ✓ |
| F4 | ✓ 224 opcode + 3 payload(B3/B10) | ✓ 全量 | ✓ 解码不解释语义（README 哲学） | ✗ 明确无 Dalvik 反汇编器 [已知常识，官方教程] | ✓ [需联网核实] | ✓ |
| F5 | ✓ dexdump norm 黄金口径(B14) | ✓ smali 格式 | ✗ | ✗ | 部分 [需联网核实] | ✓（本库 oracle） |
| F6 | ✓ 9 kind；0xFA–0xFD 盲区(B4) | ✓ 可遍历实现 | ✓ FastRef 引用搜索 | ✗ | ✗ [需联网核实] | ✗（需自行 grep） |
| F7 | ✓ 18 变体(B5) | ✓ | ✓ [需联网核实] | 部分 [需联网核实] | ✓ [需联网核实] | ✓ |
| F8 | ✓ 四类 + O(1) 批量索引(B13) | ✓ | ✓ [需联网核实] | 部分 [需联网核实] | ✓ [需联网核实] | ✓ |
| F9 | ✓ 9 kind + call_site(B9) | ✓ [需联网核实] | [需联网核实] | ✗ [需联网核实] | [需联网核实] | ✓ |
| F10 | 长度校验+raw；未展开(B7/B8) | ✓ 全量 | [需联网核实] | ✗ [需联网核实] | [需联网核实] | ✓ |
| F11 | raw 字节(B9) | ✓ | [需联网核实] | ✓ [需联网核实] | ✓ [需联网核实] | ✓ |
| F12 | ✓ 9 变体值化(B11) | 异常体系（非值化） | Result（Rust） | 返回码/异常 | Result | 退出码 |
| F13 | ✓ 三视图+JSON+退出码(B14) | 库+smali 工具链 | 库（PyO3 绑定） | 库+CLI | 库 | 纯 CLI |
| F14 | ✓ wasm/native | JVM 单平台 | Rust+Python | C++/Python/Rust | Rust | native |

**最接近对标**：① dexdump（输出口径同构，本库黄金 oracle；但是工具非库）；② androguard dex-parser（哲学同构：「只给结构事实，不解释字节码含义」，FastRef ≈ 本库 xref；Multi-DEX 为其 TODO [需联网核实]）；③ dexlib2/google-smali（功能最深，但含写回/smali 汇编，超出本库边界；JesusFreke/smali 停维护、Google fork 接棒 [需联网核实]）。
**差异化**：MoonBit 纯值化错误体系 + wasm/native 双目标 + 零第三方依赖 + 冻结 API 纯加法演进 + fail-closed 完整性校验，组合未见同类（受上述渠道限定）。
**缺失能力分类**：已声明非目标（反编译、Multi-DEX 合并、OAT/VDEX、写回、反射推断——LIEF 的 OAT/VDEX 纵深恰是本库界外）；真缺口 = B2/B4/B8/B9/B10/B15 及 B7 深度限制 → W2–W8。另参考：Go dexfinder（纯标准库+调用图+hiddenapi 检测 [需联网核实]）、Kaitai dex.ksy（声明式结构解析，无反汇编 [已知常识]）佐证「结构事实层」生态位独立成立。

## 9. 边界裁决（P3）

**本质职责（一句话）**：单 DEX 字节流 → 「结构在哪 + 值是什么 + 可信吗」的纯值化结构事实，不产出下游语义结论。
**边界判据**：输出是否仅依赖 DEX 格式规范与输入字节本身（不需要 ART 运行时约定、跨文件信息或语义推断）？是 → 界内；否 → 界外。
**灰区裁决清单**：

| 灰区 | 判据结论 | 裁决 | 落点 |
|---|---|---|---|
| SHA-1 signature 校验 | 界内（规范定义的完整性） | 纳入，值化 Bool，parse 语义防火墙 | W2 |
| zipmin CRC-32 | 界内（ZIP 规范，CLI 便利层） | 纳入，fail-closed 增强 | W3 |
| map_list 结构化 | 界内（规范结构） | 纳入，新类型不动冻结枚举 | W4 |
| debug_info 展开 | 界内（规范状态机） | 纳入，新枚举新函数 | W5 |
| fill-array-data 元素 | 界内（规范布局） | 纳入，仅字节切片不解释 | W6 |
| xref 0xFA–0xFD | 界内（invoke 目标是结构事实） | 纳入但 XrefKind 冻结 → 新类型防火墙；口径须裁决 | W7 |
| catch 多类型 | 界内（规范结构） | 纳入，新视图不动旧 struct | W8 |
| hiddenapi flags | **界外**（ART 内部约定，非 DEX 规范） | 建议文档化非目标；纳入须裁决 | W9 |
| Multi-DEX 合并 | **界外**（跨文件信息） | 建议维持非目标 + 归属声明 | W10 |
| MethodHandle 运行时目标 | 界外（运行时语义） | 维持已声明非目标 | 无 |

裁决执行原则：尊重 API 冻结——用「冻结 + 归属声明 + 外部一致性锁（黄金差分）」表达边界，而非删代码或改旧语义。