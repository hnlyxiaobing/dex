# dex 测试系统设计（第一性原理）

> 建立：2026-11-16 ｜ 状态：设计生效，随开发文档逐包落地 ｜ 适用仓库：本仓库（独立自包含）
> 配套文档：[2026-11-16-structural-fidelity-dev-plan.md](2026-11-16-structural-fidelity-dev-plan.md)（`T-W*-*` 验收 ID 一一对应；B# 证据行出自该文档 §0）
> 现状基线：2026-11-16 五门禁实测全绿，`moon test` 96/96（99 条声明 − 3 条 `#skip`，见 §6.4）。W1/W2/W3 落地后（2026-11-19）`moon test` 为 109/109（另 3 条 `#skip`）。W4 落地后（2026-11-19）`moon test` 为 115/115（另 3 条 `#skip`）。W6 落地后（2026-11-19）`moon test` 为 125/125（另 3 条 `#skip`）。W8 落地后（2026-11-19）`moon test` 为 130/130（另 3 条 `#skip`）。

## 1. 第一性原理：本库的正确性是什么

本库的数学形态：`Bytes → (结构事实值, 原始字节, 校验结论) | DexError`——单 DEX 字节流到「结构在哪 + 值是什么 + 可信吗」的纯值化映射，不产出下游语义结论（开发文档 §9 边界判据）。
正确性不可约简为以下断言，每条必须有测试层承载：

| # | 断言 | 含义 | 反例（测试必须抓住） |
|---|---|---|---|
| A1 | 寻址忠实 | 表索引/偏移/指令流顺序/uleb128 diff 与 DEX 规范一致 | class_data diff 跨段未复位（2026-11-07 真实缺陷，B6）；float/double 左对齐补零方向写反（B5）；switch payload targets 错位（B10） |
| A2 | 完整性 fail-closed | 可校验项不一致必被报告；未校验 ≠ 通过 | adler32 不符被放行（B1 守住）；SHA-1 不符无通道可查（B2 缺口 → W2）；ZIP 条目 CRC 损坏静默解压（B15 缺口 → W3） |
| A3 | 边界纯净 | 只输出声明的值类型；不产出下游语义结论 | xref 把注解引用混入调用 site；hiddenapi 位被解释成名单结论（W9 界外）；MultiDexNotMerged 被「好心」合并绕过（W10） |
| A4 | 输入安全 | 任意畸形输入不 panic/不越界/内存有界 | 截断 header 触发越界读；fill-array-data size 溢出致巨分配（B10 上界守住）；debug 状态机死循环（W5 每事件 ≥1 字节上界）；inflate 炸弹（max_output 上界，B15） |
| A5 | 契约稳定 | API 签名/CLI 记录行/退出码与文档一致，变更只加法 | 给 XrefKind 加变体破坏下游穷举；norm 记录行格式漂移使 dexdump 黄金差分失效；退出码 2 场景误返 1 |
| A6 | 平台等价 | wasm 与 native 同输入同输出 | SHA-1 自实现 Int32 溢出在两目标行为分叉（W2 风险）；uleb128 符号扩展差异 |

设计推论：A1/A2 → 性质测试 + 穷举扫描；A2 语义 → 恒等式断言 + 错误簿记（§6.2/§6.3）；A4 → 截断扫描 + 变异语料 + 边界值；A5/A6 → 门禁与差分；真实符合性 → 外部 oracle 层（dexdump，许可约束下本地可选）。

## 2. 测试分层

```text
L0 单元与程序化 fixture（每个 pub fn 行为样例；dex_test.mbt builder 体系）
L1 性质与变异（变形律/截断扫描/位翻转/边界值；fixtures_malformed_test.mbt 语料桶）
L2 受控黄金差分（tests/fixtures/*.dex + 内嵌 GOLDEN 常量；fixtures_test.mbt）
L3 外部 oracle 差分（dexdump 规范化黄金；本地可选，SKIPPED 纪律）
L4 CLI 场景 E2E（三视图 + --json + 退出码矩阵；cmd/main 测试）
L5 元契约门禁（快照/错误簿记/双目标等价/变异自检/引用实存性）
R  真实样本本地 runner（仓库外路径 + SHA-256 门禁 + 显式 SKIPPED）
```

断言×层承载表：

| 断言 | 主承载层 | 辅助层 |
|---|---|---|
| A1 寻址忠实 | L0 + L2 | L3（dexdump 黄金）、L1（变形律） |
| A2 fail-closed | L1（位翻转/畸形桶） | L0（错误簿记）、L4（拒绝场景）、R |
| A3 边界纯净 | L0（恒等式） | L5（快照冻结门禁）、L2 |
| A4 输入安全 | L1（截断扫描/变异） | L0（边界值）、L4（安全拒绝 E2E） |
| A5 契约稳定 | L5（快照门禁） | L2（记录行黄金）、L4（退出码矩阵） |
| A6 平台等价 | L5（双目标差分） | L0（wasm/native 各跑一遍 moon test） |

## 3. fixture 体系

| 类 | 形态 | 入库 | 许可 | 现状（P4 实测） |
|---|---|---|---|---|
| F-A 程序化构造 | 测试代码字节 builder | 是 | 随仓库 | ✓ dex_test.mbt builder 体系（header/六表/code_item/注解/畸形变体均可程序化构造） |
| F-B 受控文件 fixture | tests/fixtures/*.dex | 是 | 哈希登记 | ✓ 6 个 .dex 在 git 跟踪：fx-dyn.classes / fx-multidex.classes{,2} / motionshell.classes / tvshell-debug.classes / edge-dex-truncated-512；**SHA-256 登记文件 tests/ASSETS.md 缺失（B19）→ W1 补建** |
| F-C 生成器资产 | 确定性脚本产出 | 脚本入库、产物不入库 | 自产 | ✓ tools/gen-large-dex.py（4000 类/6000 字符串合成 DEX 035）+ tests/build-dyn.ps1（javac/d8 受控构建链，源 FxDyn.java 入库）；tests/work/ 为构建工作区不入库 |
| F-D 真实第三方样本 | 仓库外本地路径 | 否（红线） | 许可不明 | R runner 待建；现有 `#skip` 占位「golden dex phone-1.6.0 [SKIPPED: 第三方样本未提取]」保持不删 |

红线：F-D 永不入库；fixture 哈希变更须同步登记 + 黄金记录（防样本漂移假绿）。
builder 能力清单（F-A 构造维度）：magic/版本（035–041/非法）、checksum（正确/翻转）、endian_tag、六表偏移（合法/越界/0）、string MUTF-8（含 0xC0 0x80 编码 NUL）、class_data diff（分段复位/跨段污染）、code_item（insns_size/tries_size/handler 双偏移约定）、指令流（全 opcode 域/未定义 0x3E–0x43/超范围 0xE3–0xF9/0xFA–0xFF）、三种 payload（含 size 溢出）、encoded_value 全 18 类型（含保留码）、annotation visibility（合法/非法）、map_list（含 0x0007/0x0008）、debug 流（截断/坏 uleb）。缺口：W2 需「signature 正确/翻转」变体（builder 现不重算 SHA-1，随 W2 补）；W5 需 debug 状态机全 opcode 构造器。

## 4. L1 性质与变异

- 变形律 P#：
  - P1 无关追加不变性：合法 DEX 尾部追加字节 → `MultiDexNotMerged`（size 字段口径，B1；已有用例 dex_test.mbt L676–683）；
  - P2 索引重排协变性：string 表重排 + 全部引用同步重映射 → 解析出的名字集合不变（待建，L1 增强）；
  - P3 幂等律：同一输入两次 parse/disasm/build_xref 输出逐字节一致（纯函数无状态；待建显式用例）；
  - P4 双通道一致律：库 API 渲染与 CLI norm 记录行同源一致（L2 黄金已钉，W4–W8 新视图不得改变旧通道）；
  - P5 防火墙律（W2/W7/W8 专属）：新函数引入后，旧 API 在全部既有语料上输出逐字节不变。
- 位翻转：adler32 单 bit → BadMagic（已有）；SHA-1 区/body 单 bit → signature_ok=false（T-W2-2/3 已建，W2 落地）；ZIP CRC 单 bit → 退出码 1 + 整体拒绝（T-W3-3 已建，W3 落地）；opcode 翻转到未定义域 → InvalidInstruction（已有 0x3E 用例）。
- 边界值矩阵：insns_size=0/恰在 EOF±1；uleb128 最长 5 字节/超 5 字节；fill-array-data size=0x3fffffff/width 边界（B10 上界）；map size=0；空六表；header 恰 0x70 字节；float/double 1/2/3/4 与 1..8 字节全宽度（B5 对齐规则）。
- 截断扫描：每个 F-B fixture 全前缀（大样本抽样 + 全部结构边界点：header 各字段尾、各表项边界、code_item 头尾、payload 头尾、debug 流逐字节），只允许 DexError 9 变体，不允许 panic/挂起。现状：edge-dex-truncated-512.dex + 畸形桶已覆盖主干；**W4/W5/W6/W8 新解析路径必须各自进扫描集**（DoD 强制）。
- 变异语料：固定种子随机替换/插入/删除，每轮 ≥1000 变异体（现状：fixtures_malformed_test.mbt 语料桶为手工定点变异；随机变异 runner 待建，归 L1 增强，不阻塞 W#）。

## 5. L3 oracle 矩阵 + R runner

| oracle | 差分对象 | 规范化口径 |
|---|---|---|
| dexdump（AOSP，本库既定黄金 oracle） | header 字段/六表名字/class_data 结构/指令 operands/注解值/xref 记录行——只比本库声明输出的字段，不比下游语义 | norm 记录行逐行一致（黄金值内嵌 GOLDEN 常量；口径文档 tests/ASSETS.md §2 由 W1 补建）；signature 渲染 `前2字节...后2字节`；proto `(参数)返回`；hex 小写定宽 |
| dexdump -d（W5 新增） | debug_info 行号序列/局部变量事件 | 行号程序展开对照（T-W5-1）；oracle 版本随结果登记 |

纪律：oracle 缺失 → 显式 SKIPPED + 原因（退出码 78 口径），不得写成通过；现有 `#skip`「dex L3 device [SKIPPED: 本轮不执行真机测试]」保持单列。
R runner：样本路径 + 登记哈希 → 哈希不符拒绝执行 → 规范化差分 → 报告「本地已差分 + 哈希 + 日期」；入库 `#skip` 用例（phone-1.6.0）保留不删，真实结论永不进入通过计数。第三方样本许可不明，永不入库（红线）。

## 6. 覆盖矩阵与错误簿记

### 6.1 能力×场景×安全 覆盖矩阵（现状列 = P4 实测 B#）

| ID | 能力/场景 | L0 | L1 | L2 | L3 | L4 | 现状(P4) | 缺口→W# |
|---|---|---|---|---|---|---|---|---|
| F1 | header 校验（035–041/adler32/endian） | ✓ | ✓ | ✓ | ✓ | ✓ | B1 已实现 | SHA-1 值化→W2 |
| F2 | 六表解析 + MUTF-8 | ✓ | ✓ | ✓ | ✓ | ✓ | B1 已实现 | 无 |
| F3 | class_data diff 分段复位 | ✓ | ✓ | ✓ | ✓ | ✓ | B6 已修复+回归 | 无 |
| F4 | 指令解码（224 opcode + payload） | ✓ | ✓ | ✓ | ✓ | ✓ | B3/B10 已实现 | array 元素视图 `array_payload_view`→W6（2026-11-19 落地） |
| F5 | 反汇编渲染（norm 黄金） | ✓ | ✓ | ✓ | ✓ | ✓ | B14 已实现 | 无 |
| F6 | xref（9 kind/冻结排序） | ✓ | ✓ | ✓ | ✓ | ✓ | B4 盲区 0xFA–0xFD | 扩展索引→W7（须裁决） |
| F7 | encoded_value 18 变体 | ✓ | ✓ | ✓ | ✓ | ✓ | B5 已实现 | 无 |
| F8 | 注解四类 + O(1) 批量索引 | ✓ | ✓ | ✓ | ✓ | ✓ | B13 已实现+bench | 无 |
| F9 | MethodHandle/call_site | ✓ | ✓ | ✓ | ✓ | ✓ | B9 已实现 | 无 |
| F10 | debug_info / try-catch | ✓ | ✓ | ✓ | ✓ | ✓ | B7/B8 仅长度校验+raw | 状态机→W5；多类型 `catch_handlers`→W8（2026-11-19 落地） |
| F11 | map_list | ✓ | ✓ | ✓ | ✓ | ✓ | B9 仅 raw | 结构化视图 `map_items`→W4（2026-11-19 落地） |
| F12 | 值化错误体系（9 变体） | ✓ | ✓ | — | — | ✓ | B11；簿记 9/9（§6.2） | 新路径复用变体须补簿记 |
| F13 | CLI 三视图/JSON/退出码 | ✓ | ✓ | ✓ | ✓ | ✓ | B14 已实现 | CRC 拒绝场景已落地（W3，T-W3-3） |
| F14 | wasm/native 双目标 | ✓ | — | — | — | — | 双目标 moon test 绿；逐字节差分待建 | parity 脚本→L5 |
| S1 | 预期场景：APK→dex 条目→summary/norm/xref 端到端 | | | ✓ | ✓ | ✓ | 已实现（zipmin 路径） | 无 |
| S2 | 预期场景：--method 单方法 disasm + --json | ✓ | | ✓ | | ✓ | 已实现 | 无 |
| S3 | 安全拒绝：ZIP 魔数/尾随拼接 → MultiDexNotMerged + 退出码 1 | ✓ | ✓ | | | ✓ | 已实现 | 无 |
| S4 | 安全拒绝：--entry 用于非 APK → 退出码 2 | ✓ | | | | ✓ | 已实现 | 无 |
| S5 | 安全拒绝：CRC 损坏条目写盘前整体拒绝 | ✓ | ✓ | | | ✓ | W3 已实现（T-W3-3） | 无 |
| S6 | 预期场景：大 DEX 性能门禁（summary<5s/norm<10s） | | | | | ✓ | B13 bench 第六道可选门禁 | 无 |
| C1 | 截断/畸形无 panic（9 变体白名单） | ✓ | ✓ | | | ✓ | 主干已覆盖 | 新路径进扫描→W4/W5/W6/W8 |
| C2 | 内存有界（payload 溢出上界/inflate max_output） | ✓ | ✓ | | | ✓ | B10/B15 已实现 | 无 |
| C3 | API 冻结（快照纯加法/冻结枚举零新变体） | | | | | ✓ | L5 门禁绿 | 每包 DoD 勾选 |
| C4 | 许可红线（第三方样本零入库） | | | | | | git 跟踪清单实测合规 | ASSETS.md 登记→W1 |
| C5 | 防火墙（新函数不改旧语义） | ✓ | 待建 | | | ✓ | W2 已实现（P5 律，T-W2-5） | →W7/W8（P5 律） |

### 6.2 错误变体触发簿记（9/9 强制，现状全绿）

| 变体 | 触发 fixture（现状，显式断言变体名） | 新增触发（待建） |
|---|---|---|
| UnexpectedEof(Int32) | dex_test.mbt L640–656（截断输入/file_size 不符）；fixtures_malformed_test.mbt L157（map_off 越界）；W2 len<32 已建；W4 map 截断/map_off 越界/短输入已建（maplist_test.mbt） | W5 debug 截断 |
| BadMagic(String) | dex_test.mbt L593–604（坏 magic）；L608–623（checksum mismatch 复用口径钉死） | 无（语义 quirk 冻结） |
| UnsupportedVersion(String) | dex_test.mbt L625–636（版本不在 035–041） | 无 |
| BadTableOffset(TableKind,Int32) | dex_sem_annotations_test.mbt L1064–1077（坏 visibility/保留 value_type）；invoke 路径 res0 非 0；W4 unused 非 0 已建（maplist_test.mbt，MapList） | W5 保留 opcode 0x0B |
| InvalidIndex(TableKind,Int32) | dex_test.mbt L509–525（越界 handle）；dex_sem_annotations_test.mbt L1092–1099（class_index 越界） | W5 名字/类型索引越界 |
| InvalidInstruction(Int32,Int32) | dex_test.mbt L725–740（0x3E）；fixtures_malformed_test.mbt L174–187 | 无（0xFA–0xFF 已转正，B3） |
| BadCodeItem(Int32,String) | dex_test.mbt L744–752（code_item 越界）；payload 截断/溢出路径；W6 元素视图四错误路径已建（payloadview_test.mbt）；W8 handler 五错误路径已建（catchview_test.mbt：坏 uleb/sleb + 截断全前缀扫描） | （已全部覆盖） |
| BadDebugInfo(Int32,String) | dex_test.mbt L781–796（debug 流截断） | W5 保留 opcode 0x0B/坏 uleb |
| MultiDexNotMerged(String) | dex_test.mbt L660–683（ZIP 魔数/尾随拼接） | 无（W10 裁决前口径冻结） |

门禁：每变体 ≥1 显式用例；新增解析路径复用变体时本表同提交更新（L5 双向核对，缺一即红）。

### 6.3 恒等式断言（语义契约，全路径成立）

- I1：`parse 成功 ⇒ adler32 校验已通过`（fail-closed，B1）；反之 signature_ok=false **不**影响 parse 结果（W2 防火墙，T-W2-5）。
- I2：`EncodedValue 解码字节宽度 == 规范对齐规则`（float/double 左对齐补零、整型右对齐符号扩展，B5）；解码 consumed 字节数与 raw 切片长度一致。
- I3：`build_xref 输出排序 == method_ref 升序 × offset 升序`，且 site 集合只含 0x52–0x78 域（B4；W7 后旧索引仍满足——防火墙 T-W7-2）。
- I4：`AnnotationsIndex 逐类查询结果 == 单入口逐类重建结果`（B13 性能修复的语义等价，既有 bench 行数下限断言 CLZ|/ANN|/SVC| ≥ 类数）。
- I5：`catch_handlers(code)[i].pairs[0].0 == 旧 catch_type_index`（W8，T-W8-3，2026-11-19 落地）。
- I6：`debug_info_view.line_start == debug 流头 line_start`，且旧 raw 字节 API 输出不变（W5，T-W5-6）。
- I7：`array_payload_view.elements.length == size 且 Σwidth == data_bytes（奇数补零对齐）`（W6，T-W6-2）。
- I8：`CLI norm 记录行 == 库 API 渲染同源`（P4 双通道一致律，黄金钉死）。

### 6.4 #skip 清单（3 条，显式单列，永不计入通过）

| 用例 | 位置 | 原因 |
|---|---|---|
| golden dex phone-1.6.0 [SKIPPED: 第三方样本未提取] | fixtures_test.mbt L308–309 | F-D 红线：许可不明样本不入库；R runner 就绪后本地差分 |
| dex L3 device [SKIPPED: 本轮不执行真机测试] | fixtures_test.mbt L318–319 | 真机 oracle 本轮不执行 |
| dex malformed: 未知 chunk [SKIPPED: DEX 无 chunk 概念] | fixtures_malformed_test.mbt L194–195 | 格式无此概念，占位防误报 |

计数口径：99 条 test 声明 − 3 #skip = 96 执行（2026-11-16 实测 96/96）；W2/W3 落地后为 112 条声明 − 3 #skip = 109 执行（2026-11-19 实测 109/109）；`moon test --include-skipped` 才执行 skip 项，其结果单独报告。

## 7. L4 CLI 场景 E2E

| 场景 | 命令序列 | 断言要点（退出码+输出+落盘哈希） |
|---|---|---|
| E1 summary | `main.exe <dex> --view summary` | 0；HDR\|/DEX\| 记录行黄金；类数/方法数与库 API 一致 |
| E2 norm 全量 | `main.exe <dex> --view norm` | 0；STR\|/CLZ\|/CLSM\|/FLD\|/MTH\|/ANN\|/SVC\|/OPS\| 逐行与 dexdump 规范化黄金一致 |
| E3 xref | `main.exe <dex> --view xref` | 0；XREF\|/MREF\| 记录行冻结排序 |
| E4 JSON | `main.exe <dex> --json` | 0；RFC 8259 最小充分转义（引号/反斜杠/控制字符 \uXXXX） |
| E5 单方法 | `main.exe <dex> --method <sig>` | 0；仅目标方法 OPS\| |
| E6 APK 条目 | `main.exe <apk> --entry classes.dex` | 0；zipmin 路径与裸 dex 输出一致 |
| E7 --entry 误用 | `main.exe <dex> --entry x` | 2（参数误用，B14） |
| E8 坏 magic/checksum | `main.exe <畸形dex>` | 1；stderr 诊断；无部分记录行输出 |
| E9 ZIP 魔数直喂 | `main.exe <apk>`（无 --entry） | 1；MultiDexNotMerged 诊断 |
| E10 CRC 损坏 | `main.exe <损坏apk> --entry classes.dex` | 1；**写盘/输出前整体拒绝**（T-W3-3 已建） |
| E11 不存在文件 | `main.exe <缺失路径>` | 1；诊断不 panic |

记录行/JSON 契约冻结口径：HDR|/STR|/CLZ|/CLSM|/FLD|/MTH|/ANN|/SVC|/OPS|/XREF|/MREF|/DEX| 前缀与字段序冻结，变更即破坏（A5）；退出码矩阵 0=成功/1=解析或 IO 失败/2=参数误用逐例断言。W4–W8 新视图如需 CLI 暴露，只允许新增记录行前缀/JSON 字段的加法，另行登记黄金。

## 8. L5 元契约门禁

1. 快照门禁：`moon info` + `git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti`（纯加法；ci.yml Gate5 已挂，错误文案 W1 修正指向 docs/CHANGELOG.md）。
2. 双目标等价：同 fixture wasm/native 值输出逐字节 diff=0（现状双目标 moon test 绿；W2 SHA-1 已合入，双目标 parity 已在 W2 落地，逐字节 parity 脚本仍待建，L5 增强）。
3. 错误簿记门禁：§6.2 与测试代码双向核对（grep 变体名 ↔ 表格行），缺一即红。
4. 变异自检：注入 3 类缺陷——跳过 adler32 校验 / 放行未定义 opcode / 篡改 diff 分段复位——套件必须变红后还原复绿（对应 A2/A4/A1 各一；W2 合入后追加「跳过 SHA-1 比对」第四注入点，已随 W2 落地）。
5. 计数纪律：#skip 不计通过（§6.4）；测试过滤串以 `*` 结尾防空转假绿；bench 行数下限断言防「输出为空也算快」。
6. 引用实存性扫描（W1 新增，T-W1-1）：注释/帮助文本/CI 文案引用的仓库内路径全部实存；README API 索引与快照逐条一致（T-W1-3）。

## 9. CI 集成与执行入口

五门禁不变（check --deny-warn / build / test / fmt --check / info+快照 diff）；L0/L1/L2 挂 moon test；L3/L4/R/parity/mutation 为脚本层可选 job，缺失显式 SKIPPED；bench-dex.ps1 维持第六道可选显式门禁定位（不挂五门禁链路，理由内联于脚本注释，W1 完成自包含改写）。
复验命令（本仓库自包含，模块根执行）：

```powershell
moon check --deny-warn; moon build; moon test; moon fmt --check
moon info; git diff --exit-code -- pkg.generated.mbti cmd/main/pkg.generated.mbti
moon test --target native   # 双目标各一遍
pwsh -File tools/bench-dex.ps1   # 可选第六道（需 python + native release 构建）
```

## 10. 维护规则与验收清单

1. 新增 pub API ⇒ 同提交附 L0 样例 + L1 性质 + 矩阵/簿记更新；无测试不合入。
2. 新增解析路径 ⇒ 进截断扫描 fixture 集（W4/W5/W6/W8 各自 DoD 强制）。
3. fixture 哈希变更 ⇒ ASSETS.md 登记 + 黄金同提交更新。
4. 每包合入 ⇒ 开发文档 DoD 勾选 + 矩阵现状刷新 + CHANGELOG 测试增量。
5. 「通过」须可复验：命令 + 日期 + 计数；SKIPPED 永远单列。

落地验收（逐层勾选；未裁决工作包对应行保持「未实现」，不得预写通过）：

- [x] W1：T-W1-1 引用实存性扫描绿 / T-W1-2 五门禁+快照 diff=0 / T-W1-3 README 索引一致（2026-11-19 落地，提交 af7ae62）
- [x] W2：T-W2-1, T-W2-2, T-W2-3, T-W2-4, T-W2-5, T-W2-6（含防火墙恒等式 I1 与双目标 parity，2026-11-19 落地，提交 1225082）
- [x] W3：T-W3-1, T-W3-2, T-W3-3, T-W3-4, T-W3-5（含 E10 写盘前整体拒绝，2026-11-19 落地，提交 f410513）
- [x] W4：T-W4-1, T-W4-2, T-W4-3, T-W4-4, T-W4-5（map 黄金 + 0x0007/0x0008 原样 + 三错误路径 + 截断扫描 + 快照纯加法，2026-11-19 落地，提交 b3a4110）
- [ ] W5：T-W5-1, T-W5-2, T-W5-3, T-W5-4, T-W5-5, T-W5-6, T-W5-7（dexdump -d 差分 + 状态机边界 + I6）
- [x] W6：T-W6-1, T-W6-2, T-W6-3, T-W6-4（width 1/2/4/8 全矩阵 + 奇数 pad 恒等式 + 四错误路径 + 截断扫描 + 快照纯加法，2026-11-19 落地，提交 76ecf73）
- [ ] W7（须裁决，裁决前保持未实现）：T-W7-1, T-W7-2, T-W7-3, T-W7-4, T-W7-5（含防火墙 I3）
- [x] W8：T-W8-1, T-W8-2, T-W8-3, T-W8-4（多类型 handler 全量展开 + catch-all Some/None + I5 恒等式 + P5 防火墙 + 截断扫描 + 快照纯加法，2026-11-19 落地，提交 c170174）
- [x] W9（选项 A 裁决，零 API）：T-W9-1（README 非目标节 hiddenapi 声明已落地，§9 判据 "界外" 与 B12 灰区记录一致，2026-11-19 落地，提交待哈希）
- [ ] W10（须裁决）：T-W10-1 维持 MultiDexNotMerged 口径
- [ ] L5 增强：parity 脚本 / 随机变异 runner / 变异自检四注入点（随 W2 起逐步强制）