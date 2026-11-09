# dex · 设计决策记录（DECISIONS.md）

> 本文记录 `dex` 的关键设计决策（背景 → 决策 → 理由 → 后果），整合自开发期决策记录并整理为
> 可自足阅读的形式。仓库内所有文档与注释只引用仓库内文件；规范来源以外部公开文档 URL 注明。

## D1. `dex` 与 `apk`/`axml` 互不知晓；组合根以 Bytes 契约协作

**背景**：DEX 解析在逆向链路上游是 APK 容器（ZIP + Android 专有结构），侧向是 AXML 二进制
清单。若把 `apk → axml + dex` 实现成编译期依赖，`apk` 会成为中心节点，其公开 API 必须返回
`AxmlDoc` / `DexFile` 等下游类型，把下游格式泄漏给容器层使用者；下游一升级，容器层 API 就被迫
跟着变。另外 MoonBit 是名义类型系统：两个模块里结构相同的 `struct` 也不是同一类型，跨模块共享
类型定义会引入不必要的耦合。

**决策**：

1. `dex`、`axml`、`apk` 三模块**零跨模块 import**，各自独立 `moon check`，可被单独依赖；
2. 跨模块协作只传递**纯值字节契约**：`apk` 容器层只产出字节与索引（如 `DexEntry { name, bytes }`），
   由**组合根**（应用工程里的适配代码，不是库）把 `bytes` 交给 `dex::parse` / `axml::parse`；
   "先解析 manifest 还是先扫描 dex"由组合根决定，`apk` 不 import、不调用、不返回任何下游类型；
3. 组合模式 = **逐 dex `parse` + 调用方编排**：`classes.dex` / `classes2.dex` … 对每个 DEX 字节流
   独立调用 `parse` / `class_annotations` / `static_values`，跨 dex 的类/引用解析由上层负责；
   喂入 ZIP/APK 容器或多 dex 拼接字节时入口明确报 `MultiDexNotMerged`，不做隐式合并。

**理由**：容器读取与格式解析是可独立复用的两种能力（业界 apktool 把资源解码与 DEX 反汇编分开、
jadx 用自研 zip reader 独立读取容器，都把容器读取当作独立能力）；以 `Bytes` 为界使三个模块可并行
开发、可单独依赖，接口稳定性不随下游格式演进而破坏。

**后果**：

- 正面：任何使用者真的可以只依赖 `dex` 做字节码分析，不被迫引入 APK 层；`dex` 的错误模型只处理
  DEX 格式，边界清晰；多 dex 合并策略留在上层，本库语义保持"单个 DEX 字节流"。
- 负面：组合根要写少量显式传递代码（把 `bytes` 转交给各解析库）；调用方需要自己知道 DEX/AXML
  格式的基本概念——对逆向工具链而言这是合理知识。
- 被替代方案：`apk` 内部调用 `dex` 并返回 `DexFile`（否决：耦合 + 中心节点 + 与零 import 冲突）；
  `apk` 提供返回下游类型的便利方法（否决：重新引入下游类型，需要时由组合根封装）。

## D2. 纯 MoonBit 自研，不移植 smali/dexlib2；classfile 只作设计参照

**背景**：DEX 是 Android 应用的实际代码载体，MoonBit 生态当时没有任何 DEX 解析库（检索唯一命中
是生物序列包里的 `dexseq_demo`，误报）。业界可参照对象：google/smali 项目的 **dexlib2**（DEX 读写、
完整指令集/注解/调试信息、smali 往返）与 smali 汇编器；规范权威是 AOSP `dalvik-bytecode`
（8-bit opcode `00`–`ff`，实际定义至 `0xE2`，约 218 条，`0xE3`–`0xFF` 保留），公开稳定。
另有 mooncake 包 `iceBear67/classfile@0.2.0` 证明纯 MoonBit 可写字节码解析器。

**决策**：**纯 MoonBit 自研** DEX 解析与 Dalvik 反汇编，零第三方依赖；`dexdump`（Android
build-tools）只作开发期差分基准，不链接、不入库；`classfile@0.2.0` 只作字节码解析器的**设计参照**，
不作依赖。

**理由**：

- dexlib2/smali 是 **Java 代码库（BSD-3-Clause + AOSP Apache-2.0）**，移植到 MoonBit 意味着
  对整套 Java 实现（集合类库、异常体系、IO）做语言/运行时级重写——**移植成本高于按公开规范自研**；
  许可上虽可再分发，但"翻译式移植"仍要背负完整重写与逐行核对成本，且得不到可独立演进的 MoonBit
  API 形态。按 AOSP 公开字节码规范自研，代码量可控（六表 + code_item + 约 218 条指令表）。
- `classfile@0.2.0` `build_status=legacy`、仍带旧式 `moon.pkg.json` 清单，当前工具链（moonc
  v0.10.x）不再接受 JSON manifest，直接依赖会失败——只能借鉴其写法（字节游标 + 表驱动），
  **不作依赖**。
- `dexdump` 作为差分基准比"链接一个第三方解析器"更可信：它是格式事实上的参考实现，且不给仓库
  带来任何二进制/许可负担（本仓库 Apache-2.0；AOSP 字节码文档 CC-BY-4.0、源码片段 Apache-2.0）。

**后果**：

- 正面：仓库零依赖、全后端可构建（`preferred_target = "wasm"`），`moon check` 独立通过；许可面
  只有 Apache-2.0 与 AOSP 文档许可，无外部二进制。
- 负面：指令表大而细（约 218 条），需自维护；DEX v039/v040/v041 差异、厂商加密或畸形 DEX 都要
  自己处理——策略是带 `TableKind`/索引/偏移的显式错误 + 跳过未知结构（见 D4）。
- 被替代方案：移植 dexlib2（否决：Java→MoonBit 移植成本高于自研）；依赖 `classfile`（否决：
  legacy 清单不可依赖）；链接 dexdump/其他原生工具（否决：引入二进制与许可负担，且破坏纯值库
  定位）。

## D3. 真实 DEX 黄金差分曾发现并修复 `method_idx_diff` 分段复位 P0 缺陷（防回归记录）

**背景**：解析器先由程序化 fixture（手工拼装的六表/code_item 字节）驱动开发，全部通过后接入
真实 DEX 样本做黄金差分（工具侧 `dexdump` 规范化输出 ↔ 解析侧渲染）。首跑即发现 `parse` 对
**真实** DEX 抛 `DexError::InvalidIndex(MethodId, 49)`（tvshell-debug 样本，`method_ids_size`
只有 43）。

**缺陷与根因**：`../parse.mbt::parse_class_data` 把 `class_data_item` 的 `method_idx_diff` 在
`direct_methods` 与 `virtual_methods` 两个分段之间**连续累加**，而 AOSP libdex / `dexdump`
在每个分段各自从 0 累加（`static_fields` / `instance_fields` 同理）。实测（tvshell-debug）：
dexdump 报方法索引 24,25,26 / 27,28 / 29,33,34,35；连续累加得 24,49,50 / 27,55 / 29,62,63,64 ——
越界即抛 `InvalidIndex(MethodId, 49)`。

**决策 / 修复**：进入 instance/virtual 分段时索引**复位**（`../parse.mbt::parse_class_data`，
与 AOSP libdex 行为一致）；修复后真实样本解析侧黄金差分全通（tvshell-debug、motionshell 与后续
fx-multidex 多 dex 样本），并把该缺陷从"已知缺陷钉死用例"改为真实黄金差分常驻回归。

**理由（为什么留记录）**：

1. **防回归**：该缺陷的触发条件是"真实布局中 direct+virtual 分段且 diff 跨段"，程序化 fixture
   从未覆盖这种布局；一旦回归，只有真实样本黄金差分能抓住。
2. **方法论教训**：程序化 fixture 与实现会**互相印证同一错误假设**（"连续累加"的实现配"连续累加"
   的期望），真实工具产出的黄金差分是唯一可靠对照。这与后续在容器层发现的签名块布局缺陷同型。

**后果**：黄金期望值现内嵌于 `../fixtures_test.mbt`（`GOLDEN-BEGIN/END` 标记的黄金常量），`moon test`
即回归；任何人改动 `class_data` 解析都必须过真实样本黄金差分。开发期"工具侧↔黄金↔解析侧"三方
差分方法保留描述见 `../tests/ASSETS.md`。

## D4. 错误处理与容错口径：严格校验 + 显式错误，禁止 panic

**背景**：业界 DEX/AXML 解析工具的做法（dexlib2 用异常 + fixture + smali↔dex 往返测试；apktool
用解码告警与 `--keep-broken-res` 等降级模式，自 3.0.0 起默认 `--only-main-classes` 正是因为畸形
DEX 会让贪婪解析器崩溃；jadx 用 `--show-bad-code` + 半损坏 APK 自动修补 + 自研 zip reader 抗篡改）
给出一致启示：逆向输入天然可能是畸形/被加固的文件，解析库必须"严格校验 + 容错降级"，不能因坏
输入崩溃。

**决策**：`DexError` 为唯一失败通道（`raise DexError`，禁止 panic）；9 个错误构造全部带
`TableKind` / 索引 / 偏移便于定位；`Option` 表达"正常无结果"（如 abstract/native 方法
`code == None`），`raise` 表达"失败"，二者不混用；畸形输入（截断、magic/checksum 污染、表偏移
污染、未知 opcode）一律报 `DexError` 而非 panic，且有从真实样本派生的畸形用例（
`../fixtures_malformed_test.mbt`）钉死该行为。

**理由**：错误里带 `TableKind`/偏移才能在黄金差分中快速定位差异来源；把"解析不了"表达为错误值
而不是崩溃，上层才可能做"跳过坏结构、继续审计其余部分"的容错策略（DEX 是扁平表结构，没有
可跳过的未知 chunk，因此对 DEX 的容错形态就是显式报错 + 上层决定是否继续）。

**后果**：全部输入路径可预测失败；`DexError` 构造集合保持稳定（后续语义层新增复用既有构造，
不扩集合），错误面也属冻结面。

## D5. 开发顺序：表解析先行，指令解码与语义层随后补齐

**背景**：最早需要 DEX 能力的上层用途是"方法引用图与协议线索提取"，只需要 header + 六表 +
方法名；完整 218 条指令解码与注解/静态初值语义是后续深化需求。

**决策**：先实现 header/六表/class_def/code_item 与方法名解析，再补全约 218 条指令解码与
smali 输出，最后以**加法性新增**落地语义层（注解目录四类 / `encoded_value` 全 16 类型 /
`static_values` 静态初值（加密字符串入口）/ 结构化指令操作数视图与引用名字解析 helper）。

**理由**：按依赖方真实需要排先后，避免一次性铺开；语义层做成加法性新增（新类型 + 新函数，
入口自含：第一参数为原始 DEX `Bytes`），既有调用方零迁移。

**后果**：公开签名演进全程零破坏（`../pkg.generated.mbti` 快照 106 行插入 / 0 行删除，既有
`parse` / `disasm` / 访问器 / `Instruction` / `DexError` 等零改动）；`Instruction` 冻结结构
未动，结构化操作数以新增 `InsnOperands` 视图实现（从 `Instruction::raw` 重解码），文本 `disasm`
输出行为不变。

## D6. 先规格后实现：`declare` 声明阶段与当前状态

**背景**：开发初期按"先声明规格、后补实现"推进：数据结构用真实类型定义（只有形状、无逻辑），
函数签名用 `declare` 声明（编译器以 warning `0068 declaration_unimplemented` 提示待实现项），
公开 API 全部配 `///` 文档注释（参数所有权、错误、线程约束、非目标）。

**决策 / 现状**：所有函数体均已补齐为**真实实现**（无 `declare` 存根、无 `0068` 告警）；
`moon check --deny-warn` 0 error / 0 warning。`../pkg.generated.mbti` 为 `moon info` 生成的 API
快照，公开签名变化必须先过快照 diff 评审。

**理由**：规格先行使 API 评审与并行实现解耦；实现完成后保留文档注释与快照机制，作为公开面的
持续契约。

**后果**：仓库当前状态即"声明 + 实现合一"，新贡献者看到的每个公开函数都有真实函数体与文档注释；
破坏性 API 变更必须升主版本并更新 `../pkg.generated.mbti`。

## 外部规范来源（公开文档，非仓库文件）

- Dalvik 字节码规范：<https://source.android.com/docs/core/dalvik/dalvik-bytecode>
- smali / dexlib2（google/smali，BSD-3-Clause）：<https://github.com/JesusFreke/smali>
- dexdump、d8、aapt2 等工具属 Android SDK build-tools（本仓库开发期使用 35.0.0）。
