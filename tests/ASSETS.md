# dex · 测试样本清单（tests/ASSETS.md）

> 本文件登记本仓库 `tests/fixtures/` 与测试代码内嵌的**全部 DEX 样本**：来源、生成方式、
> SHA-256 与 `dexdump` 规范化口径。哈希均为实测值，克隆本仓库后可自行复核
> （`Get-FileHash tests\fixtures\*.dex -Algorithm SHA256`）。
> 黄金期望值**内嵌于测试代码**（`fixtures_test.mbt` 中 `GOLDEN-BEGIN/END` 标记的黄金常量），
> `moon test` 即回归；不依赖仓库外的任何脚本或黄金文件。

## 1. 样本总表（tests/fixtures/ 与内嵌样本）

| 文件 | 字节 | SHA-256 | 来源 | 生成 / 提取方式 | 主要用途 |
|---|---|---|---|---|---|
| `tests/fixtures/tvshell-debug.classes.dex` | 4368 | `1c77374ff5cbde64033dbd455af71c60793a6d1073f75f547559647132d1aeca` | 受控自建 `tvshell-debug.apk`（开发期本机构建脚本产出；APK SHA-256 `24fa4f0be0731806612dafc486af3ecd5978bf22bb8272314ffc62a6b1492093`）的 `classes.dex` 条目 | 从 APK ZIP 条目提取，提取字节与条目字节逐字节相等（脚本校验） | L1 真实样本：解析 / 反汇编 / 黄金差分 / 注解语义（`method@21` 参数注解、EnclosingMethod `VALUE_METHOD`、InnerClass `VALUE_NULL`、静态字符串初值） |
| `tests/fixtures/motionshell.classes.dex` | 3148 | `1aa28165a8b24338b218c64d52b47ea94a5cf7643e90f51c69013080d51ac3a9` | 受控自建 `motionshell.apk`（APK SHA-256 `c17abaf04acea755115a257f0d3800a452774d177ae7ecab3b20682e687ebd0b`）的 `classes.dex` 条目 | 同上 | L1 真实样本：解析 / 黄金差分 / xref 黄金 |
| `tests/fixtures/fx-multidex.classes.dex` | 2116 | `936243aa417429b480ea4a1fbabc5a6bbf548cfaa7d4d06d74b5efe1d2e9e905` | 受控自产多 dex 样本（javac 21 + d8 自建，非第三方）桶 1（`FxIface`/`FxMain`/`FxMultiA`/`FxMultiB`） | `javac` + `d8`（Android build-tools 35.0.0，`--min-api 21`）编译 `fx.multi.*` 源码产出 `classes.dex`，随受控构建流水线自动提取入库 | 多 dex 桶 1：黄金差分 / xref 黄金 / 畸形派生母本 |
| `tests/fixtures/fx-multidex.classes2.dex` | 1640 | `a6fd65c95aa7df9ec049a44f489572df582e37af4ea231564f723171d2540219` | 同上，桶 2（`FxMultiC`/`FxMultiD`，多 dex 第二个 DEX 条目） | 同上（`fx.multi.sec.*` 单独编译为 `classes2.dex`） | 多 dex 桶 2：黄金差分 / xref 黄金 |
| `tests/fixtures/edge-dex-truncated-512.dex` | 512 | `be03b400be88500e1876d95fb298a6d519bbe52c3a98550252385c023055c778` | 程序化派生（非独立来源） | 取 `fx-multidex.classes.dex` 前 512 字节截断（派生命令见 §3） | 畸形/错误路径（截断必须报 `DexError` 而非 panic） |
| 内嵌样本 `AnnoSample`（字面量内嵌于 `dex_sem_annotations_test.mbt` 等测试代码） | 4264 | `16dbf2d6cb0c56a09312af1a1d22ef955fa74c7873a95d326124b4751bc52d0d` | **自建**：`AnnoSample.java`（覆盖注解全类型值与静态初值的最小样本），受控、非第三方 | `javac 21 --release 8` + `d8`（Android build-tools 35.0.0）生成 `classes.dex`，以字面量内嵌测试代码（不经 `tests/fixtures/`） | 注解 / 常量值 / 操作数语义黄金：`encoded_value` 全 16 类型、AnnotationDefault、Signature、InnerClass、MemberClasses、字段/方法/参数注解目录、`static_values` 全值 |

> 说明：
> - `tvshell-debug` / `motionshell` 的 APK 来源为开发期受控自建产物，dex 文件是从其 ZIP 条目
>   提取的**真实编译产物**（D8 8.6.2-dev，`~~D8{...}` 版本串可从字符串表核见）。
> - `fx-multidex` 系列是本项目自有的受控构建产物（`javac`/`d8`/`aapt2` 工具链自建），源码随
>   开发期构建脚本编译；样本本身即 DEX 字节，不含第三方内容。
> - `AnnoSample` 4264 B 的 SHA-256 与字节数为开发期登记值，可对内嵌字面量重组后复核。

## 2. `dexdump` 规范化口径（黄金期望值的来源与形状）

黄金期望值取自 Android build-tools `dexdump`（开发期使用 35.0.0）对同一样本的输出，经规范化后
**内嵌**为测试常量。规范化原则：**只保留结构化字段**，去掉 `(line=N)`、`(Raw: …)`、时间戳、
绝对路径等易变文本，使文本逐行可比。

两种黄金记录行格式（与 `fixtures_test.mbt` 的 `fx_canon_dex` / `fx_canon_xref` 渲染同构）：

1. **解析黄金（dexparse 口径）**：
   - `HDR|<key>|<value>`：`magic`（如 `'dex\n035\0'`）、`checksum`（8 位 hex）、
     `signature`（首 4 + `...` + 末 4 字节短写）、`file_size`、`header_size`、
     `string_ids_size`、`type_ids_size`、`proto_ids_size`、`field_ids_size`、
     `method_ids_size`、`class_defs_size`；
   - `STR|<i>|<text>`：字符串池全量；
   - `CLZ|<desc>` + `MTH|<cls>|<name>|<proto>|0x<flags>`：按类交错，类内 direct → virtual；
   - `OPS|<cls>|<name>|<proto>|<n>|<m0> <m1> …`：**全方法 opcode 序列**——每个类每个方法
     （含 code-less 方法，`n=0` 空序列）的全量指令助记符序列；工具侧从 `dexdump -d` 逐方法
     代码块抽取，解析侧由 `@dex.parse` 的 `MethodDef.code.insns[].mnemonic` 渲染。
2. **xref 黄金**：`XREF|<caller_ref>|<offset>|<kind>|<target_ref>`——
   - `caller_ref` / `target_ref` 为 smali 风格引用名（`Lcls;->name(params)ret` /
     `Lcls;->name:type`，由 `method_ref_name` / `field_ref_name` 渲染）；
   - `offset` 为十进制 code-unit 偏移；`kind` 为固定九标签
     （`call-virtual|call-super|call-direct|call-static|call-interface|field-read-static|
     field-write-static|field-read-instance|field-write-instance`）；
   - 排序 = class_def 序 → direct → virtual × caller 内 offset 升序；无访问点 = 空输出。

**三方一致（交叉恒等式）口径**：工具侧 `dexdump` 抽取 = 解析侧渲染 = xref 索引，三者一致——
每条 `invoke-` / `iget-` / `iput-` / `sget-` / `sput-` 指令行 ↔ 一条 `XrefSite`，四元组
（caller 引用名、code offset、kind、target 引用名）两侧一致。开发期曾以独立差分脚本做
"工具侧 ↔ 黄金 ↔ 解析侧"**三方差分**（工具侧从 `dexdump -d` 抽取规范化文本，黄金为逐行快照，
解析侧由本库渲染），tvshell-debug、motionshell、fx-multidex、fx-multidex2 四样本全通过；
该差分曾抓出 `class_data_item` 的 `method_idx_diff` 未分段复位的真实缺陷（记录见
`DECISIONS.md` D3）。**黄金期望值现已内嵌测试代码，`moon test` 即回归**；三方差分的方法与
结论仅作口径说明保留，不依赖仓库外脚本。

## 3. 派生与生成命令（可复现）

```powershell
# edge-dex-truncated-512.dex：程序化派生（截断 512 B），与测试内断言字节一致
$dex = [IO.File]::ReadAllBytes('tests/fixtures/fx-multidex.classes.dex')
[IO.File]::WriteAllBytes('tests/fixtures/edge-dex-truncated-512.dex', $dex[0..511])
```

- `AnnoSample`：`javac 21 --release 8 -encoding UTF-8 -cp android.jar AnnoSample.java` 后
  `d8 --min-api 21 --lib android.jar --output . AnnoSample*.class`（Android build-tools 35.0.0），
  产出 `classes.dex`（4264 B）以字面量内嵌测试代码。
- `fx-multidex`：`javac --release 11` 编译 `fx.multi.*` / `fx.multi.sec.*` 两组源码后分别
  `d8 --min-api 21` 产出 `classes.dex`（2116 B）/ `classes2.dex`（1640 B）。

## 4. 未入库第三方样本

开发期另对若干真实第三方 APK 的 DEX 做过 `dexdump` 差分复核——**许可不明、未入库、开发期差分复核**（其二进制不随仓库分发，故本仓库不登记其内容，仅在此一句声明）。
