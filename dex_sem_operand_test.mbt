// WP-2 结构化指令操作数测试（R2 语义补全轮新增文件）。
//
// 覆盖：InsnOperands 结构化视图（regs/literal/branch/index_kind/index）、
// 按表解析名字的 helper（invoke→Lcls;->name(sig)ret、const-string→字符串池项、
// 字段引用→Lcls;->name:type、类型引用→类名）与 instruction_ref_name 一步解析。
// 既有文本 disasm 输出（Instruction::operands）保持不变（冻结基线），
// 本文件只测加法性新增视图；fixture 与辅助（sem_*）定义于 dex_sem_annotations_test.mbt。
//
// 真实样本佐证：AnnoSample.dex（javac 21 + d8 自建）main/Kind.<clinit> 指令流
// 与 dexdump -d 的操作数行逐条对照（`// method@00xx` / `// field@00xx` / `// string@00xx`）。

///|
/// 程序化 fixture：method m 的 18 条指令/payload 覆盖十种操作数格式
/// （F11n/F21s/F21h/F51l/F22s/F22b/F10t/F22t/F21t/F3rc/F35c/F21c/F22c/F23x/F10x）。
test "sem operands: 程序化 fixture 全格式结构化视图" {
  let fx = sem_build_dex()
  let dex = @dex.parse(sem_fixture_bytes(fx))
  let code = match dex.code(0) {
    Some(c) => c
    None => fail("m 应有 code")
  }
  sem_check_eq(code.insns.length(), 18, msg="17 指令 + 1 payload")
  // [0] const/4 v0, #+1
  let i0 = @dex.instruction_operands(code.insns[0])
  sem_check_eq(i0.regs, [0], msg="const/4 regs")
  sem_check_eq(i0.literal, Some(1L), msg="const/4 literal")
  sem_check(i0.branch is None)
  sem_check(i0.index_kind is @dex.IndexKind::IndexNone)
  // [1] const/16 v1, #-2
  let i1 = @dex.instruction_operands(code.insns[1])
  sem_check_eq(i1.regs, [1])
  sem_check_eq(i1.literal, Some(-2L), msg="const/16 literal")
  // [2] const/high16 v2, #+0x40600000
  let i2 = @dex.instruction_operands(code.insns[2])
  sem_check_eq(i2.regs, [2])
  sem_check_eq(
    i2.literal,
    Some(1080033280L),
    msg="const/high16 低 16 位补零",
  )
  // [3] const-wide/high16 v3, #+0x1<<48
  let i3 = @dex.instruction_operands(code.insns[3])
  sem_check_eq(i3.regs, [3])
  sem_check_eq(i3.literal, Some(281474976710656L), msg="const-wide/high16")
  // [4] const-wide v4, 0x0102030405060708
  let i4 = @dex.instruction_operands(code.insns[4])
  sem_check_eq(i4.regs, [4])
  sem_check_eq(i4.literal, Some(72623859790382856L), msg="const-wide 64 位")
  // [5] add-int/lit16 v5, v6, #+7
  let i5 = @dex.instruction_operands(code.insns[5])
  sem_check_eq(i5.regs, [5, 6], msg="lit16 regs")
  sem_check_eq(i5.literal, Some(7L))
  // [6] add-int/lit8 v7, v8, #-1
  let i6 = @dex.instruction_operands(code.insns[6])
  sem_check_eq(i6.regs, [7, 8])
  sem_check_eq(i6.literal, Some(-1L), msg="lit8 负字面量")
  // [7] goto +2
  let i7 = @dex.instruction_operands(code.insns[7])
  sem_check(i7.literal is None)
  sem_check_eq(i7.branch, Some(2), msg="goto 偏移")
  // [8] if-eq v1, v2, +5
  let i8 = @dex.instruction_operands(code.insns[8])
  sem_check_eq(i8.regs, [1, 2])
  sem_check_eq(i8.branch, Some(5))
  // [9] if-eqz v0, +3
  let i9 = @dex.instruction_operands(code.insns[9])
  sem_check_eq(i9.regs, [0])
  sem_check_eq(i9.branch, Some(3))
  // [10] invoke-static/range {v2..v4}, LTest;->m()V
  let i10 = @dex.instruction_operands(code.insns[10])
  sem_check_eq(i10.regs, [2, 3, 4], msg="range 展开")
  sem_check(i10.index_kind is @dex.IndexKind::IndexMethod)
  sem_check_eq(i10.index, 0, msg="method@0")
  // [11] invoke-virtual {v5, v6}, LTest;->n(I)V
  let i11 = @dex.instruction_operands(code.insns[11])
  sem_check_eq(i11.regs, [5, 6])
  sem_check(i11.index_kind is @dex.IndexKind::IndexMethod)
  sem_check_eq(i11.index, 1)
  // [12] const-string v0, string@14
  let i12 = @dex.instruction_operands(code.insns[12])
  sem_check_eq(i12.regs, [0])
  sem_check(i12.index_kind is @dex.IndexKind::IndexString)
  sem_check_eq(i12.index, 14)
  // [13] const-class v0, type@5
  let i13 = @dex.instruction_operands(code.insns[13])
  sem_check(i13.index_kind is @dex.IndexKind::IndexType)
  sem_check_eq(i13.index, 5)
  // [14] iget v0, v1, field@0
  let i14 = @dex.instruction_operands(code.insns[14])
  sem_check_eq(i14.regs, [0, 1])
  sem_check(i14.index_kind is @dex.IndexKind::IndexField)
  sem_check_eq(i14.index, 0)
  // [15] sget v0, field@2
  let i15 = @dex.instruction_operands(code.insns[15])
  sem_check_eq(i15.regs, [0])
  sem_check(i15.index_kind is @dex.IndexKind::IndexField)
  sem_check_eq(i15.index, 2)
  // [16] return-void
  let i16 = @dex.instruction_operands(code.insns[16])
  sem_check_eq(i16.regs.length(), 0, msg="F10x 无操作数")
  sem_check(i16.literal is None)
  sem_check(i16.branch is None)
}

///|
/// switch payload 伪指令（packed-switch-payload）返回空结构化视图。
test "sem operands: payload 伪指令空视图" {
  let fx = sem_build_dex()
  let dex = @dex.parse(sem_fixture_bytes(fx))
  let code = match dex.code(0) {
    Some(c) => c
    None => fail("m 应有 code")
  }
  let payload = code.insns[17]
  sem_check_eq(payload.mnemonic, "packed-switch-payload")
  let view = @dex.instruction_operands(payload)
  sem_check_eq(view.regs.length(), 0, msg="payload 空 regs")
  sem_check(view.literal is None)
  sem_check(view.branch is None)
  sem_check(view.index_kind is @dex.IndexKind::IndexNone)
}

///|
/// 按表解析名字的 helper：字符串池项 / 类型 / 字段 / 方法 / 综合。
test "sem operands: 按表解析名字 helper" {
  let fx = sem_build_dex()
  let dex = @dex.parse(sem_fixture_bytes(fx))
  sem_check_eq(@dex.string_ref_name(dex, 14), "bar", msg="字符串池项")
  sem_check_eq(
    @dex.type_ref_name(dex, 5),
    "LKind;",
    msg="类型引用→类名",
  )
  sem_check_eq(@dex.field_ref_name(dex, 2), "LTest;->a:I", msg="字段引用")
  sem_check_eq(@dex.method_ref_name(dex, 0), "LTest;->m()V", msg="方法引用")
  sem_check_eq(
    @dex.resolve_ref_name(dex, @dex.IndexKind::IndexMethod, 1),
    "LTest;->n(I)V",
    msg="综合解析",
  )
  sem_check_eq(
    @dex.resolve_ref_name(dex, @dex.IndexKind::IndexString, 15),
    "foo",
  )
  sem_check_eq(
    @dex.resolve_ref_name(dex, @dex.IndexKind::IndexType, 4),
    "LAnno;",
  )
  sem_check_eq(
    @dex.resolve_ref_name(dex, @dex.IndexKind::IndexField, 1),
    "LKind;->VAL:LKind;",
  )
}

///|
/// instruction_ref_name 一步解析（invoke / const-string / 字段 / 无引用指令）。
test "sem operands: instruction_ref_name 一步解析" {
  let fx = sem_build_dex()
  let dex = @dex.parse(sem_fixture_bytes(fx))
  let code = match dex.code(0) {
    Some(c) => c
    None => fail("m 应有 code")
  }
  match @dex.instruction_ref_name(dex, code.insns[10]) {
    Some(s) => sem_check_eq(s, "LTest;->m()V", msg="invoke-static/range")
    None => fail("invoke 应有引用名")
  }
  match @dex.instruction_ref_name(dex, code.insns[11]) {
    Some(s) => sem_check_eq(s, "LTest;->n(I)V", msg="invoke-virtual")
    None => fail("invoke 应有引用名")
  }
  match @dex.instruction_ref_name(dex, code.insns[12]) {
    Some(s) => sem_check_eq(s, "bar", msg="const-string→字符串池项")
    None => fail("const-string 应有引用名")
  }
  match @dex.instruction_ref_name(dex, code.insns[13]) {
    Some(s) => sem_check_eq(s, "LKind;", msg="const-class→类名")
    None => fail("const-class 应有引用名")
  }
  match @dex.instruction_ref_name(dex, code.insns[14]) {
    Some(s) => sem_check_eq(s, "LTest;->fld:I", msg="iget→类.字段:类型")
    None => fail("iget 应有引用名")
  }
  sem_check(
    @dex.instruction_ref_name(dex, code.insns[7]) is None,
    msg="goto 无引用→None",
  )
}

///|
/// 真实样本（AnnoSample.dex）：main 方法指令流与 dexdump -d 操作数逐条对照，
/// 名字解析格式 `Lcls;->name(sig)ret`（smali 风格，与 disasm 一致；
/// dexdump 显示为 `Lcls;.name:sig`，语义相同、分隔符不同）。
test "sem operands: 真实样本 AnnoSample 指令操作数" {
  let data = sem_fixture_anno_dex()
  let dex = @dex.parse(data)
  let main = dex.classes[4].direct_methods[3]
  sem_check_eq(dex.strings()[main.name_index], "main", msg="定位 main")
  let code = match main.code {
    Some(c) => c
    None => fail("main 应有 code")
  }
  sem_check_eq(
    code.insns.length(),
    8,
    msg="main 8 条指令（dexdump 对照）",
  )
  // 0000: new-instance v0, LAnnoSample$Target; // type@0009
  let i0 = @dex.instruction_operands(code.insns[0])
  sem_check_eq(i0.regs, [0])
  sem_check(i0.index_kind is @dex.IndexKind::IndexType)
  sem_check_eq(i0.index, 9, msg="type@0009")
  // 0002: invoke-direct {v0}, LAnnoSample$Target;.<init>:()V // method@0014
  let i1 = @dex.instruction_operands(code.insns[1])
  sem_check_eq(i1.regs, [0], msg="invoke 单寄存器列表")
  sem_check_eq(i1.index, 20, msg="method@0014")
  match @dex.instruction_ref_name(dex, code.insns[1]) {
    Some(s) =>
      sem_check_eq(
        s,
        "LAnnoSample$Target;-><init>()V",
        msg="invoke→类.方法(签名)",
      )
    None => fail("invoke 应有引用名")
  }
  // 0005: const v1, #f8a432eb（dexdump 以 float 打印，位模式即 -123456789）
  let i2 = @dex.instruction_operands(code.insns[2])
  sem_check_eq(i2.regs, [1])
  sem_check_eq(i2.literal, Some(-123456789L), msg="F31i 32 位字面量")
  // 0008: iput v1, v0, LAnnoSample$Target;.fieldAnno:I // field@0003
  let i3 = @dex.instruction_operands(code.insns[3])
  sem_check_eq(i3.regs, [1, 0])
  sem_check_eq(i3.index, 3, msg="field@0003")
  match @dex.instruction_ref_name(dex, code.insns[3]) {
    Some(s) =>
      sem_check_eq(
        s,
        "LAnnoSample$Target;->fieldAnno:I",
        msg="字段引用→类.字段:类型",
      )
    None => fail("iput 应有引用名")
  }
  // 000b: aget-object v2, v2, v0
  let i5 = @dex.instruction_operands(code.insns[5])
  sem_check_eq(i5.regs, [2, 2, 0], msg="F23x 三寄存器")
  sem_check(i5.index_kind is @dex.IndexKind::IndexNone)
  // 000d: invoke-static {v2}, LAnnoSample;.enc:(...) // method@0018
  match @dex.instruction_ref_name(dex, code.insns[6]) {
    Some(s) =>
      sem_check_eq(s, "LAnnoSample;->enc(Ljava/lang/String;)Ljava/lang/String;")
    None => fail("invoke-static 应有引用名")
  }
  // 000a: const/4 无引用
  sem_check(@dex.instruction_ref_name(dex, code.insns[4]) is None)
  // 按表解析名字（dexdump `// method@0002` / `// field@0001` / `// string@0009`）
  sem_check_eq(
    @dex.method_ref_name(dex, 2),
    "LAnnoSample$Kind;-><init>(Ljava/lang/String;I)V",
    msg="method@0002",
  )
  sem_check_eq(
    @dex.field_ref_name(dex, 1),
    "LAnnoSample$Kind;->ALPHA:LAnnoSample$Kind;",
    msg="field@0001",
  )
  sem_check_eq(@dex.string_ref_name(dex, 9), "ALPHA", msg="string@0009")
  sem_check_eq(@dex.type_ref_name(dex, 6), "LAnnoSample$Kind;", msg="type@0006")
}

///|
/// 错误路径：引用索引越界、IndexNone 综合解析——抛 DexError 而非 panic。
test "sem operands: 错误路径" {
  let fx = sem_build_dex()
  let dex = @dex.parse(sem_fixture_bytes(fx))
  let mut got1 = false
  ignore(@dex.string_ref_name(dex, 99)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::StringId)
      sem_check_eq(idx, 99)
      got1 = true
    }
    _ => ()
  }
  sem_check(got1, msg="string_ref_name(99) 应报 InvalidIndex")
  let mut got2 = false
  ignore(@dex.resolve_ref_name(dex, @dex.IndexKind::IndexNone, 0)) catch {
    @dex.DexError::InvalidIndex(_, _) => got2 = true
    _ => ()
  }
  sem_check(got2, msg="IndexNone 综合解析应报 InvalidIndex")
  let mut got3 = false
  ignore(@dex.method_ref_name(dex, -1)) catch {
    @dex.DexError::InvalidIndex(kind, _) => {
      sem_check(kind is @dex.TableKind::MethodId)
      got3 = true
    }
    _ => ()
  }
  sem_check(got3, msg="负索引应报 InvalidIndex")
}
