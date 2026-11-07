// WP-2 常量值语义测试（R2 语义补全轮新增文件）。
//
// 覆盖：encoded_array 公开入口、class_def.static_values_off → 静态字段初值
// （加密字符串入口：静态常量字符串/整型初值的结构化展开）、前缀省略语义。
//
// 真实样本佐证（dexdump -d -a 逐值核对）：
//   1) AnnoSample.dex —— javac 21 + d8 自建（SHA-256 与来源见 dex_sem_annotations_test.mbt）：
//      static_values 10 值含 VALUE_NULL 前缀（SArr）与 float/double 左对齐编码；
//   2) tvshell-debug.classes.dex —— 受控 APK 提取（SHA-256 1c77374f...1aeca）：
//      DEFAULT_URL / TAG 两个静态字符串常量（dexdump `value : "..."` 对照）。
// fixture 与辅助函数（sem_*）定义于 dex_sem_annotations_test.mbt（测试包共享命名空间）。

///|
/// 真实样本（AnnoSample.dex）：LAnnoSample; 的 static_values 全 10 值
/// 与 dexdump 静态字段 `value :` 行逐值对照（field_idx 序：SArr..SZ）。
test "sem consts: 真实样本 AnnoSample static_values 全值" {
  let data = sem_fixture_anno_dex()
  let values = @dex.static_values(data, 4)
  sem_check_eq(values.length(), 10, msg="10 个静态字段均有编码值")
  match values[0] {
    @dex.EncodedValue::ValueNull =>
      sem_check(
        true,
        msg="SArr 对象字段编码 VALUE_NULL（占位保证后续对齐）",
      )
    _ => fail("SArr 应为 ValueNull")
  }
  match values[1] {
    @dex.EncodedValue::ValueByte(x) => sem_check_eq(x, -8, msg="SB=-8")
    _ => fail("SB 应为 ValueByte")
  }
  match values[2] {
    @dex.EncodedValue::ValueChar(x) => sem_check_eq(x, 65, msg="SC='A'")
    _ => fail("SC 应为 ValueChar")
  }
  match values[3] {
    @dex.EncodedValue::ValueDouble(x) => sem_check_eq(x, -2.25, msg="SD=-2.25")
    _ => fail("SD 应为 ValueDouble")
  }
  match values[4] {
    @dex.EncodedValue::ValueFloat(x) => sem_check_eq(x, 3.5, msg="SF=3.5")
    _ => fail("SF 应为 ValueFloat")
  }
  match values[5] {
    @dex.EncodedValue::ValueInt(x) => sem_check_eq(x, -123456789, msg="SI")
    _ => fail("SI 应为 ValueInt")
  }
  match values[6] {
    @dex.EncodedValue::ValueLong(x) =>
      sem_check_eq(
        x,
        1311768467294899695L,
        msg="SL=0x1234567890ABCDEF（8 字节）",
      )
    _ => fail("SL 应为 ValueLong")
  }
  match values[7] {
    @dex.EncodedValue::ValueShort(x) => sem_check_eq(x, -1234, msg="SS=-1234")
    _ => fail("SS 应为 ValueShort")
  }
  match values[8] {
    @dex.EncodedValue::ValueString(x) =>
      sem_check_eq(x, "static-string", msg="ST")
    _ => fail("ST 应为 ValueString")
  }
  match values[9] {
    @dex.EncodedValue::ValueBoolean(x) => sem_check_eq(x, true, msg="SZ=true")
    _ => fail("SZ 应为 ValueBoolean")
  }
  // 与 class_def.static_fields 一一对应（前缀完整）
  sem_check_eq(dex_static_field_count(data, 4), 10, msg="static_fields 10 个")
}

///|
/// 静态字段计数辅助：class_data 头四个 uleb128 的第一个。
fn dex_static_field_count(data : Bytes, class_index : Int32) -> Int32 {
  let class_defs_off = read_u32_pub(data, 0x64)
  let base = class_defs_off + class_index * 32
  let class_data_off = read_u32_pub(data, base + 24)
  // class_data 首个 uleb128 = static_fields_size
  let mut v = 0
  let mut shift = 0
  let mut pos = class_data_off
  let mut more = true
  while more {
    let b = data.at(pos).to_int()
    pos = pos + 1
    v = v | ((b & 0x7f) << shift)
    shift = shift + 7
    if (b & 0x80) == 0 {
      more = false
    }
  }
  v
}

///|
/// 测试侧小端 u32 读取（与解析器内部实现独立）。
fn read_u32_pub(data : Bytes, off : Int32) -> Int32 {
  data.at(off).to_int() |
  (data.at(off + 1).to_int() << 8) |
  (data.at(off + 2).to_int() << 16) |
  (data.at(off + 3).to_int() << 24)
}

///|
/// 真实样本（tvshell-debug.classes.dex）：加密字符串入口——
/// Lcom/cteno/tvshell/MainActivity; 的 static_values 为 DEFAULT_URL / TAG。
test "sem consts: 真实样本 tvshell static_values（加密字符串入口）" {
  let data = sem_fixture_tvshell_dex()
  let values = @dex.static_values(data, 2)
  sem_check_eq(values.length(), 2, msg="DEFAULT_URL + TAG")
  match values[0] {
    @dex.EncodedValue::ValueString(x) =>
      sem_check_eq(x, "file:///android_asset/probe.html", msg="DEFAULT_URL")
    _ => fail("DEFAULT_URL 应为 ValueString")
  }
  match values[1] {
    @dex.EncodedValue::ValueString(x) => sem_check_eq(x, "TVSHELL", msg="TAG")
    _ => fail("TAG 应为 ValueString")
  }
  // 无 static_values 的类返回空数组（R 类）
  sem_check_eq(
    @dex.static_values(data, 3).length(),
    0,
    msg="R 类无静态初值",
  )
}

///|
/// 程序化 fixture：static_values 前缀省略语义——2 个静态字段只编码 1 个初值，
/// 尾部默认值省略（返回数组长度 ≤ static_fields 长度）。
test "sem consts: static_values 前缀省略语义" {
  let fx = sem_build_dex()
  let data = sem_fixture_bytes(fx)
  let values = @dex.static_values(data, 0)
  sem_check_eq(values.length(), 1, msg="仅编码前缀 1 值")
  match values[0] {
    @dex.EncodedValue::ValueInt(x) => sem_check_eq(x, 7, msg="a=7")
    _ => fail("应为 ValueInt")
  }
  let dex = @dex.parse(data)
  sem_check_eq(
    dex.classes[0].static_fields.length(),
    2,
    msg="static_fields=[a,b]",
  )
  sem_check_eq(
    dex.classes[0].instance_fields.length(),
    1,
    msg="instance_fields=[fld]",
  )
}

///|
/// 公开入口：encoded_array 按偏移直接解码（与 static_values 同源）。
test "sem consts: encoded_array 公开入口" {
  let fx = sem_build_dex()
  let data = sem_fixture_bytes(fx)
  let values = @dex.encoded_array(data, fx.sv_off)
  sem_check_eq(values.length(), 1, msg="与 static_values 一致")
  match values[0] {
    @dex.EncodedValue::ValueInt(x) => sem_check_eq(x, 7)
    _ => fail("应为 ValueInt")
  }
  // 空数组：AnnotationDefault.value（嵌套注解）的 arr 元素默认 {}（零长 encoded_array）
  let dir = match @dex.class_annotations(sem_fixture_anno_dex(), 1) {
    Some(d) => d
    None => fail("Meta 应有注解目录")
  }
  match dir.class_annotations.annotations[0].annotation.elements[0].value {
    @dex.EncodedValue::ValueAnnotation(meta_defaults) =>
      match meta_defaults.elements[0].value {
        @dex.EncodedValue::ValueArray(inner) =>
          sem_check_eq(inner.length(), 0, msg="空 encoded_array")
        _ => fail("应为空数组")
      }
    _ =>
      fail(
        "AnnotationDefault.value 应为 ValueAnnotation（内含 arr 元素）",
      )
  }
}

///|
/// 错误路径：class_index 越界、static_values_off=0、偏移越界——抛 DexError 而非 panic。
test "sem consts: 错误路径" {
  let fx = sem_build_dex()
  let data = sem_fixture_bytes(fx)
  // class_index 越界
  let mut got1 = false
  ignore(@dex.static_values(data, 2)) catch {
    @dex.DexError::InvalidIndex(kind, idx) => {
      sem_check(kind is @dex.TableKind::ClassDef)
      sem_check_eq(idx, 2)
      got1 = true
    }
    _ => ()
  }
  sem_check(got1, msg="static_values(2) 应报 InvalidIndex")
  // LAnno; 无 static_values_off → 空数组
  sem_check_eq(
    @dex.static_values(data, 1).length(),
    0,
    msg="static_values_off=0 → 空",
  )
  // encoded_array 偏移越界
  let mut got2 = false
  ignore(@dex.encoded_array(data, 0x20)) catch {
    @dex.DexError::BadTableOffset(_, _) => got2 = true
    _ => ()
  }
  sem_check(got2, msg="偏移落入头部应报 BadTableOffset")
}
