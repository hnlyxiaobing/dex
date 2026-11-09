///|
/// R4 白盒：DEX 038+ encoded_value（0x15/0x16）、指令表（0xFE/0xFF）与
/// method_handles_item 校验（res0 / kind）的错误路径，断言报 DexError 而非 panic。

///|
/// 空表 Ctx（白盒构造的最小解析上下文）。
fn dyn_empty_ctx() -> Ctx {
  Ctx::{
    strings: [],
    types: [],
    protos: [],
    fields: [],
    methods: [],
    handles: [],
    call_sites: [],
  }
}

///|
/// 小端写入 helper（合成表字节）。
fn dyn_put_u16(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
}

///|
fn dyn_put_u32(arr : Array[Byte], off : Int32, v : Int32) -> Unit {
  arr[off] = (v & 0xff).to_byte()
  arr[off + 1] = ((v >> 8) & 0xff).to_byte()
  arr[off + 2] = ((v >> 16) & 0xff).to_byte()
  arr[off + 3] = ((v >> 24) & 0xff).to_byte()
}

///|
/// 合成一个只含 method_handles_item 表的最小容器（map_list @0x70，表 @0x84）。
fn dyn_handle_table(kind : Int32, unused : Int32) -> Bytes {
  let arr : Array[Byte] = []
  for _ in 0..<0x100 {
    arr.push((0 : Byte))
  }
  dyn_put_u32(arr, 0x70, 1) // map_list count
  dyn_put_u16(arr, 0x74, 0x0008) // TYPE_METHOD_HANDLE_ITEM
  dyn_put_u16(arr, 0x76, 0) // map_item.unused
  dyn_put_u32(arr, 0x78, 1) // size
  dyn_put_u32(arr, 0x7c, 0x84) // offset
  dyn_put_u16(arr, 0x84, kind) // method_handle_type
  dyn_put_u16(arr, 0x86, unused) // res0
  dyn_put_u32(arr, 0x88, 0) // field_or_method_index
  Bytes::from_array(arr)
}

///|
/// 空表时 VALUE_METHOD_HANDLE（0x16）/ VALUE_METHOD_TYPE（0x15）索引越界。
test "wb dyn encoded_value 0x15/0x16 索引越界" {
  let ctx = dyn_empty_ctx()
  let mut got_handle = false
  ignore(decode_value(ctx, b"\x16\x00", 0)) catch {
    DexError::InvalidIndex(TableKind::MethodHandle, idx) => {
      assert_eq(idx, 0)
      got_handle = true
    }
    _ => ()
  }
  assert_true(got_handle, msg="0x16 空表应报 InvalidIndex(MethodHandle)")
  let mut got_type = false
  ignore(decode_value(ctx, b"\x15\x00", 0)) catch {
    DexError::InvalidIndex(TableKind::ProtoId, idx) => {
      assert_eq(idx, 0)
      got_type = true
    }
    _ => ()
  }
  assert_true(got_type, msg="0x15 空表应报 InvalidIndex(ProtoId)")
}

///|
/// method_handles_item 的 res0 非 0 / kind 超范围 → BadTableOffset(MethodHandle)。
test "wb dyn method_handle res0 / kind 非法" {
  let field_count = 0
  let method_count = 1
  let mut got_res0 = false
  ignore(
    parse_method_handles(
      dyn_handle_table(4, 1),
      0x70,
      field_count,
      method_count,
    ),
  ) catch {
    DexError::BadTableOffset(TableKind::MethodHandle, p) => {
      assert_eq(p, 0x84)
      got_res0 = true
    }
    _ => ()
  }
  assert_true(got_res0, msg="res0 非 0 应报 BadTableOffset(MethodHandle)")
  let mut got_kind = false
  ignore(
    parse_method_handles(
      dyn_handle_table(9, 0),
      0x70,
      field_count,
      method_count,
    ),
  ) catch {
    DexError::BadTableOffset(TableKind::MethodHandle, p) => {
      assert_eq(p, 0x84)
      got_kind = true
    }
    _ => ()
  }
  assert_true(got_kind, msg="kind 超范围应报 BadTableOffset(MethodHandle)")
}

///|
/// 0xFE const-method-handle / 0xFF const-method-type 的操作数标注。
test "wb dyn const-method-handle / const-method-type 解码" {
  let ctx = Ctx::{
    strings: ["LTest;", "V", "foo"],
    types: ["LTest;", "V"],
    protos: [ProtoId::{ shorty: "V", return_type: "V", parameters: [], }],
    fields: [],
    methods: [
      MethodDef::{
        class_index: 0,
        name_index: 2,
        proto_index: 0,
        access_flags: 0U,
        code_off: 0,
        code: None,
      },
    ],
    handles: [
      MethodHandleItem::{ handle_type: InvokeStatic, field_or_method_index: 0, },
    ],
    call_sites: [],
  }
  let insns = decode_insns(ctx, 0x70, 0, 2, b"\xfe\x00\x00\x00")
  assert_eq(insns.length(), 1)
  assert_eq(insns[0].mnemonic, "const-method-handle")
  assert_true(
    insns[0].operands[1].contains("method_handle@0{"),
    msg="0xFE method handle 标注",
  )
  assert_true(
    insns[0].operands[1].contains("invoke-static LTest;->foo()V"),
    msg="0xFE 句柄目标渲染",
  )
  let insns2 = decode_insns(ctx, 0x70, 0, 2, b"\xff\x10\x00\x00")
  assert_eq(insns2.length(), 1)
  assert_eq(insns2[0].mnemonic, "const-method-type")
  assert_eq(insns2[0].operands[1], "()V", msg="0xFF proto 标注")
}

///|
/// 45cc/4rcc/35c 指令截断 → BadCodeItem（宽度校验在读操作数之前）。
test "wb dyn invoke-polymorphic / invoke-custom 截断" {
  let ctx = dyn_empty_ctx()
  let mut got_fa = false
  ignore(decode_insns(ctx, 0x70, 0, 3, b"\xfa\x20\x14\x00\x10\x00")) catch {
    DexError::BadCodeItem(_, msg) => {
      assert_true(
        msg.contains("truncated"),
        msg="45cc 截断应报 BadCodeItem",
      )
      got_fa = true
    }
    _ => ()
  }
  assert_true(got_fa, msg="45cc 截断应报 BadCodeItem")
  let mut got_fc = false
  ignore(decode_insns(ctx, 0x70, 0, 2, b"\xfc\x10\x00\x00")) catch {
    DexError::BadCodeItem(_, _) => got_fc = true
    _ => ()
  }
  assert_true(got_fc, msg="35c 截断应报 BadCodeItem")
  let mut got_fb = false
  ignore(decode_insns(ctx, 0x70, 0, 3, b"\xfb\x07\x13\x00\x00\x00")) catch {
    DexError::BadCodeItem(_, _) => got_fb = true
    _ => ()
  }
  assert_true(got_fb, msg="4rcc 截断应报 BadCodeItem")
}
