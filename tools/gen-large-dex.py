#!/usr/bin/env python3
# gen-large-dex.py -- 合成「真实规模」DEX 035 fixture（离线、确定性、纯标准库）。
#
# Usage:  python tools/gen-large-dex.py --out <path> [--classes N] [--strings N]
#         从模块根 dex/ 运行；也可单独运行（无需 moon / 第三方库 / 样本 APK）。
# Output: 合法 DEX 035，约 3000-5000 个 class_def（默认 4000）。每个 class_def 都带
#         独立的 annotation_directory_item（class_annotations 指向含 1 个类注解的
#         annotation_set_item），并带 static_values_off -> encoded_array（1 个
#         VALUE_INT）。字符串池数千条（默认 6000），用于让「逐类重建全表」的旧实现
#         退化为 O(C x T)：C 个类 x T 条字符串。
# 确定性: 无随机数、无时间戳、无环境相关输入；同一参数产出完全相同的字节
#         （stdout 打印 sha256 便于复核）。
# stdout: 末尾固定一行 ASCII
#         GEN|classes=<N>|strings=<M>|size=<B>|sha256=<64hex>
#         供 bench-dex.ps1 解析「生成类数」做 fail-closed 下限断言。
# Exit:   0 = 生成 + 落盘 + 魔数/大小/checksum/file_size 自检全通过；1 = 任一失败。
#
# DEX 布局参考：dex/dex_sem_annotations_test.mbt 的 sem_build_dex() 与
# sem_b_fix_checksum()（checksum = Adler32，覆盖 signature 之后即 offset 12 起的全部字节）。
# 简化点：proto/field/method 表 size=0；map_off=0；class_data_off=0（无字段/方法）；
# 注解/静态初值项被所有类共享（偏移合法即可），但每个类都有自己的 annotation_directory_item。

import argparse
import hashlib
import os
import struct
import sys
import zlib

MAGIC = b"dex\n035\x00"
NO_INDEX = 0xFFFFFFFF
HEADER_SIZE = 0x70


def u8(v):
    return struct.pack("<B", v & 0xFF)


def u32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def patch_u32(buf, off, v):
    buf[off:off + 4] = u32(v)


def align4(buf):
    while len(buf) % 4:
        buf.append(0)


def string_item(s):
    # string_data_item: uleb(utf16_size) + MUTF-8(ASCII 子集) + 0x00
    return uleb(len(s)) + s.encode("ascii") + b"\x00"


def build(classes, nstrings):
    # ---- header 骨架（0x70 字节，稍后补丁） ---------------------------------
    buf = bytearray(MAGIC)                       # 0x00 magic[8]
    buf += b"\x00" * 4                          # 0x08 checksum（占位）
    buf += b"\x00" * 20                         # 0x0C signature[20]
    buf += b"\x00" * (HEADER_SIZE - len(buf))   # 0x20..0x70 其余字段先置零

    # ---- 字符串池（确定性） ------------------------------------------------
    # [0] 注解类型  [1] 超类  [2] 注解元素名  [3..3+C) 类描述符  其余为填充
    strings = ["LGen/Anno;", "Ljava/lang/Object;", "value"]
    for i in range(classes):
        strings.append("LGen/C%d;" % i)
    pad = 0
    while len(strings) < nstrings:
        strings.append("LGen/Pad%07d;" % pad)
        pad += 1
    nstrings = len(strings)

    # ---- 六表：string_ids / type_ids / class_defs ---------------------------
    string_ids_off = len(buf)
    for _ in strings:
        buf += u32(0)                            # string_data_off 占位，稍后补丁

    type_ids_off = len(buf)
    for i in range(nstrings):
        buf += u32(i)                           # type_ids[i] -> strings[i]

    class_defs_off = len(buf)
    for i in range(classes):
        buf += u32(3 + i)                       # class_idx -> "LGen/C<i>;"
        buf += u32(0x1)                         # access_flags = PUBLIC
        buf += u32(1)                           # superclass_idx -> Ljava/lang/Object;
        buf += u32(0)                           # interfaces_off = 0
        buf += u32(NO_INDEX)                    # source_file_idx = NO_INDEX
        buf += u32(0)                           # annotations_off（稍后补丁）
        buf += u32(0)                           # class_data_off = 0（无字段/方法）
        buf += u32(0)                           # static_values_off（稍后补丁）

    # ---- string_data_item x N，回补丁 string_ids ----------------------------
    for i, s in enumerate(strings):
        patch_u32(buf, string_ids_off + i * 4, len(buf))
        buf += string_item(s)
    align4(buf)

    # ---- annotation_item（共享）: RUNTIME LGen/Anno;{value=7} ----------------
    # u8 visibility + encoded_annotation(type_idx uleb, size uleb,
    #   {name_idx uleb + encoded_value}...)；VALUE_INT(1 字节)=7 -> 0x04 0x07
    ann_item_off = len(buf)
    buf += u8(1)                                # VISIBILITY_RUNTIME
    buf += uleb(0)                              # type_idx -> types[0] = "LGen/Anno;"
    buf += uleb(1)                              # 1 个元素
    buf += uleb(2)                              # name_idx -> strings[2] = "value"
    buf += u8(0x04) + u8(7)                    # VALUE_INT 7
    align4(buf)

    # ---- annotation_set_item（共享）: 1 个 annotation_item -------------------
    ann_set_off = len(buf)
    buf += u32(1) + u32(ann_item_off)

    # ---- annotation_directory_item x C（每类独立 16 字节） ------------------
    # class_annotations_off + fields_size + methods_size + params_size，后三者为 0
    ann_dir_base = len(buf)
    for _ in range(classes):
        buf += u32(ann_set_off) + u32(0) + u32(0) + u32(0)

    # ---- static_values encoded_array（共享）: [VALUE_INT 1] ------------------
    sv_off = len(buf)
    buf += uleb(1) + u8(0x04) + u8(1)

    # ---- 回补丁每个 class_def 的 annotations_off / static_values_off --------
    for i in range(classes):
        patch_u32(buf, class_defs_off + i * 32 + 20, ann_dir_base + i * 16)
        patch_u32(buf, class_defs_off + i * 32 + 28, sv_off)

    # ---- header 字段 -------------------------------------------------------
    patch_u32(buf, 0x20, len(buf))              # file_size 必须精确等于实际长度
    patch_u32(buf, 0x24, HEADER_SIZE)           # header_size = 0x70
    patch_u32(buf, 0x28, 0x12345678)            # endian_tag（小端）
    patch_u32(buf, 0x34, 0)                     # map_off = 0（read_ctx 不读取）
    patch_u32(buf, 0x38, nstrings)              # string_ids_size
    patch_u32(buf, 0x3C, string_ids_off)
    patch_u32(buf, 0x40, nstrings)              # type_ids_size
    patch_u32(buf, 0x44, type_ids_off)
    patch_u32(buf, 0x48, 0)                     # proto_ids_size = 0
    patch_u32(buf, 0x50, 0)                     # field_ids_size = 0
    patch_u32(buf, 0x58, 0)                     # method_ids_size = 0
    patch_u32(buf, 0x60, classes)               # class_defs_size
    patch_u32(buf, 0x64, class_defs_off)

    # checksum = Adler32 覆盖 [12, file_size)，与 sem_b_fix_checksum 同口径
    checksum = zlib.adler32(bytes(buf[12:])) & 0xFFFFFFFF
    patch_u32(buf, 0x08, checksum)
    return bytes(buf), classes, nstrings, checksum


def self_check(data, classes, nstrings, checksum):
    """落盘前自检：文件大小、魔数、file_size 字段、checksum。"""
    if len(data) < HEADER_SIZE + 16:
        raise ValueError("生成的 DEX 过小: %d bytes" % len(data))
    if data[:8] != MAGIC:
        raise ValueError("魔数不符: %r" % data[:8])
    if struct.unpack_from("<I", data, 0x20)[0] != len(data):
        raise ValueError("header.file_size 字段与实际长度不一致")
    if struct.unpack_from("<I", data, 0x60)[0] != classes:
        raise ValueError("header.class_defs_size 与生成类数不一致")
    if (zlib.adler32(data[12:]) & 0xFFFFFFFF) != checksum:
        raise ValueError("checksum 自检失败")
    if struct.unpack_from("<I", data, 0x38)[0] != nstrings:
        raise ValueError("header.string_ids_size 与字符串数不一致")
    return True


def main():
    ap = argparse.ArgumentParser(
        description="生成确定性、离线可复现的大规模合法 DEX 035 fixture"
    )
    ap.add_argument("--out", required=True, help="输出 .dex 路径")
    ap.add_argument("--classes", type=int, default=4000,
                    help="class_def 数量（默认 4000，推荐 3000-5000）")
    ap.add_argument("--strings", type=int, default=6000,
                    help="字符串池条数（默认 6000，需 >= classes + 3）")
    args = ap.parse_args()

    if args.classes < 1:
        print("error: --classes 必须 >= 1", file=sys.stderr)
        return 1
    if args.strings < args.classes + 3:
        print("error: --strings 必须 >= --classes + 3", file=sys.stderr)
        return 1

    try:
        data, classes, nstrings, checksum = build(args.classes, args.strings)
        self_check(data, classes, nstrings, checksum)

        out = os.path.abspath(args.out)
        parent = os.path.dirname(out) or "."
        os.makedirs(parent, exist_ok=True)
        with open(out, "wb") as f:
            f.write(data)

        # 落盘复读校验：文件大小、魔数、字节一致
        with open(out, "rb") as f:
            disk = f.read()
        if disk != data or len(disk) < HEADER_SIZE or disk[:8] != MAGIC:
            raise ValueError("落盘复读校验失败")
    except (OSError, ValueError) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1

    sha = hashlib.sha256(data).hexdigest()
    print("GEN|classes=%d|strings=%d|size=%d|sha256=%s" %
          (classes, nstrings, len(data), sha))
    print("gen-large-dex: wrote %s (%d bytes, magic=dex/035)" % (out, len(data)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
