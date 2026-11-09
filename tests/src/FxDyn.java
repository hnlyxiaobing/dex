// 受控样本源码（dex/tests/build-dyn.ps1 构建）：038+ 指令组 + payload 语义样本。
// 目标指令面：
//   1) lambda / 方法引用 -> invokedynamic -> d8(min-api 26) 保留 invoke-custom（0xfc）
//      + call_site_id_item + method_handles_item（bootstrap MethodHandle 常量）；
//   2) MethodHandle.invoke / invokeExact（签名多态）-> invoke-polymorphic（0xfa）；
//   3) packed-switch / sparse-switch / fill-array-data payload（0x0100/0x0200/0x0300）。
// 许可：Apache-2.0（本仓库同许可，受控自产，见 tests/ASSETS.md）。
package fx.dyn;

import java.lang.invoke.MethodHandle;
import java.lang.invoke.MethodHandles;
import java.lang.invoke.MethodType;

public class FxDyn {
  /** 函数式接口：lambda 转 invokedynamic 的 call site 目标。 */
  public interface IntOp {
    int apply(int x);
  }

  /** 捕获 lambda -> invoke-custom（call_site@）。 */
  public static IntOp makeAdder(int base) {
    return x -> x + base;
  }

  /** 非捕获 lambda -> invoke-custom。 */
  public static IntOp makeSquare() {
    return x -> x * x;
  }

  /** 方法引用 -> invoke-custom（bootstrap 带 MethodHandle 常量）。 */
  public static Runnable makeRunner() {
    return FxDyn::staticTarget;
  }

  public static void staticTarget() {}

  /** MethodHandle.invoke（签名多态）-> invoke-polymorphic。 */
  public static int polyInvoke(MethodHandle mh, int a, int b) throws Throwable {
    return (int) mh.invoke(a, b);
  }

  /** MethodHandle.invokeExact（签名多态）-> invoke-polymorphic。 */
  public static int polyExact(MethodHandle mh, int a) throws Throwable {
    return (int) mh.invokeExact(a);
  }

  /** 6 参数签名多态调用 -> invoke-polymorphic/range（4rcc 布局）。 */
  public static Object polyRange(
      MethodHandle mh, Object a, Object b, Object c, Object d, Object e, Object f)
      throws Throwable {
    return mh.invoke(a, b, c, d, e, f);
  }

  /** Lookup.findStatic -> 常量池 method_handle 引用（const-method-handle 面）。 */
  public static MethodHandle lookupAdd() throws Throwable {
    return MethodHandles.lookup()
        .findStatic(FxDyn.class, "add", MethodType.methodType(int.class, int.class, int.class));
  }

  public static int add(int a, int b) {
    return a + b;
  }

  /** packed-switch-payload（连续 case）。 */
  public static int packedSwitch(int x) {
    switch (x) {
      case 1:
        return 10;
      case 2:
        return 20;
      case 3:
        return 30;
      case 4:
        return 40;
      default:
        return -1;
    }
  }

  /** sparse-switch-payload（离散 case）。 */
  public static int sparseSwitch(int x) {
    switch (x) {
      case 5:
        return 1;
      case 500:
        return 2;
      case 50000:
        return 3;
      default:
        return 0;
    }
  }

  /** fill-array-data-payload（int[] 初始化值数据块）。 */
  public static int sumArray() {
    int[] a = {1, 2, 3, 4, 5, 6, 7, 8};
    int s = 0;
    for (int v : a) {
      s += v;
    }
    return s;
  }

  /** fill-array-data-payload（long[]，8 字节元素宽）。 */
  public static long sumLongArray() {
    long[] a = {1L, 2L, 3L, 4L};
    long s = 0;
    for (long v : a) {
      s += v;
    }
    return s;
  }
}
