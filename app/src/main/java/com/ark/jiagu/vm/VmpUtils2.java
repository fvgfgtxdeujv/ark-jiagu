package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.iface.MethodParameter;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 第二代 VMP 工具类（嵌入式方案）
 *
 * <p>与第一代的区别：
 * <ul>
 *   <li>不生成独立壳 dex（无 StubApp）</li>
 *   <li>VMP 类直接注入原始 dex，自带 &lt;clinit&gt; 通过 System.loadLibrary 加载 SO</li>
 *   <li>不修改 AndroidManifest.xml，不劫持 Application</li>
 *   <li>仅保护用户指定的方法，不自动扫描 Activity</li>
 *   <li>SO 通过 JNI_OnLoad 自动注册 native 方法到 VMP 类</li>
 * </ul>
 *
 * <p>使用方式：
 * <pre>
 * // 1. 定义方法规则（类名.方法名，支持通配符）
 * String[] rules = {
 *     "com.example.MainActivity.onCreate",
 *     "com.example.LoginActivity.onResume",
 *     "com.example.Payment.*"
 * };
 *
 * // 2. 抽取方法到 bin
 * VmpJiaguEntry.extractMethodsToBin(dexDir, rules);
 *
 * // 3. 重写 dex（原始方法替换为 VMP 调用）
 * VmpJiaguEntry.rewriteExtractedMethodsToVmCallDex(dexDir, "ArkStub", "com.example.VMP");
 * </pre>
 */
public class VmpUtils2 {

    /**
     * 默认 VMP 类名（包在 com.ark.safe 下，避免和应用类冲突）
     */
    public static final String DEFAULT_VMP_CLASS_NAME = "com.ark.safe.VMP";

    /**
     * 默认 SO 名称
     */
    public static final String DEFAULT_SO_NAME = "ArkStub";

    /**
     * 生成嵌入式 VMP 类（带 &lt;clinit&gt; 自动加载 SO）
     *
     * <p>生成的类结构：
     * <pre>
     * package com.ark.safe;
     *
     * public class VMP {
     *     static { System.loadLibrary("ArkStub"); }
     *
     *     public VMP() { super(); }
     *     protected void attachBaseContext(Context ctx) { super.attachBaseContext(ctx); }
     *
     *     public static native void callVoid(int methodId, Object thiz, Object[] args);
     *     public static native boolean callBoolean(int methodId, Object thiz, Object[] args);
     *     // ... 各种返回类型的 native 方法
     * }
     * </pre>
     *
     * <p>SO 加载时机：VMP 类被 dexclassfinde 时自动触发 &lt;clinit&gt;
     */
    public static com.android.tools.smali.dexlib2.iface.ClassDef createVmpClassEmbedded(
            String soName,
            String fullClassName) {

        if (fullClassName == null || fullClassName.trim().isEmpty()) {
            throw new IllegalArgumentException("VMP 类名不能为空");
        }

        String cleanClassName = fullClassName.trim();
        String classType = "L" + cleanClassName.replace('.', '/') + ";";

        // ---------- <clinit>：System.loadLibrary(soName) ----------
        List<com.android.tools.smali.dexlib2.iface.instruction.Instruction> clinitInstructions =
                Arrays.asList(
                        new ImmutableInstruction21c(
                                Opcode.CONST_STRING,
                                0,
                                new ImmutableStringReference(soName != null ? soName : DEFAULT_SO_NAME)
                        ),
                        new ImmutableInstruction35c(
                                Opcode.INVOKE_STATIC,
                                1,
                                0,
                                0,
                                0,
                                0,
                                0,
                                new ImmutableMethodReference(
                                        "Ljava/lang/System;",
                                        "loadLibrary",
                                        Collections.singletonList("Ljava/lang/String;"),
                                        "V"
                                )
                        ),
                        new ImmutableInstruction10x(Opcode.RETURN_VOID)
                );

        com.android.tools.smali.dexlib2.iface.MethodImplementation clinitImpl =
                new ImmutableMethodImplementation(
                        1,
                        clinitInstructions,
                        Collections.emptyList(),
                        Collections.emptyList()
                );

        com.android.tools.smali.dexlib2.iface.Method clinitMethod = new ImmutableMethod(
                classType,
                "<clinit>",
                Collections.emptyList(),
                "V",
                AccessFlags.STATIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                clinitImpl
        );

        // ---------- <init> ----------
        com.android.tools.smali.dexlib2.iface.MethodImplementation initImpl =
                new ImmutableMethodImplementation(
                        1,
                        Arrays.asList(
                                new ImmutableInstruction35c(
                                        Opcode.INVOKE_DIRECT,
                                        1,
                                        0,
                                        0,
                                        0,
                                        0,
                                        0,
                                        new ImmutableMethodReference(
                                                "Ljava/lang/Object;",
                                                "<init>",
                                                Collections.emptyList(),
                                                "V"
                                        )
                                ),
                                new ImmutableInstruction10x(Opcode.RETURN_VOID)
                        ),
                        null,
                        null
                );

        com.android.tools.smali.dexlib2.iface.Method initMethod = new ImmutableMethod(
                classType,
                "<init>",
                Collections.emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                initImpl
        );

        // ---------- attachBaseContext (保留，方便 SO 获取 Context) ----------
        com.android.tools.smali.dexlib2.iface.Method attachMethod = new ImmutableMethod(
                classType,
                "attachBaseContext",
                Collections.singletonList(
                        new ImmutableMethodParameter(
                                "Landroid/content/Context;",
                                Collections.emptySet(),
                                null
                        )
                ),
                "V",
                AccessFlags.PROTECTED.getValue() | AccessFlags.NATIVE.getValue(),
                null,
                null,
                null
        );

        // ---------- native call 方法 ----------
        List<MethodParameter> commonParams = Arrays.asList(
                new ImmutableMethodParameter("I", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Collections.emptySet(), null),
                new ImmutableMethodParameter("[Ljava/lang/Object;", Collections.emptySet(), null)
        );

        int nativeFlags = AccessFlags.PUBLIC.getValue()
                | AccessFlags.STATIC.getValue()
                | AccessFlags.NATIVE.getValue();

        List<com.android.tools.smali.dexlib2.iface.Method> nativeMethods = Arrays.asList(
                new ImmutableMethod(classType, "callVoid",    commonParams, "V",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callBoolean", commonParams, "Z",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callByte",    commonParams, "B",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callShort",   commonParams, "S",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callChar",    commonParams, "C",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callInt",     commonParams, "I",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callLong",    commonParams, "J",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callFloat",   commonParams, "F",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callDouble",  commonParams, "D",                                    nativeFlags, null, null, null),
                new ImmutableMethod(classType, "callObject",  commonParams, "Ljava/lang/Object;",                   nativeFlags, null, null, null)
        );

        List<com.android.tools.smali.dexlib2.iface.Method> allMethods = new java.util.ArrayList<>();
        allMethods.add(clinitMethod);
        allMethods.add(initMethod);
        allMethods.add(attachMethod);
        allMethods.addAll(nativeMethods);

        return new ImmutableClassDef(
                classType,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                "VMP.java",
                null,
                Collections.emptyList(),
                allMethods
        );
    }
}
