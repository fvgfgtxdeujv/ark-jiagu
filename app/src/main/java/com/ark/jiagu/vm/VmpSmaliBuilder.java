package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.DexFileFactory;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.MethodParameter;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction10x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11n;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction11x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction22x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction23x;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction31i;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction3rc;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

class VmpSmaliBuilder {

    public static ClassDef createVmpClass(String soName, String packageName) {
        if (packageName == null || packageName.trim().isEmpty()) {
            throw new IllegalArgumentException("鍖呭悕涓嶈兘涓虹┖");
        }

        String cleanPackageName = packageName.trim();
        String classType = "L" + cleanPackageName.replace('.', '/') + "/VMP;";

        List<Method> methods = new ArrayList<>();

        // public VMP()
        MethodImplementation initImpl = new ImmutableMethodImplementation(
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

        methods.add(new ImmutableMethod(
                classType,
                "<init>",
                Collections.emptyList(),
                "V",
                AccessFlags.PUBLIC.getValue() | AccessFlags.CONSTRUCTOR.getValue(),
                null,
                null,
                initImpl
        ));

        List<MethodParameter> commonParams = Arrays.asList(
                new ImmutableMethodParameter("I", Collections.emptySet(), null),
                new ImmutableMethodParameter("Ljava/lang/Object;", Collections.emptySet(), null),
                new ImmutableMethodParameter("[Ljava/lang/Object;", Collections.emptySet(), null)
        );

        int nativeFlags = AccessFlags.PUBLIC.getValue()
                | AccessFlags.STATIC.getValue()
                | AccessFlags.NATIVE.getValue();

        methods.add(new ImmutableMethod(
                classType,
                "callVoid",
                commonParams,
                "V",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callBoolean",
                commonParams,
                "Z",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callByte",
                commonParams,
                "B",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callShort",
                commonParams,
                "S",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callChar",
                commonParams,
                "C",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callInt",
                commonParams,
                "I",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callLong",
                commonParams,
                "J",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callFloat",
                commonParams,
                "F",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callDouble",
                commonParams,
                "D",
                nativeFlags,
                null,
                null,
                null
        ));

        methods.add(new ImmutableMethod(
                classType,
                "callObject",
                commonParams,
                "Ljava/lang/Object;",
                nativeFlags,
                null,
                null,
                null
        ));

        return new ImmutableClassDef(
                classType,
                AccessFlags.PUBLIC.getValue(),
                "Ljava/lang/Object;",
                Collections.emptyList(),
                "VMP.java",
                null,
                Collections.emptyList(),
                methods
        );
    }

    static ClassDef rewriteClassForVmCall(String dexName, ClassDef classDef, String vmpClassType) {
        boolean isInterface = (classDef.getAccessFlags() & AccessFlags.INTERFACE.getValue()) != 0;

        if (isInterface) {
            return classDef;
        }

        List<Method> newMethods = new ArrayList<>();

        for (Method method : classDef.getMethods()) {
            String signature = buildMethodSignature(method);

            if (isForbiddenExtractMethod(method)) {
                newMethods.add(method);
                continue;
            }

            MethodImplementation impl = method.getImplementation();
            if (impl == null) {
                newMethods.add(method);
                continue;
            }

            ExtractedMethodInfo info = getExtractedMethodInfo(
                    dexName,
                    classDef.getType(),
                    method.getName(),
                    signature
            );

            if (info != null) {
                Method newMethod = buildVmCallMethod(method, info, vmpClassType);
                newMethods.add(newMethod);

                System.out.println("方法重写为VM调用壳："
                        + dexName
                        + " "
                        + classDef.getType()
                        + "->"
                        + method.getName()
                        + signature
                        + " methodId=" + info.methodId
                        + " returnType=" + method.getReturnType());
            } else {
                newMethods.add(method);
            }
        }

        return new ImmutableClassDef(
                classDef.getType(),
                classDef.getAccessFlags(),
                classDef.getSuperclass(),
                classDef.getInterfaces(),
                classDef.getSourceFile(),
                classDef.getAnnotations(),
                classDef.getFields(),
                newMethods
        );
    }
    private static Method buildVmCallMethod(Method oldMethod,
                                            ExtractedMethodInfo info,
                                            String vmpClassType) {
        List<Instruction> instructions = new ArrayList<>();

        String returnType = oldMethod.getReturnType();
        boolean isStatic = (oldMethod.getAccessFlags() & AccessFlags.STATIC.getValue()) != 0;
        System.out.println("生成VM调用壳 method="
                + oldMethod.getDefiningClass()
                + "->"
                + oldMethod.getName()
                + buildMethodSignature(oldMethod)
                + " isStatic=" + isStatic
                + " methodId=" + info.methodId);
        List<String> parameterTypes = new ArrayList<>();
        for (CharSequence type : oldMethod.getParameterTypes()) {
            parameterTypes.add(String.valueOf(type));
        }

        int localCount = 8;
        int paramRegisterCount = isStatic ? 0 : 1;

        for (String type : parameterTypes) {
            paramRegisterCount += getTypeRegisterCount(type);
        }

        int totalRegisterCount = localCount + paramRegisterCount;

        int regMethodId = 0;
        int regThis = 1;
        int regArgs = 2;
        int regIndex = 3;
        int regTempObj = 4;
        int regReturn = 4;

        int pBase = localCount;
        int thisRegister = isStatic ? -1 : pBase;
        int firstParamRegister = isStatic ? pBase : pBase + 1;

        instructions.add(new ImmutableInstruction31i(
                Opcode.CONST,
                regMethodId,
                info.methodId
        ));

        if (isStatic) {
            instructions.add(new ImmutableInstruction11n(
                    Opcode.CONST_4,
                    regThis,
                    0
            ));
        } else {
            instructions.add(new ImmutableInstruction22x(
                    Opcode.MOVE_OBJECT_FROM16,
                    regThis,
                    thisRegister
            ));
        }

        appendBuildArgsArrayInstructions(
                instructions,
                parameterTypes,
                firstParamRegister,
                regArgs,
                regIndex,
                regTempObj
        );

        appendCallAndReturnInstructions(
                instructions,
                returnType,
                vmpClassType,
                regMethodId,
                regThis,
                regArgs,
                regReturn
        );

        MethodImplementation impl = new ImmutableMethodImplementation(
                totalRegisterCount,
                instructions,
                null,
                null
        );

        int newAccessFlags = oldMethod.getAccessFlags();
        newAccessFlags &= ~AccessFlags.NATIVE.getValue();
        newAccessFlags &= ~AccessFlags.ABSTRACT.getValue();

        return new ImmutableMethod(
                oldMethod.getDefiningClass(),
                oldMethod.getName(),
                oldMethod.getParameters(),
                oldMethod.getReturnType(),
                newAccessFlags,
                oldMethod.getAnnotations(),
                null,
                impl
        );
    }
    private static void appendBuildArgsArrayInstructions(List<Instruction> instructions,
                                                         List<String> parameterTypes,
                                                         int firstParamRegister,
                                                         int regArgs,
                                                         int regIndex,
                                                         int regTempObj) {
        instructions.add(new ImmutableInstruction31i(
                Opcode.CONST,
                regIndex,
                parameterTypes.size()
        ));

        instructions.add(new ImmutableInstruction22c(
                Opcode.NEW_ARRAY,
                regArgs,
                regIndex,
                new ImmutableTypeReference("[Ljava/lang/Object;")
        ));

        int currentParamRegister = firstParamRegister;

        for (int i = 0; i < parameterTypes.size(); i++) {
            String type = parameterTypes.get(i);

            instructions.add(new ImmutableInstruction31i(
                    Opcode.CONST,
                    regIndex,
                    i
            ));

            if (isPrimitiveType(type)) {
                appendBoxPrimitiveInstruction(
                        instructions,
                        type,
                        currentParamRegister,
                        regTempObj
                );

                instructions.add(new ImmutableInstruction23x(
                        Opcode.APUT_OBJECT,
                        regTempObj,
                        regArgs,
                        regIndex
                ));
            } else {
                instructions.add(new ImmutableInstruction23x(
                        Opcode.APUT_OBJECT,
                        currentParamRegister,
                        regArgs,
                        regIndex
                ));
            }

            currentParamRegister += getTypeRegisterCount(type);
        }
    }
    private static void appendBoxPrimitiveInstruction(List<Instruction> instructions,
                                                      String type,
                                                      int paramRegister,
                                                      int regTempObj) {
        String owner;
        String methodName = "valueOf";
        List<String> params;
        String ret;

        if ("Z".equals(type)) {
            owner = "Ljava/lang/Boolean;";
            params = Collections.singletonList("Z");
            ret = "Ljava/lang/Boolean;";
        } else if ("B".equals(type)) {
            owner = "Ljava/lang/Byte;";
            params = Collections.singletonList("B");
            ret = "Ljava/lang/Byte;";
        } else if ("S".equals(type)) {
            owner = "Ljava/lang/Short;";
            params = Collections.singletonList("S");
            ret = "Ljava/lang/Short;";
        } else if ("C".equals(type)) {
            owner = "Ljava/lang/Character;";
            params = Collections.singletonList("C");
            ret = "Ljava/lang/Character;";
        } else if ("I".equals(type)) {
            owner = "Ljava/lang/Integer;";
            params = Collections.singletonList("I");
            ret = "Ljava/lang/Integer;";
        } else if ("J".equals(type)) {
            owner = "Ljava/lang/Long;";
            params = Collections.singletonList("J");
            ret = "Ljava/lang/Long;";
        } else if ("F".equals(type)) {
            owner = "Ljava/lang/Float;";
            params = Collections.singletonList("F");
            ret = "Ljava/lang/Float;";
        } else if ("D".equals(type)) {
            owner = "Ljava/lang/Double;";
            params = Collections.singletonList("D");
            ret = "Ljava/lang/Double;";
        } else {
            throw new IllegalArgumentException("包名不能为空");
        }

        if ("J".equals(type) || "D".equals(type)) {
            instructions.add(new ImmutableInstruction3rc(
                    Opcode.INVOKE_STATIC_RANGE,
                    paramRegister,
                    2,
                    new ImmutableMethodReference(
                            owner,
                            methodName,
                            params,
                            ret
                    )
            ));
        } else {
            instructions.add(new ImmutableInstruction3rc(
                    Opcode.INVOKE_STATIC_RANGE,
                    paramRegister,
                    1,
                    new ImmutableMethodReference(
                            owner,
                            methodName,
                            params,
                            ret
                    )
            ));
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.MOVE_RESULT_OBJECT,
                regTempObj
        ));
    }
    private static void appendCallAndReturnInstructions(List<Instruction> instructions,
                                                        String returnType,
                                                        String vmpClassType,
                                                        int regMethodId,
                                                        int regThis,
                                                        int regArgs,
                                                        int regReturn) {
        String callMethodName = getCallMethodNameByReturnType(returnType);
        String callReturnType = getCallReturnType(returnType);

        // ==================== 调试模式检测：Java 端获取 FLAG_DEBUGGABLE ====================
        // 璋冪敤 VMP.isDebuggable()锛岀粨鏋滃瓨鍒?regIndex (v3)
        // isDebuggable() 内部通过 ActivityThread 获取 Application 并检查 FLAG_DEBUGGABLE
        instructions.add(new ImmutableInstruction35c(
                Opcode.INVOKE_STATIC,
                3,
                0,
                0,
                0,
                0,
                0,
                new ImmutableMethodReference(
                        vmpClassType,
                        "isDebuggable",
                        Collections.emptyList(),
                        "Z"
                )
        ));
        instructions.add(new ImmutableInstruction11x(Opcode.MOVE_RESULT, 3));
        // ====================================================

        instructions.add(new ImmutableInstruction3rc(
                Opcode.INVOKE_STATIC_RANGE,
                regMethodId,
                4, // 4 涓弬鏁帮細methodId, this, args, isDebuggable
                new ImmutableMethodReference(
                        vmpClassType,
                        callMethodName,
                        Arrays.asList(
                                "I",
                                "Ljava/lang/Object;",
                                "[Ljava/lang/Object;",
                                "Z"  // isDebuggable
                        ),
                        callReturnType
                )
        ));

        if ("V".equals(returnType)) {
            instructions.add(new ImmutableInstruction10x(Opcode.RETURN_VOID));
            return;
        }

        if ("J".equals(returnType) || "D".equals(returnType)) {
            instructions.add(new ImmutableInstruction11x(
                    Opcode.MOVE_RESULT_WIDE,
                    regReturn
            ));

            instructions.add(new ImmutableInstruction11x(
                    Opcode.RETURN_WIDE,
                    regReturn
            ));
            return;
        }

        if (isPrimitiveType(returnType)) {
            instructions.add(new ImmutableInstruction11x(
                    Opcode.MOVE_RESULT,
                    regReturn
            ));

            instructions.add(new ImmutableInstruction11x(
                    Opcode.RETURN,
                    regReturn
            ));
            return;
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.MOVE_RESULT_OBJECT,
                regReturn
        ));

        if (!"Ljava/lang/Object;".equals(returnType)) {
            instructions.add(new ImmutableInstruction21c(
                    Opcode.CHECK_CAST,
                    regReturn,
                    new ImmutableTypeReference(returnType)
            ));
        }

        instructions.add(new ImmutableInstruction11x(
                Opcode.RETURN_OBJECT,
                regReturn
        ));
    }
    private static String getCallMethodNameByReturnType(String returnType) {
        if ("V".equals(returnType)) {
            return "callVoid";
        }

        if ("Z".equals(returnType)) {
            return "callBoolean";
        }

        if ("B".equals(returnType)) {
            return "callByte";
        }

        if ("S".equals(returnType)) {
            return "callShort";
        }

        if ("C".equals(returnType)) {
            return "callChar";
        }

        if ("I".equals(returnType)) {
            return "callInt";
        }

        if ("J".equals(returnType)) {
            return "callLong";
        }

        if ("F".equals(returnType)) {
            return "callFloat";
        }

        if ("D".equals(returnType)) {
            return "callDouble";
        }

        return "callObject";
    }

    private static String getCallReturnType(String returnType) {
        if ("V".equals(returnType)) {
            return "V";
        }

        if (isPrimitiveType(returnType)) {
            return returnType;
        }

        return "Ljava/lang/Object;";
    }
    private static int getTypeRegisterCount(String type) {
        if ("J".equals(type) || "D".equals(type)) {
            return 2;
        }

        return 1;
    }
    private static boolean isPrimitiveType(String type) {
        return "Z".equals(type)
                || "B".equals(type)
                || "S".equals(type)
                || "C".equals(type)
                || "I".equals(type)
                || "J".equals(type)
                || "F".equals(type)
                || "D".equals(type);
    }
    static void writeCombinedDex(File dexDir,
                                 int outDexIndex,
                                 List<ClassDef> classes) throws IOException {
        String outName = outDexIndex == 1 ? "classes_c.dex" : "classes" + outDexIndex + "_c.dex";
        File outFile = new File(dexDir, outName);

        DexFile outDex = new ImmutableDexFile(
                Opcodes.getDefault(),
                classes
        );

        DexFileFactory.writeDexFile(outFile.getAbsolutePath(), outDex);

        System.out.println("输出重写dex：" + outFile.getAbsolutePath()
                + " classCount=" + classes.size());
    }
    static int countClassMethods(ClassDef classDef) {
        int count = 0;
        for (Method ignored : classDef.getMethods()) {
            count++;
        }
        return count;
    }

    static void replaceOriginalDexWithCombinedDex(File dexDir) throws IOException {
        if (dexDir == null || !dexDir.isDirectory()) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        // 1. 删除原始 dex：classes.dex、classes2.dex、classes3.dex...
        int oldIndex = 1;
        while (true) {
            String oldName = oldIndex == 1 ? "classes.dex" : "classes" + oldIndex + ".dex";
            File oldDex = new File(dexDir, oldName);

            if (!oldDex.exists()) {
                break;
            }

            if (!oldDex.delete()) {
                throw new IOException("删除原始dex失败： + oldDex.getAbsolutePath());
            }

            System.out.println("宸插垹闄ゅ師濮媎ex锛? + oldDex.getName());
            oldIndex++;
        }

import com.android.tools.smali.dexlib2.AccessFlags;
        int newIndex = 1;
        while (true) {
            String tempName = newIndex == 1 ? "classes_c.dex" : "classes" + newIndex + "_c.dex";
            File tempDex = new File(dexDir, tempName);

            if (!tempDex.exists()) {
                break;
            }

            String finalName = newIndex == 1 ? "classes.dex" : "classes" + newIndex + ".dex";
            File finalDex = new File(dexDir, finalName);

            if (!tempDex.renameTo(finalDex)) {
                throw new IOException("重命名dex失败：
                        + tempDex.getAbsolutePath()
                        + " -> "
                        + finalDex.getAbsolutePath());
            }

            System.out.println("宸查噸鍛藉悕dex锛? + tempDex.getName() + " -> " + finalDex.getName());
            newIndex++;
        }

        if (newIndex == 1) {
            throw new IOException("未找到新生成的 *_c.dex 文件");
        }
    }

    public static DexFile createVmpShellDex(String soName, String packageName) {
        ClassDef vmpClass = createVmpClass(soName, packageName);

        List<ClassDef> classes = new ArrayList<>();
        classes.add(vmpClass);

        return new ImmutableDexFile(
                Opcodes.getDefault(),
                classes
        );
    }
}
