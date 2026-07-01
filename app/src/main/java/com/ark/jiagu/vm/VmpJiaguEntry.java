package com.ark.jiagu.vm;

import static com.ark.jiagu.vm.VmpUtils.*;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.DexFile;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.DexFileFactory;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef;
import com.android.tools.smali.dexlib2.immutable.ImmutableDexFile;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation;
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodParameter;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction21c;
import com.android.tools.smali.dexlib2.immutable.instruction.ImmutableInstruction35c;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableMethodReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
public class VmpJiaguEntry {


    /**
     * :TODO
     * 解压 APK 中的 AndroidManifest.xml 和连续合法 dex 文件。
     * 合法 dex：
     * classes.dex
     * classes2.dex
     * classes3.dex
     * ...
     * 如果中间断号，例如没有 classes4.dex，则停止继续解压。
     */
    public static void extractManifestAndDex(File apkFile, File outDir) throws IOException {
        if (apkFile == null || !apkFile.isFile()) {
            throw new IOException("APK文件不存在");
        }

        if (outDir == null) {
            throw new IOException("输出目录为空");
        }

        if (!outDir.exists() && !outDir.mkdirs()) {
            throw new IOException("创建输出目录失败：" + outDir.getAbsolutePath());
        }

        try (ZipFile zipFile = new ZipFile(apkFile)) {
            VMPextractEntry(zipFile, "AndroidManifest.xml", new File(outDir, "AndroidManifest.xml"));

            int index = 1;
            while (true) {
                String dexName = index == 1 ? "classes.dex" : "classes" + index + ".dex";
                ZipEntry dexEntry = zipFile.getEntry(dexName);

                if (dexEntry == null) {
                    break;
                }

                VMPextractEntry(zipFile, dexName, new File(outDir, dexName));
                index++;
            }
        }
    }


    //----------------------------------------------------------------------------------------------------------






    private static void vmpLog(LogCallback callback, String msg) {
        if (callback != null) {
            callback.log(msg);
        } else {
            System.out.println(msg);
        }
    }
    public interface LogCallback {
        void log(String msg);
    }
    public static void extractMethodsToBin(File dexDir, String... methodRules) throws IOException {
        extractMethodsToBin(dexDir, null, methodRules);
    }

    /**
     * :TODO
     * 抽取方法到bin
     * */
    public static void extractMethodsToBin(File dexDir, LogCallback logCallback, String... methodRules) throws IOException {
        if (dexDir == null || !dexDir.isDirectory()) {
            throw new IOException("dex目录不存在");
        }

        EXTRACTED_METHOD_MAP.clear();

        List<MethodRule> rules = parseMethodRules(methodRules);
        if (rules.isEmpty()) {
            throw new IOException("抽取规则为空");
        }

        List<ExtractMethodBlock> blocks = new ArrayList<>();

        Map<Integer, OpcodeMapEntry> opcodeMap = new LinkedHashMap<>();
        List<Integer> opcodePool = buildRandomOpcodePool();
        int[] opcodePoolIndex = new int[]{0};

        int nextMethodId = 1;
        int dexIndex = 1;

        while (true) {
            String dexName = dexIndex == 1 ? "classes.dex" : "classes" + dexIndex + ".dex";
            File dexFile = new File(dexDir, dexName);

            if (!dexFile.isFile()) {
                System.out.println("dex编号断开，停止扫描：" + dexName);
                break;
            }

            if (!isValidDexFile(dexFile)) {
                vmpLog(logCallback, "跳过非法dex文件：" + dexFile.getAbsolutePath());
                break;
            }

            DexBackedDexFile dex;
            try {
                dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());
            } catch (Throwable e) {
                System.out.println("解析dex失败，停止扫描：" + dexFile.getName());
                System.out.println("失败原因：" + e.getMessage());
                break;
            }

            for (ClassDef classDef : dex.getClasses()) {
                String javaClassName = dexTypeToJavaName(classDef.getType());

                for (Method method : classDef.getMethods()) {
                    if (!matchAnyRule(rules, javaClassName, method.getName())) {
                        continue;
                    }

                    if (isForbiddenExtractMethod(method)) {
                        continue;
                    }

                    MethodImplementation impl = method.getImplementation();
                    if (impl == null) {
                        continue;
                    }

                    if (hasUnsupportedInvokeDynamicInstruction(impl)) {
                        continue;
                    }

                    ExtractMethodBlock block = new ExtractMethodBlock();

                    block.methodId = nextMethodId++;
                    block.dexName = dexFile.getName();
                    block.className = classDef.getType();
                    block.methodName = method.getName();
                    block.methodSignature = buildMethodSignature(method);
                    block.accessFlags = method.getAccessFlags();

                    // ==================== 寄存器别名（魔改#7） ====================
                    // 生成随机偏移量 (0~7)，加到所有寄存器索引上
                    // 使每次加固后的寄存器映射不同，增加动态分析难度
                    int aliasOffset = fakeRandom.nextInt(8);
                    block.registerAliasOffset = aliasOffset;
                    block.registerCount = impl.getRegisterCount() + aliasOffset;
                    // ====================================================

                    block.paramCount = method.getParameters().size();
                    block.returnType = method.getReturnType();
                    block.isStatic = (method.getAccessFlags() & AccessFlags.STATIC.getValue()) != 0;

                    block.parameterTypes = new ArrayList<>();
                    for (CharSequence paramType : method.getParameterTypes()) {
                        block.parameterTypes.add(String.valueOf(paramType));
                    }

                    int codeUnitOffset = 0;
                    Random fakeRandom = new Random(System.currentTimeMillis() ^ instruction.hashCode());

                    for (Instruction instruction : impl.getInstructions()) {
                        ExtractInstruction extracted = buildExtractInstruction(
                                instruction,
                                codeUnitOffset,
                                opcodeMap,
                                opcodePool,
                                opcodePoolIndex
                        );

                        // ==================== 寄存器别名（魔改#7） ====================
                        // 将所有寄存器索引加上随机偏移量
                        if (aliasOffset > 0) {
                            for (int i = 0; i < extracted.registers.size(); i++) {
                                extracted.registers.set(i, extracted.registers.get(i) + aliasOffset);
                            }
                        }
                        // ====================================================

                        block.instructions.add(extracted);

                        codeUnitOffset += instruction.getCodeUnits();

                        // ==================== 假指令插入（魔改#6） ====================
                        // 在每条真实指令后插入 0~2 条 NOP 假指令
                        // 假指令使用已分配的 vmOpcode，VM 执行时无害但增加分析难度
                        int fakeCount = fakeRandom.nextInt(3); // 0, 1, 或 2 条
                        for (int f = 0; f < fakeCount; f++) {
                            ExtractInstruction fakeInsn = new ExtractInstruction();
                            fakeInsn.codeUnitOffset = codeUnitOffset;
                            // 使用 NOP 的真实 opcode (0x00) 对应的 vmOpcode
                            fakeInsn.vmOpcode = getOrCreateVmOpcode(
                                    Opcode.NOP, opcodeMap, opcodePool, opcodePoolIndex
                            );
                            fakeInsn.formatName = "NOP(fake)";
                            fakeInsn.codeUnits = 1; // NOP 占 1 个 code unit
                            fakeInsn.literalType = 0;
                            fakeInsn.literalValue = 0;
                            fakeInsn.offsetType = 0;
                            fakeInsn.offsetValue = 0;
                            fakeInsn.referenceType = 0;
                            fakeInsn.referenceData = null;
                            fakeInsn.extraReferenceType = 0;
                            fakeInsn.extraReferenceData = null;
                            block.instructions.add(fakeInsn);
                            codeUnitOffset += 1;
                        }
                        // ====================================================
                    }

                    block.tryBlocks = buildExtractTryBlocks(impl);

                    blocks.add(block);
                    recordExtractedMethod(block);

                    vmpLog(logCallback, "已抽取 methodId=" + block.methodId
                            + " dex=" + block.dexName);
                }
            }

            dexIndex++;
        }

        File plainBinFile = new File(dexDir, "vmp_plain.bin");
        File binFile = new File(dexDir, "vmp.bin");
        File txtFile = new File(dexDir, "vmp.txt");

        List<ClassIndexEntry> indexEntries = writeVmpBinary(plainBinFile, opcodeMap, blocks);
        xorEncryptVmpBinFile(plainBinFile, binFile);
        writeVmpText(txtFile, opcodeMap, indexEntries, blocks);

        if (plainBinFile.exists()) {
            plainBinFile.delete();
        }

        vmpLog(logCallback, "抽取完成，总数量=" + blocks.size());
        vmpLog(logCallback, "opcode映射数量=" + opcodeMap.size());
        vmpLog(logCallback, "方法索引表数量=" + indexEntries.size());
    }

    /**
     * :TODO
     * 重组dex - 第二代嵌入式方案
     * 不再生成独立的壳 dex，而是：
     * 1. 将 VMP 类直接注入原始 dex 的第一个 dex 文件
     * 2. 被保护的方法体替换为 VMP.callXxx() 调用
     * 3. 不修改 AndroidManifest，不劫持 Application
     * */
    public static void rewriteExtractedMethodsToVmCallDex(File dexDir,
                                                          LogCallback logCallback,
                                                          String soName,
                                                          String vmpClassName) throws IOException {
        if (dexDir == null || !dexDir.isDirectory()) {
            throw new IOException("dex目录不存在");
        }

        if (EXTRACTED_METHOD_MAP.isEmpty()) {
            vmpLog(logCallback, "VMP未抽取到任何方法，跳过dex重写");
            return;
        }

        if (vmpClassName == null || vmpClassName.trim().isEmpty()) {
            throw new IOException("VMP类名为空");
        }

        String cleanSoName = soName != null ? soName.trim() : VmpUtils2.DEFAULT_SO_NAME;
        String cleanVmpClassName = vmpClassName.trim();

        vmpLog(logCallback, "第二代嵌入式方案：VMP类=" + cleanVmpClassName
                + " SO=" + cleanSoName);

        // 第一步：生成 VMP 类（带 <clinit> 自动加载 SO）
        com.android.tools.smali.dexlib2.iface.ClassDef vmpClass =
                com.ark.jiagu.vm.VmpUtils2.createVmpClassEmbedded(cleanSoName, cleanVmpClassName);

        // 第二步：重写每个 dex，注入 VMP 类（只注入一次到第一个 dex），替换方法体
        int dexIndex = 1;
        boolean vmpInjected = false;

        while (true) {
            String dexName = dexIndex == 1 ? "classes.dex" : "classes" + dexIndex + ".dex";
            File dexFile = new File(dexDir, dexName);

            if (!dexFile.isFile()) {
                System.out.println("dex编号断开，停止重写：" + dexName);
                break;
            }

            if (!isValidDexFile(dexFile)) {
                System.out.println("跳过非法dex文件：" + dexFile.getAbsolutePath());
                dexIndex++;
                continue;
            }

            DexBackedDexFile dex;
            try {
                dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault());
            } catch (Throwable e) {
                System.out.println("解析dex失败，停止重写：" + dexFile.getName() + " " + e.getMessage());
                vmpLog(logCallback, "解析dex失败：" + dexFile.getName());
                break;
            }

            List<com.android.tools.smali.dexlib2.iface.ClassDef> allClasses = new ArrayList<>();

            // 第一个 dex 注入 VMP 类
            if (!vmpInjected) {
                allClasses.add(vmpClass);
                vmpInjected = true;
                vmpLog(logCallback, "VMP 类已注入到：" + dexName);
            }

            for (ClassDef classDef : dex.getClasses()) {
                ClassDef newClass = rewriteClassForVmCall(dexName, classDef,
                        "L" + cleanVmpClassName.replace('.', '/') + ";");
                allClasses.add(newClass);
            }

            // 写出新的 dex
            File outDex = new File(dexDir, dexName + ".tmp");
            DexFile outDexFile = new ImmutableDexFile(
                    Opcodes.getDefault(),
                    allClasses
            );

            try {
                DexFileFactory.writeDexFile(outDex.getAbsolutePath(), outDexFile);
            } catch (Exception e) {
                throw new IOException("写出dex失败：" + dexName + " " + e.getMessage(), e);
            }

            // 替换原始 dex
            if (!dexFile.delete()) {
                throw new IOException("删除原始dex失败：" + dexFile.getAbsolutePath());
            }
            if (!outDex.renameTo(dexFile)) {
                throw new IOException("替换dex失败：" + outDex.getAbsolutePath());
            }

            int methodCount = 0;
            for (ClassDef cd : allClasses) {
                methodCount += countClassMethods(cd);
            }

            vmpLog(logCallback, "重写完成：" + dexName
                    + " classCount=" + allClasses.size()
                    + " methodCount=" + methodCount);

            allClasses.clear();
            dex = null;
            System.gc();

            dexIndex++;
        }

        vmpLog(logCallback, "第二代嵌入式 VMP 重写完成，VMP类=" + cleanVmpClassName);
        System.out.println("第二代嵌入式 VMP 重写完成");
    }

    /**
     * :TODO
     * 解析bin文件以校验读取是否正常
     * */
    public static void parseVmpBinByMethodId(File binFile, int targetMethodId) throws IOException {
        if (binFile == null || !binFile.isFile()) {
            throw new IOException("bin文件不存在");
        }

        long startNs = System.nanoTime();

        try (RandomAccessFile raf = new RandomAccessFile(binFile, "r")) {
            byte[] magic = new byte[4];
            readFully(raf, magic);

            String magicText = new String(magic, StandardCharsets.UTF_8);
            System.out.println("magic=" + magicText);

            if (!"AVMP".equals(magicText)) {
                throw new IOException("bin格式错误，magic不匹配");
            }

            int version = readIntLE(raf);
            System.out.println("version=" + version);

            if (version != 5) {
                throw new IOException("当前解析器只支持version=5，当前version=" + version);
            }

            // ==================== 读取 opcode 随机化密钥 ====================
            byte[] opcodeKey = new byte[16];
            int keyBytesRead = raf.read(opcodeKey);
            if (keyBytesRead != 16) {
                throw new IOException("读取opcode密钥失败，期望16字节，实际" + keyBytesRead + "字节");
            }

            // 辅助方法：用密钥解密 int
            java.util.function.IntUnaryOperator decrypt = (encrypted) -> {
                int result = encrypted;
                for (int i = 0; i < 4; i++) {
                    result ^= (opcodeKey[i] & 0xff);
                }
                return result;
            };
            // ====================================================

            int opcodeMapCount = readIntLE(raf);
            System.out.println("opcodeMapCount=" + opcodeMapCount);

            Map<Integer, OpcodeMapEntry> vmOpcodeMap = new LinkedHashMap<>();

            System.out.println("========== 解析opcode映射表 ==========");
            for (int i = 0; i < opcodeMapCount; i++) {
                int encryptedVmOpcode = readIntLE(raf);
                int encryptedRealOpcode = readIntLE(raf);
                String realOpcodeName = readStringLE(raf);

                // 用密钥解密 opcode 值
                int vmOpcode = decrypt.applyAsInt(encryptedVmOpcode);
                int realOpcode = decrypt.applyAsInt(encryptedRealOpcode);

                OpcodeMapEntry entry = new OpcodeMapEntry();
                entry.vmOpcode = vmOpcode;
                entry.realOpcode = realOpcode;
                entry.realOpcodeName = realOpcodeName;

                vmOpcodeMap.put(vmOpcode, entry);

                System.out.println("map[" + i + "] vmOpcode=0x"
                        + String.format("%02x", vmOpcode)
                        + " -> realOpcode=0x" + Integer.toHexString(realOpcode)
                        + " -> realOpcodeName=" + realOpcodeName);
            }

            int methodIndexCount = readIntLE(raf);
            long indexTableOffset = raf.getFilePointer();

            System.out.println("========== 解析methodId索引表 ==========");
            System.out.println("methodIndexCount=" + methodIndexCount);
            System.out.println("indexTableOffset=" + indexTableOffset);

            ClassIndexEntry targetIndex = null;

            for (int i = 0; i < methodIndexCount; i++) {
                ClassIndexEntry index = new ClassIndexEntry();
                index.methodId = readIntLE(raf);
                index.offset = readLongLE(raf);
                index.size = readIntLE(raf);

                System.out.println("index[" + i + "] methodId=" + index.methodId
                        + " offset=" + index.offset
                        + " size=" + index.size);

                if (index.methodId == targetMethodId) {
                    targetIndex = index;
                }
            }

            if (targetIndex == null) {
                long endNs = System.nanoTime();
                System.out.println("未找到目标methodId：" + targetMethodId);
                System.out.println("解析耗时=" + ((endNs - startNs) / 1000000.0) + " ms");
                return;
            }

            System.out.println("========================================");
            System.out.println("命中目标索引");
            System.out.println("targetMethodId=" + targetMethodId);
            System.out.println("blockOffset=" + targetIndex.offset);
            System.out.println("blockSize=" + targetIndex.size);
            System.out.println("开始seek到数据块地址：" + targetIndex.offset);

            raf.seek(targetIndex.offset);

            long blockStartPos = raf.getFilePointer();

            int methodId = readIntLE(raf);
            String dexName = readStringLE(raf);
            String className = readStringLE(raf);
            String methodName = readStringLE(raf);
            String methodSignature = readStringLE(raf);
            int accessFlags = readIntLE(raf);
            int registerCount = readIntLE(raf);
            int paramCount = readIntLE(raf);
            String returnType = readStringLE(raf);
            int isStaticValue = readIntLE(raf);

            int parameterTypeCount = readIntLE(raf);
            List<String> parameterTypes = new ArrayList<>();
            for (int i = 0; i < parameterTypeCount; i++) {
                parameterTypes.add(readStringLE(raf));
            }

            int instructionCount = readIntLE(raf);

            System.out.println("========================================");
            System.out.println("开始解析目标方法数据块");
            System.out.println("blockStartPos=" + blockStartPos);
            System.out.println("methodId=" + methodId);
            System.out.println("dexName=" + dexName);
            System.out.println("className=" + className);
            System.out.println("methodName=" + methodName);
            System.out.println("methodSignature=" + methodSignature);
            System.out.println("accessFlags=0x" + Integer.toHexString(accessFlags));
            System.out.println("registerCount=" + registerCount);
            System.out.println("paramCount=" + paramCount);
            System.out.println("returnType=" + returnType);
            System.out.println("isStatic=" + (isStaticValue != 0));
            System.out.println("parameterTypes=" + parameterTypes);
            System.out.println("instructionCount=" + instructionCount);

            for (int insnIndex = 0; insnIndex < instructionCount; insnIndex++) {
                long insnOffset = raf.getFilePointer();

                int codeUnitOffset = readIntLE(raf);

                // 读取加密的 vmOpcode 并用密钥解密
                int encryptedVmOpcode = readIntLE(raf);
                int vmOpcode = encryptedVmOpcode ^ (opcodeKey[8] & 0xff);

                String formatName = readStringLE(raf);
                int codeUnits = readIntLE(raf);

                int regCount = readIntLE(raf);
                List<Integer> registers = new ArrayList<>();
                for (int i = 0; i < regCount; i++) {
                    registers.add(readIntLE(raf));
                }

                int literalType = readIntLE(raf);
                long literalValue = readLongLE(raf);

                int offsetType = readIntLE(raf);
                int offsetValue = readIntLE(raf);

                int referenceType = readIntLE(raf);
                String referenceData = readStringLE(raf);
                int extraReferenceType = readIntLE(raf);
                String extraReferenceData = readStringLE(raf);
                OpcodeMapEntry opcodeEntry = vmOpcodeMap.get(vmOpcode);

                System.out.println();
                System.out.println("  instruction[" + insnIndex + "]");
                System.out.println("    insnOffset=" + insnOffset);
                System.out.println("    vmOpcode=0x" + String.format("%02x", vmOpcode));

                if (opcodeEntry != null) {
                    System.out.println("    mapRealOpcode=0x" + Integer.toHexString(opcodeEntry.realOpcode));
                    System.out.println("    mapRealOpcodeName=" + opcodeEntry.realOpcodeName);
                } else {
                    System.out.println("    mapRealOpcode=未找到");
                    System.out.println("    mapRealOpcodeName=未找到");
                }

                System.out.println("    codeUnitOffset=" + codeUnitOffset);
                System.out.println("    formatName=" + formatName);
                System.out.println("    codeUnits=" + codeUnits);
                System.out.println("    registerCount=" + regCount);
                System.out.println("    registers=" + registers);
                System.out.println("    literalType=" + literalType);
                System.out.println("    literalValue=" + literalValue);
                System.out.println("    offsetType=" + offsetType);
                System.out.println("    offsetValue=" + offsetValue);
                System.out.println("    referenceType=" + referenceType);
                System.out.println("    referenceData=" + referenceData);
                System.out.println("    extraReferenceType=" + extraReferenceType);
                System.out.println("    extraReferenceData=" + extraReferenceData);
            }

            int tryBlockCount = readIntLE(raf);

            System.out.println();
            System.out.println("tryBlockCount=" + tryBlockCount);

            for (int i = 0; i < tryBlockCount; i++) {
                int startCodeAddress = readIntLE(raf);
                int codeUnitCount = readIntLE(raf);
                int handlerCount = readIntLE(raf);

                System.out.println("  tryBlock[" + i + "]");
                System.out.println("    startCodeAddress=" + startCodeAddress);
                System.out.println("    codeUnitCount=" + codeUnitCount);
                System.out.println("    handlerCount=" + handlerCount);

                for (int h = 0; h < handlerCount; h++) {
                    String exceptionType = readStringLE(raf);
                    int handlerCodeAddress = readIntLE(raf);

                    System.out.println("      handler[" + h + "]");
                    System.out.println("        exceptionType=" + exceptionType);
                    System.out.println("        handlerCodeAddress=" + handlerCodeAddress);
                }
            }

            long blockEndPos = raf.getFilePointer();
            long parsedSize = blockEndPos - blockStartPos;

            System.out.println("========================================");
            System.out.println("目标methodId解析完成：" + targetMethodId);
            System.out.println("blockEndPos=" + blockEndPos);
            System.out.println("parsedBlockSize=" + parsedSize);
            System.out.println("indexBlockSize=" + targetIndex.size);

            if (parsedSize != targetIndex.size) {
                System.out.println("警告：解析出来的数据块大小和索引表记录不一致");
            }

            long endNs = System.nanoTime();
            System.out.println("解析耗时=" + ((endNs - startNs) / 1000000.0) + " ms");
        }
    }

}