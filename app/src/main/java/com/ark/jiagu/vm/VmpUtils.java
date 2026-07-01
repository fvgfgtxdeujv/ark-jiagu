package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.AccessFlags;
import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.iface.ClassDef;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodReference;
import com.android.tools.smali.dexlib2.iface.Reference;
import com.android.tools.smali.dexlib2.iface.reference.MethodProtoReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodHandleReference;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
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
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableStringReference;
import com.android.tools.smali.dexlib2.immutable.reference.ImmutableTypeReference;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * VMP 加固工具类（第二代嵌入式方案）
 *
 * <p>本类已拆分为多个职责单一的模块：
 * <ul>
 *   <li>{@link VmpMethodMatcher} - 方法规则解析与匹配</li>
 *   <li>{@link VmpMethodFilter} - 方法过滤</li>
 *   <li>{@link VmpOpcodeMap} - Opcode 映射池</li>
 *   <li>{@link VmpDexReader} - DEX 读取与类型工具</li>
 *   <li>{@link VmpInstructionExtractor} - 指令提取</li>
 *   <li>{@link VmpReferenceSerializer} - 引用序列化</li>
 *   <li>{@link VmpMethodTracker} - 方法记录/查找</li>
 *   <li>{@link VmpBinFormat} - vmp.bin 写入</li>
 *   <li>{@link VmpBinFormat} - 二进制写入 + 加密工具</li>
 *   <li>{@link VmpSmaliBuilder} - VMP 类生成 + DEX 重写</li>
 *   <li>{@link VmpTextWriter} - 调试文本输出</li>
 * </ul>
 *
 * <p>本类保留为薄 Facade，所有方法委托给对应模块。
 * VmpJiaguEntry 通过 {@code import static VmpUtils.*} 调用，保持向后兼容。
 */
public class VmpUtils {

    // ==================== 静态字段 ====================
    static final Map<String, ExtractedMethodInfo> EXTRACTED_METHOD_MAP = new LinkedHashMap<>();

    // ==================== 内部数据类（VmpJiaguEntry 直接使用） ====================

    static class MethodRule {
        String raw;
        String packageName;
        String className;
        String methodName;
    }

    static class ExtractMethodBlock {
        int methodId;
        String dexName;
        String className;
        String methodName;
        String methodSignature;
        int accessFlags;
        int registerCount;
        int paramCount;
        String returnType;

        boolean isStatic;
        List<String> parameterTypes = new ArrayList<>();

        List<ExtractInstruction> instructions = new ArrayList<>();
        List<ExtractTryBlock> tryBlocks = new ArrayList<>();
    }

    static class OpcodeMapEntry {
        int vmOpcode;
        int realOpcode;
        String realOpcodeName;
    }

    static class ExtractInstruction {
        int codeUnitOffset;
        int vmOpcode;

        String formatName;
        int codeUnits;

        List<Integer> registers = new ArrayList<>();

        int literalType = 0;
        long literalValue = 0;

        int offsetType = 0;
        int offsetValue = 0;

        int referenceType = 0;
        String referenceData = null;

        int extraReferenceType = 0;
        String extraReferenceData = null;
    }

    static class ClassIndexEntry {
        int methodId;
        long offset;        // 方法块数据偏移（元数据 + 碎片指令）
        int size;           // 方法块大小
        int writeOrder;     // 写入顺序（打乱存储用）
        List<Long> fragmentOffsets; // 后续碎片偏移列表（指令分片用）
    }

    static class ExtractTryBlock {
        int startCodeAddress;
        int codeUnitCount;
        List<ExtractExceptionHandler> handlers = new ArrayList<>();
    }

    static class ExtractExceptionHandler {
        String exceptionType;
        int handlerCodeAddress;
    }

    // ==================== 公共 API（Facade 委托） ====================

    // --- DEX 读取与验证 ---
    static void VMPextractEntry(ZipFile zipFile, String entryName, File outFile) throws IOException {
        VmpDexReader.VMPextractEntry(zipFile, entryName, outFile);
    }

    static String buildMethodSignature(Method method) {
        return VmpDexReader.buildMethodSignature(method);
    }

    static String buildMethodReferenceSignature(MethodReference methodRef) {
        return VmpDexReader.buildMethodReferenceSignature(methodRef);
    }

    static String dexTypeToJavaName(String dexType) {
        return VmpDexReader.dexTypeToJavaName(dexType);
    }

    static boolean isValidDexFile(File file) {
        return VmpDexReader.isValidDexFile(file);
    }

    static byte[] readAllBytes(File file) throws IOException {
        return VmpDexReader.readAllBytes(file);
    }

    static void writeIntLE(FileOutputStream out, int value) throws IOException {
        VmpDexReader.writeIntLE(out, value);
    }

    static int readIntLE(RandomAccessFile in) throws IOException {
        return VmpDexReader.readIntLE(in);
    }

    static long readLongLE(RandomAccessFile in) throws IOException {
        return VmpDexReader.readLongLE(in);
    }

    static String readStringLE(RandomAccessFile in) throws IOException {
        return VmpDexReader.readStringLE(in);
    }

    static void readFully(RandomAccessFile in, byte[] data) throws IOException {
        VmpDexReader.readFully(in, data);
    }

    // --- 方法规则匹配 ---
    static List<MethodRule> parseMethodRules(String... methodRules) {
        return VmpMethodMatcher.parseMethodRules(methodRules);
    }

    static boolean matchAnyRule(List<MethodRule> rules, String javaClassName, String methodName) {
        return VmpMethodMatcher.matchAnyRule(rules, javaClassName, methodName);
    }

    static boolean matchRule(MethodRule rule, String javaClassName, String methodName) {
        return VmpMethodMatcher.matchRule(rule, javaClassName, methodName);
    }

    static boolean matchPart(String rulePart, String value) {
        return VmpMethodMatcher.matchPart(rulePart, value);
    }

    // --- 方法过滤 ---
    static boolean isForbiddenExtractMethod(Method method) {
        return VmpMethodFilter.isForbiddenExtractMethod(method);
    }

    static boolean hasUnsupportedInvokeDynamicInstruction(MethodImplementation impl) {
        return VmpMethodFilter.hasUnsupportedInvokeDynamicInstruction(impl);
    }

    // --- Opcode 映射 ---
    static List<Integer> buildRandomOpcodePool() {
        return VmpOpcodeMap.buildRandomOpcodePool();
    }

    static int getOrCreateVmOpcode(Opcode opcode,
                                   Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap,
                                   List<Integer> opcodePool,
                                   int[] opcodePoolIndex) {
        return VmpOpcodeMap.getOrCreateVmOpcode(opcode, opcodeMap, opcodePool, opcodePoolIndex);
    }

    // --- 指令提取 ---
    static ExtractInstruction buildExtractInstruction(Instruction instruction,
                                                      int codeUnitOffset,
                                                      Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap,
                                                      List<Integer> opcodePool,
                                                      int[] opcodePoolIndex) {
        return VmpInstructionExtractor.buildExtractInstruction(
                instruction, codeUnitOffset, opcodeMap, opcodePool, opcodePoolIndex);
    }

    static List<ExtractTryBlock> buildExtractTryBlocks(MethodImplementation impl) {
        return VmpInstructionExtractor.buildExtractTryBlocks(impl);
    }

    // --- vmp.bin 写入 ---
    static List<ClassIndexEntry> writeVmpBinary(File outFile,
                                                Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap,
                                                List<ExtractMethodBlock> blocks) throws IOException {
        return VmpBinFormat.writeVmpBinary(outFile, opcodeMap, blocks);
    }

    static void xorEncryptVmpBinFile(File plainFile, File encryptedFile) throws IOException {
        VmpBinFormat.xorEncryptVmpBinFile(plainFile, encryptedFile);
    }

    // --- 加密 ---
    static byte[] multiLayerEncrypt(byte[] data, byte[] xorKey) throws Exception {
        return VmpBinFormat.multiLayerEncrypt(data, xorKey);
    }

    static int generateBlockKey(int methodId) {
        return VmpBinFormat.generateBlockKey(methodId);
    }

    static byte[] computeBlockChainHash(ExtractMethodBlock block, long blockOffset, long dataLen) {
        return VmpBinFormat.computeBlockChainHash(block, blockOffset, dataLen);
    }

    static long rotateLong(long value, int seed) {
        return VmpBinFormat.rotateLong(value, seed);
    }

    static int rotateInt(int value, int seed) {
        return VmpBinFormat.rotateInt(value, seed);
    }

    // --- 二进制写入辅助 ---
    static void writeStringLE(RandomAccessFile out, String value) throws IOException {
        VmpBinFormat.writeStringLE(out, value);
    }

    static void writeIntLE(RandomAccessFile out, int value) throws IOException {
        VmpBinFormat.writeIntLE(out, value);
    }

    static void writeLongLE(RandomAccessFile out, long value) throws IOException {
        VmpBinFormat.writeLongLE(out, value);
    }

    static void writeBytes(RandomAccessFile out, byte[] data) throws IOException {
        VmpBinFormat.writeBytes(out, data);
    }

    static int xorByte(byte[] key, int index) {
        return VmpBinFormat.xorByte(key, index);
    }

    static int[] generatePermutation(int size) {
        return VmpBinFormat.generatePermutation(size);
    }

    static long estimateBlockSize(ExtractMethodBlock block) {
        return VmpBinFormat.estimateBlockSize(block);
    }

    static void writeVarInt(RandomAccessFile out, int value) throws IOException {
        VmpBinFormat.writeVarInt(out, value);
    }

    static void writeInstructionsEncrypted(RandomAccessFile raf,
                                           List<ExtractInstruction> instructions,
                                           byte[] blockKey,
                                           Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap) throws IOException {
        VmpBinFormat.writeInstructionsEncrypted(raf, instructions, blockKey, opcodeMap);
    }

    static void writeVarLong(RandomAccessFile out, long value) throws IOException {
        VmpBinFormat.writeVarLong(out, value);
    }

    static void writeSingleInstructionEncrypted(RandomAccessFile raf,
                                                ExtractInstruction insn,
                                                byte[] blockKey,
                                                Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap) throws IOException {
        VmpBinFormat.writeSingleInstructionEncrypted(raf, insn, blockKey, opcodeMap);
    }

    // --- 方法追踪 ---
    static String buildExtractedMethodKey(String dexName, String className,
                                          String methodName, String methodSignature) {
        return VmpMethodTracker.buildExtractedMethodKey(dexName, className, methodName, methodSignature);
    }

    static void recordExtractedMethod(ExtractMethodBlock block) {
        VmpMethodTracker.recordExtractedMethod(block);
    }

    static ExtractedMethodInfo getExtractedMethodInfo(String dexName, String className,
                                                      String methodName, String methodSignature) {
        return VmpMethodTracker.getExtractedMethodInfo(dexName, className, methodName, methodSignature);
    }

    // --- VMP 类生成 ---
    public static ClassDef createVmpClass(String soName, String packageName) {
        return VmpSmaliBuilder.createVmpClass(soName, packageName);
    }

    public static DexFile createVmpShellDex(String soName, String packageName) {
        return VmpSmaliBuilder.createVmpShellDex(soName, packageName);
    }

    static ClassDef rewriteClassForVmCall(String dexName, ClassDef classDef, String vmpClassType) {
        return VmpSmaliBuilder.rewriteClassForVmCall(dexName, classDef, vmpClassType);
    }

    // --- DEX 文件操作 ---
    static void writeCombinedDex(File dexDir, int outDexIndex, List<ClassDef> classes) throws IOException {
        VmpSmaliBuilder.writeCombinedDex(dexDir, outDexIndex, classes);
    }

    static int countClassMethods(ClassDef classDef) {
        return VmpSmaliBuilder.countClassMethods(classDef);
    }

    static void replaceOriginalDexWithCombinedDex(File dexDir) throws IOException {
        VmpSmaliBuilder.replaceOriginalDexWithCombinedDex(dexDir);
    }

    // --- 引用序列化 ---
    static String buildMethodProtoSignature(MethodProtoReference protoRef) {
        return VmpReferenceSerializer.buildMethodProtoSignature(protoRef);
    }

    static String buildReferenceText(Reference reference) {
        return VmpReferenceSerializer.buildReferenceText(reference);
    }

    static int getReferenceTypeCode(Reference reference) {
        return VmpReferenceSerializer.getReferenceTypeCode(reference);
    }

    static String vmpEscape(String s) {
        return VmpReferenceSerializer.vmpEscape(s);
    }

    static String buildMethodHandleText(MethodHandleReference handle) {
        return VmpReferenceSerializer.buildMethodHandleText(handle);
    }

    static String buildEncodedValueText(EncodedValue value) {
        return VmpReferenceSerializer.buildEncodedValueText(value);
    }

    // --- 调试输出 ---
    static void writeVmpText(File outFile,
                             Map<Integer, OpcodeMapEntry> opcodeMap,
                             List<ClassIndexEntry> indexEntries,
                             List<ExtractMethodBlock> blocks) {
        VmpTextWriter.writeVmpText(outFile, opcodeMap, indexEntries, blocks);
    }
}
