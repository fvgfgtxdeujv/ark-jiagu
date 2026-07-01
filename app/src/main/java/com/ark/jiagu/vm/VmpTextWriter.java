package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

class VmpTextWriter {

    static void writeVmpText(File outFile,
                             Map<Integer, OpcodeMapEntry> opcodeMap,
                             List<ClassIndexEntry> indexEntries,
                             List<ExtractMethodBlock> blocks) throws IOException {
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(outFile), StandardCharsets.UTF_8))) {

            pw.println("magic=AVMP");
            pw.println("version=5");
            pw.println();

            pw.println("========== 自定义opcode映射表 ==========");
            pw.println("opcodeMapCount=" + opcodeMap.size());
            for (OpcodeMapEntry entry : opcodeMap.values()) {
                pw.println("vmOpcode=0x" + String.format("%02x", entry.vmOpcode)
                        + " -> realOpcode=0x" + Integer.toHexString(entry.realOpcode)
                        + " -> realOpcodeName=" + entry.realOpcodeName);
            }

            pw.println();
            pw.println("========== methodId索引表 ==========");
            pw.println("methodIndexCount=" + indexEntries.size());
            for (ClassIndexEntry index : indexEntries) {
                pw.println("methodId=" + index.methodId
                        + " offset=" + index.offset
                        + " size=" + index.size);
            }

            pw.println();
            pw.println("========== 方法数据块 ==========");
            pw.println("methodBlockCount=" + blocks.size());
            pw.println();

            for (ExtractMethodBlock block : blocks) {
                pw.println("========================================");
                pw.println("methodId=" + block.methodId);
                pw.println("dexName=" + block.dexName);
                pw.println("className=" + block.className);
                pw.println("methodName=" + block.methodName);
                pw.println("methodSignature=" + block.methodSignature);
                pw.println("accessFlags=0x" + Integer.toHexString(block.accessFlags));
                pw.println("registerCount=" + block.registerCount);
                pw.println("paramCount=" + block.paramCount);
                pw.println("returnType=" + block.returnType);
                pw.println("isStatic=" + block.isStatic);
                pw.println("parameterTypes=" + block.parameterTypes);
                pw.println("instructionCount=" + block.instructions.size());

                int index = 0;
                for (ExtractInstruction insn : block.instructions) {
                    pw.println();
                    pw.println("  instruction[" + index + "]");
                    pw.println("    codeUnitOffset=" + insn.codeUnitOffset);
                    pw.println("    vmOpcode=0x" + String.format("%02x", insn.vmOpcode));
                    pw.println("    formatName=" + insn.formatName);
                    pw.println("    codeUnits=" + insn.codeUnits);
                    pw.println("    registers=" + insn.registers);
                    pw.println("    literalType=" + insn.literalType);
                    pw.println("    literalValue=" + insn.literalValue);
                    pw.println("    offsetType=" + insn.offsetType);
                    pw.println("    offsetValue=" + insn.offsetValue);
                    pw.println("    referenceType=" + insn.referenceType);
                    pw.println("    referenceData=" + insn.referenceData);
                    pw.println("    extraReferenceType=" + insn.extraReferenceType);
                    pw.println("    extraReferenceData=" + insn.extraReferenceData);
                    index++;
                }

                pw.println();
                pw.println("tryBlockCount=" + block.tryBlocks.size());

                for (int i = 0; i < block.tryBlocks.size(); i++) {
                    ExtractTryBlock tryBlock = block.tryBlocks.get(i);

                    pw.println("  tryBlock[" + i + "]");
                    pw.println("    startCodeAddress=" + tryBlock.startCodeAddress);
                    pw.println("    codeUnitCount=" + tryBlock.codeUnitCount);
                    pw.println("    handlerCount=" + tryBlock.handlers.size());

                    for (int h = 0; h < tryBlock.handlers.size(); h++) {
                        ExtractExceptionHandler handler = tryBlock.handlers.get(h);

                        pw.println("      handler[" + h + "]");
                        pw.println("        exceptionType=" + handler.exceptionType);
                        pw.println("        handlerCodeAddress=" + handler.handlerCodeAddress);
                    }
                }

                pw.println();
            }
        }
    }
}
