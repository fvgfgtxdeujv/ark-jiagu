package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.instruction.NarrowLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.SwitchElement;
import com.android.tools.smali.dexlib2.iface.instruction.ThreeRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.TwoRegisterInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.WideLiteralInstruction;
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload;
import com.android.tools.smali.dexlib2.iface.instruction.formats.PackedSwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.formats.SparseSwitchPayload;
import com.android.tools.smali.dexlib2.iface.instruction.DualReferenceInstruction;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.ExceptionHandler;
import com.android.tools.smali.dexlib2.iface.TryBlock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

class VmpInstructionExtractor {

    static ExtractInstruction buildExtractInstruction(Instruction instruction,
                                                      int codeUnitOffset,
                                                      Map<Integer, VmpOpcodeMap.OpcodeMapEntry> opcodeMap,
                                                      List<Integer> opcodePool,
                                                      int[] opcodePoolIndex) {
        ExtractInstruction out = new ExtractInstruction();

        out.codeUnitOffset = codeUnitOffset;
        if (instruction instanceof ArrayPayload) {
            ArrayPayload payload = (ArrayPayload) instruction;

            out.vmOpcode = VmpOpcodeMap.getOrCreateVmOpcode(
                    Opcode.NOP,
                    opcodeMap,
                    opcodePool,
                    opcodePoolIndex
            );

            out.formatName = "ArrayPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 100;
            out.literalValue = payload.getElementWidth();

            out.offsetType = 100;
            out.offsetValue = payload.getArrayElements().size();

            out.referenceType = 100;

            StringBuilder sb = new StringBuilder();
            List<Number> elements = payload.getArrayElements();

            for (int i = 0; i < elements.size(); i++) {
                if (i > 0) {
                    sb.append(",");
                }
                sb.append(elements.get(i).longValue());
            }

            out.referenceData = sb.toString();

            return out;
        }
        if (instruction instanceof PackedSwitchPayload) {
            PackedSwitchPayload payload = (PackedSwitchPayload) instruction;

            out.vmOpcode = VmpOpcodeMap.getOrCreateVmOpcode(
                    Opcode.NOP,
                    opcodeMap,
                    opcodePool,
                    opcodePoolIndex
            );

            out.formatName = "PackedSwitchPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 101;
            out.literalValue = 0;

            out.offsetType = 101;
            out.offsetValue = payload.getSwitchElements().size();

            out.referenceType = 101;

            StringBuilder sb = new StringBuilder();
            List<? extends SwitchElement> elements = payload.getSwitchElements();

            for (int i = 0; i < elements.size(); i++) {
                SwitchElement element = elements.get(i);

                if (i > 0) {
                    sb.append(",");
                }

                sb.append(element.getKey());
                sb.append(":");
                sb.append(element.getOffset());
            }

            out.referenceData = sb.toString();

            return out;
        }

        if (instruction instanceof SparseSwitchPayload) {
            SparseSwitchPayload payload = (SparseSwitchPayload) instruction;

            out.vmOpcode = VmpUtils.getOrCreateVmOpcode(
                    Opcode.NOP,
                    opcodeMap,
                    opcodePool,
                    opcodePoolIndex
            );

            out.formatName = "SparseSwitchPayload";
            out.codeUnits = instruction.getCodeUnits();

            out.literalType = 102;
            out.literalValue = 0;

            out.offsetType = 102;
            out.offsetValue = payload.getSwitchElements().size();

            out.referenceType = 102;

            StringBuilder sb = new StringBuilder();
            List<? extends SwitchElement> elements = payload.getSwitchElements();

            for (int i = 0; i < elements.size(); i++) {
                SwitchElement element = elements.get(i);

                if (i > 0) {
                    sb.append(",");
                }

                sb.append(element.getKey());
                sb.append(":");
                sb.append(element.getOffset());
            }

            out.referenceData = sb.toString();

            return out;
        }





        out.vmOpcode = VmpOpcodeMap.getOrCreateVmOpcode(
                instruction.getOpcode(),
                opcodeMap,
                opcodePool,
                opcodePoolIndex
        );

        out.formatName = String.valueOf(instruction.getOpcode().format);
        out.codeUnits = instruction.getCodeUnits();

        if (instruction instanceof FiveRegisterInstruction) {
            FiveRegisterInstruction insn = (FiveRegisterInstruction) instruction;
            int count = insn.getRegisterCount();
            if (count >= 1) out.registers.add(insn.getRegisterC());
            if (count >= 2) out.registers.add(insn.getRegisterD());
            if (count >= 3) out.registers.add(insn.getRegisterE());
            if (count >= 4) out.registers.add(insn.getRegisterF());
            if (count >= 5) out.registers.add(insn.getRegisterG());
        } else if (instruction instanceof RegisterRangeInstruction) {
            RegisterRangeInstruction insn = (RegisterRangeInstruction) instruction;
            for (int i = 0; i < insn.getRegisterCount(); i++) {
                out.registers.add(insn.getStartRegister() + i);
            }
        } else if (instruction instanceof ThreeRegisterInstruction) {
            ThreeRegisterInstruction insn = (ThreeRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
            out.registers.add(insn.getRegisterB());
            out.registers.add(insn.getRegisterC());
        } else if (instruction instanceof TwoRegisterInstruction) {
            TwoRegisterInstruction insn = (TwoRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
            out.registers.add(insn.getRegisterB());
        } else if (instruction instanceof OneRegisterInstruction) {
            OneRegisterInstruction insn = (OneRegisterInstruction) instruction;
            out.registers.add(insn.getRegisterA());
        }

        if (instruction instanceof WideLiteralInstruction) {
            WideLiteralInstruction insn = (WideLiteralInstruction) instruction;
            out.literalType = 2;
            // ==================== 甯搁噺姹犲姞瀵嗭紙榄旀敼#8锛?====================
            // 用codeUnitOffset产生XOR密钥，每条指令的字面量加密密钥不同
            int litKey = (int)((codeUnitOffset * 0x9E3779B9L) & 0xFF);
            out.literalValue = insn.getWideLiteral() ^ litKey;
            // ====================================================
        } else if (instruction instanceof NarrowLiteralInstruction) {
            NarrowLiteralInstruction insn = (NarrowLiteralInstruction) instruction;
            out.literalType = 1;
            int litKey = (int)((codeUnitOffset * 0x9E3779B9L) & 0xFF);
            out.literalValue = insn.getNarrowLiteral() ^ litKey;
        }

        if (instruction instanceof OffsetInstruction) {
            OffsetInstruction insn = (OffsetInstruction) instruction;
            out.offsetType = 1;
            out.offsetValue = insn.getCodeOffset();
        }

        if (instruction instanceof ReferenceInstruction) {
            Reference reference = ((ReferenceInstruction) instruction).getReference();

            out.referenceType = VmpReferenceSerializer.getReferenceTypeCode(reference);
            out.referenceData = VmpReferenceSerializer.buildReferenceText(reference);
        }

        if (instruction instanceof DualReferenceInstruction) {
            Reference reference2 = ((DualReferenceInstruction) instruction).getReference2();

            out.extraReferenceType = VmpReferenceSerializer.getReferenceTypeCode(reference2);
            out.extraReferenceData = VmpReferenceSerializer.buildReferenceText(reference2);
        }

        return out;
    }

    static List<ExtractTryBlock> buildExtractTryBlocks(MethodImplementation impl) {
        List<ExtractTryBlock> result = new ArrayList<>();

        if (impl == null || impl.getTryBlocks() == null) {
            return result;
        }

        for (TryBlock<? extends ExceptionHandler> tryBlock : impl.getTryBlocks()) {
            ExtractTryBlock out = new ExtractTryBlock();
            out.startCodeAddress = tryBlock.getStartCodeAddress();
            out.codeUnitCount = tryBlock.getCodeUnitCount();

            for (ExceptionHandler handler : tryBlock.getExceptionHandlers()) {
                ExtractExceptionHandler h = new ExtractExceptionHandler();
                h.exceptionType = handler.getExceptionType();
                h.handlerCodeAddress = handler.getHandlerCodeAddress();
                out.handlers.add(h);
            }

            result.add(out);
        }

        return result;
    }
}
