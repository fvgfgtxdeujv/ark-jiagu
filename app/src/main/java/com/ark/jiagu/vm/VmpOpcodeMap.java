package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.Opcodes;
import java.util.*;

class VmpOpcodeMap {

    private static final Map<Opcode, OpcodeMapEntry> OPCODE_MAP = new LinkedHashMap<>();
    private static final List<Integer> VM_OPCODE_POOL = new ArrayList<>();
    private static int nextVmOpcode = 1;

    static List<Integer> buildRandomOpcodePool() {
        List<Integer> list = new ArrayList<>();
        for (int i = 1; i <= 255; i++) {
            list.add(i);
        }
        Collections.shuffle(list, new Random(System.currentTimeMillis()));
        return list;
    }

    static int getRealDexOpcodeValue(Opcode opcode) {
        switch (opcode) {

            case NOP: return 0x00;
            case MOVE: return 0x01;
            case MOVE_FROM16: return 0x02;
            case MOVE_16: return 0x03;
            case MOVE_WIDE: return 0x04;
            case MOVE_WIDE_FROM16: return 0x05;
            case MOVE_WIDE_16: return 0x06;
            case MOVE_OBJECT: return 0x07;
            case MOVE_OBJECT_FROM16: return 0x08;
            case MOVE_OBJECT_16: return 0x09;
            case MOVE_RESULT: return 0x0a;
            case MOVE_RESULT_WIDE: return 0x0b;
            case MOVE_RESULT_OBJECT: return 0x0c;
            case MOVE_EXCEPTION: return 0x0d;
            case RETURN_VOID: return 0x0e;
            case RETURN: return 0x0f;
            case RETURN_WIDE: return 0x10;
            case RETURN_OBJECT: return 0x11;
            case CONST_4: return 0x12;
            case CONST_16: return 0x13;
            case CONST: return 0x14;
            case CONST_HIGH16: return 0x15;
            case CONST_WIDE_16: return 0x16;
            case CONST_WIDE_32: return 0x17;
            case CONST_WIDE: return 0x18;
            case CONST_WIDE_HIGH16: return 0x19;
            case CONST_STRING: return 0x1a;
            case CONST_STRING_JUMBO: return 0x1b;
            case CONST_CLASS: return 0x1c;
            case MONITOR_ENTER: return 0x1d;
            case MONITOR_EXIT: return 0x1e;
            case CHECK_CAST: return 0x1f;
            case INSTANCE_OF: return 0x20;
            case ARRAY_LENGTH: return 0x21;
            case NEW_INSTANCE: return 0x22;
            case NEW_ARRAY: return 0x23;
            case FILLED_NEW_ARRAY: return 0x24;
            case FILLED_NEW_ARRAY_RANGE: return 0x25;
            case FILL_ARRAY_DATA: return 0x26;
            case THROW: return 0x27;
            case GOTO: return 0x28;
            case GOTO_16: return 0x29;
            case GOTO_32: return 0x2a;
            case PACKED_SWITCH: return 0x2b;
            case SPARSE_SWITCH: return 0x2c;
            case CMPL_FLOAT: return 0x2d;
            case CMPG_FLOAT: return 0x2e;
            case CMPL_DOUBLE: return 0x2f;
            case CMPG_DOUBLE: return 0x30;
            case CMP_LONG: return 0x31;
            case IF_EQ: return 0x32;
            case IF_NE: return 0x33;
            case IF_LT: return 0x34;
            case IF_GE: return 0x35;
            case IF_GT: return 0x36;
            case IF_LE: return 0x37;
            case IF_EQZ: return 0x38;
            case IF_NEZ: return 0x39;
            case IF_LTZ: return 0x3a;
            case IF_GEZ: return 0x3b;
            case IF_GTZ: return 0x3c;
            case IF_LEZ: return 0x3d;
            case AGET: return 0x44;
            case AGET_WIDE: return 0x45;
            case AGET_OBJECT: return 0x46;
            case AGET_BOOLEAN: return 0x47;
            case AGET_BYTE: return 0x48;
            case AGET_CHAR: return 0x49;
            case AGET_SHORT: return 0x4a;
            case APUT: return 0x4b;
            case APUT_WIDE: return 0x4c;
            case APUT_OBJECT: return 0x4d;
            case APUT_BOOLEAN: return 0x4e;
            case APUT_BYTE: return 0x4f;
            case APUT_CHAR: return 0x50;
            case APUT_SHORT: return 0x51;
            case IGET: return 0x52;
            case IGET_WIDE: return 0x53;
            case IGET_OBJECT: return 0x54;
            case IGET_BOOLEAN: return 0x55;
            case IGET_BYTE: return 0x56;
            case IGET_CHAR: return 0x57;
            case IGET_SHORT: return 0x58;
            case IPUT: return 0x59;
            case IPUT_WIDE: return 0x5a;
            case IPUT_OBJECT: return 0x5b;
            case IPUT_BOOLEAN: return 0x5c;
            case IPUT_BYTE: return 0x5d;
            case IPUT_CHAR: return 0x5e;
            case IPUT_SHORT: return 0x5f;
            case SGET: return 0x60;
            case SGET_WIDE: return 0x61;
            case SGET_OBJECT: return 0x62;
            case SGET_BOOLEAN: return 0x63;
            case SGET_BYTE: return 0x64;
            case SGET_CHAR: return 0x65;
            case SGET_SHORT: return 0x66;
            case SPUT: return 0x67;
            case SPUT_WIDE: return 0x68;
            case SPUT_OBJECT: return 0x69;
            case SPUT_BOOLEAN: return 0x6a;
            case SPUT_BYTE: return 0x6b;
            case SPUT_CHAR: return 0x6c;
            case SPUT_SHORT: return 0x6d;
            case INVOKE_VIRTUAL: return 0x6e;
            case INVOKE_SUPER: return 0x6f;
            case INVOKE_DIRECT: return 0x70;
            case INVOKE_STATIC: return 0x71;
            case INVOKE_INTERFACE: return 0x72;
            case INVOKE_VIRTUAL_RANGE: return 0x74;
            case INVOKE_SUPER_RANGE: return 0x75;
            case INVOKE_DIRECT_RANGE: return 0x76;
            case INVOKE_STATIC_RANGE: return 0x77;
            case INVOKE_INTERFACE_RANGE: return 0x78;
            case NEG_INT: return 0x7b;
            case NOT_INT: return 0x7c;
            case NEG_LONG: return 0x7d;
            case NOT_LONG: return 0x7e;
            case NEG_FLOAT: return 0x7f;
            case NEG_DOUBLE: return 0x80;
            case INT_TO_LONG: return 0x81;
            case INT_TO_FLOAT: return 0x82;
            case INT_TO_DOUBLE: return 0x83;
            case LONG_TO_INT: return 0x84;
            case LONG_TO_FLOAT: return 0x85;
            case LONG_TO_DOUBLE: return 0x86;
            case FLOAT_TO_INT: return 0x87;
            case FLOAT_TO_LONG: return 0x88;
            case FLOAT_TO_DOUBLE: return 0x89;
            case DOUBLE_TO_INT: return 0x8a;
            case DOUBLE_TO_LONG: return 0x8b;
            case DOUBLE_TO_FLOAT: return 0x8c;
            case INT_TO_BYTE: return 0x8d;
            case INT_TO_CHAR: return 0x8e;
            case INT_TO_SHORT: return 0x8f;
            case ADD_INT: return 0x90;
            case SUB_INT: return 0x91;
            case MUL_INT: return 0x92;
            case DIV_INT: return 0x93;
            case REM_INT: return 0x94;
            case AND_INT: return 0x95;
            case OR_INT: return 0x96;
            case XOR_INT: return 0x97;
            case SHL_INT: return 0x98;
            case SHR_INT: return 0x99;
            case USHR_INT: return 0x9a;
            case ADD_LONG: return 0x9b;
            case SUB_LONG: return 0x9c;
            case MUL_LONG: return 0x9d;
            case DIV_LONG: return 0x9e;
            case REM_LONG: return 0x9f;
            case AND_LONG: return 0xa0;
            case OR_LONG: return 0xa1;
            case XOR_LONG: return 0xa2;
            case SHL_LONG: return 0xa3;
            case SHR_LONG: return 0xa4;
            case USHR_LONG: return 0xa5;
            case ADD_FLOAT: return 0xa6;
            case SUB_FLOAT: return 0xa7;
            case MUL_FLOAT: return 0xa8;
            case DIV_FLOAT: return 0xa9;
            case REM_FLOAT: return 0xaa;
            case ADD_DOUBLE: return 0xab;
            case SUB_DOUBLE: return 0xac;
            case MUL_DOUBLE: return 0xad;
            case DIV_DOUBLE: return 0xae;
            case REM_DOUBLE: return 0xaf;
            case ADD_INT_2ADDR: return 0xb0;
            case SUB_INT_2ADDR: return 0xb1;
            case MUL_INT_2ADDR: return 0xb2;
            case DIV_INT_2ADDR: return 0xb3;
            case REM_INT_2ADDR: return 0xb4;
            case AND_INT_2ADDR: return 0xb5;
            case OR_INT_2ADDR: return 0xb6;
            case XOR_INT_2ADDR: return 0xb7;
            case SHL_INT_2ADDR: return 0xb8;
            case SHR_INT_2ADDR: return 0xb9;
            case USHR_INT_2ADDR: return 0xba;
            case ADD_LONG_2ADDR: return 0xbb;
            case SUB_LONG_2ADDR: return 0xbc;
            case MUL_LONG_2ADDR: return 0xbd;
            case DIV_LONG_2ADDR: return 0xbe;
            case REM_LONG_2ADDR: return 0xbf;
            case AND_LONG_2ADDR: return 0xc0;
            case OR_LONG_2ADDR: return 0xc1;
            case XOR_LONG_2ADDR: return 0xc2;
            case SHL_LONG_2ADDR: return 0xc3;
            case SHR_LONG_2ADDR: return 0xc4;
            case USHR_LONG_2ADDR: return 0xc5;
            case ADD_FLOAT_2ADDR: return 0xc6;
            case SUB_FLOAT_2ADDR: return 0xc7;
            case MUL_FLOAT_2ADDR: return 0xc8;
            case DIV_FLOAT_2ADDR: return 0xc9;
            case REM_FLOAT_2ADDR: return 0xca;
            case ADD_DOUBLE_2ADDR: return 0xcb;
            case SUB_DOUBLE_2ADDR: return 0xcc;
            case MUL_DOUBLE_2ADDR: return 0xcd;
            case DIV_DOUBLE_2ADDR: return 0xce;
            case REM_DOUBLE_2ADDR: return 0xcf;
            case ADD_INT_LIT16: return 0xd0;
            case RSUB_INT: return 0xd1;
            case MUL_INT_LIT16: return 0xd2;
            case DIV_INT_LIT16: return 0xd3;
            case REM_INT_LIT16: return 0xd4;
            case AND_INT_LIT16: return 0xd5;
            case OR_INT_LIT16: return 0xd6;
            case XOR_INT_LIT16: return 0xd7;
            case ADD_INT_LIT8: return 0xd8;
            case RSUB_INT_LIT8: return 0xd9;
            case MUL_INT_LIT8: return 0xda;
            case DIV_INT_LIT8: return 0xdb;
            case REM_INT_LIT8: return 0xdc;
            case AND_INT_LIT8: return 0xdd;
            case OR_INT_LIT8: return 0xde;
            case XOR_INT_LIT8: return 0xdf;
            case SHL_INT_LIT8: return 0xe0;
            case SHR_INT_LIT8: return 0xe1;
            case USHR_INT_LIT8: return 0xe2;
            case INVOKE_POLYMORPHIC: return 0xfa;
            case INVOKE_POLYMORPHIC_RANGE: return 0xfb;
            case INVOKE_CUSTOM: return 0xfc;
            case INVOKE_CUSTOM_RANGE: return 0xfd;
            case CONST_METHOD_HANDLE: return 0xfe;
            case CONST_METHOD_TYPE: return 0xff;

            default:
                throw new RuntimeException(
                        "不支持的Opcode: "
                                + opcode.name()
                                + " ordinal="
                                + opcode.ordinal()
                );
        }
    }

    static int getOrCreateVmOpcode(Opcode opcode,
                                   Map<Integer, OpcodeMapEntry> opcodeMap,
                                   List<Integer> opcodePool,
                                   int[] opcodePoolIndex) {
        int realOpcode = getRealDexOpcodeValue(opcode);
        String realOpcodeName = opcode.name();

        OpcodeMapEntry old = opcodeMap.get(realOpcode);
        if (old != null) {
            return old.vmOpcode;
        }

        if (opcodePoolIndex[0] >= opcodePool.size()) {
            throw new IllegalStateException("自定义opcode数量超过255");
        }

        int vmOpcode = opcodePool.get(opcodePoolIndex[0]);
        opcodePoolIndex[0]++;

        OpcodeMapEntry entry = new OpcodeMapEntry();
        entry.vmOpcode = vmOpcode;
        entry.realOpcode = realOpcode;
        entry.realOpcodeName = realOpcodeName;

        opcodeMap.put(realOpcode, entry);

        System.out.println("生成opcode映射: 自定义opcode=0x"
                + String.format("%02x", vmOpcode)
                + " -> 真实opcode=0x" + Integer.toHexString(realOpcode)
                + " -> 真实指令=" + realOpcodeName);

        return vmOpcode;
    }
}
