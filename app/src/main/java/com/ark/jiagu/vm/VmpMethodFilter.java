package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodImplementation;

class VmpMethodFilter {

    static boolean isForbiddenExtractMethod(Method method) {
        if (method == null) {
            return true;
        }

        String name = method.getName();
        int flags = method.getAccessFlags();

        if ("<init>".equals(name) || "<clinit>".equals(name)) {
            return true;
        }

        if ((flags & AccessFlags.ABSTRACT.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.NATIVE.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.BRIDGE.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.SYNTHETIC.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.DECLARED_SYNCHRONIZED.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.SYNCHRONIZED.getValue()) != 0) {
            return true;
        }

        if ((flags & AccessFlags.VARARGS.getValue()) != 0) {
            return true;
        }

        return false;
    }

    static boolean hasUnsupportedInvokeDynamicInstruction(MethodImplementation impl) {
        if (impl == null) {
            return true;
        }
        return false;
    }
}
