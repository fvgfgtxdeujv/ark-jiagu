package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.iface.reference.CallSiteReference;
import com.android.tools.smali.dexlib2.iface.reference.FieldReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodHandleReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodProtoReference;
import com.android.tools.smali.dexlib2.iface.reference.MethodReference;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import com.android.tools.smali.dexlib2.iface.reference.StringReference;
import com.android.tools.smali.dexlib2.iface.reference.TypeReference;
import com.android.tools.smali.dexlib2.iface.value.BooleanEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.ByteEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.CharEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.DoubleEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.EncodedValue;
import com.android.tools.smali.dexlib2.iface.value.FloatEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.IntEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.LongEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodHandleEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.MethodTypeEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.ShortEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.StringEncodedValue;
import com.android.tools.smali.dexlib2.iface.value.TypeEncodedValue;

import java.util.List;

class VmpReferenceSerializer {

    static String buildMethodProtoSignature(MethodProtoReference protoRef) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : protoRef.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(protoRef.getReturnType());

        return sb.toString();
    }

    static String buildReferenceText(Reference reference) {
        if (reference == null) {
            return null;
        }

        if (reference instanceof StringReference) {
            return ((StringReference) reference).getString();
        }

        if (reference instanceof TypeReference) {
            return ((TypeReference) reference).getType();
        }

        if (reference instanceof FieldReference) {
            FieldReference field = (FieldReference) reference;
            return field.getDefiningClass()
                    + "->" + field.getName()
                    + ":" + field.getType();
        }

        if (reference instanceof MethodReference) {
            MethodReference method = (MethodReference) reference;
            return method.getDefiningClass()
                    + "->" + method.getName()
                    + buildMethodReferenceSignature(method);
        }

        if (reference instanceof MethodProtoReference) {
            return buildMethodProtoSignature((MethodProtoReference) reference);
        }

        if (reference instanceof MethodHandleReference) {
            return buildMethodHandleText((MethodHandleReference) reference);
        }

        if (reference instanceof CallSiteReference) {
            CallSiteReference callSite = (CallSiteReference) reference;

            StringBuilder sb = new StringBuilder();

            sb.append("name=").append(vmpEscape(callSite.getName())).append("\n");
            sb.append("methodName=").append(vmpEscape(callSite.getMethodName())).append("\n");
            sb.append("methodProto=").append(vmpEscape(buildMethodProtoSignature(callSite.getMethodProto()))).append("\n");
            sb.append("methodHandle=").append(vmpEscape(buildMethodHandleText(callSite.getMethodHandle()))).append("\n");

            List<? extends EncodedValue> extraArgs = callSite.getExtraArguments();
            sb.append("extraCount=").append(extraArgs.size()).append("\n");

            for (int i = 0; i < extraArgs.size(); i++) {
                sb.append("extra").append(i).append("=")
                        .append(vmpEscape(buildEncodedValueText(extraArgs.get(i))))
                        .append("\n");
            }

            return sb.toString();
        }

        return String.valueOf(reference);
    }

    static int getReferenceTypeCode(Reference reference) {
        if (reference instanceof StringReference) {
            return 1;
        }

        if (reference instanceof TypeReference) {
            return 2;
        }

        if (reference instanceof FieldReference) {
            return 3;
        }

        if (reference instanceof MethodReference) {
            return 4;
        }

        if (reference instanceof MethodProtoReference) {
            return 5;
        }

        if (reference instanceof MethodHandleReference) {
            return 6;
        }

        if (reference instanceof CallSiteReference) {
            return 7;
        }

        return 9;
    }

    static String vmpEscape(String s) {
        if (s == null) {
            return "";
        }

        return s.replace("%", "%25")
                .replace("\n", "%0A")
                .replace("=", "%3D")
                .replace("|", "%7C")
                .replace(";", "%3B");
    }

    static String buildMethodHandleText(MethodHandleReference handle) {
        if (handle == null) {
            return "";
        }

        Reference member = handle.getMemberReference();

        return handle.getMethodHandleType()
                + "|" + getReferenceTypeCode(member)
                + "|" + vmpEscape(buildReferenceText(member));
    }

    static String buildEncodedValueText(EncodedValue value) {
        if (value == null) {
            return "null|";
        }

        if (value instanceof StringEncodedValue) {
            return "string|" + vmpEscape(((StringEncodedValue) value).getValue());
        }

        if (value instanceof TypeEncodedValue) {
            return "type|" + vmpEscape(((TypeEncodedValue) value).getValue());
        }

        if (value instanceof MethodTypeEncodedValue) {
            return "proto|" + vmpEscape(buildMethodProtoSignature(((MethodTypeEncodedValue) value).getValue()));
        }

        if (value instanceof MethodHandleEncodedValue) {
            return "handle|" + vmpEscape(buildMethodHandleText(((MethodHandleEncodedValue) value).getValue()));
        }

        if (value instanceof IntEncodedValue) {
            return "int|" + ((IntEncodedValue) value).getValue();
        }

        if (value instanceof LongEncodedValue) {
            return "long|" + ((LongEncodedValue) value).getValue();
        }

        if (value instanceof FloatEncodedValue) {
            return "float|" + ((FloatEncodedValue) value).getValue();
        }

        if (value instanceof DoubleEncodedValue) {
            return "double|" + ((DoubleEncodedValue) value).getValue();
        }

        if (value instanceof BooleanEncodedValue) {
            return "boolean|" + (((BooleanEncodedValue) value).getValue() ? "1" : "0");
        }

        if (value instanceof ByteEncodedValue) {
            return "byte|" + ((ByteEncodedValue) value).getValue();
        }

        if (value instanceof ShortEncodedValue) {
            return "short|" + ((ShortEncodedValue) value).getValue();
        }

        if (value instanceof CharEncodedValue) {
            return "char|" + (int) ((CharEncodedValue) value).getValue();
        }

        return "unknown|" + vmpEscape(String.valueOf(value));
    }
}
