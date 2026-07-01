package com.ark.jiagu.vm;

import java.util.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

class VmpMethodTracker {

    static class ExtractedMethodInfo {
        int methodId;
        String dexName;
        String className;
        String methodName;
        String methodSignature;
        int accessFlags;
        int registerCount;
        int paramCount;
        String returnType;
    }

    static final Map<String, ExtractedMethodInfo> EXTRACTED_METHOD_MAP = new LinkedHashMap<>();

    static String buildExtractedMethodKey(String dexName, String className, String methodName, String methodSignature) {
        return dexName + "|" + className + "->" + methodName + methodSignature;
    }

    static void recordExtractedMethod(ExtractMethodBlock block) {
        if (block == null) {
            return;
        }

        ExtractedMethodInfo info = new ExtractedMethodInfo();
        info.methodId = block.methodId;
        info.dexName = block.dexName;
        info.className = block.className;
        info.methodName = block.methodName;
        info.methodSignature = block.methodSignature;
        info.accessFlags = block.accessFlags;
        info.registerCount = block.registerCount;
        info.paramCount = block.paramCount;
        info.returnType = block.returnType;

        String key = buildExtractedMethodKey(
                block.dexName,
                block.className,
                block.methodName,
                block.methodSignature
        );

        EXTRACTED_METHOD_MAP.put(key, info);

        System.out.println("记录待native重写方法 key=" + key
                + " methodId=" + block.methodId
                + " accessFlags=0x" + Integer.toHexString(block.accessFlags)
                + " returnType=" + block.returnType);
    }

    private static ExtractedMethodInfo getExtractedMethodInfo(String dexName,
                                                              String className,
                                                              String methodName,
                                                              String methodSignature) {
        String key = buildExtractedMethodKey(dexName, className, methodName, methodSignature);
        return EXTRACTED_METHOD_MAP.get(key);
    }
}
