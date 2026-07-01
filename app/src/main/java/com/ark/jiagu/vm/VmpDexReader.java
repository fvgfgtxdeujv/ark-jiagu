package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.Method;
import com.android.tools.smali.dexlib2.iface.MethodReference;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

class VmpDexReader {

    static final Map<String, ExtractedMethodInfo> EXTRACTED_METHOD_MAP = new LinkedHashMap<>();
    static void VMPextractEntry(ZipFile zipFile, String entryName, File outFile) throws IOException {
        ZipEntry entry = zipFile.getEntry(entryName);
        if (entry == null) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        File parent = outFile.getParentFile();
        if (parent != null && !parent.exists() && !parent.mkdirs()) {
            throw new IOException("鍒涘缓鐩綍澶辫触锛? + parent.getAbsolutePath());
        }

        try (InputStream in = zipFile.getInputStream(entry);
             FileOutputStream out = new FileOutputStream(outFile)) {

            byte[] buffer = new byte[8192];
            int len;

            while ((len = in.read(buffer)) != -1) {
                out.write(buffer, 0, len);
            }
        }
    }

    static String buildMethodSignature(Method method) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : method.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(method.getReturnType());

        return sb.toString();
    }

    static String buildMethodReferenceSignature(MethodReference methodRef) {
        StringBuilder sb = new StringBuilder();
        sb.append("(");

        for (CharSequence paramType : methodRef.getParameterTypes()) {
            sb.append(paramType);
        }

        sb.append(")");
        sb.append(methodRef.getReturnType());

        return sb.toString();
    }

    static String dexTypeToJavaName(String dexType) {
        if (dexType == null) {
            return "";
        }

        if (dexType.startsWith("L") && dexType.endsWith(";")) {
            dexType = dexType.substring(1, dexType.length() - 1);
        }

        return dexType.replace('/', '.');
    }

    static boolean isValidDexFile(File file) {
        if (file == null || !file.isFile() || file.length() < 0x70) {
            return false;
        }

        try (FileInputStream in = new FileInputStream(file)) {
            byte[] magic = new byte[4];
            int read = in.read(magic);

            if (read != 4) {
                return false;
            }

            return magic[0] == 'd'
                    && magic[1] == 'e'
                    && magic[2] == 'x'
                    && magic[3] == '\n';
        } catch (Exception e) {
            return false;
        }
    }

    static byte[] readAllBytes(File file) throws IOException {
        try (FileInputStream in = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            int offset = 0;

            while (offset < data.length) {
                int read = in.read(data, offset, data.length - offset);

                if (read == -1) {
                    break;
                }

                offset += read;
            }

            if (offset != data.length) {
                throw new IOException("读取文件不完整：" + file.getAbsolutePath());
            }

            return data;
        }
    }
    static void writeIntLE(FileOutputStream out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }

    static int readIntLE(RandomAccessFile in) throws IOException {
        int b0 = in.read();
        int b1 = in.read();
        int b2 = in.read();
        int b3 = in.read();

        if ((b0 | b1 | b2 | b3) < 0) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        return (b0 & 0xff)
                | ((b1 & 0xff) << 8)
                | ((b2 & 0xff) << 16)
                | ((b3 & 0xff) << 24);
    }

    static long readLongLE(RandomAccessFile in) throws IOException {
        long b0 = in.read();
        long b1 = in.read();
        long b2 = in.read();
        long b3 = in.read();
        long b4 = in.read();
        long b5 = in.read();
        long b6 = in.read();
        long b7 = in.read();

        if ((b0 | b1 | b2 | b3 | b4 | b5 | b6 | b7) < 0) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        return (b0 & 0xff)
                | ((b1 & 0xff) << 8)
                | ((b2 & 0xff) << 16)
                | ((b3 & 0xff) << 24)
                | ((b4 & 0xff) << 32)
                | ((b5 & 0xff) << 40)
                | ((b6 & 0xff) << 48)
                | ((b7 & 0xff) << 56);
    }

    static String readStringLE(RandomAccessFile in) throws IOException {
        int len = readIntLE(in);

        if (len == -1) {
            return null;
        }

        if (len < 0) {
            throw new IOException("字符串长度非法：" + len);
        }

        byte[] data = new byte[len];
        readFully(in, data);

        return new String(data, StandardCharsets.UTF_8);
    }

    static void readFully(RandomAccessFile in, byte[] data) throws IOException {
        int offset = 0;

        while (offset < data.length) {
            int read = in.read(data, offset, data.length - offset);
            if (read == -1) {
            throw new IOException("APK中未找到文件：" + entryName);
            }
            offset += read;
        }
    }

    static String buildExtractedMethodKey(String dexName, String className, String methodName, String methodSignature) {
        return dexName + "|" + className + "->" + methodName + methodSignature;
    }
}
