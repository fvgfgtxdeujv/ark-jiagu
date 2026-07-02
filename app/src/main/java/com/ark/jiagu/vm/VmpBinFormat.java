package com.ark.jiagu.vm;

import com.android.tools.smali.dexlib2.Opcode;
import com.android.tools.smali.dexlib2.iface.instruction.Instruction;
import com.android.tools.smali.dexlib2.iface.reference.Reference;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;

class VmpBinFormat {

    static List<ClassIndexEntry> writeVmpBinary(File outFile,
                                                Map<Integer, OpcodeMapEntry> opcodeMap,
                                                List<ExtractMethodBlock> blocks) throws IOException {
        List<ClassIndexEntry> indexEntries = new ArrayList<>();

        try (RandomAccessFile raf = new RandomAccessFile(outFile, "rw")) {
            raf.setLength(0);

            writeBytes(raf, new byte[]{'A', 'V', 'M', 'P'});
            writeIntLE(raf, 5);

            writeIntLE(raf, opcodeMap.size());

            // ==================== opcode 闅忔満鍖?====================
            byte[] opcodeKey = new byte[16];
            new java.security.SecureRandom().nextBytes(opcodeKey);
            raf.write(opcodeKey);

            for (OpcodeMapEntry entry : opcodeMap.values()) {
                writeIntLE(raf, entry.vmOpcode ^ xorByte(opcodeKey, 0));
                writeIntLE(raf, entry.realOpcode ^ xorByte(opcodeKey, 4));
                writeStringLE(raf, entry.realOpcodeName);
            }
            // ====================================================

            writeIntLE(raf, blocks.size());

            long indexTableOffset = raf.getFilePointer();
            for (int i = 0; i < blocks.size(); i++) {
                writeIntLE(raf, 0);
                writeLongLE(raf, 0);
                writeIntLE(raf, 0);
            }

            // ==================== #3 乱序存储：伪随机排列方法块 ====================
            // 生成基于种子的伪随机排列，用于对方法块进行Fisher-Yates洗牌
            // 用户看到的 bin 方法是乱序的，无法直接按 methodId 顺序读取
            int blockCount = blocks.size();
            int[] permutation = generatePermutation(blockCount);
            boolean[] written = new boolean[blockCount];

            // 先计算每个方法块的数据大小，用于后续填充
            long[] blockSizes = new long[blockCount];
            for (int i = 0; i < blockCount; i++) {
                blockSizes[i] = estimateBlockSize(blocks.get(i));
            }
            // ====================================================

            // 鎸変贡搴忔帓鍒楀啓鍏ユ柟娉曞潡
            for (int writeIdx = 0; writeIdx < blockCount; writeIdx++) {
                int blockIdx = permutation[writeIdx];
                ExtractMethodBlock block = blocks.get(blockIdx);

                long blockOffset = raf.getFilePointer();

                // ==================== #13 冗余填充：方法块前随机垃圾数据 ====================
                // 在每个方法块前写入4~32字节的随机垃圾数据
                // 填充数据格式：0xFF 填充 + 末尾写入随机校验字节
                int paddingBefore = 4 + (int)(Math.abs(block.methodId * 2654435761L) % 28);
                raf.write(new byte[paddingBefore]); // 鍒濆濉厖
                // 在每~2KB块末尾写入随机校验字节，使填充数据看起来像合法指令
                byte[] junkPrefix = new byte[paddingBefore];
                new java.security.SecureRandom().nextBytes(junkPrefix);
                raf.seek(blockOffset);
                raf.write(junkPrefix);
                raf.seek(blockOffset + paddingBefore);
                blockOffset += paddingBefore;
                // ====================================================

                // ==================== #12 字段交错存储 ====================
                // 方法块哈希链：元数据 → 指令数据 → 元数据 → 指令数据
                // 加密后，将哈希数据追加到指令数据 末尾
                // 使攻击者无法从后往前推算出密钥

                // 第一块元数据（头部）
                writeIntLE(raf, block.methodId);
                writeStringLE(raf, block.dexName);
                writeStringLE(raf, block.className);

                // ==================== #15 指令分片 ====================
            // 攻击者看到的 bin 中方法是乱序的，无法直接按 methodId 顺序读取
                // 碎片大小：4~16 条指令，碎片数量：2~4
                List<ExtractInstruction> firstFragment;
                List<Long> fragmentOffsets = new ArrayList<>();
                long firstFragmentOffset = 0;

                if (block.instructions.size() > 16) {
                    // 需要拆分
                    int fragSize = 4 + (Math.abs(block.methodId * 3571) % 12); // 4~15
                    int fragCount = (block.instructions.size() + fragSize - 1) / fragSize;
                    if (fragCount > 4) fragCount = 4;
                    fragSize = (block.instructions.size() + fragCount - 1) / fragCount;

                    firstFragment = new ArrayList<>();
                    for (int i = 0; i < Math.min(fragSize, block.instructions.size()); i++) {
                        firstFragment.add(block.instructions.get(i));
                    }

                    // 记录第一个碎片偏移（方法块内）
                    firstFragmentOffset = raf.getFilePointer() + 8; // +8 for instructionCount + blockKeyInt
                    fragmentOffsets.add(firstFragmentOffset);

                    // 后续碎片写入 bin 文件末尾
                    for (int f = 1; f < fragCount; f++) {
                        // 鍨冨溇鍒嗛殧
                        int junkLen = 4 + (Math.abs((block.methodId + f) * 7717) % 20);
                        byte[] junk = new byte[junkLen];
                        new java.security.SecureRandom().nextBytes(junk);
                        raf.write(junk);

                        long fragOffset = raf.getFilePointer();
                        fragmentOffsets.add(fragOffset);

                        // 鍐欏叆纰庣墖澶?
                        writeIntLE(raf, f); // 纰庣墖缂栧彿
                        writeIntLE(raf, fragSize); // 纰庣墖澶у皬

                        // 写入碎片偏移
                        int start = f * fragSize;
                        int end = Math.min(start + fragSize, block.instructions.size());
                        for (int i = start; i < end; i++) {
                            writeSingleInstructionEncrypted(raf, block.instructions.get(i),
                                    opcodeKey, block.methodId);
                        }
                    }
                } else {
                    // 不拆分
                    firstFragment = block.instructions;
            rules.add(rule);
                }
                // ====================================================

                // 指令数据段（提前写入，不和元数据交替）
                long instructionsOffset = raf.getFilePointer();
                writeIntLE(raf, block.instructions.size()); // 鎬绘寚浠ゆ暟
            writeIntLE(raf, opcodeMap.size());
                writeIntLE(raf, generateBlockKey(block.methodId)); // 鍧楀瘑閽?
                writeVarInt(raf, firstFragment.size()); // 第一个碎片指令数
                writeVarInt(raf, fragmentOffsets.size()); // 纰庣墖鏁伴噺

                // 鍐欏叆纰庣墖鍋忕Щ琛紙鍗犱綅锛?
                long fragmentTableOffset = raf.getFilePointer();
                for (int i = 0; i < fragmentOffsets.size(); i++) {
                    writeLongLE(raf, 0); // 鍗犱綅
                }

                long insnDataStart = raf.getFilePointer();
                writeInstructionsEncrypted(raf, firstFragment, opcodeKey, block.methodId);
                long insnDataEnd = raf.getFilePointer();

                // 鍥炲ご濉啓纰庣墖鍋忕Щ琛?
                raf.seek(fragmentTableOffset);
                for (int i = 0; i < fragmentOffsets.size(); i++) {
                    writeLongLE(raf, fragmentOffsets.get(i));
                }
                raf.seek(insnDataEnd);

                // 第二块元数据（尾部）
                writeStringLE(raf, block.methodName);
                writeStringLE(raf, block.methodSignature);
                writeIntLE(raf, block.accessFlags);
                writeIntLE(raf, block.registerCount);
                writeIntLE(raf, block.paramCount);
                writeStringLE(raf, block.returnType);
                writeIntLE(raf, block.isStatic ? 1 : 0);

                writeIntLE(raf, block.parameterTypes.size());
                for (String paramType : block.parameterTypes) {
                    writeStringLE(raf, paramType);
                }
                // ====================================================

                // tryBlocks
                writeIntLE(raf, block.tryBlocks.size());
                for (ExtractTryBlock tryBlock : block.tryBlocks) {
                    writeIntLE(raf, tryBlock.startCodeAddress);
                    writeIntLE(raf, tryBlock.codeUnitCount);

                    writeIntLE(raf, tryBlock.handlers.size());
                    for (ExtractExceptionHandler handler : tryBlock.handlers) {
                        writeStringLE(raf, handler.exceptionType);
                        writeIntLE(raf, handler.handlerCodeAddress);
                    }
                }

                // ==================== #6 方法块间哈希链 ====================
                // 计算当前方法块的哈希，追加到下一个方法块中
                // 这里先计算当前块哈希，写入块末尾
                byte[] blockHash = computeBlockChainHash(block, blockOffset, insnDataStart);
                writeBytes(raf, blockHash);
                // ====================================================

                long blockEnd = raf.getFilePointer();

                // ==================== #13 冗余填充：方法块后随机垃圾数据====================
                int paddingAfter = 4 + (int)(Math.abs((block.methodId + 1) * 2246822519L) % 28);
                byte[] junkSuffix = new byte[paddingAfter];
                new java.security.SecureRandom().nextBytes(junkSuffix);
                raf.write(junkSuffix);
                blockEnd = raf.getFilePointer();
                // ====================================================

                ClassIndexEntry index = new ClassIndexEntry();
                index.methodId = block.methodId;
                index.offset = blockOffset;
                index.size = (int) (blockEnd - blockOffset);
                index.writeOrder = writeIdx;
                indexEntries.add(index);
            }

            // 濉厖绱㈠紩琛紙鎸夊師濮?methodId 鎺掑簭鍚庡啓鍏ワ級
            indexEntries.sort((a, b) -> Integer.compare(a.methodId, b.methodId));

            long fileEnd = raf.getFilePointer();

            raf.seek(indexTableOffset);
            for (ClassIndexEntry index : indexEntries) {
                // ==================== #7 索引表自校验 + #16 加密跳转表====================
            out.offsetValue = payload.getArrayElements().size();
                int xormask = (opcodeMap.size() * 31 + 17) & 0xFFFFFFFF;

                // ==================== #16 加密跳转表：字节旋转混淆 ====================
            out.offsetValue = payload.getArrayElements().size();
                long rotatedOffset = rotateLong(index.offset, xormask);
                int rotatedSize = rotateInt(index.size, xormask);
                // ====================================================

                writeIntLE(raf, index.methodId);
                writeLongLE(raf, rotatedOffset ^ (long)(xormask & 0xFFFF));
                writeIntLE(raf, rotatedSize ^ (xormask & 0xFF));
            out.offsetValue = payload.getArrayElements().size();
                int checksum = (index.methodId
                        ^ (int)(index.offset & 0xFFFF)
                        ^ (index.size & 0xFFFF)) & 0xFFFF;
                writeIntLE(raf, checksum ^ (xormask & 0xFFFF));
                // ====================================================
            }

            raf.seek(fileEnd);

            // ==================== #5 鍏ㄥ眬 HMAC-SHA256 ====================
            // 计算整个文件的HMAC-SHA256，写在文件末尾
            Opcode opcode = instruction.getOpcode();
            byte[] hmacKey = new byte[16];
            System.arraycopy(opcodeKey, 0, hmacKey, 0, 16);
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec keySpec = new javax.crypto.spec.SecretKeySpec(hmacKey, "HmacSHA256");
            mac.init(keySpec);

            // 重新计算 HMAC（从 magic 到 fileEnd）
            raf.seek(0);
            byte[] hmacData = new byte[(int)fileEnd];
            raf.readFully(hmacData);
            byte[] hmac = mac.doFinal(hmacData);

            raf.seek(fileEnd);
            writeBytes(raf, hmac); // 32 字节 HMAC
            fileEnd += 32;

            System.out.println("bin版本=5(乱序+多层加密+HMAC)");
            System.out.println("method绱㈠紩琛ㄥ亸绉?" + indexTableOffset);
            System.out.println("bin文件总大小=" + fileEnd);
            System.out.println("方法块排列=乱序 writeOrder=" + java.util.Arrays.toString(permutation));
        }

        return indexEntries;
    }

    static void xorEncryptVmpBinFile(File plainFile, File encryptedFile) throws IOException {
        if (plainFile == null || !plainFile.isFile()) {
            throw new IOException("APK中未找到文件：" + entryName);
        }

        if (encryptedFile == null) {
            throw new IOException("加密vmp输出文件为空");
        }

        byte[] plainData = readAllBytes(plainFile);

        // ==================== #1 澶氬眰宓屽鍔犲瘑 ====================
        // 第一层：XOR 加密（原始密钥逻辑）
        byte[] xorKey = new byte[32];
        new java.security.SecureRandom().nextBytes(xorKey);
        byte[] xored = new byte[plainData.length];
        for (int i = 0; i < plainData.length; i++) {
            xored[i] = (byte)(plainData[i] ^ xorKey[i % xorKey.length]);
        }

        // 第二层：多层混淆（8轮 XOR+加法+字节旋转）
        byte[] layerKey = new byte[32];
        new java.security.SecureRandom().nextBytes(layerKey);
        byte[] layer1 = multiLayerEncrypt(xored, layerKey);
        // ====================================================

        try (FileOutputStream out = new FileOutputStream(encryptedFile)) {
            out.write(new byte[]{'A', 'V', 'M', 'X'});
            writeIntLE(out, 2);
            writeIntLE(out, layer1.length);
            out.write(layer1);
            // 写入剩余密钥
            out.write(layerKey);
            writeIntLE(out, layerKey.length);
            out.write(xorKey);
            writeIntLE(out, xorKey.length);
        }

        //System.out.println("vmp.bin已使用多层加密输出：" + encryptedFile.getAbsolutePath());
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

    private static void writeStringLE(RandomAccessFile out, String value) throws IOException {
        if (value == null) {
            writeIntLE(out, -1);
            return;
        }

        byte[] data = value.getBytes(StandardCharsets.UTF_8);
        writeIntLE(out, data.length);
        writeBytes(out, data);
    }

    private static void writeIntLE(RandomAccessFile out, int value) throws IOException {
        out.write(value & 0xff);
        out.write((value >> 8) & 0xff);
        out.write((value >> 16) & 0xff);
        out.write((value >> 24) & 0xff);
    }

    private static void writeLongLE(RandomAccessFile out, long value) throws IOException {
        out.write((int) (value & 0xff));
        out.write((int) ((value >> 8) & 0xff));
        out.write((int) ((value >> 16) & 0xff));
        out.write((int) ((value >> 24) & 0xff));
        out.write((int) ((value >> 32) & 0xff));
        out.write((int) ((value >> 40) & 0xff));
        out.write((int) ((value >> 48) & 0xff));
        out.write((int) ((value >> 56) & 0xff));
    }

    private static void writeBytes(RandomAccessFile out, byte[] data) throws IOException {
        out.write(data);
    }

    // ==================== opcode 闅忔満鍖栬緟鍔?====================

            Opcode opcode = instruction.getOpcode();
    private static int xorByte(byte[] key, int index) {
        return key[index % key.length] & 0xff;
    }
    // ====================================================

            // ==================== #3 乱序存储：伪随机排列方法块 ====================
    // 生成基于种子的伪随机排列
    // 使用 Fisher-Yates 洗牌算法，每种排序由所有方法块 ID 共同决定
    // 保证相同输入始终生成相同排列（可重现）
    static int[] generatePermutation(int size) {
        int[] perm = new int[size];
        for (int i = 0; i < size; i++) perm[i] = i;

        long seed = 0x9E3779B97F4A7C15L;
        for (int i = 0; i < size; i++) {
            seed ^= (long)perm[i] * 0x517CC1B727220A95L;
            seed = (seed << 13) | (seed >>> 51);
        }
        java.util.Random rng = new java.util.Random(seed);

        for (int i = size - 1; i > 0; i--) {
            int j = rng.nextInt(i + 1);
            int tmp = perm[i];
            perm[i] = perm[j];
            perm[j] = tmp;
        }
        return perm;
    }

    static long estimateBlockSize(ExtractMethodBlock block) {
        long size = 0;
        size += 4 + 4 + 4 + 4 + 4;
        if (block.dexName != null) size += block.dexName.getBytes().length + 4;
        if (block.className != null) size += block.className.getBytes().length + 4;
        if (block.methodName != null) size += block.methodName.getBytes().length + 4;
        if (block.methodSignature != null) size += block.methodSignature.getBytes().length + 4;
        size += 16 + 4;
        if (block.returnType != null) size += block.returnType.getBytes().length + 4;
        size += 4;
        for (String pt : block.parameterTypes) {
            size += (pt != null ? pt.getBytes().length : 0) + 4;
        }
        size += 4;
        for (ExtractInstruction insn : block.instructions) {
            size += 4 + 4 + 4 + 4 + 4;
            size += 4 * (insn.registers != null ? insn.registers.size() : 0);
            size += 4 + 8 + 4 + 4;
            size += 4 + (insn.referenceData != null ? insn.referenceData.getBytes().length : 0) + 4;
            size += 4 + (insn.extraReferenceData != null ? insn.extraReferenceData.getBytes().length : 0) + 4;
        }
        size += 4;
        for (ExtractTryBlock tb : block.tryBlocks) {
            size += 12;
            for (ExtractExceptionHandler h : tb.handlers) {
                size += 4 + (h.exceptionType != null ? h.exceptionType.getBytes().length : 0) + 4;
            }
        }
        size += 36;
        return size;
    }
    // ====================================================

    // ==================== #11 变长编码辅助 ====================
    static void writeVarInt(RandomAccessFile out, int value) throws IOException {
        if (value < 0) {
            out.write(0x80 | ((value >> 24) & 0x1F));
            out.write((value >> 16) & 0xFF);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
            out.write(0xFF);
        } else if (value < 128) {
            out.write(value);
        } else if (value < 16384) {
            out.write(0x80 | (value >> 8));
            out.write(value & 0xFF);
        } else if (value < 2097152) {
            out.write(0xC0 | (value >> 16));
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
        } else if (value < 268435456) {
            out.write(0xE0 | (value >> 24));
            out.write((value >> 16) & 0xFF);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
        } else {
            out.write(0xF0);
            out.write((value >> 24) & 0xFF);
            out.write((value >> 16) & 0xFF);
            out.write((value >> 8) & 0xFF);
            out.write(value & 0xFF);
        }
    }

    static void writeInstructionsEncrypted(RandomAccessFile raf,
                                           List<ExtractInstruction> instructions,
                                           byte[] opcodeKey,
                                           int methodId) throws IOException {
        int blockKeyInt = generateBlockKey(methodId);

        long prevLiteralValue = 0;
        boolean hasPrevLiteral = false;

        for (ExtractInstruction insn : instructions) {
            writeVarInt(raf, insn.codeUnitOffset);
            writeVarInt(raf, insn.vmOpcode ^ xorByte(opcodeKey, 8));
            writeStringLE(raf, insn.formatName);
            writeVarInt(raf, insn.codeUnits);
            writeVarInt(raf, insn.registers.size());

            for (Integer reg : insn.registers) {
                writeVarInt(raf, reg ^ (blockKeyInt & 0xFF));
            }

            writeVarInt(raf, insn.literalType);

            boolean isOverlap = hasPrevLiteral
                    && insn.literalType > 0
                    && (insn.literalValue ^ (blockKeyInt & 0xFFFFFFFFL))
                    == (prevLiteralValue ^ (blockKeyInt & 0xFFFFFFFFL));
            raf.write(isOverlap ? 1 : 0);

            if (!isOverlap) {
                long encryptedLiteral = insn.literalValue ^ (blockKeyInt & 0xFFFFFFFFL);
                writeVarLong(raf, encryptedLiteral);
                prevLiteralValue = insn.literalValue;
                hasPrevLiteral = true;
            }

            writeVarInt(raf, insn.offsetType);
            writeVarInt(raf, insn.offsetValue ^ (blockKeyInt & 0xFF));

            writeIntLE(raf, insn.referenceType);
            writeStringLE(raf, insn.referenceData);

            writeIntLE(raf, insn.extraReferenceType);
            writeStringLE(raf, insn.extraReferenceData);
        }
    }

    static void writeVarLong(RandomAccessFile out, long value) throws IOException {
        if (value >= 0 && value < 128) {
            out.write((int)value);
        } else if (value >= -64 && value < 64) {
            out.write(0x80 | ((int)(value >> 8) & 0x3F));
            out.write((int)(value & 0xFF));
        } else {
            out.write(0xFF);
            out.write((int)((value >> 56) & 0xFF));
            out.write((int)((value >> 48) & 0xFF));
            out.write((int)((value >> 40) & 0xFF));
            out.write((int)((value >> 32) & 0xFF));
            out.write((int)((value >> 24) & 0xFF));
            out.write((int)((value >> 16) & 0xFF));
            out.write((int)((value >> 8) & 0xFF));
            out.write((int)(value & 0xFF));
        }
    }

    // 写入片段偏移表（用于碎片化）
    static void writeSingleInstructionEncrypted(RandomAccessFile raf,
                                                 ExtractInstruction insn,
                                                 byte[] opcodeKey,
                                                 int methodId) throws IOException {
        int blockKeyInt = generateBlockKey(methodId);

        writeVarInt(raf, insn.codeUnitOffset);
        writeVarInt(raf, insn.vmOpcode ^ xorByte(opcodeKey, 8));
        writeStringLE(raf, insn.formatName);
        writeVarInt(raf, insn.codeUnits);
        writeVarInt(raf, insn.registers.size());

        for (Integer reg : insn.registers) {
            writeVarInt(raf, reg ^ (blockKeyInt & 0xFF));
        }

        writeVarInt(raf, insn.literalType);

        long encryptedLiteral = insn.literalValue ^ (blockKeyInt & 0xFFFFFFFFL);
        writeVarLong(raf, encryptedLiteral);

        writeVarInt(raf, insn.offsetType);
        writeVarInt(raf, insn.offsetValue ^ (blockKeyInt & 0xFF));

        writeIntLE(raf, insn.referenceType);
        writeStringLE(raf, insn.referenceData);

        writeIntLE(raf, insn.extraReferenceType);
        writeStringLE(raf, insn.extraReferenceData);
    }

    static int generateBlockKey(int methodId) {
        int key = methodId;
        key = (key * 0x9E3779B9) ^ 0x517CC1B7;
        key = ((key >> 16) ^ key) * 0x45D9F3B;
        key = ((key >> 16) ^ key) * 0x45D9F3B;
        key = (key >> 16) ^ key;
        return key & 0xFFFFFFFF;
    }

    static byte[] computeBlockChainHash(ExtractMethodBlock block, long blockOffset, long dataLen) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(block.className.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(block.methodName.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update(block.methodSignature.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            md.update((byte)(block.methodId & 0xFF));
            md.update((byte)((block.methodId >> 8) & 0xFF));
            md.update((byte)(block.instructions.size() & 0xFF));
            md.update((byte)((block.instructions.size() >> 8) & 0xFF));
            md.update((byte)((blockOffset >> 0) & 0xFF));
            md.update((byte)((blockOffset >> 8) & 0xFF));
            md.update((byte)((blockOffset >> 16) & 0xFF));
            md.update((byte)((blockOffset >> 24) & 0xFF));
            md.update((byte)(dataLen & 0xFF));
            md.update((byte)((dataLen >> 8) & 0xFF));
            return md.digest();
        } catch (Exception e) {
            return new byte[32];
        }
    }

    static byte[] multiLayerEncrypt(byte[] data, byte[] xorKey) throws Exception {
        byte[] result = data.clone();

        for (int i = 0; i < result.length; i++) {
            result[i] = (byte)(result[i] ^ xorKey[i % xorKey.length]);
        }

        int rounds = 8;
        int keyLen = xorKey.length;
        for (int round = 0; round < rounds; round++) {
            for (int i = 0; i < result.length; i++) {
                int keyByte = xorKey[(i + round) % keyLen] & 0xFF;
                result[i] = (byte)((result[i] + keyByte) & 0xFF);
                result[i] = (byte)(((result[i] & 0xFF) << 3) | ((result[i] & 0xFF) >> 5));
                result[i] = (byte)(result[i] ^ xorKey[(i + round * 3) % keyLen]);
            }
        }

        for (int i = 0; i < result.length; i += 16) {
            int end = Math.min(i + 16, result.length);
            byte[] block = new byte[end - i];
            System.arraycopy(result, i, block, 0, block.length);
            for (int j = 0; j < block.length; j++) {
                int newPos = (j * 7) % block.length;
                result[i + newPos] = block[j];
            }
        }

        return result;
    }

    // ==================== #16 加密跳转表辅助：字节旋转混淆 ====================
            long indexTableOffset = raf.getFilePointer();
            out.offsetValue = payload.getArrayElements().size();
    static long rotateLong(long value, int seed) {
        int shift = (seed & 0x1F) + 1; // 1~32 位旋转
        if (shift == 32) shift = 0;
        long rotated = (value << shift) | (value >>> (32 - shift));
        // 涓?mask 娣峰悎
        rotated ^= ((long)seed << 16) | (seed & 0xFFFFL);
        return rotated & 0xFFFFFFFFL;
    }

    static int rotateInt(int value, int seed) {
        int shift = (seed & 0x1F) + 1; // 1~32 位旋转
        if (shift == 32) shift = 0;
        int rotated = (value << shift) | (value >>> (32 - shift));
        // 涓?mask 娣峰悎
        rotated ^= (seed & 0xFFFF);
        return rotated;
    }
    // ====================================================

}
