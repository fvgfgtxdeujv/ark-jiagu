package com.ark.jiagu.vm;

import java.io.File;
import java.io.IOException;

/**
 * Ark 加固第二代 - 独立运行器
 *
 * <p>用法：
 * <pre>
 * java -cp "smali.jar:VmpRunner.jar" com.ark.jiagu.vm.VmpRunner \
 *     --apk input.apk \
 *     --output output(已加固).apk \
 *     --rules rules.txt \
 *     [--vmp-class com.ark.safe.VMP] \
 *     [--so-name ArkStub]
 * </pre>
 *
 * <p>rules.txt 格式（每行一条规则）：
 * <pre>
 * # 注释行以 # 开头
 * com.example.MainActivity.onCreate
 * com.example.LoginActivity.onResume
 * com.example.Payment.*
 * </pre>
 */
public class VmpRunner {

    public static void main(String[] args) throws Exception {
        Options options = parseArgs(args);

        if (options.apkFile == null || options.rulesFile == null) {
            printUsage();
            System.exit(1);
        }

        File apkFile = new File(options.apkFile);
        if (!apkFile.isFile()) {
            System.err.println("错误：APK 文件不存在：" + options.apkFile);
            System.exit(1);
        }

        String[] rules = loadRules(options.rulesFile);
        if (rules.length == 0) {
            System.err.println("错误：规则文件为空或没有有效规则");
            System.exit(1);
        }

        String outputPath = options.outputPath;
        if (outputPath == null || outputPath.trim().isEmpty()) {
            String apkName = apkFile.getName();
            String outputName = apkName.toLowerCase().endsWith(".apk")
                    ? apkName.substring(0, apkName.length() - 4) + "(已加固).apk"
                    : apkName + "(已加固).apk";
            outputPath = new File(apkFile.getParentFile(), outputName).getAbsolutePath();
        }

        String vmpClassName = options.vmpClassName != null
                ? options.vmpClassName : VmpUtils2.DEFAULT_VMP_CLASS_NAME;
        String soName = options.soName != null
                ? options.soName : VmpUtils2.DEFAULT_SO_NAME;

        System.out.println("========================================");
        System.out.println("Ark 加固第二代（嵌入式 VMP）");
        System.out.println("========================================");
        System.out.println("输入 APK：" + apkFile.getAbsolutePath());
        System.out.println("输出 APK：" + outputPath);
        System.out.println("VMP 类：" + vmpClassName);
        System.out.println("SO 名称：" + soName);
        System.out.println("规则数量：" + rules.length);
        System.out.println();

        File workDir = new File(apkFile.getParentFile(), apkFile.getName() + "_work");
        if (workDir.exists()) {
            deleteDir(workDir);
        }
        workDir.mkdirs();

        try {
            // 1. 解压 APK
            System.out.println("[1/4] 解压 APK...");
            VmpJiaguEntry.extractManifestAndDex(apkFile, workDir);

            // 2. 抽取方法
            System.out.println("[2/4] 抽取方法到 VMP bin...");
            VmpJiaguEntry.extractMethodsToBin(
                    workDir,
                    msg -> System.out.println("  " + msg),
                    rules
            );

            // 3. 重写 dex
            System.out.println("[3/4] 重写 dex（嵌入式注入 VMP 类）...");
            VmpJiaguEntry.rewriteExtractedMethodsToVmCallDex(
                    workDir,
                    msg -> System.out.println("  " + msg),
                    soName,
                    vmpClassName
            );

            // 4. 重新打包
            System.out.println("[4/4] 重新打包 APK...");
            rebuildApk(apkFile, workDir, new File(outputPath));

            System.out.println();
            System.out.println("========================================");
            System.out.println("加固完成：" + outputPath);
            System.out.println("========================================");

        } finally {
            // 清理临时目录
            if (workDir.exists()) {
                deleteDir(workDir);
            }
        }
    }

    // ==================== 参数解析 ====================

    private static class Options {
        String apkFile;
        String outputPath;
        String rulesFile;
        String vmpClassName;
        String soName;
    }

    private static Options parseArgs(String[] args) {
        Options opts = new Options();

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "--apk":
                    if (i + 1 < args.length) opts.apkFile = args[++i];
                    break;
                case "--output":
                    if (i + 1 < args.length) opts.outputPath = args[++i];
                    break;
                case "--rules":
                    if (i + 1 < args.length) opts.rulesFile = args[++i];
                    break;
                case "--vmp-class":
                    if (i + 1 < args.length) opts.vmpClassName = args[++i];
                    break;
                case "--so-name":
                    if (i + 1 < args.length) opts.soName = args[++i];
                    break;
                case "--help":
                case "-h":
                    printUsage();
                    System.exit(0);
                    break;
            }
        }

        return opts;
    }

    private static void printUsage() {
        System.out.println("Ark 加固第二代 - 嵌入式 VMP");
        System.out.println();
        System.out.println("用法：");
        System.out.println("  VmpRunner --apk <input.apk> --rules <rules.txt> [选项]");
        System.out.println();
        System.out.println("必选参数：");
        System.out.println("  --apk <path>      输入 APK 文件路径");
        System.out.println("  --rules <path>    方法规则文件路径（每行一条规则）");
        System.out.println();
        System.out.println("可选参数：");
        System.out.println("  --output <path>   输出 APK 路径（默认：原文件名(已加固).apk）");
        System.out.println("  --vmp-class <name>  VMP 类名（默认：com.ark.safe.VMP）");
        System.out.println("  --so-name <name>   SO 库名（默认：ArkStub）");
        System.out.println("  --help            显示帮助");
        System.out.println();
        System.out.println("规则文件格式（rules.txt）：");
        System.out.println("  # 注释行以 # 开头");
        System.out.println("  com.example.MainActivity.onCreate");
        System.out.println("  com.example.LoginActivity.onResume");
        System.out.println("  com.example.Payment.*");
    }

    // ==================== 辅助方法 ====================

    private static String[] loadRules(String rulesFile) throws IOException {
        File file = new File(rulesFile);
        if (!file.isFile()) {
            throw new IOException("规则文件不存在：" + rulesFile);
        }

        java.util.List<String> rules = new java.util.ArrayList<>();
        java.nio.file.Files.lines(file.toPath())
                .map(String::trim)
                .filter(line -> !line.isEmpty() && !line.startsWith("#"))
                .forEach(rules::add);

        return rules.toArray(new String[0]);
    }

    private static void rebuildApk(File originalApk, File workDir, File outputApk) throws Exception {
        java.util.Set<String> skipNames = new java.util.HashSet<>();

        // 收集原始 APK 中的 dex 名称
        try (java.util.zip.ZipFile checkZip = new java.util.zip.ZipFile(originalApk)) {
            for (int i = 1; ; i++) {
                String dexName = i == 1 ? "classes.dex" : "classes" + i + ".dex";
                java.util.zip.ZipEntry entry = checkZip.getEntry(dexName);
                if (entry == null) break;
                skipNames.add(dexName);
            }
        }

        skipNames.add("AndroidManifest.xml");

        File libDir = new File(workDir, "lib");
        if (libDir.exists() && libDir.isDirectory()) {
            collectLibSkipNames(libDir, libDir, skipNames);
        }

        try (java.util.zip.ZipFile zipFile = new java.util.zip.ZipFile(originalApk);
             java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(
                     new java.io.FileOutputStream(outputApk))) {

            zos.setLevel(9);

            java.util.Enumeration<? extends java.util.zip.ZipEntry> entries = zipFile.entries();

            while (entries.hasMoreElements()) {
                java.util.zip.ZipEntry oldEntry = entries.nextElement();
                String name = oldEntry.getName();

                if (skipNames.contains(name)) {
                    continue;
                }

                if (oldEntry.isDirectory()) {
                    addDirectoryZipEntry(zos, name, oldEntry);
                    continue;
                }

                try (java.io.InputStream in = zipFile.getInputStream(oldEntry)) {
                    addZipEntryStream(zos, name, in, oldEntry);
                }
            }

            // 写入新 dex
            File newClassesDex = new File(workDir, "classes.dex");
            try (java.io.FileInputStream in = new java.io.FileInputStream(newClassesDex)) {
                addZipEntryStream(zos, "classes.dex", in, null);
            }

            // 写入 SO
            if (libDir.exists() && libDir.isDirectory()) {
                addLibDirToZipStream(zos, libDir, libDir);
            }
        }
    }

    private static void addZipEntryStream(java.util.zip.ZipOutputStream zos, String name,
                                          java.io.InputStream in, java.util.zip.ZipEntry oldEntry) throws Exception {
        java.io.File tempFile = null;

        try {
            java.util.zip.ZipEntry newEntry = new java.util.zip.ZipEntry(name);

            if (oldEntry != null) {
                newEntry.setTime(oldEntry.getTime());
                newEntry.setComment(oldEntry.getComment());
                newEntry.setExtra(oldEntry.getExtra());
            }

            if (oldEntry != null && shouldStoreEntry(name, oldEntry)) {
                tempFile = java.io.File.createTempFile("ark_zip_", ".tmp");

                java.util.zip.CRC32 crc32 = new java.util.zip.CRC32();
                long size = 0;

                try (java.io.FileOutputStream tempOut = new java.io.FileOutputStream(tempFile)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = in.read(buffer)) != -1) {
                        tempOut.write(buffer, 0, len);
                        crc32.update(buffer, 0, len);
                        size += len;
                    }
                    tempOut.flush();
                }

                newEntry.setMethod(java.util.zip.ZipEntry.STORED);
                newEntry.setSize(size);
                newEntry.setCompressedSize(size);
                newEntry.setCrc(crc32.getValue());

                zos.putNextEntry(newEntry);

                try (java.io.FileInputStream tempIn = new java.io.FileInputStream(tempFile)) {
                    byte[] buffer = new byte[8192];
                    int len;
                    while ((len = tempIn.read(buffer)) != -1) {
                        zos.write(buffer, 0, len);
                    }
                }

                zos.closeEntry();
            } else {
                newEntry.setMethod(java.util.zip.ZipEntry.DEFLATED);

                zos.putNextEntry(newEntry);

                byte[] buffer = new byte[8192];
                int len;
                while ((len = in.read(buffer)) != -1) {
                    zos.write(buffer, 0, len);
                }

                zos.closeEntry();
            }
        } finally {
            try { in.close(); } catch (Exception ignored) {}
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }

    private static void addDirectoryZipEntry(java.util.zip.ZipOutputStream zos, String name,
                                             java.util.zip.ZipEntry oldEntry) throws Exception {
        if (!name.endsWith("/")) {
            name = name + "/";
        }

        java.util.zip.ZipEntry newEntry = new java.util.zip.ZipEntry(name);

        if (oldEntry != null) {
            newEntry.setTime(oldEntry.getTime());
            newEntry.setComment(oldEntry.getComment());
            newEntry.setExtra(oldEntry.getExtra());
        }

        zos.putNextEntry(newEntry);
        zos.closeEntry();
    }

    private static void addLibDirToZipStream(java.util.zip.ZipOutputStream zos, File rootDir, File currentDir) throws Exception {
        File[] files = currentDir.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                addLibDirToZipStream(zos, rootDir, file);
                continue;
            }

            String relativePath = rootDir.toURI().relativize(file.toURI()).getPath();
            String zipName = "lib/" + relativePath;

            try (java.io.FileInputStream in = new java.io.FileInputStream(file)) {
                addZipEntryStream(zos, zipName, in, null);
            }
        }
    }

    private static void collectLibSkipNames(File rootLibDir, File current, java.util.Set<String> skipNames) {
        File[] files = current.listFiles();
        if (files == null) return;

        for (File file : files) {
            if (file.isDirectory()) {
                collectLibSkipNames(rootLibDir, file, skipNames);
            } else {
                String rootPath = rootLibDir.getAbsolutePath();
                String filePath = file.getAbsolutePath();
                String relative = filePath.substring(rootPath.length());
                if (relative.startsWith("/") || relative.startsWith("\\")) {
                    relative = relative.substring(1);
                }
                skipNames.add("lib/" + relative.replace("\\", "/"));
            }
        }
    }

    private static boolean shouldStoreEntry(String name, java.util.zip.ZipEntry oldEntry) {
        if (oldEntry.getMethod() == java.util.zip.ZipEntry.STORED) {
            return true;
        }

        String lower = name.toLowerCase();
        return lower.endsWith(".arsc")
                || lower.endsWith(".png")
                || lower.endsWith(".jpg")
                || lower.endsWith(".jpeg")
                || lower.endsWith(".webp")
                || lower.endsWith(".mp3")
                || lower.endsWith(".mp4")
                || lower.endsWith(".ogg")
                || lower.endsWith(".wav");
    }

    private static void deleteDir(File dir) {
        if (dir == null || !dir.exists()) return;

        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                if (file.isDirectory()) {
                    deleteDir(file);
                } else {
                    file.delete();
                }
            }
        }
        dir.delete();
    }
}
