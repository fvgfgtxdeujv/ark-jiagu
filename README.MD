# Ark 加固 2.1 By：菜鸟八哥

第二代嵌入式 VMP 加固工具，相比第一代的主要改进：

## 第二代 vs 第一代

| 特性 | 第一代（旧） | 第二代（新） |
|------|------------|------------|
| 壳方案 | StubApp 壳 dex + 壳 SO + manifest 劫持 | 无壳，VMP 类直接注入原始 dex |
| SO 加载 | StubApp.<clinit> 通过 System.setProperty 触发 | VMP.<clinit> 直接 System.loadLibrary |
| 方法选择 | 自动扫描所有 Activity.onCreate | 用户手动配置 `类名.方法名` 规则 |
| Manifest 修改 | 劫持 Application 指向 StubApp | 不修改，原始入口保持不变 |
| native 注册 | 通过 System.getProperty("ark") 查找壳类名 | 直接 FindClass("com/ark/safe/VMP") |
| 脱壳难度 | 需要脱壳 dex + 还原 StubApp | 直接在原始 dex 中分析 VMP |

## 第二代架构

```
原始 APK
  │
  ├─ 解压 dex + manifest
  │
  ├─ 按规则抽取指定方法的 dalvik 指令
  │   └─ 输出 vmp.bin（指令映射表 + 方法索引表 + 加密的方法数据）
  │
  ├─ 重写原始 dex：
  │   ├─ 注入 VMP 类（com.ark.safe.VMP）
  │   │   ├─ <clinit> → System.loadLibrary("ArkStub")
  │   │   ├─ attachBaseContext（native）
  │   │   └─ callVoid/callInt/...（native，由 JNI_OnLoad 注册）
  │   │
  │   └─ 被保护方法替换为 VMP.callXxx(methodId, this, args)
  │
  ├─ 注入 lib/ 目录（ArkStub SO）
  │
  └─ 重新打包 APK（原始 manifest，原始 Application）
```

## 方法规则配置

规则文件格式（每行一条）：

```
# 注释以 # 开头
# 格式：包名.类名.方法名

# 保护单个方法
com.example.app.MainActivity.onCreate
com.example.app.LoginActivity.onResume

# 通配符：保护某个类的所有方法
com.example.app.PaymentActivity.*

# 保护加密/签名相关方法
com.example.crypto.CryptoUtils.decrypt
com.example.security.SignVerifier.verify
```

规则匹配逻辑：
- `*` 匹配任意包名/类名/方法名
- `com.example.A.*` 匹配 A 的所有方法
- `*.B.onCreate` 匹配任意包下的 B.onCreate

## 源码文件说明

### Java 层

| 文件 | 说明 |
|------|------|
| `VmpUtils.java` | 核心工具类：dex 解析、指令提取、bin 文件生成、方法重写 |
| `VmpUtils2.java` | **新增**：第二代 VMP 类生成器，生成带 `<clinit>` 的嵌入式 VMP 类 |
| `VmpJiaguEntry.java` | 加固入口：解压 APK → 抽取 → 重写 dex |
| `VmpRunner.java` | **新增**：命令行独立运行器，脱离 Android 环境也能用 |
| `MainActivity.java` | Android GUI：设置方法规则 → 执行加固 |

### C++ 层

| 文件 | 说明 |
|------|------|
| `ArkVMP.cpp` | **修改**：去掉 `getStubClassNameFromProperty`，直接注册到 `com/ark/safe/VMP` |
| `VmpRuntime.cpp` | VM 运行时：解析 vmp.bin → 指令分发 |
| `VmpInterpreter.cpp` | 指令执行引擎 |
| `VmHandlers.cpp` | 各 dalvik 指令的 C++ 实现 |
| `VmpParser.cpp` | vmp.bin 解析器 |

## SO 加载流程

```
VMP 类被 dexclassfinde（首次调用被保护方法时）
  → <clinit> 执行
  → System.loadLibrary("ArkStub")
  → SO 加载
  → JNI_OnLoad 被调用
  → FindClass("com/ark/safe/VMP")
  → RegisterNatives 注册 callVoid/callInt/...
  → 后续 VMP.callXxx 调用进入 native 层
  → VmpRuntime_Execute → VmpInterpreter_Execute
```

## 使用方式

### Android GUI
1. 打开应用，点击设置
2. 配置方法规则（每行一条 `类名.方法名`）
3. 选择 VMP 类名（默认 com.ark.safe.VMP）
4. 选择 SO 名称（默认 ArkStub）
5. 选择要加固的 APK
6. 点击加固

### 命令行
```bash
java -cp "smali.jar:VmpRunner.jar" com.ark.jiagu.vm.VmpRunner \
    --apk input.apk \
    --rules rules.txt \
    --output output.apk
```

## 声明

本源码属于半成品，仅用作学习交流。
- VMP 指令已实现全部 256 条 dalvik 指令（含 INVOKE_CUSTOM_RANGE、CONST_METHOD_HANDLE、CONST_METHOD_TYPE）
- 加固后大概率会有问题，需要根据日志修复 VmHandlers.cpp
- 未做任何加密保护，vmp.bin 中存放明文指令

## 已实现的加固特性（魔改清单）

| # | 特性 | 实现位置 | git commit |
|---|------|---------|------------|
| 1 | JNI_OnLoad ptrace 自关联检测 | ArkAntiDebug.cpp | 魔改#1-4 |
| 2 | Frida 检测（maps + fd） | ArkAntiDebug.cpp | 魔改#1-4 |
| 3 | Tracer 检测（TracerPid + getppid） | ArkAntiDebug.cpp | 魔改#1-4 |
| 4 | 时间差检测（单步跟踪检测） | ArkAntiDebug.cpp | 魔改#1-4 |
| 5 | Opcode 随机化（每次加固不同映射表） | VmpUtils.java / VmpParser.cpp | 魔改#5 |
| 6 | 假指令插入（NOP 混淆） | VmpJiaguEntry.java | 魔改#6 |
| 7 | 寄存器别名（随机偏移寄存器索引） | VmpUtils.java / VmpTypes.h | 魔改#7 |
| 8 | 常量池加密（字面量 XOR 混淆） | VmpUtils.java / VmpParser.cpp | 魔改#8 |
| 9 | SO 自校验（CRC32 定期检测） | ArkVMP.cpp / VmpRuntime.cpp | 魔改#9 |
| 10 | DEX 完整性校验（SHA256） | ArkAntiDebug.cpp | 魔改#10 |
| 11 | 多级交叉校验（SO↔DEX 绑定） | ArkAntiDebug.cpp | 魔改#11 |
| 12 | 签名链（方法块 SHA256 防篡改） | VmpUtils.java / VmpParser.cpp | 魔改#12 |
| 13 | 控制流扁平化（dispatch state 替代 pc++） | VmpInterpreter.cpp | 魔改#13 |
| 14 | 不透明谓词（IF_NEZ/IF_EQZ 永远分支） | VmpJiaguEntry.java | 魔改#14 |
| 15 | 代码虚拟化（嵌套迷你 VM 执行加密字节码） | VmHandlers.cpp | 魔改#15 |
| 16 | 栈混淆（运行时动态寄存器映射 regPerm） | VmContext.h / VmContext.cpp | 魔改#16 |
| 18 | 自解密（每方法块独立 XOR 密钥） | VmpUtils.java / VmpParser.cpp | 魔改#18 |
| 19 | 指令重叠（相邻指令共享字面量） | VmpUtils.java / VmpParser.cpp | 魔改#19 |
| 20 | 垃圾指令增强（5种类型：MOVE/AND/OR/XOR/ADD） | VmpJiaguEntry.java | 魔改#20 |
| 21 | 跳转混淆（try-catch 代替直接跳转） | VmpJiaguEntry.java | 魔改#21 |
| 22 | 数据即代码（VMOP_EXEC_DATA 迷你解释器） | VmHandlers.cpp | 魔改#22 |

## 原始代码

原始代码（被 VMP 保护前）：
```java
protected void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView(R.layout.activity_main);
}
```

VMP 保护后：
```java
protected void onCreate(Bundle bundle) {
    VMP.callVoid(1, this, new Object[]{bundle});
}
```
