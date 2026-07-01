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
  │   └─ 输出 vmp.bin（多层加密 + 乱序方法块 + 变长编码 + HMAC 校验）
  │
  ├─ 重写原始 dex：
  │   ├─ 注入 VMP 类（com.ark.safe.VMP）
  │   │   ├─ <clinit> → System.loadLibrary("ArkStub")
  │   │   ├─ attachBaseContext（native）
  │   │   └─ callVoid/callInt/...（native，由 JNI_OnLoad 注册）
  │   │
  │   └─ 被保护方法替换为 VMP.callXxx(methodId, this, args)
  │
  ├─ 注入 lib// 目录（ArkStub SO）
  │
  └─ 重新打包 APK（原始 manifest，原始 Application）
```

## vmp.bin 文件格式

vmp.bin 是第二代嵌入式 VMP 的核心数据文件，包含所有被保护方法的指令信息。

### 文件结构（version=5）

```
┌─────────────────────────────────────────┐
│  Magic: 'A' 'V' 'M' 'P' (4 bytes)      │
├─────────────────────────────────────────┤
│  Version: 5 (4 bytes, LE int)           │
├─────────────────────────────────────────┤
│  #1 多层加密：16字节 opcode 密钥         │
├─────────────────────────────────────────┤
│  Opcode 映射表（XOR 混淆）               │
│  count → [vmOpcode, realOpcode, name]×N │
├─────────────────────────────────────────┤
│  方法索引表（#16 加密跳转表）             │
│  count → [methodId, offset, size, cs]×N │
│  offset/size 经过旋转+XOR 混淆            │
├─────────────────────────────────────────┤
│  方法块数据（#3 乱序存储）                │
│  每个块包含：                             │
│  ┌─ #13 冗余填充（前 4~32 字节垃圾）     │
│  ├─ #12 交错元数据：methodId/dexName/   │
│  │  className（头部）                    │
│  ├─ 指令数据段：#11变长编码 + #18自解密  │
│  │  + #19指令重叠 + #2分块XOR密钥       │
│  ├─ #12 交错元数据：methodName/sig/     │
│  │  flags/params（尾部）                 │
│  ├─ try-catch 块                        │
│  ├─ #6 哈希链（32字节 SHA256）           │
│  └─ #13 冗余填充（后 4~32 字节垃圾）     │
├─────────────────────────────────────────┤
│  #5 HMAC-SHA256（32字节尾部校验）        │
└─────────────────────────────────────────┘

#15 指令分片：长指令序列拆为 2~4 个碎片，
  碎片偏移表记录在方法块内，碎片散布在
  bin 文件末尾，碎片间有随机垃圾分隔。
```

### 解密流程

```
AVMX 加密文件
  │
  ├─ 第一层：XOR 解密（32字节密钥）
  │
  ├─ 第二层：#1 多层轮混淆（8轮 XOR+加法+旋转）
  │
  └─ 输出 AVMP 明文（可直接解析）
```

### 方法块读取流程

```
索引表查询 methodId
  │
  ├─ #16 逆旋转变换还原 offset/size
  ├─ #7 校验和验证
  │
  └─ 定位到方法块起始
      │
      ├─ #13 跳过前冗余填充
      ├─ #12 读取头部元数据
      ├─ #11 变长解码指令数据
      │   ├─ #18 块密钥 XOR 解密
      │   ├─ #19 指令重叠还原
      │   └─ #2 分块密钥派生
      ├─ #12 读取尾部元数据
      ├─ #6 哈希链校验
      └─ #13 跳过后冗余填充
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
| `ArkVMP.cpp` | SO 自校验 + JNI_OnLoad 注册 |
| `VmpRuntime.cpp` | VM 运行时：解析 vmp.bin → 指令分发 + SO/DEX 交叉校验 |
| `VmpInterpreter.cpp` | 指令执行引擎（控制流扁平化 dispatch） |
| `VmHandlers.cpp` | 各 dalvik 指令的 C++ 实现（含数据即代码/代码虚拟化） |
| `VmHandlers.h` | handler 函数声明 |
| `VmpParser.cpp` | vmp.bin 多层解密 + 变长解码 + 哈希链 + HMAC 校验 |
| `VmpTypes.h` | 数据结构定义（含 regPerm 寄存器混淆） |
| `VmContext.h/cpp` | VM 执行上下文（dispatch state + 寄存器映射） |
| `VmOpcodeDef.h` | Dalvik opcode 常量定义 |
| `VmOpcodeHandler.cpp` | opcode → handler 分发表 |
| `ArkAntiDebug.cpp` | 反调试检测（ptrace/Frida/Tracer/时间差） |
| `ArkAntiDebug.h` | 反调试接口声明 |

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
- vmp.bin 已实现多层加密保护：乱序存储 + 多层轮混淆 + HMAC 校验 + 索引自校验 + 哈希链

## vmp.bin 加密特性清单

| # | 特性 | 作用 | 文件 |
|---|------|------|------|
| 1 | 多层嵌套加密 | 双层密钥（XOR + 8轮轮混淆 + 字节置换） | VmpUtils.java / VmpParser.cpp |
| 2 | 分块独立加密 | 每方法块独立 XOR 密钥，密钥由 methodId 派生 | VmpUtils.java / VmpParser.cpp |
| 3 | 乱序存储 | Fisher-Yates 洗牌，方法块伪随机排列 | VmpUtils.java / VmpParser.cpp |
| 5 | HMAC-SHA256 | 全局完整性校验，密钥绑定 opcode 映射表 | VmpUtils.java / VmpParser.cpp |
| 6 | 哈希链 | 方法块间链式 SHA256 绑定，改一破全 | VmpUtils.java / VmpParser.cpp |
| 7 | 索引自校验 | 索引表 offset/size 旋转+XOR 混淆 + 校验和 | VmpUtils.java / VmpParser.cpp |
| 11 | 变长编码 | int/long 用 1~9 字节编码，小型值更紧凑 | VmpUtils.java / VmpParser.cpp |
| 12 | 字段交错存储 | 元数据（头部）→ 指令 → 元数据（尾部），破坏顺序 | VmpUtils.java / VmpParser.cpp |
| 13 | 冗余填充 | 方法块前后 4~32 字节随机垃圾，掩盖真实边界 | VmpUtils.java / VmpParser.cpp |
| 15 | 指令分片 | 长指令拆为 2~4 碎片，散布 bin 末尾 + 垃圾分隔 | VmpUtils.java / VmpParser.cpp |
| 16 | 加密跳转表 | 索引表 offset/size 旋转混淆，静态分析无法直接读取 | VmpUtils.java / VmpParser.cpp |

## 运行时加固特性清单

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
