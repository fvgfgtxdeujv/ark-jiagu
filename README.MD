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
- VMP 指令实现了 250/256 条，剩余 6 条未实现
- 加固后大概率会有问题，需要根据日志修复 VmHandlers.cpp
- 未做任何加密保护，vmp.bin 中存放明文指令

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
