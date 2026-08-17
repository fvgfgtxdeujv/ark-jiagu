# ark-jiagu 加固流水线修复进度

## 目标
修复 ark-jiagu VMP 加固流水线，使 LogFox 加固后能正常安装、启动、运行。

## 已完成修复（全部编译通过，已推送 `git@github.com:fvgfgtxdeujv/ark-jiagu.git`）

| 提交 | 内容 |
|------|------|
| `a9b6b0a` | 方法抽取规则改为类前缀匹配子包（修复"抽取 0 个方法"） |
| `9f64dcb` | VMP 类名经 `System.getProperty("ark")` 动态传递（修复 JNI 注册隐患） |
| `df168eb` | call 方法补齐 isDebuggable 4 参 + IF_EQZ 改 Format21t |
| `a2d21e0` | 开发模式单方法/单类出错跳过，方便测试 |
| `b7a5224` | 35c 寄存器计数修正（getApplicationInfo A=6→3） |
| `8560576` | RETURN 指令改 Format11x |
| `1de0d1d` | 类型描述符补齐 `L...;` 格式（修复崩溃日志根因） |
| `f81447c` | isDebuggable 改反射获取 Application，规避 hidden API 限制 |
| `e308ad1` | 反射结果 CHECK_CAST 为 Context，修复 VerifyError |

## 崩溃日志根因
`Invalid type descriptor: 'android/app/ActivityThread'`：
- isDebuggable 方法 6 处类型引用使用裸类型名，dex 校验失败导致壳 APK 启动崩溃
- 已在 `1de0d1d` 修复

## 验证情况
- JVM 端到端测试通过：实际执行加固代码生成壳 dex，写读回校验全部引用合法
- `ActivityThread.currentApplication()` 属 hidden API greylist，允许调用，无风险

## 待办
- 在手机上重装 `app-debug.apk`，重新加固 LogFox 测试
- 若有新崩溃日志，继续排查
