# 用户指令记忆

## 格式

### 项目知识条目
Agent 在任务执行过程中发现的条目应遵循以下格式：

[项目知识摘要]
- Date: [YYYY-MM-DD]
- Context: Agent 在执行 [具体任务描述] 时发现
- Category: [运维部署|构建方法|测试方法|排错调试|工作流协作|环境配置]
- Instructions:
  - [具体的知识点，逐行描述]

## 条目

[Android 构建：x86_64 模拟器兼容性]
- Date: 2026-07-14
- Context: Agent 修复 Android APK 在雷电模拟器 9 上崩溃的问题时发现
- Category: 构建方法
- Instructions:
  - 雷电模拟器等 x86_64 Android 模拟器无法直接运行 ARM64 Go 二进制（二进制翻译层不支持 Go 运行时的某些指令，即使是被条件分支保护的 LSE 指令也会导致 SIGILL）
  - 必须编译 x86_64 (amd64) 版本：`GOARCH=amd64 GOOS=linux CGO_ENABLED=0 go build -buildmode=pie`，然后用 `patchelf --set-interpreter "/system/bin/linker64"` 修改解释器
  - 运行时通过 `Build.SUPPORTED_64_BIT_ABIS` 检测架构，选择对应二进制：`x86_64` → `vect_server_amd64`，否则 → `vect_server_arm64`
  - APK assets 中需同时包含两个架构的二进制文件