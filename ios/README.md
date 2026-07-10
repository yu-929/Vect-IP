# Vect IP - iOS App

Vect IP 优选器的原生 iOS 客户端。Go 引擎编译为静态链接库嵌入 App，在 iPhone 本地运行 HTTP 服务器 + WKWebView 加载界面，**完全不依赖外部服务器**。

## 项目结构

```
ios/
├── build-libvect.sh            # Go → iOS arm64 静态库编译脚本
├── VectApp.xcodeproj/           # Xcode 项目
├── VectApp/
│   ├── VectApp.swift            # App 入口，启动 Go server
│   ├── ContentView.swift        # WKWebView 加载 localhost
│   ├── WebView.swift            # WKWebView 封装
│   ├── SettingsView.swift       # 关于页面
│   ├── AppSettings.swift        # 本地服务器地址
│   ├── VectApp-Bridging-Header.h # C 桥接头，声明 StartVectServer
│   ├── Assets.xcassets/
│   └── Info.plist
├── libvect/
│   ├── server.go                # Go 源码：HTTP server + 引擎 + embed web
│   └── web/                     # 前端 HTML 资源（embed）
└── README.md
```

## 构建步骤

### 前置条件

- macOS 13+（Ventura）+ Xcode 15+
- Go 1.21+（安装：`brew install go`）
- Apple Developer 账号

### 第一步：编译 Go 静态库

```bash
cd ios
./build-libvect.sh
```

会在 `VectApp/` 目录下生成 `libvect.a` 和 `libvect.h`。

### 第二步：Xcode 编译

1. 用 Xcode 打开 `VectApp.xcodeproj`
2. 在 Signing & Capabilities 中选择自己的 Apple Team
3. 连接 iPhone 或选择模拟器
4. Cmd+R 运行

### 第三步：生成 IPA

**Archive 导出：**
1. Product > Archive
2. Distribute App > Development / Ad Hoc
3. 选择签名证书，导出 IPA

**命令行导出：**
```bash
xcodebuild archive \
  -project VectApp.xcodeproj \
  -scheme VectApp \
  -configuration Release \
  -archivePath build/VectApp.xcarchive

xcodebuild -exportArchive \
  -archivePath build/VectApp.xcarchive \
  -exportPath build/VectApp.ipa \
  -exportOptionsPlist exportOptions.plist
```

需要 `exportOptions.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>development</string>
    <key>signingStyle</key>
    <string>automatic</string>
</dict>
</plist>
```

## 工作原理

1. App 启动时 Swift 调用 `StartVectServer(8080)`（C 函数，由 Go 编译为静态库）
2. Go 引擎在后台以 goroutine 启动 HTTP 服务器监听 `127.0.0.1:8080`
3. WKWebView 加载 `http://127.0.0.1:8080`，显示前端界面
4. 扫描操作通过 HTTP API 调用本机 Go 引擎
5. **完全离线运行，不依赖任何外部服务器**

## 注意事项

- 编译 `libvect.a` 必须在 macOS 上进行（需要 iOS SDK）
- Go 引擎编译需要 `CGO_ENABLED=1` 和 iOS arm64 交叉编译工具链
- 首次构建前先运行 `./build-libvect.sh` 生成静态库
- 扫描过程会消耗网络流量和电量