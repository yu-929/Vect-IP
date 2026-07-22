# Cloudflare VECT 矢量优选工具

基于蒙特卡洛搜索算法的 Cloudflare IP 优选工具，用更少探测次数从海量网段中找出延迟低、速度快、稳定性好的 IP。

## 特性

- **智能搜索** — 递进式下钻 + Thompson Sampling，自动平衡探索与利用
- **下载测速** — 对候选 IP 执行真实带宽测试，筛选高速节点
- **SpeedFusion 综合评分** — 搜索阶段融合下载速度，排序同时考虑延迟和带宽
- **Jitter 抖动感知** — 多轮探测自动计算抖动，过滤不稳定的 IP
- **Colo 多样性** — 强制结果覆盖不同数据中心，避免单点依赖
- **跳过失败轮次** — 探测失败后快速跳过，不浪费预算
- **Web 控制台** — 浏览器 / iOS / Android 均可操作，支持实时进度推送
- **DNS 自动上传** — 扫描完成后自动推送到 Cloudflare / Vercel DNS
- **GitHub 上传** — 支持将结果上传到 GitHub 仓库
- **路由追踪** — 探测路径可视化，了解网络拓扑
- **ASN 信息** — 自动识别 IP 所属 ASN 和运营商
- **自定义测速地址** — 支持任意 HTTP 下载测速 URL

## 安装

```bash
curl -sL https://raw.githubusercontent.com/yu-929/Vect-IP/main/install.sh | bash
```

或从 [Release](https://github.com/yu-929/Vect-IP/releases/latest) 下载二进制。

更新：`curl -sL https://raw.githubusercontent.com/yu-929/Vect-IP/main/install.sh | bash -s update`
卸载：`curl -sL https://raw.githubusercontent.com/yu-929/Vect-IP/main/install.sh | bash -s uninstall`

## 快速开始

```bash
vect -v --budget 3000 --concurrency 100 --cidr-file ./ipv4cidr.txt --out text
```

## CLI 参数

### 搜索参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--budget` | 2000 | 总探测次数 |
| `--concurrency` | 200 | 并发数 |
| `--heads` | 4 | 搜索头数量（IPv6 建议 16） |
| `--top` | 20 | 输出 Top N |
| `--timeout` | 3s | 单次探测超时 |
| `--cidr` | - | 直接指定网段，可重复 |
| `--cidr-file` | - | 从文件读取网段 |
| `--out` | jsonl | 输出格式：text/jsonl/csv |
| `--out-file` | - | 输出到文件 |
| `-v` | 关闭 | 显示进度 |
| `--seed` | 0 | 随机种子（0=时间） |
| `--colo` | - | 数据中心白名单（逗号分隔） |
| `--colo-exclude` | - | 数据中心黑名单（逗号分隔） |

### 下载测速

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--download-top` | 5 | 测速数量（0=关闭） |
| `--download-bytes` | 50000000 | 下载字节数 |
| `--download-timeout` | 45s | 单 IP 超时 |
| `--download-url` | - | 自定义测速地址 |
| `--download-mode` | sequential | 顺序模式=直到达标 / 默认模式=固定数量 |
| `--download-concurrency` | 5 | 测速并发数 |

### SpeedFusion 综合评分

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--speed-fusion` | 关闭 | 搜索阶段融合下载速度到评分 |

SpeedFusion 开启后，搜索过程中对每个候选 IP 做轻量下载测速（100KB），
综合评分 = 延迟 - 下载速度 * 0.5，搜索方向同时受延迟和速度影响。
搜索结束后对全部候选运行完整下载测速，按准确速度重新排序。

### 高级参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--beam` | 32 | 每搜索头候选数 |
| `--diversity-weight` | 0.3 | 多样性权重 |
| `--split-interval` | 20 | 拆分检查间隔 |
| `--min-samples-split` | 5 | 最小采样数 |
| `--split-step-v4` | 2 | IPv4 下钻步长 |
| `--split-step-v6` | 4 | IPv6 下钻步长 |
| `--max-bits-v4` | 24 | IPv4 最大前缀 |
| `--max-bits-v6` | 56 | IPv6 最大前缀 |
| `--rounds` | 6 | 每 IP 测试轮次 |
| `--skip-first` | 1 | 跳过前 N 次 |
| `--host` | example.com | 目标域名 |
| `--path` | /cdn-cgi/trace | 请求路径 |
| `--jitter-fusion` | 关闭 | 抖动融入评分（ScoreMS += Jitter * 0.3） |
| `--skip-failed-rounds` | 关闭 | 失败轮次快速跳过 |
| `--colo-diversity` | 关闭 | 强制结果覆盖不同数据中心 |

### DNS 上传

| 参数 | 说明 |
|------|------|
| `--dns-provider` | cloudflare 或 vercel |
| `--dns-token` | API Token（或环境变量 `CF_API_TOKEN` / `VERCEL_TOKEN`） |
| `--dns-zone` | Zone ID 或域名 |
| `--dns-subdomain` | 子域名前缀 |
| `--dns-upload-count` | 上传数量 |

```bash
export CF_API_TOKEN="xxx" CF_ZONE_ID="xxx"
vect --cidr-file ./ipv4cidr.txt --dns-provider cloudflare --dns-subdomain cf -v
```

## 算法

核心思路是**递进式下钻**：发现某段表现好就继续细分探索，差的区域不再浪费探测次数。

| 机制 | 作用 |
|------|------|
| 多头分散探索 | 并行探索不同区域，排斥力防止陷入同一局部最优 |
| Thompson Sampling | 自动平衡探索 vs 利用，无需手动调参 |
| 多轮取平均 | 每 IP 默认测 6 次，跳过首次握手，结果更稳定 |
| 递进式下钻 | 好段继续细分，差段放弃，逐步收敛到最优区域 |

### SpeedFusion 综合评分

SpeedFusion 将带宽测试融入搜索过程：

1. **搜索阶段** — 每探测一个候选 IP，做完延迟探测后立即做一次轻量下载测速（100KB）
2. **综合评分** — `ScoreMS = TotalMS + JitterMS*0.3 - DownloadMbps*0.5`
3. **智能筛选** — `TopNCollector` 使用综合评分决定保留哪些候选
4. **后处理** — 对所有候选运行完整下载测速，用准确数据重新排序

相比传统"先搜索延迟再测速"的方案，搜索阶段融合速度能更早排除速度快但延迟差的节点，搜索结果更精准。

### 核心参数建议

| 场景 | budget | concurrency | heads | 说明 |
|------|--------|-------------|-------|------|
| 快速测试 | 500 | 50 | 4 | 几秒出结果 |
| 日常使用 | 2000 | 100 | 4 | 1-2 分钟 |
| 深度优选 | 5000 | 200 | 4 | 3-5 分钟 |
| IPv6 扫描 | 3000 | 200 | 16 | 更多头搜索大空间 |

## Web 控制台

`vect-web` 提供 Web 界面，支持浏览器 / iOS / Android 访问：

```bash
# 直接运行
go run ./cmd/vect-web

# 或构建后运行
go build -o vect-web ./cmd/vect-web
./vect-web
```

默认监听 `:8080`，打开浏览器访问即可。

### 功能

- **扫描页** — 配置参数、发起扫描、实时查看进度和结果
- **历史页** — 查看历史扫描记录，支持 DNS/GitHub 上传
- **设置页** — 路由追踪、SpeedFusion、Jitter 融合、Colo 多样性等高级开关

![Web 控制台](https://raw.githubusercontent.com/yu-929/Vect-IP/main/logo/web.png)

## 移动端

### iOS

从 Release 下载 `.ipa`，通过侧载安装。支持 Web 控制台全部功能。

### Android

从 Release 下载 `.apk` 直接安装。支持 Web 控制台全部功能。

## 网段文件

仓库自带 Cloudflare 高可见度网段（来源 bgp.he.net/AS13335）：

- `ipv4cidr.txt` — 约 180 万 IP
- `ipv6cidr.txt` — 约 2^56 个 IP

格式：每行一个 CIDR，支持空行和 `#` 注释。

## 构建

需要 Go 1.20+：

```bash
# 命令行工具
go build -o vect ./cmd/vect

# Web 控制台
go build -o vect-web ./cmd/vect-web
```

## License

GNU General Public License v3.0