# Vect

> 高宽之网、低延之址，可遇而不可强求。

Cloudflare IP 优选工具。基于蒙特卡洛搜索算法，用更少探测次数从网段中找出延迟更低、更稳定的 IP。另提供 Web 控制台，支持 iOS/Android 移动端发起扫描。

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

## 核心参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--budget` | 2000 | 总探测次数 |
| `--concurrency` | 200 | 并发数 |
| `--heads` | 4 | 搜索头数量（IPv6 建议 16） |
| `--top` | 20 | 输出 Top N |
| `--timeout` | 3s | 单次超时 |
| `--cidr` | - | 直接指定网段，可重复 |
| `--cidr-file` | - | 从文件读取网段 |
| `--out` | jsonl | 输出格式：text/jsonl/csv |
| `--out-file` | - | 输出到文件 |
| `-v` | 关闭 | 显示进度 |

## 算法简介

核心思路是**递进式下钻**：发现某段表现好就继续细分探索，差的区域不再浪费探测次数。

| 机制 | 作用 |
|------|------|
| 多头分散探索 | 并行探索不同区域，排斥力防止陷入同一局部最优 |
| Thompson Sampling | 自动平衡探索 vs 利用，无需手动调参 |
| 多轮取平均 | 每 IP 默认测 6 次，跳过首次握手，结果更稳定 |

## 可选功能

### 下载测速

按延迟排序后对头部 IP 进行带宽测试：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--download-top` | 5 | 测速数量（0=关闭） |
| `--download-bytes` | 50000000 | 下载字节数 |
| `--download-timeout` | 45s | 单 IP 超时 |
| `--download-url` | - | 自定义测速地址 |
| `--download-mode` | sequential | 顺序模式=直到达标 / 默认模式=固定数量 |

指定 `--download-url` 时默认下载完整文件算速度，加 `--download-bytes` 可限制读取量。

```bash
vect -v --cidr-file ./ipv4cidr.txt --download-url https://your-domain.com/largefile --out text
```

### DNS 自动上传

搜索完成后将结果推送到 DNS：

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

### CDN 节点过滤

`--colo HKG,SJC` 白名单，`--colo-exclude LAX,DFW` 黑名单，两者互斥。

## 高级参数

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
| `--seed` | 0 | 随机种子（0=时间） |
| `--host` | example.com | 目标域名 |
| `--path` | /cdn-cgi/trace | 请求路径 |

## Web 控制台

`vect-web` 提供 Web 界面，通过 iOS/Android App 或浏览器访问：

```bash
go run ./cmd/vect-web
```

Web 包含三个页面：扫描（执行搜索）、历史（查看记录）、设置（路由追踪开关及高级参数）。

## 网段文件

仓库自带 Cloudflare 高可见度网段（来源 bgp.he.net/AS13335）：

- `ipv4cidr.txt` — 约 180 万 IP
- `ipv6cidr.txt` — 约 2^56 个 IP

格式：每行一个 CIDR，支持空行和 `#` 注释。

## 构建

需要 Go 1.22+：

```bash
# 命令行工具
go build -o vect ./cmd/mcis

# Web 控制台
go build -o vect-web ./cmd/vect-web
```

## License

GNU General Public License v3.0
