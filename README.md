# Scanner

Scanner 是一个使用 Go 编写的跨平台授权安全评估工具。当前版本是 MVP，已实现目标解析、TCP Connect 端口扫描、服务识别、HTTP 指纹识别、被动代理扫描、HTTPS 解密代理、漏洞情报更新，以及 JSON / HTML / CSV 报告输出。

本项目定位于合法授权的渗透测试、企业资产自查和安全评估。所有高风险能力都必须显式开启，并且默认以非破坏性检测为边界。

## 合法使用与安全边界

请仅在获得明确授权的目标上使用本工具。命令行默认要求提供 `--authorized`，否则不会开始扫描。

当前实现遵循以下边界：

- 不实现持久化、隐蔽驻留、日志绕过、恶意载荷投递、数据窃取等能力。
- 漏洞检测以“确认是否可能存在”为目标，不写入 WebShell，不执行系统命令，不读取敏感文件，不破坏数据。
- 弱口令相关能力默认关闭，并要求 `--enable-bruteforce`、速率限制、最大尝试次数、目标白名单和密码脱敏。
- 被动代理必须配置 `--proxy-allow-hosts`，避免拦截或探测非授权目标。
- 漏洞情报更新只采集元数据和参考链接，不自动下载、编译、运行或导入公开 EXP。

## 项目结构

- `cmd/scanner`：CLI 入口。
- `internal/utils`：目标输入解析。
- `internal/portscan`：高并发 TCP Connect 端口扫描。
- `internal/service`：Banner 抓取与服务识别。
- `internal/core`：统一资产、端口、指纹、漏洞和报告数据结构。
- `internal/fingerprint`：基于 YAML 规则的 HTTP 指纹识别。
- `internal/scheduler`：扫描调度、并发控制和速率限制。
- `internal/output`：JSON、HTML、CSV 报告输出。
- `internal/passive`：被动扫描规则与安全主动探测。
- `internal/proxy`：带白名单的 HTTP/HTTPS 被动代理。
- `internal/intel`：漏洞情报采集与安全 POC 候选队列。
- `internal/poc`：非破坏性 POC 插件接口。
- `internal/brute`：弱口令安全策略与脱敏逻辑。
- `fingerprints`：可扩展指纹规则。
- `docs`：架构、插件开发和漏洞情报流程文档。

更多说明：

- [架构设计](docs/architecture.md)
- [插件开发](docs/plugin-development.md)
- [漏洞情报流程](docs/vulnerability-intelligence.md)

## 构建

```bash
go build -o scanner ./cmd/scanner
```

Windows：

```powershell
go build -o scanner.exe ./cmd/scanner
```

## 基础扫描示例

```bash
scanner -t 192.168.1.1 --authorized
scanner -t 192.168.1.0/24 --authorized
scanner -t 192.168.1.1 -p 22,80,443,3306 --authorized
scanner -t 192.168.1.0/24 --service-ports web,tomcat,ssh,mysql,postgresql,redis,rabbitmq,elasticsearch,kafka --authorized
scanner -u https://example.com --webscan --authorized
scanner -f targets.txt --authorized
```

输出 HTML 报告：

```bash
scanner -t 192.168.1.1 --authorized --format html --output reports/result.html
```

使用配置文件：

```bash
scanner -t 192.168.1.1 --config config.example.yaml --authorized
```

## 已实现能力

- 单个 IP、CIDR、域名、URL、文件输入和混合目标解析。
- 目标排除：`--exclude`。
- 默认常见端口、自定义端口、端口范围、全端口扫描。
- 按服务端口组精确扫描：Web、Tomcat、SSH、FTP、MySQL、PostgreSQL、Redis、RabbitMQ、Elasticsearch、Kafka、SOCKS、FRP、HTTP Proxy 等。
- TCP Connect 扫描，并支持并发和超时控制。
- 基于端口、Banner、HTTP 响应的服务识别。
- 类似资产测绘的服务画像输出：协议、应用、产品、版本、TLS 证书、标题、标签、置信度和证据。
- HTTP Title、Server Header、X-Powered-By、Cookie、Body 关键词指纹识别。
- JSON、HTML、CSV 报告输出。
- 被动 HTTP 代理扫描。
- HTTPS 解密代理，支持自动生成本地 CA。
- 被动漏洞发现与有限的安全主动探测。
- NVD / CISA KEV 漏洞情报更新。
- 单元测试覆盖目标解析、端口解析、指纹规则、报告输出、弱口令策略、被动扫描、代理和证书生成。

## 被动代理扫描

启动 HTTP 被动代理：

```bash
scanner --passive-proxy --proxy-listen 127.0.0.1:8088 --proxy-allow-hosts example.com,*.example.org --authorized --output reports/passive.html --format html
```

然后将浏览器或测试客户端的 HTTP 代理设置为：

```text
127.0.0.1:8088
```

被动代理会记录授权目标的 HTTP 请求和响应摘要，并执行以下非破坏性检查：

- 缺失安全响应头。
- Cookie 缺少 `HttpOnly` / `Secure` / `SameSite`。
- 敏感 Token / Key 格式泄露。
- 内网 IP 泄露。
- Debug 信息和堆栈泄露。
- 目录列表。
- Git / SVN 泄露特征。
- Swagger / OpenAPI 暴露。
- Spring Boot actuator 暴露。

### 安全主动探测

默认不启用主动探测。需要显式开启：

```bash
scanner --passive-proxy --proxy-allow-hosts example.com --proxy-active-probes --proxy-max-active-per-request 4 --authorized
```

当前主动探测是有边界的安全验证，包括：

- 反射标记检测。
- 单引号触发 SQL 错误特征检测。
- 使用 `https://example.com/` 作为安全标记的开放跳转检测。

这些探测都有请求数量限制，不执行命令，不读取文件，不写入数据。

## HTTPS 解密

默认情况下，HTTPS `CONNECT` 只做隧道转发，不解密流量。

如需在授权测试中解密 HTTPS，请显式启用：

```bash
scanner --passive-proxy --proxy-https-decrypt --proxy-generate-ca --proxy-allow-hosts example.com --authorized --output reports/passive-https.html --format html
```

首次运行会生成：

- `certs/scanner-ca.pem`：需要导入浏览器或系统信任区。
- `certs/scanner-ca-key.pem`：代理用于签发临时站点证书的私钥，请妥善保管。

也可以使用自定义 CA：

```bash
scanner --passive-proxy --proxy-https-decrypt --proxy-ca-cert certs/my-ca.pem --proxy-ca-key certs/my-ca-key.pem --proxy-allow-hosts example.com --authorized
```

注意：只有 CA 公钥证书不够，例如 Burp 的 `cacert.der` 本身不能用于动态签发站点证书；HTTPS 解密需要匹配的 CA 私钥。

## 漏洞情报更新

漏洞持续更新，Scanner 提供情报更新模式，用于采集结构化漏洞元数据并生成“待人工审核”的安全 POC 候选队列。

```bash
scanner --intel-update --intel-sources nvd,kev --intel-days 7 --authorized --intel-output data/vuln-intel.json
```

当前支持：

- NVD CVE API：CVE、CVSS、CWE、参考链接等。
- CISA KEV：已知被利用漏洞目录。

设计上也支持扩展到：

- GitHub Advisory Database。
- GitHub 仓库、Issue、Release。
- 厂商安全公告。
- 博客、RSS、公众号文章归档。

安全策略：

- 只采集漏洞元数据和参考链接。
- 不自动下载 EXP。
- 不自动执行 EXP。
- 不直接把公开 EXP 转成扫描插件。
- 所有 POC 都必须人工改写为非破坏性 `safe_check=true` 检测。

## 报告格式

支持：

- `json`
- `html`
- `csv`

示例：

```bash
scanner -t 192.168.1.1 --authorized --format json --output reports/result.json
scanner -t 192.168.1.1 --authorized --format html --output reports/result.html
scanner -t 192.168.1.1 --authorized --format csv --output reports/result.csv
```

## 服务端口组

可以用 `--service-ports` 按服务类型选择端口，比全端口扫描更轻，也比默认端口更聚焦：

```bash
scanner -t 192.168.1.0/24 --service-ports mysql,redis,kafka --authorized
scanner -t 192.168.1.0/24 --service-ports web,tomcat,rabbitmq,elasticsearch --authorized
scanner -t 192.168.1.0/24 --service-ports ftp,socks,frp,proxy --authorized
scanner -t 192.168.1.1 -p 22,2222 --service-ports postsql,mysql --authorized
```

当前内置服务组：

- `web`：`80,81,443,3000,5000,5601,7001,7002,8000,8080,8081,8082,8088,8090,8099,8443,8888,9000,9080,9443,10000,18080`
- `tomcat`：`8005,8009,8080,8081,8082,8443`
- `ssh`：`22,2222`
- `ftp`：`20,21,2121`
- `mysql`：`3306,33060`
- `postgresql` / `postgres` / `postsql`：`5432,5433`
- `redis`：`6379,6380`
- `rabbitmq`：`4369,5671,5672,15671,15672,25672`
- `elasticsearch` / `es`：`9200,9300`
- `kafka`：`9092,9093,9094`
- `socks`：`1080,1081,1086,1088,9050,9150`
- `frp`：`6000,7000,7001,7400,7500`
- `proxy`：`3128,8000,8080,8081,8088,8888`

`-p` 和 `--service-ports` 可以合并使用，最终端口会自动去重并排序。

## 资产测绘输出

扫描报告会在顶层 `assets` 字段中输出资产服务画像，也会在每个主机的 `hosts[].assets` 中保留主机维度结果。字段包括：

- `host` / `port` / `transport`
- `protocol`：如 `http`、`https`、`ssh`、`ftp`、`mysql`、`postgresql`、`redis`、`amqp`、`kafka`、`socks5`、`frp` 等。
- `service`：具体服务名称，如 `rabbitmq-management`、`elasticsearch`、`tomcat-ajp`。
- `product` / `version`
- `url` / `title`
- `tls` / `tls_cn` / `tls_sans`
- `tags`：如 `web`、`database`、`message-queue`、`middleware`、`remote-access`、`file-transfer`、`proxy`、`tunnel`。
- `confidence`：识别置信度。
- `evidence`：识别依据，如端口启发、Banner、HTTP 状态、Server Header、TLS 证书等。

示例：

```bash
scanner -t 192.168.1.1 --service-ports web,mysql,redis,rabbitmq,elasticsearch,kafka --authorized --format json --output reports/assets.json
```

这类输出可用于后续做企业资产清单、暴露面统计、协议分布、重点中间件排查和漏洞情报匹配。

## 配置文件

参考 [config.example.yaml](config.example.yaml)：

```yaml
scan:
  concurrency: 200
  port_concurrency: 1000
  web_concurrency: 50
  timeout: 3s
  retries: 1
  rate_limit: 100
  safe_mode: true
```

使用：

```bash
scanner -t 192.168.1.1 --config config.example.yaml --authorized
```

## 测试

```bash
go test ./...
```

## 跨平台构建

Windows：

```bash
GOOS=windows GOARCH=amd64 go build -o dist/scanner-windows-amd64.exe ./cmd/scanner
```

Linux：

```bash
GOOS=linux GOARCH=amd64 go build -o dist/scanner-linux-amd64 ./cmd/scanner
```

macOS Intel：

```bash
GOOS=darwin GOARCH=amd64 go build -o dist/scanner-darwin-amd64 ./cmd/scanner
```

macOS Apple Silicon：

```bash
GOOS=darwin GOARCH=arm64 go build -o dist/scanner-darwin-arm64 ./cmd/scanner
```

## 后续计划

- URL 爬虫。
- 更完整的被动扫描规则。
- 更丰富的 Web 漏洞安全验证。
- 非破坏性 POC 插件框架与内置安全 POC。
- 显式授权的弱口令模块。
- 断点续扫、缓存和更强的调度器。
- GitHub Advisory、供应商公告、RSS / 公众号归档等情报源适配器。
- Web UI 和资产管理。
