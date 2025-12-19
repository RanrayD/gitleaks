# 使用 Gitleaks 对公司 GitLab 进行大批量 Secret 扫描：一次可复用的实践记录

本文记录“公司 GitLab 大规模密钥/敏感配置扫描”的落地实践：从安装 Gitleaks、单仓扫描，到面对上万项目时如何“先筛选、再分批、可中断可续跑”地完成审计闭环。

> 说明：文中所有 URL、Token、路径均已脱敏。请根据实际情况替换为真实环境。

---

## 1. 背景与目标

在企业 GitLab 中，密钥泄露常见于以下场景：

- **硬编码的凭据 (Hardcoded Credentials)**
  - 云服务商 AK/SK (AWS, Aliyun, Tencent Cloud, Azure, GCP)
  - 数据库连接字符串 (JDBC URL, ODBC DSN) 中包含的明文密码
  - 内部服务调用的 API Token / Secret / Auth Header
  - 测试代码中遗留的“临时”账号密码或 Mock 数据

- **配置文件误提交 (Configuration Files)**
  - `.env`, `.env.production` 等环境变量文件
  - `application.yml`, `config.json`, `settings.py` 等包含敏感信息的配置文件
  - 容器编排文件 (Kubernetes Secret manifests, Docker Compose) 中明文写入的密钥
  - Maven `settings.xml`, npm `.npmrc`, pip `pip.conf` 中包含的私有仓库认证信息

- **加密相关文件 (Encryption & Certificates)**
  - 私钥文件 (RSA, DSA, EC Private Keys, `.pem`, `.key`)
  - 证书文件 (Keystore `.jks`, `.p12`, `.pfx`) 及其密码
  - 对称加密的密钥 (AES Key) 或盐值 (Salt)

- **第三方服务集成 (Third-party SaaS)**
  - Slack Webhook URL, Discord Webhook
  - Stripe / PayPal 支付密钥
  - OpenAI API Key, DingTalk/WeChat Robot Token

- **历史记录与日志 (Git History & Logs)**
  - 密钥曾经提交过，即使后来在最新 commit 中删除，仍存在于 Git 历史 (`.git` 目录) 中
  - 调试日志 (Debug Log), 崩溃转储 (Dump files) 中包含的敏感内存数据

本次审计目标：

- 使用 **Gitleaks** 对 GitLab 项目进行 Secret 扫描
- 支持 **单仓扫描** 与 **大规模批量扫描**
- 扫描前先按“最近提交时间”筛选出近期活跃项目（例如 `2025-07-01` 之后有提交）
- 自动化分批运行，**可随时中断**，下次从进度继续，不从头再来

---

## 2. 开始前的先决条件（非常重要）

在动手之前，至少确认以下条件：

- **项目可视权限**：你的账号能看到目标群组/项目（建议使用具备全局可视或审计权限的账号）
- **合法的访问 Token**：用于调用 GitLab API / 克隆仓库
  - 建议使用最小权限原则：如果仅做读取，优先使用只读 Token（如 `read_api` / `read_repository`，以实际 GitLab 权限模型为准）
- **网络可达性**：能从扫描机器访问 GitLab Web（`https://gitlab.example.com`）与 Git 端口（HTTP/HTTPS）
- **合规/授权**：确保已获得公司内部合规授权（避免“越权扫描”）

---

## 3. 环境与依赖

本文以 Windows 为例（PowerShell）。其他系统同理。

- `Python 3.10+`（用于自动化脚本）
- `git`（用于拉取仓库）
- `gitleaks`（主扫描工具，本文使用二进制方式）

建议单独准备一个工作目录，例如：

- `D:\sec-tools\gitleaks\`
- 其中放置：`gitleaks.exe`、`gitlab_scanner.py`、输出目录 `reports\`

---

## 4. 安装 Gitleaks（Windows 二进制）

1）从官方 Releases 下载对应平台的 zip（示例：`gitleaks_8.x.x_windows_x64.zip`）。

2）解压后将 `gitleaks.exe` 放入工作目录，例如：

- `D:\sec-tools\gitleaks\gitleaks.exe`

3）验证安装：

```powershell
.\gitleaks.exe version
```

若输出版本号（如 `8.30.0`），即安装成功。

---

## 5. 基础用法：单仓扫描（默认规则）

### 5.1 克隆仓库（建议全量克隆，确保扫描历史）

```powershell
git clone https://gitlab.example.com/group/project.git
```

### 5.2 扫描并输出报告

```powershell
.\gitleaks.exe detect --source .\project --report-format json --report-path .\report.json
```

说明：

- `detect`：扫描模式
- `--source`：扫描目标目录（建议指向仓库根目录，含 `.git`）
- `--report-format json` / `--report-path`：落盘报告，便于留存审计证据

---

## 6. 自定义检测规则（关键词/内部 Token 格式）

Gitleaks 支持通过 TOML 配置自定义规则。常见场景：

- 你们内部 Token 有固定前缀/格式（如 `COMP-TOKEN-...`）
- 想对特定文件名或路径做额外检测

### 6.1 配置文件示例

创建 `gitleaks.toml`（示例）：

```toml
title = "Company Custom Rules"

[[rules]]
id = "company-internal-token"
description = "Detected internal token"
regex = '''COMP-TOKEN-[A-Za-z0-9_-]{20,}'''
tags = ["internal", "critical"]
```

### 6.2 使用自定义规则扫描

```powershell
.\gitleaks.exe detect --source .\project --config .\gitleaks.toml --report-format json --report-path .\report.json
```

提示：

- 自定义规则应尽量减少误报（正则尽量贴合真实 Token 格式）
- 对“关键字”类型的规则要谨慎：纯关键字匹配会产生大量噪声，建议结合格式、长度、前后缀等约束

---

## 7. 面对上万项目：推荐策略（筛选 + 分批 + 可续跑）

当 GitLab 项目达到上万级别时，直接全量扫描通常不现实：

- 时间成本高（仓库数量 × 拉取时间 × 扫描时间）
- IO 压力大
- 误报处理压力大

实践中更推荐先做**范围收敛**：例如“最近半年有提交/发布活动的项目优先”。

本文采用的策略：

1. **先筛选**：只保留最近提交时间在 `2025-07-01` 之后的项目（可改为你需要的日期）
2. **把筛选结果落盘**：输出为一个 CSV（包含扫描所需字段 + 最近提交时间）
3. **再从 CSV 读取进行扫描**：分批扫描（每 20 个一组）
4. **进度保存**：每处理完一个项目写入进度文件，可 `Ctrl+C` 中断，下次续跑
5. **结果落盘**：每个项目一个 JSON 报告，便于后续工单/整改跟踪

---

## 8. 自动化：批量筛选并汇总“符合条件的项目清单”（不执行扫描）

本实践脚本位于（示例）：

- `D:\sec-tools\gitleaks\gitlab_scanner.py`

### 8.1 使用环境变量传入 Token（避免硬编码）

```powershell
$env:GITLAB_TOKEN="***REDACTED***"
```

### 8.2 自动分批拉取并汇总（每批 500 个）

以下命令会：

- 每批获取 500 个项目（脚本内部会按 GitLab API `per_page=100` 分页组合）
- 计算每个项目默认分支最近提交时间
- 只把符合 `--cutoff-date` 的项目写入汇总文件
- **中间过程不扫描**

```powershell
python .\gitlab_scanner.py --export-filtered-all --cutoff-date 2025-07-01
```

输出文件（示例）：

- `reports\filtered_projects_since_20250701_all.csv`

字段：

- `project_id,name,path_with_namespace,web_url,default_branch,http_url_to_repo,last_commit_time`

> 磁盘占用说明：CSV 为纯文本，体积很小；真正占空间的是仓库克隆目录，而筛选阶段不克隆仓库，因此不会产生大量磁盘占用。

---

## 9. 从汇总 CSV 开始扫描（20 个为一组）

### 9.1 推荐：自动连续跑（非交互）

```powershell
$env:GITLAB_TOKEN="***REDACTED***"
python .\gitlab_scanner.py --scan-from-filtered --filtered-projects-file .\reports\filtered_projects_since_20250701_all.csv --batch-size 20 --no-prompt --progress-file .\reports\scan_progress_since_20250701_all.txt
```

说明：

- `--batch-size 20`：每组 20 个项目
- `--no-prompt`：不需要每批回车确认，自动连续跑
- `--progress-file ...`：指定进度文件（非常关键）

### 9.2 如何中断？如何续跑？

- **中断**：在运行脚本的终端按 `Ctrl + C`
- **续跑**：再次执行同一条命令，并保持使用同一个 `--progress-file` 路径，脚本会从上次进度继续
- **强制从头开始**：增加 `--reset-progress` 或删除进度文件

---

## 10. 扫描报告与落盘位置

默认输出目录（示例）：

- `D:\sec-tools\gitleaks\reports\`

报告文件命名示例：

- `batch_1_projectName_12345_report.json`

这样能避免不同项目重名导致报告覆盖。

当 Gitleaks 发现疑似泄漏时，报告里常见字段包括：

- `File` / `Line`：命中位置
- `RuleID`：命中规则
- `Secret` / `Match`：命中内容（注意脱敏处理）

建议在审计落地中建立以下处置流程：

- 分级：高危（有效凭据/生产配置）> 中危（疑似 Token/弱口令）> 低危（误报/测试样例）
- 处置：立即吊销/轮换 → 排查影响面 → 添加扫描规则/白名单 → 复扫验证

---

## 11. 进阶：海量报告的自动化合并 (JSON to CSV)

当扫描了数千个项目后，你会得到数千个 JSON 文件。逐个查看效率极低，推荐将其聚合为一个 CSV 表格，便于在 Excel 中进行筛选、透视和分发。

我们提供了一个专用脚本 `gitleaks_reports_to_csv.py` 来完成此任务。

### 11.1 功能特点

- **自动遍历**：递归扫描 `reports` 目录下的所有 `.json` 报告
- **字段提取**：自动提取 `File`, `RuleID`, `Author`, `Date`, `Message`, `Entropy`, `Match` 等关键字段
- **Excel 兼容**：输出的 CSV 使用 `utf-8-sig` 编码，**解决 Excel 打开中文乱码问题**

### 11.2 使用方法

```powershell
python .\gitleaks_reports_to_csv.py --reports-dir .\reports --output .\reports\gitleaks_findings.csv
```

运行后，你将得到一个 `gitleaks_findings.csv` 文件。你可以直接用 Excel 打开它，对 `RuleID` 进行数据透视，快速识别高频误报或高危泄露。

---

## 12. 常见问题与排障

### 12.1 Windows 清理目录时出现 `WinError 32`（文件占用）

在 Windows 上，`.git` 目录可能被索引/杀软短暂占用，导致删除失败。

实践处理：

- 清理逻辑增加重试与指数退避（脚本可实现）
- 即使清理失败，也不要让脚本崩溃（避免整批扫描中断）

### 12.2 API 分页与 `per_page` 上限

GitLab API 常见限制：

- `per_page` 最大通常为 `100`

因此当你希望“每批 500 个”时，需要脚本内部拉取 5 页来凑满一批。

---

## 13. 安全注意事项（务必遵守）

- Token 不要硬编码在脚本/文档里，推荐用环境变量：`$env:GITLAB_TOKEN="..."`（或 CI 的 Secret）
- 不要在终端输出、截图、报告中泄露真实密钥
- 报告文件建议受控存储（加密盘/权限隔离/最小可见范围）
- 对命中的真实凭据，优先采取“吊销/轮换”，而不是仅删除代码

---

## 14. 快速操作清单（复制即用）

**A. 汇总筛选（不扫描）**

```powershell
$env:GITLAB_TOKEN="***REDACTED***"
python .\gitlab_scanner.py --export-filtered-all --cutoff-date 2025-07-01
```

**B. 从汇总文件开始扫描（20 个一组，自动续跑）**

```powershell
$env:GITLAB_TOKEN="***REDACTED***"
python .\gitlab_scanner.py --scan-from-filtered --filtered-projects-file .\reports\filtered_projects_since_20250701_all.csv --batch-size 20 --no-prompt --progress-file .\reports\scan_progress_since_20250701_all.txt
```

**C. 中断/续跑**

- 中断：`Ctrl + C`
- 续跑：重复执行 B（同一个 `--progress-file`）

**D. 报告合并 (JSON -> CSV)**

```powershell
python .\gitleaks_reports_to_csv.py --reports-dir .\reports --output .\reports\gitleaks_findings.csv
```

---

到这里，你就拥有了一个可复用的企业级 Secret 扫描工作流：**先收敛范围，再批量扫描，结果可追溯，进度可续跑**。如果你后续希望进一步降低误报（例如引入自定义规则、白名单、或二次校验），建议在现有规则基础上逐步迭代，不要一开始就写大量“纯关键字”规则。
