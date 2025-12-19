快速操作清单

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
