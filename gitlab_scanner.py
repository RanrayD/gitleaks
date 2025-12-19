import os
import shutil
import subprocess
import requests
import time
import argparse
from datetime import datetime, timezone
import csv
import math

# --- 配置区域 ---
GITLAB_URL = "http://git.ppdaicorp.com"  # GitLab 实例地址
PRIVATE_TOKEN = os.environ.get("GITLAB_TOKEN", "YOUR_PRIVATE_TOKEN")
GITLEAKS_PATH = r"D:\code_review\gitleaks\gitleaks.exe" # Gitleaks 可执行文件路径
WORK_DIR = r"D:\code_review\gitleaks\temp_scan_workspace" # 临时工作目录
REPORT_DIR = r"D:\code_review\gitleaks\reports" # 报告存放目录
DEFAULT_PROJECT_LIMIT = 500
DEFAULT_CUTOFF_DATE = "2025-07-01"
DEFAULT_BATCH_SIZE = 20 # 每批处理数量

# 确保必要的目录存在
os.makedirs(WORK_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)

def get_last_scanned_index(progress_file):
    """读取上次扫描到的项目索引"""
    if os.path.exists(progress_file):
        try:
            with open(progress_file, 'r') as f:
                return int(f.read().strip())
        except ValueError:
            return 0
    return 0

def save_progress(progress_file, index):
    """保存当前扫描进度"""
    with open(progress_file, 'w') as f:
        f.write(str(index))

def parse_gitlab_datetime(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def get_project_last_commit_time(project_id, default_branch, session, headers):
    if not default_branch:
        return None
    url = f"{GITLAB_URL}/api/v4/projects/{project_id}/repository/commits"
    params = {"ref_name": default_branch, "per_page": 1}
    response = session.get(url, headers=headers, params=params, timeout=15)
    response.raise_for_status()
    commits = response.json()
    if not commits:
        return None
    commit = commits[0]
    return parse_gitlab_datetime(commit.get("committed_date") or commit.get("created_at"))

def cleanup_dir(path):
    if not os.path.exists(path):
        return

    def remove_readonly(func, p, _):
        try:
            os.chmod(p, 0o777)
        except OSError:
            pass
        func(p)

    for attempt in range(8):
        try:
            shutil.rmtree(path, onerror=remove_readonly)
            return
        except PermissionError:
            time.sleep(0.2 * (2 ** attempt))
        except OSError:
            time.sleep(0.2 * (2 ** attempt))

    try:
        shutil.rmtree(path, onerror=remove_readonly)
    except Exception as e:
        print(f"  [X] 清理失败: {path} ({e})")

def get_projects_page(per_page, page):
    headers = {"PRIVATE-TOKEN": PRIVATE_TOKEN}
    try:
        per_page = min(100, max(1, per_page))
        page = max(1, page)
        url = f"{GITLAB_URL}/api/v4/projects?per_page={per_page}&page={page}&order_by=id&sort=asc&simple=false"
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, list) else []
    except requests.exceptions.RequestException as e:
        print(f"[!] 获取项目列表失败: {e}")

    return []

def get_projects_batch(batch_size, batch_index):
    per_page = 100
    pages_per_batch = int(math.ceil(batch_size / per_page))
    start_page = 1 + (max(1, batch_index) - 1) * pages_per_batch

    projects = []
    last_page = start_page - 1
    for p in range(start_page, start_page + pages_per_batch):
        page_projects = get_projects_page(per_page, p)
        last_page = p
        if not page_projects:
            break

        projects.extend(page_projects)
        if len(projects) >= batch_size:
            projects = projects[:batch_size]
            break

    return projects, start_page, last_page

def write_filtered_projects_header(output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "project_id",
            "name",
            "path_with_namespace",
            "web_url",
            "default_branch",
            "http_url_to_repo",
            "last_commit_time",
        ])

def append_filtered_projects_rows(output_path, projects, projects_commit_info):
    with open(output_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        for project in projects:
            project_id = project.get("id")
            dt = projects_commit_info.get(project_id, {}).get("last_commit_dt")
            writer.writerow([
                project_id,
                project.get("name", ""),
                project.get("path_with_namespace", ""),
                project.get("web_url", ""),
                project.get("default_branch", ""),
                project.get("http_url_to_repo", ""),
                dt.isoformat() if dt else "",
            ])

def export_commit_report(projects, projects_commit_info, cutoff_dt, output_path):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "project_id",
            "name",
            "path_with_namespace",
            "web_url",
            "default_branch",
            "last_commit_time",
            "meets_cutoff",
            "error",
        ])

        for project in projects:
            project_id = project.get("id")
            info = projects_commit_info.get(project_id, {})
            dt = info.get("last_commit_dt")
            meets = bool(dt and dt >= cutoff_dt)
            writer.writerow([
                project_id,
                project.get("name", ""),
                project.get("path_with_namespace", ""),
                project.get("web_url", ""),
                project.get("default_branch", ""),
                dt.isoformat() if dt else "",
                "yes" if meets else "no",
                info.get("error", ""),
            ])

def export_filtered_projects(filtered_projects, projects_commit_info, output_path, cutoff_dt):
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "project_id",
            "name",
            "path_with_namespace",
            "web_url",
            "default_branch",
            "http_url_to_repo",
        ])

        for project in filtered_projects:
            project_id = project.get("id")
            info = projects_commit_info.get(project_id, {})
            dt = info.get("last_commit_dt")
            writer.writerow([
                project_id,
                project.get("name", ""),
                project.get("path_with_namespace", ""),
                project.get("web_url", ""),
                project.get("default_branch", ""),
                project.get("http_url_to_repo", ""),
            ])

def load_projects_from_csv(input_path):
    projects = []
    with open(input_path, "r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            project_id = row.get("project_id")
            try:
                project_id = int(project_id) if project_id else None
            except ValueError:
                project_id = None

            projects.append({
                "id": project_id,
                "name": row.get("name") or "",
                "path_with_namespace": row.get("path_with_namespace") or "",
                "web_url": row.get("web_url") or "",
                "default_branch": row.get("default_branch") or "",
                "http_url_to_repo": row.get("http_url_to_repo") or "",
            })

    return projects

def parse_cutoff_date(value):
    dt = datetime.strptime(value, "%Y-%m-%d")
    return dt.replace(tzinfo=timezone.utc)

def scan_project(project, batch_id):
    """扫描单个项目"""
    project_name = project['name']
    repo_url = project['http_url_to_repo']
    if not repo_url:
        print(f"  [X] [{project_name}] 缺少 http_url_to_repo，跳过")
        return
    # 在 URL 中插入 token 以便免密 clone
    # 格式: http://oauth2:TOKEN@git.example.com/group/project.git
    auth_repo_url = repo_url.replace("http://", f"http://oauth2:{PRIVATE_TOKEN}@", 1)
    
    target_dir = os.path.join(WORK_DIR, f"{project_name}_{project['id']}")
    report_file = os.path.join(REPORT_DIR, f"batch_{batch_id}_{project_name}_{project['id']}_report.json")
    
    print(f"  > [{project_name}] 正在克隆...")
    try:
        # 1. Clone 仓库 (静默模式)
        subprocess.run(
            ["git", "clone", auth_repo_url, target_dir], 
            check=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL
        )
        
        # 2. 运行 Gitleaks 扫描
        print(f"  > [{project_name}] 正在扫描...")
        cmd = [
            GITLEAKS_PATH, "detect",
            "--source", target_dir,
            "--report-path", report_file,
            "--report-format", "json",
            "--exit-code", "0" # 即使发现泄漏也不抛出错误码，保证脚本继续运行
        ]
        
        # 可选：如果你想用自定义规则，取消下面这行的注释
        # cmd.extend(["--config", "gitleaks.toml"])
        
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # 3. 检查是否有结果
        if os.path.exists(report_file) and os.path.getsize(report_file) > 5: # >5 bytes 意味着不是空的 []
             print(f"  [!] [{project_name}] 发现疑似泄漏！报告已保存。")
        else:
             # 如果文件存在但为空数组(即无泄漏)，可以选择删除报告以节省空间
             if os.path.exists(report_file):
                 os.remove(report_file)
             print(f"  [✓] [{project_name}] 安全。")

    except subprocess.CalledProcessError as e:
        print(f"  [X] [{project_name}] 处理出错: {e}")
    except Exception as e:
        print(f"  [X] [{project_name}] 未知错误: {e}")
    finally:
        # 4. 清理：删除克隆的代码目录
        cleanup_dir(target_dir)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--export-filtered", action="store_true")
    parser.add_argument("--export-filtered-all", action="store_true")
    parser.add_argument("--scan-from-filtered", action="store_true")
    parser.add_argument("--cutoff-date", default=DEFAULT_CUTOFF_DATE)
    parser.add_argument("--page", type=int, default=1)
    parser.add_argument("--project-limit", type=int, default=DEFAULT_PROJECT_LIMIT)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--filtered-projects-file", default="")
    parser.add_argument("--progress-file", default="")
    parser.add_argument("--no-prompt", action="store_true")
    parser.add_argument("--reset-progress", action="store_true")
    args = parser.parse_args()

    cutoff_dt = parse_cutoff_date(args.cutoff_date)
    cutoff_suffix = cutoff_dt.strftime("%Y%m%d")
    batch_index = max(1, args.page)
    filtered_projects_file = args.filtered_projects_file or os.path.join(REPORT_DIR, f"filtered_projects_since_{cutoff_suffix}_page_{batch_index}.csv")
    commit_report_file = os.path.join(REPORT_DIR, f"project_last_commit_times_page_{batch_index}.csv")
    progress_file = args.progress_file or os.path.join(REPORT_DIR, f"scan_progress_since_{cutoff_suffix}_page_{batch_index}.txt")
    aggregated_filtered_file = os.path.join(REPORT_DIR, f"filtered_projects_since_{cutoff_suffix}_all.csv")

    if PRIVATE_TOKEN == "YOUR_PRIVATE_TOKEN":
        print("[!] 请先编辑脚本，填入你的 GitLab Private Token！")
        return

    project_limit = max(1, args.project_limit)
    batch_size = max(1, args.batch_size)

    if args.scan_from_filtered:
        if not os.path.exists(progress_file):
            save_progress(progress_file, 0)
        scan_projects = load_projects_from_csv(filtered_projects_file)
        total_projects = len(scan_projects)
        print(f"[*] 已从筛选文件加载项目: {filtered_projects_file} ({total_projects})")
        if total_projects == 0:
            print(f"[!] 筛选文件为空，未发现需要扫描的项目: {filtered_projects_file}")
            return
    else:
        if args.export_filtered_all:
            print(f"[*] 将按每批 {project_limit} 个项目，自动分批导出符合条件的项目列表")
            print(f"[*] 截止时间: {cutoff_dt.date()}")
            print(f"[*] 汇总输出文件: {aggregated_filtered_file}")
            write_filtered_projects_header(aggregated_filtered_file)

            total_projects_seen = 0
            total_projects_matched = 0
            batch_no = 1

            headers = {"PRIVATE-TOKEN": PRIVATE_TOKEN}
            session = requests.Session()

            while True:
                all_projects, start_page, last_page = get_projects_batch(project_limit, batch_no)
                if not all_projects:
                    break

                print(f"\n=== 导出批次 {batch_no} (API 页 {start_page}-{last_page}, 项目数 {len(all_projects)}) ===")

                projects_commit_info = {}
                for project in all_projects:
                    project_id = project.get("id")
                    default_branch = project.get("default_branch")
                    try:
                        dt = get_project_last_commit_time(project_id, default_branch, session, headers)
                        projects_commit_info[project_id] = {"last_commit_dt": dt, "error": ""}
                    except requests.exceptions.RequestException as e:
                        projects_commit_info[project_id] = {"last_commit_dt": None, "error": str(e)}
                    except ValueError as e:
                        projects_commit_info[project_id] = {"last_commit_dt": None, "error": str(e)}

                matched = []
                for project in all_projects:
                    project_id = project.get("id")
                    dt = projects_commit_info.get(project_id, {}).get("last_commit_dt")
                    if dt and dt >= cutoff_dt:
                        matched.append(project)

                append_filtered_projects_rows(aggregated_filtered_file, matched, projects_commit_info)

                total_projects_seen += len(all_projects)
                total_projects_matched += len(matched)
                print(f"[*] 本批符合条件: {len(matched)} / {len(all_projects)}")

                if len(all_projects) < project_limit:
                    break

                batch_no += 1

            if total_projects_seen == 0:
                print("[!] 未获取到任何项目，请检查 Token 权限或网络")
                return

            if total_projects_matched == 0:
                print(f"[!] 已处理 {total_projects_seen} 个项目，但没有项目满足最近提交时间 >= {cutoff_dt.date()}")
                return

            print(f"\n[+] 已处理项目总数: {total_projects_seen}")
            print(f"[+] 符合条件项目总数: {total_projects_matched}")
            print(f"[+] 汇总文件: {aggregated_filtered_file}")
            return

        print(f"[*] 正在从 {GITLAB_URL} 获取项目列表...")
        all_projects, start_page, last_page = get_projects_batch(project_limit, batch_index)
        print(f"    - 获取批次 {batch_index} (API 页 {start_page}-{last_page})，项目数: {len(all_projects)}")
        print(f"[+] 总共获取到 {len(all_projects)} 个项目")

        headers = {"PRIVATE-TOKEN": PRIVATE_TOKEN}
        session = requests.Session()
        projects_commit_info = {}

        for project in all_projects:
            project_id = project.get("id")
            default_branch = project.get("default_branch")
            try:
                dt = get_project_last_commit_time(project_id, default_branch, session, headers)
                projects_commit_info[project_id] = {"last_commit_dt": dt, "error": ""}
            except requests.exceptions.RequestException as e:
                projects_commit_info[project_id] = {"last_commit_dt": None, "error": str(e)}
            except ValueError as e:
                projects_commit_info[project_id] = {"last_commit_dt": None, "error": str(e)}

        export_commit_report(all_projects, projects_commit_info, cutoff_dt, commit_report_file)
        print(f"[*] 最近提交时间清单已生成: {commit_report_file}")

        scan_projects = []
        for project in all_projects:
            project_id = project.get("id")
            dt = projects_commit_info.get(project_id, {}).get("last_commit_dt")
            if dt and dt >= cutoff_dt:
                scan_projects.append(project)

        export_filtered_projects(scan_projects, projects_commit_info, filtered_projects_file, cutoff_dt)
        print(f"[*] 筛选项目清单已生成: {filtered_projects_file}")
        print(f"[*] 满足提交时间筛选的项目数: {len(scan_projects)} / {len(all_projects)}")
        total_projects = len(scan_projects)

        if total_projects == 0:
            print(f"[!] 前 {project_limit} 个项目中，没有项目满足最近提交时间 >= {cutoff_dt.date()}，本次不执行扫描")
            return

        if args.export_filtered:
            return
    
    start_index = get_last_scanned_index(progress_file)
    if start_index > total_projects:
        start_index = 0
        save_progress(progress_file, 0)
    if start_index > 0:
        print(f"\n[*] 检测到上次扫描进度，将从第 {start_index + 1} 个项目继续开始...")
        if args.reset_progress:
            start_index = 0
            save_progress(progress_file, 0)
            print("[*] 进度已重置，从头开始扫描。")
        elif not args.no_prompt:
            reset = input(">>> 是否重新开始所有扫描？(y/N): ")
            if reset.lower() == 'y':
                start_index = 0
                save_progress(progress_file, 0)
                print("[*] 进度已重置，从头开始扫描。")

    # 分批处理
    for i in range(start_index, total_projects, batch_size):
        batch = scan_projects[i:i + batch_size]
        batch_id = (i // batch_size) + 1
        print(f"\n=== 开始处理第 {batch_id} 批 (项目 {i+1} - {min(i+batch_size, total_projects)}) ===")
        
        for idx, project in enumerate(batch):
            scan_project(project, batch_id)
            # 实时保存进度：每处理完一个项目就保存一次，或者每批保存一次均可
            # 这里选择每处理完一个项目保存，最为保险
            current_real_index = i + idx + 1
            save_progress(progress_file, current_real_index)
            
        print(f"=== 第 {batch_id} 批处理完毕 ===")
        
        if i + batch_size < total_projects:
            if args.no_prompt:
                continue
            user_input = input("\n>>> 按回车键继续下一批扫描 (输入 'q' 退出): ")
            if user_input.lower() == 'q':
                print("[*] 用户终止扫描。")
                break

if __name__ == "__main__":
    main()
