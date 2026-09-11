# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import stat
import subprocess

def _build_open_file_paths():
    open_paths = set()
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except Exception:
        return open_paths

    for pid in pids:
        fd_dir = f"/proc/{pid}/fd"
        try:
            for fd in os.listdir(fd_dir):
                try:
                    target = os.readlink(os.path.join(fd_dir, fd))
                    if target.startswith("/"):
                        open_paths.add(target)
                except Exception:
                    continue
        except Exception:
            continue
    return open_paths

def _rpm_owns(file_path):
    """rpm -qf로 Rocky Linux 공식 패키지 소속 파일인지 확인."""
    try:
        result = subprocess.run(
            ["rpm", "-qf", file_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return result.returncode == 0
    except Exception:
        return True

def Check():
    result = {
        "item_id": "U-33",
        "item_Level": "Low",
        "title": "숨겨진 파일 및 디렉토리 검색 및 제거",
        "status": "Vulnerable",
        "description": "공격자가 백도어 및 악성 파일 은닉을 목적으로 생성해 둔 불필요하거나 의심스러운 숨겨진 파일/디렉토리 방치 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 시스템 운영 및 쉘 환경 유지에 필수적인 표준 숨김 파일을 제외하고, 불필요하거나 의심스러운 숨겨진 파일 및 디렉토리가 식별되지 않은 경우"
    }

    standard_whitelist = [
        ".profile", ".bashrc", ".bash_logout", ".bash_history", ".bash_profile",
        ".ssh", ".cache", ".local", ".config", ".gnupg", ".pam_environment",
        ".viminfo", ".lesshst", ".bash_login", ".kshrc", ".cshrc", ".login", ".exrc", ".netrc"
    ]

    search_roots = ["/root", "/tmp", "/var/tmp"]

    passwd_path = "/etc/passwd"
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip() or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 6:
                        home_dir = parts[5].strip()
                        if home_dir and os.path.isdir(home_dir) and home_dir not in ["/", "/dev", "/nonexistent"]:
                            search_roots.append(home_dir)
        except Exception:
            pass

    search_roots = sorted(list(set(search_roots)))
    suspicious_hidden_items = []

    for root_dir in search_roots:
        if not os.path.exists(root_dir):
            continue

        cmd = [
            "find", root_dir, "-xdev",
            "(",
                "-name", "node_modules", "-o", "-name", ".git", "-o", "-name", ".svn",
                "-o", "-name", "venv", "-o", "-name", ".venv", "-o", "-name", "__pycache__",
            ")",
            "-prune",
            "-o",
            "(", "-type", "f", "-o", "-type", "d", ")", "-name", ".*", "-print",
        ]

        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            stdout, _ = process.communicate()
            found_items = [line.strip() for line in stdout.splitlines() if line.strip()]

            for item in found_items:
                base_name = os.path.basename(item)
                if base_name in [".", ".."]:
                    continue

                is_safe = False
                for wl in standard_whitelist:
                    if base_name == wl or item.endswith(f"/{wl}") or f"/{wl}/" in item:
                        is_safe = True
                        break

                if not is_safe:
                    suspicious_hidden_items.append(item)
        except Exception:
            continue

    if not suspicious_hidden_items:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 점검 대상 경로 내에 시스템 표준 설정을 벗어난 의심스러운 숨겨진 파일 및 디렉토리가 발견되지 않았습니다."
        return result

    open_file_paths = None
    high_items, medium_items, low_items = [], [], []

    for item in suspicious_hidden_items:
        is_file = os.path.isfile(item) and not os.path.islink(item)
        if not is_file:
            low_items.append(item)
            continue

        try:
            mode = os.stat(item).st_mode
        except Exception:
            low_items.append(item)
            continue

        has_exec_bit = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if not has_exec_bit:
            low_items.append(item)
            continue

        if open_file_paths is None:
            open_file_paths = _build_open_file_paths()

        if item in open_file_paths:
            medium_items.append(item)
        elif _rpm_owns(item):
            low_items.append(item)
        else:
            high_items.append(item)

    total = len(suspicious_hidden_items)
    setting_lines = [
        f"[WARN] 출처가 불분명하거나 공격자가 은닉했을 위험이 있는 숨겨진 파일/디렉토리 총 {total}건 발견 "
        f"(우선검토 {len(high_items)} / 실행중-확인필요 {len(medium_items)} / 참고 {len(low_items)}건)"
    ]

    max_display = 8
    if high_items:
        setting_lines.append(
            f"[우선검토] 실행 가능 + 현재 미사용 + RPM 패키지 소속 아님:\n  "
            + "\n  ".join(high_items[:max_display])
            + (f"\n  외 {len(high_items) - max_display}건" if len(high_items) > max_display else "")
        )
    if medium_items:
        setting_lines.append(
            f"[실행중-확인필요] 실행 가능 + 프로세스 사용 중:\n  "
            + "\n  ".join(medium_items[:max_display])
            + (f"\n  외 {len(medium_items) - max_display}건" if len(medium_items) > max_display else "")
        )
    if low_items:
        setting_lines.append(
            f"[참고] 실행 비트 없음/디렉터리/RPM 패키지 소속 등 상대적으로 낮은 우선순위 {len(low_items)}건"
        )

    result["status"] = "Vulnerable"
    result["current_setting"] = "\n\n".join(setting_lines)

    banner = [
        "# [주의] rm은 되돌릴 수 없습니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤",
        "# 아래 확인 명령으로 각 항목의 실제 내용/용도를 먼저 반드시 확인하십시오.",
        "",
        "# ===== [우선검토] 먼저 확인하십시오 =====",
    ]
    cmds = []
    for item in high_items:
        cmds.append(f"ls -al {item} && file {item}")
    if medium_items:
        cmds.append("")
        cmds.append("# ===== [실행중-확인필요] 이 파일을 열고 있는 프로세스를 확인하십시오 =====")
        for item in medium_items:
            cmds.append(f"ls -al {item} && fuser -v {item}")
    if low_items:
        cmds.append("")
        cmds.append(f"# ===== [참고] {len(low_items)}건은 우선순위가 낮아 생략했습니다. =====")

    footer = [
        "",
        "# 확인 결과 불필요한 것으로 판단되는 경우에만 개별 제거",
        "# 예시: rm -f <파일>  또는  rm -rf <디렉터리>",
    ]
    result["remediation_cmd"] = "\n".join(banner + cmds + footer)

    return result
