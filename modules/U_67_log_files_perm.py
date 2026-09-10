# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import stat

_UTMP_STYLE_FILES = {"wtmp", "btmp", "lastlog"}

def _is_utmp_style_file(basename):
    return basename.split(".")[0] in _UTMP_STYLE_FILES

def Check():
    result = {
        "item_id": "U-67",
        "item_Level": "Medium",
        "title": "로그 디렉터리 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "비인가자에 의한 감사 로그 임의 훼손 및 은닉을 방지하기 위해 /var/log 디렉터리 내 주요 로그 파일들의 소유권(root)과 보안 권한(644 이하)을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] /var/log 디렉터리 내 주요 핵심 로그 파일들의 소유자가 root 또는 해당 서비스의 전용 시스템 계정이고, 파일 권한이 644 이하(단, wtmp/btmp/lastlog의 표준 그룹 쓰기 비트는 예외)인 경우"
    }

    log_dir = "/var/log"

    if not os.path.isdir(log_dir):
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] 표준 로그 보관 디렉터리({log_dir})가 식별되지 않아 수동 확인이 필요합니다."
        return result

    # Rocky Linux GID/UID 기준 (일반 사용자는 UID >= 1000)
    uid_min = 1000
    try:
        with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                if line.startswith("UID_MIN"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        uid_min = int(parts[1])
                        break
    except Exception:
        pass

    vulnerable_files = []
    remediation_cmds = []

    try:
        for root_path, dirs, files in os.walk(log_dir):
            for file_name in files:
                file_full_path = os.path.join(root_path, file_name)

                if os.path.islink(file_full_path):
                    continue

                try:
                    f_stat = os.stat(file_full_path)
                    owner_uid = f_stat.st_uid
                    mode = f_stat.st_mode
                    permission_int = stat.S_IMODE(mode)
                    permission_oct = oct(permission_int)[2:]

                    excess_mask = stat.S_IXUSR | stat.S_IWGRP | stat.S_IWOTH
                    has_excess_permission = (permission_int & excess_mask) != 0
                    if has_excess_permission and _is_utmp_style_file(file_name):
                        has_excess_permission = (permission_int & (stat.S_IXUSR | stat.S_IWOTH)) != 0

                    is_owner_bad = owner_uid != 0 and owner_uid >= uid_min

                    if is_owner_bad or has_excess_permission:
                        relative_path = os.path.relpath(file_full_path, log_dir)
                        vulnerable_files.append(f"{relative_path}(권한:{permission_oct}, UID:{owner_uid})")

                        if is_owner_bad:
                            remediation_cmds.append(f"chown root {file_full_path}")
                        if has_excess_permission:
                            if _is_utmp_style_file(file_name):
                                remediation_cmds.append(f"chmod u-x,o-w {file_full_path}")
                            else:
                                remediation_cmds.append(f"chmod 644 {file_full_path}")

                except (FileNotFoundError, PermissionError, OSError):
                    continue

        if not vulnerable_files:
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] /var/log 디렉터리 내 주요 시스템 로그 파일 소유권 및 권한(644 이하)이 적절히 관리되고 있습니다."
        else:
            display_limit = 5
            v_summary = ", ".join(vulnerable_files[:display_limit])
            if len(vulnerable_files) > display_limit:
                v_summary += f" 외 {len(vulnerable_files) - display_limit}건 더 존재"

            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] 로그 무단 유출 및 훼손에 노출된 취약 속성 로그 파일이 탐지되었습니다 -> ({v_summary})"

            banner = ["# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요."]
            result["remediation_cmd"] = "\n".join(banner + list(dict.fromkeys(remediation_cmds)))

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] 로그 디렉터리 분석 도중 예외 발생: {str(e)}"

    return result
