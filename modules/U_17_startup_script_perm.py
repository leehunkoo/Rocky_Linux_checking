# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import glob
import os
import stat

def Check():
    result = {
        "item_id": "U-17",
        "item_Level": "High",
        "title": "시스템 시작 스크립트 권한 설정",
        "status": "Vulnerable",
        "description": "시스템 부팅 시 자동 실행되는 시작 스크립트 파일의 변조를 방지하기 위해 파일 소유자(root) 및 일반 사용자 쓰기 권한 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 시스템 시작 스크립트 파일의 소유자가 root이고, 일반 사용자(Others)의 쓰기 권한이 제거된 경우"
    }

    # Rocky Linux 시작 스크립트 및 systemd 유닛 경로
    script_patterns = [
        "/etc/rc.d/rc.local",
        "/etc/rc.local",
        "/etc/rc.d/init.d/*",
        "/etc/init.d/*",
        "/etc/rc*.d/*",
        "/etc/systemd/system/*",
        "/usr/lib/systemd/system/*"
    ]

    vulnerable_files = []
    target_files = []
    for pattern in script_patterns:
        target_files.extend(glob.glob(pattern))

    unique_real_paths = sorted(set(os.path.realpath(f) for f in target_files))

    checked_files_count = 0
    for real_path in unique_real_paths:
        if not os.path.isfile(real_path):
            continue

        try:
            checked_files_count += 1
            file_stat = os.stat(real_path)
            owner_uid = file_stat.st_uid
            mode = file_stat.st_mode
            permission_int = stat.S_IMODE(mode)

            others_writable = (permission_int & stat.S_IWOTH) != 0

            if owner_uid != 0 or others_writable:
                permission_oct = format(permission_int, "03o")
                vulnerable_files.append(f"{os.path.basename(real_path)}(권한:{permission_oct}, UID:{owner_uid})")
        except Exception:
            continue

    if checked_files_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 점검 대상 시작 스크립트가 존재하지 않습니다."
    elif not vulnerable_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 총 {checked_files_count}개의 자동 시작 스크립트 소유권(root) 및 타인 쓰기 제한 정책이 준수되고 있습니다."
    else:
        max_display = 5
        displayed_files = vulnerable_files[:max_display]
        total_vuln_count = len(vulnerable_files)

        summary_msg = f"총 {total_vuln_count}개의 시작 스크립트 설정 미흡 발견\n-> " + ", ".join(displayed_files)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 더 존재함"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 일반 사용자가 변조 가능한 취약한 시작 스크립트가 존재합니다:\n{summary_msg}"

        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "for file in " + " ".join(script_patterns) + "; do\n"
            "  if [ -f \"$file\" ]; then\n"
            "    chown root \"$file\" 2>/dev/null\n"
            "    chmod o-w \"$file\" 2>/dev/null\n"
            "  fi\n"
            "done"
        )

    return result
