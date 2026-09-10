# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-21",
        "item_Level": "High",
        "title": "/etc/(r)syslog.conf 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "로그 저장 경로 변조 및 악의적인 로그 누락 유도를 차단하기 위해 /etc/(r)syslog.conf 파일의 소유자(root 등)와 권한(640 이하) 설정을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 존재하는 syslog 설정 파일의 소유자가 root, bin, sys 중 하나이고, 권한이 640 이하인 경우"
    }

    target_files = [
        "/etc/syslog.conf",
        "/etc/rsyslog.conf"
    ]

    allowed_uids = [0, 2, 3]
    vulnerable_elements = []
    remediation_cmds = []
    checked_files_count = 0

    for file_path in target_files:
        if not os.path.exists(file_path):
            continue

        try:
            checked_files_count += 1
            file_stat = os.stat(file_path)
            owner_uid = file_stat.st_uid
            mode = file_stat.st_mode
            permission_int = stat.S_IMODE(mode)
            permission_oct = format(permission_int, "03o")

            # 가이드라인 판단 기준: 640 이하 (소유자 rw-, 그룹 r--, 타인 권한 전무)
            excess_mask = stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
            has_excess_permission = (permission_int & excess_mask) != 0

            # 허용된 소유자가 아니거나 권한 허용 기준을 초과하면 취약 누적
            if owner_uid not in allowed_uids or has_excess_permission:
                vulnerable_elements.append(f"{os.path.basename(file_path)}(권한:{permission_oct}, UID:{owner_uid})")
                remediation_cmds.append(f"chown root {file_path} && chmod 640 {file_path}")

        except Exception:
            continue

    
    # KISA 가이드 최종 판정
    if checked_files_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 점검 대상이 되는 rsyslog.conf 및 syslog.conf 파일이 존재하지 않습니다."
        return result

    if not vulnerable_elements:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 존재하는 총 {checked_files_count}개의 로그 설정 파일 소유권 및 권한 규격(640 이하)이 모두 안전합니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 관리자 외 인가되지 않은 권한 변경 우려가 있는 취약한 로그 설정 파일이 발견되었습니다: {', '.join(vulnerable_elements)}"
        header = (
            "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 뒤쪽 명령/줄은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
        )
        result["remediation_cmd"] = header + "\n".join(remediation_cmds)

    return result