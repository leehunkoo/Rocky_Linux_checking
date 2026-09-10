# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-16",
        "item_Level": "High",
        "title": "/etc/passwd 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "/etc/passwd 파일의 계정 정보 변조 및 root 권한 탈취를 차단하기 위해 파일 소유자(root)와 권한(644 이하)이 적절히 관리되는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "#[수동 점검 가이드 라인]\n"
            "ls -l /etc/passwd\n"
            "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "chown root /etc/passwd && chmod 644 /etc/passwd"
        ),
        "exception_guide": "[양호] /etc/passwd 파일의 소유자가 root 계정이고, 파일 권한이 644 이하인 경우"
    }

    file_path = "/etc/passwd"

    # 파일 존재 여부 검증
    if not os.path.exists(file_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/passwd 파일이 시스템 내에 존재하지 않아 수동 점검이 필요합니다."
        return result
    
    try:
        # 파일의 물리적 메타데이터(소유자, GID, 권한 비트) 추출
        file_stat = os.stat(file_path)
        
        owner_uid = file_stat.st_uid
        mode = file_stat.st_mode
        permission_oct = format(stat.S_IMODE(mode), "03o")
        permission_int = stat.S_IMODE(mode)

        # KISA 가이드 기준 권한 파싱 및 판정
        group_writable = (permission_int & stat.S_IWGRP) != 0
        others_writable = (permission_int & stat.S_IWOTH) != 0

        summary_msg = f"소유자 UID: {owner_uid} | 파일 권한: {permission_oct}"

        # 소유자가 root(UID 0)가 아니거나, 그룹/타인에게 쓰기 권한이 허용된 경우 취약 처리
        if owner_uid != 0:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/passwd 파일의 소유자가 root가 아닙니다. ({summary_msg})"
        elif group_writable or others_writable:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/passwd 파일의 권한 설정이 권고 기준(644 이하)을 초과했습니다. ({summary_msg})"
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] /etc/passwd 파일의 소유자 및 권한 설정이 안전합니다. ({summary_msg})"

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"/etc/passwd 속성 해석 중 예외 발생: {str(e)}"

    return result