# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-19",
        "item_Level": "High",
        "title": "/etc/hosts 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "/etc/hosts 파일의 임의 변조를 통한 DNS 방해 및 파밍(Pharming) 공격을 방지하기 위해 파일 소유자(root)와 권한(644 이하)이 적절히 관리되는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "chown root /etc/hosts && chmod 644 /etc/hosts"
        ),
        "exception_guide": "[양호] /etc/hosts 파일의 소유자가 root 계정이고, 파일 권한이 644 이하인 경우"
    }

    file_path = "/etc/hosts"

    # 1. 파일 존재 여부 검증
    if not os.path.exists(file_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/hosts 파일이 시스템 내에 존재하지 않아 수동 점검이 필요합니다."
        return result

    try:
        file_stat = os.stat(file_path)
        
        owner_uid = file_stat.st_uid
        mode = file_stat.st_mode
        permission_oct = format(stat.S_IMODE(mode), "03o") # 8진수 문자열 반환 (예: '644')
        permission_int = stat.S_IMODE(mode)

        # KISA 가이드 최종 판정
        group_writable = (permission_int & stat.S_IWGRP) != 0
        others_writable = (permission_int & stat.S_IWOTH) != 0

        summary_msg = f"소유자 UID: {owner_uid} | 파일 권한: {permission_oct}"

        # 소유자가 root(UID 0)가 아니거나, 그룹/타인에게 쓰기 권한이 허용된 경우 취약 처리
        if owner_uid != 0:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/hosts 파일의 소유자가 root가 아닙니다. ({summary_msg})"
        elif group_writable or others_writable:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/hosts 파일의 권한 설정이 권고 기준(644 이하)을 초과했습니다. ({summary_msg})"
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] /etc/hosts 파일의 소유자 및 권한 설정이 안전합니다. ({summary_msg})"

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"/etc/hosts 속성 해석 중 예외 발생: {str(e)}"

    return result