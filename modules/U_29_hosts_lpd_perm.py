# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-29",
        "item_Level": "Low",
        "title": "hosts.lpd 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "로컬 프린트 서비스 오남용 및 호스트 정보 유출을 차단하기 위해 /etc/hosts.lpd 파일의 존재 여부와 소유자(root) 및 권한(600 이하)을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "chown root /etc/hosts.lpd && chmod 600 /etc/hosts.lpd"
        ),
        "exception_guide": "[양호] /etc/hosts.lpd 파일이 존재하지 않거나, 불가피하게 사용 시 파일 소유자가 root이고 권한이 600 이하인 경우"
    }

    file_path = "/etc/hosts.lpd"

    if not os.path.exists(file_path):
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 /etc/hosts.lpd 파일이 존재하지 않아 잠재적 보안 취약점이 제거된 상태입니다."
        return result
    
    try:
        # 2. 파일이 불가피하게 존재하는 경우 메타데이터 파싱 및 교차 검증
        file_stat = os.stat(file_path)
        owner_uid = file_stat.st_uid
        mode = file_stat.st_mode
        permission_oct = oct(stat.S_IMODE(mode))[2:]
        permission_int = stat.S_IMODE(mode)

        # KISA 가이드 최종 판정
        excess_mask = 0o177 | stat.S_IXUSR

        has_excess_permission = (permission_int & excess_mask) != 0
        summary_msg = f"소유자 UID: {owner_uid} | 파일 권한: {permission_oct}"

        # 소유자가 root(UID 0)가 아니거나 600 권한을 만족하지 못할 경우 취약 처리
        if owner_uid != 0:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/hosts.lpd 파일이 존재하나 소유자가 root가 아닙니다. ({summary_msg})"
        elif has_excess_permission:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/hosts.lpd 파일의 권한이 권고 기준(600 이하)을 초과했습니다. ({summary_msg})"
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] /etc/hosts.lpd 파일이 존재하나 소유자 및 권한 설정이 안전하게 수립되어 있습니다. ({summary_msg})"

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"/etc/hosts.lpd 파일 속성 해석 중 예외 발생: {str(e)}"

    return result