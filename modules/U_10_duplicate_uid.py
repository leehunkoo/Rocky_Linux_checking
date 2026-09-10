# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-10",
        "item_Level": "Medium",
        "title": "동일한 UID 금지",
        "status": "Vulnerable",
        "description": "/etc/passwd 파일 내 UID가 동일한 사용자 계정이 존재하여 권한 중복 및 감사 추적 방해가 발생하는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 존재 여부 검증
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일이 존재하지 않아 수동으로 점검이 필요합니다."
        return result
    
    uid_map = {}
    duplicate_violations = []

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 3:
                    username = parts[0].strip()
                    uid = parts[2].strip()

                    if uid not in uid_map:
                        uid_map[uid] = []
                    uid_map[uid].append(username)
        
        # 중복 UID 추출
        for uid, users in uid_map.items():
            if len(users) > 1:
                duplicate_violations.append(f"UID {uid} 공유 계정: ({', '.join(users)})")

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일 해석 중 오류가 발생하였습니다: {str(e)}"
        return result
    
    # KISA 가이드 최종 판정
    if not duplicate_violations:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시스템 내에 동일한 UID를 공유하여 사용하는 중복 계정이 존재하지 않습니다."

    else:
        result['status'] = "Vulnerable"
        result['current_setting'] = f"[WARN] 동일한 UID를 사용하는 계정 그룹이 발견되었습니다. -> {', '.join(duplicate_violations) }"

        remediation_cmds = [
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.",
            "# 아래 계정들 중 어떤 UID로 바꿀지는 관리자가 직접 판단해야 하므로 예시로만 제공합니다.",
        ]
        for uid, users in uid_map.items():
            if len(users) > 1:
                # 첫 번째 계정은 유지, 중복된 나머지 계정들에 대해 변경 권고 명령어 표시
                for duplicate_user in users[1:]:
                    remediation_cmds.append(f"# 예시: usermod -u <변경할_UID> {duplicate_user}")
        result["remediation_cmd"] = '\n'.join(remediation_cmds)

    return result