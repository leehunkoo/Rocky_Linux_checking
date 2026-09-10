# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-04",
        "item_Level": "High",
        "title": "패스워드 파일 보호",
        "status": "Vulnerable",
        "description": "사용자 계정 패스워드가 암호화되어 shadow 패스워드 정책(x 표시)을 사용하는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            """
            # shadow 패스워드 전환 (모든 계정 일괄 적용)
            sudo pwconv

            # 패스워드 필드가 비어있는 계정이 있는 경우 추가 조치 필요
            # sudo passwd -l <계정명>   ← 해당 계정 잠금 처리
            """
        ),
        "exception_guide": "[양호] /etc/passwd 파일의 패스워드 필드가 모두 'x'로 표시되어 shadow 패스워드를 사용하는 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 존재 여부 확인
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일이 존재하지 않습니다. 시스템 환경 확인이 필요합니다."
        return result
    
    shadow_used = True
    no_shadow_users = []
    empty_pw_users = []

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    pw_field = parts[1]

                    if pw_field == "":
                        shadow_used = False
                        empty_pw_users.append(username)
                    elif pw_field != "x":
                        shadow_used = False
                        no_shadow_users.append(username)

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 읽기 실패: {str(e)}"
        return result

    # KISA 가이드 최종 판정
    if shadow_used:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 모든 계정의 패스워드 필드가 'x'로 표시되어 shadow 비밀번호가 정상 적용되어 있습니다."
    else:
        parts = []
        if no_shadow_users:
            parts.append(f"shadow 미적용: {', '.join(no_shadow_users)}")
        if empty_pw_users:
            parts.append(f"패스워드 없음(계정 잠금 필요): {', '.join(empty_pw_users)}")
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] {' | '.join(parts)}"

    return result    