# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-08",
        "item_Level": "Midium",
        "title": "관리자 그룹에 최소한의 계정 포함",
        "status": "Vulnerable",
        "description": "시스템 관리자 그룹(root)에 권한 남용을 방지하기 위해 최소한의 허용된 계정만 존재하고 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "#[관리자 그룹에 포함된 불필요한 계정을 그룹원에서 제거 방법 가이드]\ngpasswd -d <username> root\n[수동 점검]\ncat /etc/group | grep -E '(root)'",
        "exception_guide": "[양호] 관리자 그룹(root)에 root 계정 외에 불필요한 관리 목적 이외의 계정이 등록되어 있지 않은 경우"
    }

    group_path = "/etc/group"

    # 파일 존재 여부 검증
    if not os.path.exists(group_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{group_path} 설정 파일이 존재하지 않아 수동으로 확인이 필요합니다."
        return result
    
    root_group_members = []
    root_group_found = False

    try:
        with open(group_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 4 and parts[0] == "root":
                    root_group_found = True

                    # 4번째 필드에 쉼표? 구분 된 그룹원 리스트 파싱
                    members_str = parts[3].strip()
                    if members_str:
                        root_group_members = [m.strip() for m in members_str.split(",") if m.strip()]
                    break

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{group_path} 파일 읽기 실패: {str(e)}"
        return result
    
    # 예외 케이스: 파일 내 root 그룹 정의가 누락 된 경우
    if not root_group_found:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{group_path} 파일 내 root 그룹 정보가 발견되지 않았습니다."
        return result
    
    # KISA 가이드 최종 판정
    # root 혼자 있거나, 비어있는 경우(UID 매핑으로 root만 적용됨으로 안전)
    unnecessary_members = [user for user in root_group_members if user != "root"]

    summary_msg = f"현재 root 그룹 등록 계정: [{', '.join(root_group_members) if root_group_members else '없음(기본 값)'}]"

    if not unnecessary_members:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 관리자 그룹에 불필요한 인가 외 계정이 존재하지 않습니다. ({summary_msg})"

    else:
        result["status"] = "Vulnerable"
        result['current_setting'] = f"[WRAN] 관리자 그룹에 인가되지 않은 계정이 등록되어 권한 남용 위험이 있습니다: {', '.join(unnecessary_members)} ({summary_msg})"

        # 불필요한 계정을 그룹에서 제거 하는 방법(gpasswd -d)
        remediation_cmds = [f"gpasswd -d {user} root" for user in unnecessary_members]
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result