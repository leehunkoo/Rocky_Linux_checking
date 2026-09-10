# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-05",
        "item_Level": "High",
        "title": "root 이외의 계정이 UID가 0인 경우 점검",
        "status": "Vulnerable",
        "description": "root 이외의 다른 시스템 계정이 슈퍼유저 권한(UID 0)을 중복 사용하고 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "# 예시: 위험 계정의 UID를 0 이외의 중복되지 않는 일반 UID로 변경\n# usermod -u <변경할_UID> <사용자_이름> \n# [주의] id가 하나일 경우 sudo 그룹을 꼭 넣어주어야 함.(usermod -aG wheel <username>)\n# id <username> ",
        "exception_guide": "[양호] root 계정 외에 UID가 0인 계정이 존재하지 않는 경우 (UID 값은 3번째 필드, GID 값은 4번째 필드)"
    }

    passwd_path = "/etc/passwd"

    # 파일이 존재 여부 확인
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일이 존재하지 않습니다. 시스템 환경 확인이 필요합니다."
        return result
    
    uid_zero_users = []

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 3:
                    username = parts[0]
                    uid_field = parts[2]

                    # 세 번째 필드 UID가 0인(root) 경우 탐지
                    if uid_field == '0':
                        uid_zero_users.append(username)
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일 읽기 실패: {str(e)}"
        return result
    
    # KISA 가이드 최종 판정
    if len(uid_zero_users) == 1 and "root" in uid_zero_users:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내의 UID가 0(root)인 계정은 root가 유일합니다."
    else:
        extra_user = [user for user in uid_zero_users if user != "root"]
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] root 이외에 SuperUser 권한(UID 0)을 가진 계정이 발견되었습니다: {', '.join(extra_user)}"

        # 발견된 취약 계정을 맞춤형 조치 명령어 동적 생성 표기
        if extra_user:
            cmd_list = [f"# 예시: usermod -u <변경할_UID> {user}" for user in extra_user]
            result["remediation_cmd"] = "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤, 아래 예시를 참고해 실제 UID로 바꿔서 실행하세요.\n" + "\n".join(cmd_list)

    return result