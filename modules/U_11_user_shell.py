# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-11",
        "item_Level": "Low",
        "title": "사용자 shell 점검",
        "status": "Vulnerable",
        "description": "로그인이 불필요한 기본/시스템 계정에 기본 쉘이 부여되어 비인가자가 이를 악용할 위험이 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "# 로그인이 불필요한 계정에 /bin/false 또는 /sbin/nologin 쉘 부여\n1. usermod -s /bin/false\n2. usermod -s /sbin/nologin\n\n** 불필요한 계정 리스트 **\n'daemon', 'bin', 'sys', 'adm', 'listen', 'nobody', 'nobody4', 'noaccess', 'diag', 'operator', 'games', 'gopher'",
        "exception_guide": "[양호] 로그인이 필요하지 않은 기본 계정에 /bin/false 또는 /sbin/nologin 쉘이 정상적으로 부여된 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 존재 여부 점검
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일이 존재하지 않아 수동 점검이 필요합니다."
        return result
    
    # KISA 가이드 기준 로그인이 불필요한 계정 목록(Default)
    unnecessary_login_users = [
        "daemon", "bin", "sys", "adm", "listen", "nobody", "nobody4", "noaccess", "diag", "operator", "games", "gopher"
    ]

    # 안전하다고 판단하는 로그인 차단 쉘 목록 (Rocky Linux)
    secure_shells = ["/bin/false","/sbin/nologin", "/usr/sbin/nologin"]

    vulnerable_accounts = []
    checked_accounts_status = []

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 7:
                    username = parts[0].strip()
                    shell = parts[6].strip()

                    # 불필요한 계정 목록(Defualt) 실제하는 경우에 검증
                    if username in unnecessary_login_users:
                        checked_accounts_status.append(f"{username}:{shell}")

                        # 차단 쉘이 부여되어 있지 않다면 취약 계정 분류
                        if shell not in secure_shells:
                            vulnerable_accounts.append(username)
    
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일 해석 중 오류가 발생하였습니다: {str(e)}"
        return result
    
    # 종합 점검 현황 텍스트 구성
    current_status_summary = f"검증 대상 상태 -> {', '.join(checked_accounts_status) if checked_accounts_status else '검증 대상 계정 없음'}"

    # KISA 가이드 최종 판정 (실제 취약 계정 유무를 기준으로 판정)
    if not vulnerable_accounts:
        result["status"] = "PASS(양호)"
        if checked_accounts_status:
            result["current_setting"] = f"[양호] 로그인이 불필요한 기본 계정에 모두 안전한 차단 쉘이 부여되어 있습니다. ({current_status_summary})"
        else:
            result["current_setting"] = "[양호] 시스템 내에 KISA 가이드에서 지정한 로그인이 불필요한 기본 계정이 존재하지 않습니다."

    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 로그인 불필요함에도 정상 로그인 쉘을 배정받은 계정이 존재합니다. {', '.join(vulnerable_accounts)} ({current_status_summary})"

        remediation_cmds = [f"usermod -s /sbin/nologin {user}" for user in vulnerable_accounts]
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result