# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os

def Check():
    result = {
        "item_id": "U-55",
        "item_Level": "Medium",
        "title": "FTP 계정 shell 제한",
        "status": "Vulnerable",
        "description": "FTP 서비스 계정을 통한 비인가자의 무단 원격 터미널 접속 및 시스템 명령어 실행 취약점을 원천 차단하기 위해 기본 ftp 계정의 로그인 쉘 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] FTP 서비스를 사용하지 않아 ftp 계정이 존재하지 않거나, ftp 계정의 로그인 쉘이 /bin/false 또는 /usr/sbin/nologin으로 지정되어 있는 경우"
    }

    passwd_path = "/etc/passwd"
    secure_shells = ["/bin/false", "/sbin/nologin", "/usr/sbin/nologin"]

    # 1. /etc/passwd 파일 미존재 시 예외 처리 (Manual Check)
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "[확인필요] 시스템 계정 정보 파일(/etc/passwd)이 식별되지 않아 수동 점검이 필요합니다."
        return result

    try:
        ftp_account_exists = False
        ftp_shell = ""
        
        # 2. /etc/passwd 내 ftp 계정 탐색 및 일곱 번째 쉘 필드 파싱
        with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                # 콜론(:) 구분자로 스플릿 연산 처리
                fields = line.split(":")
                if len(fields) >= 7 and fields[0] == "ftp":
                    ftp_account_exists = True
                    ftp_shell = fields[6].strip()
                    break

        # KISA 가이드 최종 판정
        if not ftp_account_exists:
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] 시스템 내에 기본 ftp 관리 계정이 존재하지 않습니다. (N/A 또는 서비스 미사용으로 안전함)"
            return result

        # 로그인 쉘의 제한 규격 충족 여부 비트 연산 대용 크로스 매칭
        if ftp_shell in secure_shells:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] 기본 ftp 계정의 로그인 쉘이 비활성 쉘({ftp_shell})로 정상 제한되어 원격 접근 위험이 통제되어 있습니다."
        else:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] ftp 계정에 쉘 권한({ftp_shell})이 부여되어 있어 비인가자가 원격 터미널 명령어를 실행할 수 있는 잠재적 위험이 존재합니다."
            result["remediation_cmd"] = (
                "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
                "usermod -s /bin/false ftp"
            )

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] 파일 파싱 중 오류가 발생했습니다: {str(e)}"

    return result