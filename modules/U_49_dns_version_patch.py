# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import subprocess

def Check():
    result = {
        "item_id": "U-49",
        "item_Level": "High",
        "title": "DNS 보안 버전 패치",
        "status": "Vulnerable",
        "description": "DoS 공격 및 네임서버 원격 침입 취약점을 차단하기 위해 가동 중인 BIND(named) 서비스의 보안 패치 및 최신 버전 유지 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] DNS 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 주기적인 패치 관리를 통해 최신 보안 버전을 유지하고 있는 경우"
    }

    dns_service = "named"
    dns_active = False

    try:
        exit_code = subprocess.call(["systemctl", "is-active", "--quiet", dns_service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exit_code == 0:
            dns_active = True
    except Exception:
        pass

    if not dns_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 BIND(named) DNS 서비스가 활성화되어 있지 않습니다. (네임서버 미사용 상태로 해당없음 N/A 처리)"
        return result

    bind_version = "버전 획득 실패"
    try:
        version_out = subprocess.check_output(["named", "-v"], text=True, stderr=subprocess.DEVNULL)
        if version_out:
            bind_version = version_out.strip()
    except Exception:
        pass

    result["status"] = "Manual Check"
    result["current_setting"] = f"[확인필요] 현재 BIND DNS 서비스가 가동 중입니다. 최신 보안 패치 적용 여부를 검토하십시오 -> (현재 실행 버전: {bind_version})"

    result["remediation_cmd"] = (
        "# [방법 1] DNS 서비스를 사용하지 않는 경우: named 데몬 정지 및 비활성화\n"
        "if systemctl is-active --quiet named 2>/dev/null; then\n"
        "  systemctl stop named 2>/dev/null\n"
        "  systemctl disable named 2>/dev/null\n"
        "fi\n"
        "\n"
        "# [방법 2] DNS 서비스가 필요한 경우: dnf를 통한 BIND 패키지 최신화\n"
        "dnf update -y bind bind-utils"
    )

    return result
