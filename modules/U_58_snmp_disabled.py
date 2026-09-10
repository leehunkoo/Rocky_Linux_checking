# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import subprocess

def Check():
    result = {
        "item_id": "U-58",
        "item_Level": "Medium",
        "title": "불필요한 SNMP 서비스 구동 점검",
        "status": "Vulnerable",
        "description": "비인가자의 악의적인 시스템 정보 수집 및 중요 인프라 환경 설정 무단 변조를 차단하기 위해 원칙적으로 금지된 SNMP 서비스의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] SNMP 서비스를 사용하지 않아 관련 데몬 유닛이 완전히 비활성화되어 있거나 시스템 내에 설치되지 않은 경우"
    }

    snmp_service = "snmpd"
    snmp_active = False

    # [Step 1] systemd API 매커니즘을 활용하여 snmpd 서비스의 실시간 활성 구동 상태 추적
    try:
        # systemctl is-active 실행 결과 코드가 0이면 현재 동작 중인 프로세스로 판정
        exit_code = subprocess.call(["systemctl", "is-active", "--quiet", snmp_service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exit_code == 0:
            snmp_active = True
    except Exception:
        pass

    # KISA 가이드 최종 판정
    if not snmp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 불필요한 SNMP 서비스(snmpd)가 가동 중이지 않거나 설치되지 않아 정보 유출 취약성이 차단되어 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 원격 정보 노출 위험이 있는 SNMP 서비스 데몬({snmp_service})이 가동 중으로 식별되었습니다."
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "# 1. systemd 기반 활성 구동형 SNMP 서비스 데몬 영구 정지 및 비활성화\n"
            "if systemctl is-active --quiet snmpd 2>/dev/null; then\n"
            "  systemctl stop snmpd 2>/dev/null\n"
            "  systemctl disable snmpd 2>/dev/null\n"
            "fi"
        )

    return result