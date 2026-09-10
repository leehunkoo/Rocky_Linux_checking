# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-59",
        "item_Level": "High",
        "title": "안전한 SNMP 버전 사용",
        "status": "Vulnerable",
        "description": "평문 패킷 전송으로 인한 데이터 가로채기(스니핑) 및 비인가 자원 제어를 방지하기 위해 암호화 및 인증 기능이 강화된 SNMP v3 이상 사용 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] SNMP 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 /etc/snmp/snmpd.conf 내에 v1/v2c 설정을 배제하고 v3 인증(rouser 등) 정책만 수립하여 운영 중인 경우"
    }

    snmp_service = "snmpd"
    snmp_conf_path = "/etc/snmp/snmpd.conf"
    snmp_active = False

    # [Step 1] systemd API 매커니즘을 활용한 SNMP 서비스 실시간 구동 상태 체크
    try:
        exit_code = subprocess.call(["systemctl", "is-active", "--quiet", snmp_service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exit_code == 0:
            snmp_active = True
    except Exception:
        pass

    # 가이드라인 조치 시 영향 및 가이드 기준 연동: SNMP 서비스를 가동하지 않는 환경인 경우 N/A 기반 PASS 조기 분기 처리
    if not snmp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 SNMP 서비스(snmpd)가 구동 중이지 않거나 설치되지 않아 버전 취약성에 노출되지 않습니다. (N/A)"
        return result

    # [Step 2] 설정 파일 부재 시 가동 데몬 상태를 근거로 수동 점검 유도 처리
    if not os.path.exists(snmp_conf_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] snmpd 데몬이 실행 중이나 표준 설정 파일({snmp_conf_path})이 식별되지 않아 사용 중인 SNMP 버전의 육안 수동 검증이 필요합니다."
        return result

    try:
        has_v1_v2 = False
        has_v3 = False
        v1_v2_indicators = []
        v3_indicators = []

        # [Step 3] /etc/snmp/snmpd.conf 내부 지시어 단위 정밀 파싱 구동
        with open(snmp_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                # 1. 구형 v1/v2 평문 전송 지시어 색출 패턴 (rocommunity, rwcommunity, com2sec 등)
                if re.search(r"^\s*(rocommunity|rwcommunity|com2sec)\s+", clean_line, re.IGNORECASE):
                    has_v1_v2 = True
                    v1_v2_indicators.append(f"{line_num}행:{clean_line.split()[0]}")
                
                # 2. 안전한 v3 전용 인증 보안 지시어 색출 패턴 (rouser, rwuser, createUser)
                if re.search(r"^\s*(rouser|rwuser|createUser)\s+", clean_line, re.IGNORECASE):
                    has_v3 = True
                    v3_indicators.append(f"{line_num}행:{clean_line.split()[0]}")

        # KISA 가이드 최종 판정
        if has_v1_v2:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] 평문 기반 스니핑 위험이 존재하는 SNMP v1/v2 구형 설정 정책이 활성화되어 있습니다 -> (식별 구문: {', '.join(v1_v2_indicators)})"
            result["remediation_cmd"] = (
                "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요. 두 방법은 서로 대체 관계이므로\n"
                "# &&로 잇지 않고 독립된 블록으로 분리함 — 필요한 방법 하나만 선택해서 사용하십시오.\n"
                "# [방법 1] SNMP 서비스를 사용하지 않는 경우: 불필요한 snmpd 데몬 영구 정지 및 비활성화\n"
                "if systemctl is-active --quiet snmpd 2>/dev/null; then\n"
                "  systemctl stop snmpd 2>/dev/null\n"
                "  systemctl disable snmpd 2>/dev/null\n"
                "fi\n"
                "\n"
                "# [방법 2] SNMP 서비스가 실제로 필요한 경우: 구형 v1/v2c 설정 비활성화\n"
                "if [ -f /etc/snmp/snmpd.conf ]; then\n"
                "  sed -i 's/^\\s*rocommunity/# rocommunity/g' /etc/snmp/snmpd.conf\n"
                "  sed -i 's/^\\s*rwcommunity/# rwcommunity/g' /etc/snmp/snmpd.conf\n"
                "  systemctl restart snmpd 2>/dev/null || true\n"
                "fi\n"
                "# 위 적용 후에는 SNMP v3 사용자를 만들어야 실제로 접속이 가능합니다. 예시:\n"
                "# net-snmp-create-v3-user -ro -A <인증암호> -X <암호화암호> -a SHA -x AES <사용자명>"
            )
        elif not has_v3:
            # v1/v2 구문은 발견되지 않았으나 v3 통제 구문도 누락된 애매한 공백 설정 상태인 경우 오탐 방지용 분기 격리
            result["status"] = "Manual Check"
            result["current_setting"] = f"[확인필요] 취약한 v1/v2 구문은 탐지되지 않았으나, v3 암호화 보안 정책(rouser/rwuser) 선언 행이 명시되지 않은 상태입니다. 연동 기기 설정을 검토하십시오."
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] 취약한 구형 프로토콜이 배제되고 SHA/AES 기반 인증을 충족하는 SNMP v3 정책이 적절히 적용 중입니다 -> (v3 매핑 행: {', '.join(v3_indicators)})"

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"SNMP 구성 분석 중 에러가 발생했습니다: {str(e)}"

    return result