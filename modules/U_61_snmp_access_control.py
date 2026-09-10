# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-61",
        "item_Level": "High",
        "title": "SNMP Access Control 설정",
        "status": "Vulnerable",
        "description": "비인가자의 무단 SNMP 접근 및 원격 자원 정보 유출, 설정을 무단 변조하는 행위를 차단하기 위해 SNMP 서비스 접근 제어(IP/네트워크 제한) 수립 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] SNMP 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 /etc/snmp/snmpd.conf 내에 전역 허용(default) 구문을 배제하고 인가된 특정 IP 또는 네트워크 주소로만 접근 제어 설정을 적용한 경우"
    }

    snmp_service = "snmpd"
    snmp_conf_path = "/etc/snmp/snmpd.conf"
    snmp_active = False

    # [Step 1] systemd API 기법을 활용한 SNMP 서비스 실시간 구동 상태 체크
    try:
        exit_code = subprocess.call(["systemctl", "is-active", "--quiet", snmp_service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exit_code == 0:
            snmp_active = True
    except Exception:
        pass

    # 가이드라인 조치 시 영향 연동: SNMP 서비스를 가동하지 않는 환경인 경우 N/A 기반 PASS 처리
    if not snmp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 SNMP 서비스(snmpd)가 구동 중이지 않거나 설치되지 않아 접근 제어 취약성에 노출되지 않습니다. (N/A)"
        return result

    if not os.path.exists(snmp_conf_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] snmpd 데몬은 활성화되어 있으나 설정 파일({snmp_conf_path})이 부재합니다. 서비스 접근 제어 대상을 수동 확인하십시오."
        return result

    try:
        vulnerable_lines = []
        has_access_control = True
        has_v1_v2_active = False

        # [Step 2] /etc/snmp/snmpd.conf 설정 파일 파싱
        with open(snmp_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                # rocommunity, rwcommunity, com2sec 등 v1/v2 계열 접근 매핑 구문 분석
                if re.search(r"^\s*(rocommunity|rwcommunity|rocommunity6|rwcommunity6|com2sec)\s+", clean_line, re.IGNORECASE):
                    has_v1_v2_active = True
                    tokens = clean_line.split()
                    
                    # 지시어 형태가 주입되어 있으나 허용 타깃 명세가 아예 누락되었거나 'default'로 무차별 오픈되어 있는지 검증
                    if len(tokens) >= 2:
                        line_content_lower = clean_line.lower()
                        # default 키워드가 포함되어 있거나, 토큰 개수가 부족하여 네트워크 격리 주소가 명시되지 않은 상태 확인
                        if "default" in line_content_lower or len(tokens) < 3:
                            has_access_control = False
                            vulnerable_lines.append(f"{line_num}행:전역개방('{tokens[0]}')")

        # KISA 가이드 최종 판정
        if not has_v1_v2_active:
            # v1/v2 구문 없이 v3 중심(rouser 등 자체 ACL 내포) 구조인 경우 통과 처리
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] 기본 네트워크 보안 관리를 위해 자체적인 사용자 기반 접근 통제 프로토콜(SNMP v3) 정책을 수립하여 운용 중입니다."
        elif not has_access_control:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] 특정 호스트 IP 주소 제한 없이 전체(default)로 SNMP 접근이 개방되어 취약합니다 -> ({', '.join(vulnerable_lines)})"
            result["remediation_cmd"] = (
                "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요. 두 방법은 서로 대체 관계이므로\n"
                "# &&로 잇지 않고 독립된 블록으로 분리함 — 필요한 방법 하나만 선택해서 사용하십시오.\n"
                "# [방법 1] SNMP 서비스를 사용하지 않는 경우: 불필요한 snmpd 데몬 영구 정지 및 비활성화\n"
                "if systemctl is-active --quiet snmpd 2>/dev/null; then\n"
                "  systemctl stop snmpd 2>/dev/null\n"
                "  systemctl disable snmpd 2>/dev/null\n"
                "fi\n"
                "\n"
                "# [방법 2] SNMP 서비스가 실제로 필요한 경우: /etc/snmp/snmpd.conf 에서 아래 식별된 전역(default)\n"
                "# 허용 줄을 실제 허용할 네트워크 대역으로 직접 수정한 뒤 재시작하십시오.\n"
                "# 예시: rocommunity <String값> 192.168.1.0/24\n"
                "# systemctl restart snmpd"
            )
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] 가동 중인 모든 SNMP 커뮤니티 맵 정책에 선별적인 네트워크 범위 및 소스 IP 접근 제한 설정이 안전하게 수립되어 있습니다."

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"SNMP 접근 제어 구문 해석 중 에러가 발생했습니다: {str(e)}"

    return result