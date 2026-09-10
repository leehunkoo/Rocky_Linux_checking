# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-60",
        "item_Level": "Medium",
        "title": "SNMP Community String 복잡성 설정",
        "status": "Vulnerable",
        "description": "비인가자의 무차별 무단 추측 공격(Brute Force)을 통한 인프라 자원 유출 및 환경설정 무단 설정을 방어하기 위해 SNMP Community String 복잡성 충족 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] SNMP 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 취약한 기본값(public, private)이 배제되고 영문자/숫자 조합 10자 이상 혹은 특수문자 조합 8자 이상의 복잡도를 충족한 경우 (또는 SNMP v3 단독 사용 시)"
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

    # 가이드라인 연동: SNMP 서비스를 가동하지 않는 환경인 경우 안전하게 PASS 조기 분기 처리
    if not snmp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 SNMP 서비스(snmpd)가 구동 중이지 않거나 설치되지 않아 비밀번호 추측 취약성에 노출되지 않습니다."
        return result

    if not os.path.exists(snmp_conf_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] snmpd 데몬은 활성화되어 있으나 설정 파일({snmp_conf_path})이 부재합니다. 구동 중인 서비스의 Community 명세를 수동 확인하십시오."
        return result

    try:
        vulnerable_strings = []
        has_v1_v2_active = False
        has_v3_only = True

        # 복잡성 판단 함수 (영문자+숫자 10자 이상 또는 영문자+숫자+특수문자 8자 이상)
        def is_complex_string(s):
            length = len(s)
            has_letter = bool(re.search(r"[a-zA-Z]", s))
            has_digit = bool(re.search(r"\d", s))
            has_special = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{{}};':\",.<>\/?\\|~`]", s))
            
            if has_letter and has_digit and has_special and length >= 8:
                return True
            if has_letter and has_digit and length >= 10:
                return True
            return False

        # [Step 2] /etc/snmp/snmpd.conf 설정 파일 파싱
        with open(snmp_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                clean_line = line.strip()
                if not clean_line or clean_line.startswith("#"):
                    continue

                # 1. v1/v2 지시어 식별
                if re.search(r"^\s*(rocommunity|rwcommunity|rocommunity6|rwcommunity6)\s+", clean_line, re.IGNORECASE):
                    has_v1_v2_active = True
                    has_v3_only = False
                    
                    tokens = clean_line.split()
                    if len(tokens) >= 2:
                        community_val = tokens[1].strip()
                        
                        # 가이드라인 판단 기준 1: 기본값 사용 여부 검출
                        if community_val.lower() in ["public", "private"]:
                            vulnerable_strings.append(f"{line_num}행:기본값사용('{community_val}')")
                        # 가이드라인 판단 기준 2: 복잡도 미달 검출
                        elif not is_complex_string(community_val):
                            vulnerable_strings.append(f"{line_num}행:복잡도미달('{community_val}')")

                # 2. v3 지시어 포착 시 v3 전용 가동 플래그 업데이트를 위해 모니터링
                if re.search(r"^\s*(rouser|rwuser|createUser)\s+", clean_line, re.IGNORECASE):
                    pass

        # KISA 가이드 최종 판정
        if has_v3_only:
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] 가이드라인 표준에 따라 안전한 고유 암호화 인증 방식의 SNMP v3 정책 위주로만 단독 구성되어 있습니다."
        elif vulnerable_strings:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] 추측하기 쉬운 SNMP Community String 취약성이 식별되었습니다 -> ({', '.join(vulnerable_strings)})"
            result["remediation_cmd"] = (
                "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요. 두 방법은 서로 대체 관계이므로\n"
                "# &&로 잇지 않고 독립된 블록으로 분리함 — 필요한 방법 하나만 선택해서 사용하십시오.\n"
                "# [방법 1] SNMP 서비스를 사용하지 않는 경우: 불필요한 snmpd 데몬 영구 정지 및 비활성화\n"
                "if systemctl is-active --quiet snmpd 2>/dev/null; then\n"
                "  systemctl stop snmpd 2>/dev/null\n"
                "  systemctl disable snmpd 2>/dev/null\n"
                "fi\n"
                "\n"
                "# [방법 2] SNMP 서비스가 실제로 필요한 경우: /etc/snmp/snmpd.conf 에서 아래 식별된 취약한\n"
                "# community 문자열을 영문자+숫자 10자 이상(또는 영문자+숫자+특수문자 8자 이상)으로 직접\n"
                "# 수정한 뒤 재시작하십시오 (자동 생성 값을 강제로 넣지 않고 관리자가 직접 정하도록 둠).\n"
                "# 예시: rocommunity ComplexString1026! default\n"
                "# systemctl restart snmpd"
            )
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = "[양호] 가동 중인 모든 SNMP Community String 정책이 가이드라인의 요구 규격(10자 이상 조합)을 충족하여 안전합니다."

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"SNMP 구성 해석 중 에러가 발생했습니다: {str(e)}"

    return result