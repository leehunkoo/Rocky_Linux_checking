# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-38",
        "item_Level": "High",
        "title": "DoS 공격에 취약한 서비스 비활성화",
        "status": "Vulnerable",
        "description": "시스템 자원 고갈 및 정보 유출을 유발하는 DoS 취약 서비스(echo, discard, daytime, chargen) 및 다량의 트래픽을 유발할 수 있는 인프라 서비스(NTP, DNS, SNMP, SMTP)의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] if/for/&& 로 이어진 스크립트입니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤\n"
            "# (다시 sudo를 붙이지 말고) 전체를 붙여넣어 실행하세요.\n"
            "# 1. 레거시 inetd.conf 내 DoS 취약 서비스 주석 처리\n"
            "if [ -f /etc/inetd.conf ]; then\n"
            "  for svc in echo discard daytime chargen; do\n"
            "    sed -i \"s/^\\s*$svc/#$svc/g\" /etc/inetd.conf\n"
            "  done\n"
            "fi &&\n"
            "# 2. xinetd.d 하위 DoS 취약 설정 파일 강제 비활성화\n"
            "for xfile in echo discard daytime chargen; do\n"
            "  if [ -f /etc/xinetd.d/$xfile ]; then\n"
            "    if grep -q 'disable' /etc/xinetd.d/$xfile; then\n"
            "      sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/$xfile\n"
            "    else\n"
            "      sed -i '/}/i \\\\tdisable = yes' /etc/xinetd.d/$xfile\n"
            "    fi\n"
            "  fi\n"
            "done &&\n"
            "systemctl restart xinetd 2>/dev/null || service xinetd restart 2>/dev/null || true &&\n"
            "# 3. systemd 독립 구동형 DoS 취약 서비스 및 소켓 유닛 일괄 영구 정지\n"
            "for s_unit in echo discard daytime chargen; do\n"
            "  for suffix in service socket; do\n"
            "    if systemctl is-active --quiet $s_unit.$suffix 2>/dev/null; then\n"
            "      systemctl stop $s_unit.$suffix\n"
            "      systemctl disable $s_unit.$suffix\n"
            "    fi\n"
            "  done\n"
            "done\n"
            "# 4. [인프라 보완 조치] 업무상 불필요한 인프라성 서비스 추가 정지 (필요 시 선택적 가동)\n"
            "# 예시 가이드라인 커맨드:\n"
            "# systemctl stop named ntp snmpd postfix 2>/dev/null\n"
            "# systemctl disable named ntp snmpd postfix 2>/dev/null"
        ),
        "exception_guide": "[양호] echo, discard, daytime, chargen 등 DoS 취약 서비스가 모두 비활성화되어 있고, 인프라 서비스(NTP/DNS/SNMP/SMTP)가 안전하게 관리 중인 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_dir = "/etc/xinetd.d"
    
    # 1. KISA 가이드라인 명시 필수 차단 대상 4대 서비스
    core_dos_services = ["echo", "discard", "daytime", "chargen"]
    
    # 2. 제공해주신 세부 명세표 연동 추가 인프라 서비스군
    infra_services = {
        "ntp": ["ntp", "ntpd", "chrony"],
        "dns": ["named", "bind9"],
        "snmp": ["snmpd"],
        "smtp": ["postfix", "sendmail", "exim4"]
    }
    
    services_active = False
    detected_locations = []
    infra_active_details = []

    # [Step 1] /etc/inetd.conf 내 활성화 상태 점검 (핵심 DoS 서비스)
    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for svc in core_dos_services:
                        if re.search(r"^\s*" + svc + r"\s+", line):
                            services_active = True
                            detected_locations.append(f"inetd.conf:{svc}")
        except Exception:
            pass

    # [Step 2] /etc/xinetd.d/ 내부 서비스 설정 파일 검사 (핵심 DoS 서비스)
    if os.path.exists(xinetd_dir) and os.path.isdir(xinetd_dir):
        for svc in core_dos_services:
            target_file = os.path.join(xinetd_dir, svc)
            if os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                        is_disabled = False
                        if disable_match and disable_match.group(1).lower() == "yes":
                            is_disabled = True
                        
                        if not is_disabled:
                            services_active = True
                            detected_locations.append(f"xinetd.d/{svc}")
                except Exception:
                    pass

    # [Step 3] systemd 기반 핵심 DoS 서비스 및 소켓 유닛 구동 상태 스캔
    for svc in core_dos_services:
        for suffix in ["service", "socket"]:
            unit_name = f"{svc}.{suffix}"
            try:
                exit_code = subprocess.call(["systemctl", "is-active", "--quiet", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if exit_code == 0:
                    services_active = True
                    detected_locations.append(f"systemd:{unit_name}")
            except Exception:
                pass

    # [Step 4] 제공된 명세표 기반 인프라 서비스(NTP, DNS, SNMP, SMTP) 동작 정보 수집
    # 해당 서비스들은 서버의 주 용도(DNS 서버, 메일 서버 등)에 따라 활성화가 필수적일 수 있으므로
    # 핵심 DoS 서비스가 켜져 있으면 무조건 '취약', 핵심은 꺼져있으나 인프라 서비스가 켜져있다면 '확인필요(Manual Check)' 분기로 매핑하여 안정성을 보호합니다.
    for category, daemon_list in infra_services.items():
        for daemon in daemon_list:
            try:
                exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if exit_code == 0:
                    infra_active_details.append(f"{category.upper()}({daemon})")
            except Exception:
                pass

    # KISA 가이드 최종 판정
    if services_active:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] DoS 공격에 직접적으로 취약한 핵심 서비스가 활성화되어 있습니다 -> (탐지 경로: {', '.join(detected_locations)})"
    elif infra_active_details:
        # 핵심 DoS 서비스는 꺼져있으나, 트래픽 유발형 서비스가 가동 중인 경우 운영 목적 확인 프로세스로 유도 (오탐 예방)
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] 핵심 DoS 서비스는 차단되었으나, 인프라 서비스 가동이 식별되었습니다. 운영 목적(서버 용도)이 부합하는지 검토 필요 -> (활성 데몬: {', '.join(infra_active_details)})"
    else:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] echo, discard, daytime, chargen 및 추가 인프라성 서비스가 모두 안전하게 비활성화되어 DoS 요인이 통제된 상태입니다."

    return result