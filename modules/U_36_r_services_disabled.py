# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-36",
        "item_Level": "High",
        "title": "r 계열 서비스 비활성화",
        "status": "Vulnerable",
        "description": "인증 절차 없는 무단 원격 쉘 명령 실행 및 터미널 접속 백도어 악용을 차단하기 위해 r 계열 서비스(rlogin, rsh, rexec)의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# 1. 레거시 inetd.conf 내 r 계열 서비스(rlogin, rsh, rexec) 일괄 주석 처리\n"
            "if [ -f /etc/inetd.conf ]; then\n"
            "  sed -i 's/^\\s*rlogin/#rlogin/g' /etc/inetd.conf\n"
            "  sed -i 's/^\\s*rsh/#rsh/g' /etc/inetd.conf\n"
            "  sed -i 's/^\\s*rexec/#rexec/g' /etc/inetd.conf\n"
            "fi &&\n"
            "# 2. xinetd.d 하위 r 계열 설정 파일(rlogin, rsh, rexec) 강제 비활성화\n"
            "for rfile in rlogin rsh rexec; do\n"
            "  if [ -f /etc/xinetd.d/$rfile ]; then\n"
            "    if grep -q 'disable' /etc/xinetd.d/$rfile; then\n"
            "      sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/$rfile\n"
            "    else\n"
            "      sed -i '/}/i \\\\tdisable = yes' /etc/xinetd.d/$rfile\n"
            "    fi\n"
            "  fi\n"
            "done &&\n"
            "systemctl restart xinetd 2>/dev/null || true &&\n"
            "# 3. systemd 독립 구동형 r 계열 서비스 데몬 탐색 후 일괄 영구 정지\n"
            "for rsvc in rlogin.service rsh.service rexec.service rlogind.service rshd.service rexecd.service; do\n"
            "  if systemctl is-active --quiet $rsvc 2>/dev/null; then\n"
            "    systemctl stop $rsvc\n"
            "    systemctl disable $rsvc\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] rlogin, rsh, rexec 등 취약한 원격 제어 서비스가 비활성화되어 있거나 패키지 자체가 시스템 내에 존재하지 않는 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_dir = "/etc/xinetd.d"
    r_services = ["rlogin", "rsh", "rexec"]
    
    r_services_active = False
    detected_locations = []

    # [Step 1] /etc/inetd.conf 내 r 계열 지시어 수집 및 주석 해제 상태 진단
    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # 공백을 분리하여 행 시작이 rlogin, rsh, rexec 패턴인지 식별
                    for svc in r_services:
                        if re.search(r"^\s*" + svc + r"\s+", line):
                            r_services_active = True
                            detected_locations.append(f"inetd.conf:{svc}")
        except Exception:
            pass

    # [Step 2] /etc/xinetd.d/ 하위 서비스 정의 파일 분석
    if os.path.exists(xinetd_dir) and os.path.isdir(xinetd_dir):
        for svc in r_services:
            target_file = os.path.join(xinetd_dir, svc)
            if os.path.exists(target_file):
                try:
                    with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        # 주석 처리되지 않은 구문 중 disable = no 상태 추적
                        disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                        is_disabled = False
                        if disable_match:
                            if disable_match.group(1).lower() == "yes":
                                is_disabled = True
                        
                        # disable=yes가 명시적으로 박혀있지 않은 경우 대기 모드로 간주하여 위험 판정
                        if not is_disabled:
                            r_services_active = True
                            detected_locations.append(f"xinetd.d/{svc}")
                except Exception:
                    pass

    # [Step 3] 현대 Rocky Linux 표준 인프라 환경의 systemd 활성 유닛 스캔
    # 서비스 이름 변종 및 데몬 패턴 포괄 정의
    systemd_targets = ["rlogin.service", "rsh.service", "rexec.service", "rlogind.service", "rshd.service", "rexecd.service"]
    for svc in systemd_targets:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                r_services_active = True
                detected_locations.append(f"systemd:{svc}")
        except Exception:
            pass

    # KISA 가이드 최종 판정
    if not r_services_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] rlogin, rsh, rexec 등 인증이 생략되는 취약한 r 계열 서비스가 비활성화 상태이거나 원천 차단되어 안전합니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 별도의 인증 없이 시스템 쉘 명령이 실행될 수 있는 r 계열 서비스가 활성화되어 있습니다 -> (탐지 노출 경로: {', '.join(detected_locations)})"

    return result