# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-52",
        "item_Level": "Medium",
        "title": "Telnet 서비스 비활성화",
        "status": "Vulnerable",
        "description": "원격 접속 시 평문 전송으로 인한 스니핑 및 계정/중요 정보 유출을 차단하기 위해 취약한 Telnet 프로토콜의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 원격 접속용 Telnet 서비스가 비활성화되어 있거나 시스템 내에 관련 서비스 데몬 및 패키지가 설치되지 않은 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_path = "/etc/xinetd.d/telnet"
    
    telnet_active = False
    detected_locations = []

    # [Step 1] /etc/inetd.conf 내 Telnet 지시어의 활성화 상태 파싱
    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if re.search(r"^\s*telnet\s+", line):
                        telnet_active = True
                        detected_locations.append("inetd.conf:telnet")
                        break
        except Exception:
            pass

    # [Step 2] /etc/xinetd.d/telnet 파일 내 disable 설정 유무 검사
    if os.path.exists(xinetd_path):
        try:
            with open(xinetd_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                is_disabled = False
                if disable_match and disable_match.group(1).lower() == "yes":
                    is_disabled = True
                
                if not is_disabled:
                    telnet_active = True
                    detected_locations.append("xinetd.d/telnet")
        except Exception:
            pass

    # [Step 3] systemd 기반 telnet 서비스 및 소켓 아키텍처 구동 상태 스캔
    systemd_telnet_targets = ["telnet.socket", "telnet.service", "telnetd.service", "telnetd.socket"]
    for unit_name in systemd_telnet_targets:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                telnet_active = True
                detected_locations.append(f"systemd:{unit_name}")
        except Exception:
            pass

    # KISA 가이드 최종 판정
    if not telnet_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 평문 도청 취약점이 존재하는 Telnet 원격 접속 서비스가 비활성화 상태이거나 설치되지 않아 안전합니다."
    else:
        unique_locations = sorted(list(set(detected_locations)))
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 평문 암호 노출 위험이 있는 취약한 Telnet 원격 제어 서비스가 활성화되어 있습니다 -> (탐지 경로: {', '.join(unique_locations)})"

        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 전체를 붙여넣어 실행하세요.\n"
            "# 1. 레거시 inetd.conf 내 telnet 서비스 주석 처리\n"
            "if [ -f /etc/inetd.conf ]; then\n"
            "  sed -i 's/^\\s*telnet/#telnet/g' /etc/inetd.conf\n"
            "fi &&\n"
            "# 2. xinetd.d 하위 telnet 설정 파일 강제 비활성화\n"
            "if [ -f /etc/xinetd.d/telnet ]; then\n"
            "  if grep -q 'disable' /etc/xinetd.d/telnet; then\n"
            "    sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/telnet\n"
            "  else\n"
            "    sed -i '/}/i \\\\tdisable = yes' /etc/xinetd.d/telnet\n"
            "  fi\n"
            "fi &&\n"
            "systemctl restart xinetd 2>/dev/null || service xinetd restart 2>/dev/null || true &&\n"
            "# 3. systemd 독립 구동형 telnet 서비스 및 소켓 유닛 일괄 영구 정지 및 비활성화\n"
            "for t_unit in telnet telnetd; do\n"
            "  for suffix in service socket; do\n"
            "    if systemctl is-active --quiet $t_unit.$suffix 2>/dev/null; then\n"
            "      systemctl stop $t_unit.$suffix 2>/dev/null\n"
            "      systemctl disable $t_unit.$suffix 2>/dev/null\n"
            "    fi\n"
            "  done\n"
            "done &&\n"
            "# 4. 안전한 원격 접속을 위한 SSH 서비스 활성화 강제화\n"
            "systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null || true"
        )

    return result