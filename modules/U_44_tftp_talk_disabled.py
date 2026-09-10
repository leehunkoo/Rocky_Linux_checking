# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-44",
        "item_Level": "High",
        "title": "tftp, talk 서비스 비활성화",
        "status": "Vulnerable",
        "description": "인증 절차가 없어 보안에 취약한 TFTP 및 세션 노출 위험이 있는 TALK, NTALK 서비스의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "# 1. xinetd.d 하위 tftp, talk 설정 비활성화\n"
            "for xfile in tftp talk ntalk; do\n"
            "  if [ -f /etc/xinetd.d/$xfile ]; then\n"
            "    sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/$xfile 2>/dev/null || true\n"
            "  fi\n"
            "done &&\n"
            "# 2. systemd 독립 구동형 tftp, talk 서비스 정지 및 비활성화\n"
            "for s_unit in tftp.socket tftp.service tftp-server talk.service ntalk.service; do\n"
            "  if systemctl is-active --quiet $s_unit 2>/dev/null; then\n"
            "    systemctl stop $s_unit 2>/dev/null\n"
            "    systemctl disable $s_unit 2>/dev/null\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] tftp, talk, ntalk 서비스가 모두 비활성화되어 있거나 시스템 내에 설치되지 않은 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_dir = "/etc/xinetd.d"
    target_services = ["tftp", "talk", "ntalk"]
    systemd_units = [
        "tftp.service", "tftp.socket", "tftp-server.service", "tftpd-hpa.service",
        "talk.service", "talkd.service", "ntalk.service", "ntalkd.service"
    ]

    services_active = False
    detected_locations = []

    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for svc in target_services:
                        if re.search(r"^\s*" + svc + r"\s+", line):
                            services_active = True
                            detected_locations.append(f"inetd.conf:{svc}")
        except Exception:
            pass

    if os.path.exists(xinetd_dir) and os.path.isdir(xinetd_dir):
        for svc in target_services:
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

    for unit_name in systemd_units:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                services_active = True
                detected_locations.append(f"systemd:{unit_name}")
        except Exception:
            pass

    if not services_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] tftp, talk, ntalk 서비스가 모두 안전하게 비활성화되어 있거나 설치되지 않았습니다."
    else:
        unique_locations = sorted(list(set(detected_locations)))
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 보안에 취약한 통신 서비스가 활성화되어 있습니다 -> (활성 경로: {', '.join(unique_locations)})"

    return result
