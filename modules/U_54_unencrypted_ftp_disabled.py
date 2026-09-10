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
        "item_id": "U-54",
        "item_Level": "Medium",
        "title": "암호화되지 않는 FTP 서비스 비활성화",
        "status": "Vulnerable",
        "description": "평문 전송으로 인한 스니핑 및 계정 정보 유출을 차단하기 위해 보안성(SFTP, FTPS 등)이 결여된 구형 원격 FTP 서비스의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 암호화되지 않은 FTP 서비스가 비활성화되어 있거나 시스템 내에 관련 서비스 데몬 및 패키지가 설치되지 않은 경우"
    }

    xinetd_path = "/etc/xinetd.d/ftp"
    ftp_active = False
    detected_locations = []

    if os.path.exists(xinetd_path):
        try:
            with open(xinetd_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                is_disabled = False
                if disable_match and disable_match.group(1).lower() == "yes":
                    is_disabled = True
                if not is_disabled:
                    ftp_active = True
                    detected_locations.append("xinetd.d/ftp")
        except Exception:
            pass

    # Rocky Linux 독립 구동형 메이저 FTP 서비스
    systemd_ftp_targets = ["vsftpd.service", "proftpd.service"]
    for unit_name in systemd_ftp_targets:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", unit_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                ftp_active = True
                detected_locations.append(f"systemd:{unit_name.split('.')[0]}")
        except Exception:
            pass

    if not ftp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 평문 암호 노출 위험이 있는 FTP 서비스가 비활성화 상태이거나 설치되지 않아 안전합니다. (SFTP 사용 권고)"
    else:
        unique_locations = sorted(list(set(detected_locations)))
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 스니핑 공격에 취약한 암호화되지 않은 원격 FTP 서비스가 실행 중입니다 -> (활성: {', '.join(unique_locations)})"
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "for ftp_svc in vsftpd proftpd; do\n"
            "  if systemctl is-active --quiet $ftp_svc 2>/dev/null; then\n"
            "    systemctl stop $ftp_svc 2>/dev/null\n"
            "    systemctl disable $ftp_svc 2>/dev/null\n"
            "  fi\n"
            "done"
        )

    return result
