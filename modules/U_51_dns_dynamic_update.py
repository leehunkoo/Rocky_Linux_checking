# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import subprocess

def Check():
    result = {
        "item_id": "U-51",
        "item_Level": "Medium",
        "title": "DNS 서비스의 취약한 동적 업데이트 설정 금지",
        "status": "Vulnerable",
        "description": "비인가자에 의한 DNS 레코드 무단 변조 및 피싱 공격을 예방하기 위해 DNS 동적 업데이트(allow-update) 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] DNS 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 allow-update { none; }; 등으로 동적 업데이트를 제한한 경우"
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
        result["current_setting"] = "[양호] 시스템 내에서 BIND(named) DNS 서비스가 활성화되어 있지 않습니다. (N/A)"
        return result

    bind_config_files = ["/etc/named.conf", "/etc/named.rfc1912.zones"]
    allow_update_found = False
    is_secure_update = True
    detected_lines = []

    for config_path in bind_config_files:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    for idx, line in enumerate(lines, 1):
                        clean_line = line.strip()
                        if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                            continue
                        if "allow-update" in clean_line:
                            allow_update_found = True
                            detected_lines.append(f"{os.path.basename(config_path)}:{idx}행")
                            if "any" in clean_line.lower() or "none" not in clean_line.lower():
                                is_secure_update = False
            except Exception:
                continue

    if not allow_update_found or is_secure_update:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] DNS 동적 업데이트(allow-update)가 비활성화(none)되었거나 안전하게 제어되고 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] DNS 동적 업데이트가 제한되지 않아 레코드 위변조 위험이 있습니다 -> (위치: {', '.join(detected_lines)})"
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "if [ -f /etc/named.conf ]; then\n"
            "  sed -i 's/allow-update\\s*{[^}]*};/allow-update { none; };/g' /etc/named.conf\n"
            "  systemctl restart named 2>/dev/null || true\n"
            "fi"
        )

    return result
