# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import subprocess

def Check():
    result = {
        "item_id": "U-50",
        "item_Level": "High",
        "title": "DNS ZoneTransfer 설정",
        "status": "Vulnerable",
        "description": "비인가자에 의한 내부 호스트 정보 및 전체 네트워크 토폴로지 대량 유출을 차단하기 위해 DNS Zone Transfer 전송 제한(allow-transfer) 설정 상태를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] DNS 서비스를 사용하지 않아 데몬이 완전히 비활성화되어 있거나(N/A), 사용 시 allow-transfer 설정을 통해 허가된 특정 Secondary Name Server로만 Zone 정보 전송을 제한한 경우"
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
        result["current_setting"] = "[양호] 시스템 내에서 BIND(named) DNS 서비스가 활성화되어 있지 않습니다. (네임서버 미사용 상태로 해당없음 N/A 처리)"
        return result

    # Rocky Linux BIND 표준 설정 경로
    bind_config_files = [
        "/etc/named.conf",
        "/etc/named.rfc1912.zones",
        "/etc/named.root.key"
    ]

    allow_transfer_found = False
    is_secure_transfer = True
    detected_lines = []

    for config_path in bind_config_files:
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    lines = content.splitlines()
                    for idx, line in enumerate(lines, 1):
                        clean_line = line.strip()
                        if not clean_line or clean_line.startswith("#") or clean_line.startswith("//"):
                            continue
                        if "allow-transfer" in clean_line:
                            allow_transfer_found = True
                            detected_lines.append(f"{os.path.basename(config_path)}:{idx}행")
                            if "any" in clean_line.lower():
                                is_secure_transfer = False
            except Exception:
                continue

    if not allow_transfer_found:
        result["status"] = "Vulnerable"
        result["current_setting"] = "[WARN] DNS 서비스의 allow-transfer(Zone Transfer 제한) 정책이 누락되어 Zone 정보가 유출될 수 있습니다."
    elif not is_secure_transfer:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] DNS Zone Transfer 허용 대상으로 전체 개방(any) 정책이 식별되었습니다. (위치: {', '.join(detected_lines)})"
    else:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 허가된 대상 또는 로컬로만 정보 복제가 제한되어 있습니다. (식별 경로: {', '.join(detected_lines)})"

    if result["status"] == "Vulnerable":
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "# 1. /etc/named.conf options 블록 내 allow-transfer { none; }; 또는 신뢰 IP 지정\n"
            "if [ -f /etc/named.conf ]; then\n"
            "  if grep -q 'allow-transfer' /etc/named.conf; then\n"
            "    sed -i 's/allow-transfer\\s*{[^}]*};/allow-transfer { none; };/g' /etc/named.conf\n"
            "  else\n"
            "    sed -i '/options\\s*{/a \\\\tallow-transfer { none; };' /etc/named.conf\n"
            "  fi\n"
            "  systemctl restart named 2>/dev/null || true\n"
            "fi\n"
            "# 실제 Secondary DNS가 있는 경우 allow-transfer { <Secondary_IP>; }; 로 변경하십시오."
        )

    return result
