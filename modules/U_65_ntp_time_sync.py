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
        "item_id": "U-65",
        "item_Level": "Medium",
        "title": "NTP 및 시각 동기화 설정",
        "status": "Vulnerable",
        "description": "보안 침해 사고 및 시스템 장애 발생 시 감사 로그의 무결성과 신뢰도를 확보하기 위해 신뢰할 수 있는 타임 서버와의 주기적인 시각 동기화(Chrony/NTP) 수립 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] Chrony(chrony.conf) 또는 NTP(ntp.conf) 설정 내에 유효한 동기화 대상 타임 서버(server/pool)가 명시되어 있고 관련 동기화 데몬이 정상 작동 중인 경우"
    }

    # Rocky Linux 표준 시간 동기화 데몬은 chronyd
    time_daemons = ["chronyd", "chrony", "ntpd", "ntp"]
    active_daemons = []

    for daemon in time_daemons:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                active_daemons.append(daemon)
        except Exception:
            continue

    if not active_daemons:
        result["status"] = "Vulnerable"
        result["current_setting"] = "[WARN] 시스템 내에서 chronyd 등 시간 동기화 서비스가 구동되고 있지 않습니다."
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "dnf install -y chrony && systemctl enable --now chronyd"
        )
        return result

    server_defined = False
    config_checked_paths = []
    remediation_script_blocks = []

    # Rocky Linux chrony 설정 파일 (/etc/chrony.conf)
    for active_daemon in active_daemons:
        if "chrony" in active_daemon:
            chrony_conf = "/etc/chrony.conf"
            if not os.path.exists(chrony_conf):
                chrony_conf = "/etc/chrony/chrony.conf"

            if os.path.exists(chrony_conf):
                config_checked_paths.append(chrony_conf)
                try:
                    with open(chrony_conf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            clean_line = line.strip()
                            if clean_line.startswith("#") or not clean_line:
                                continue
                            if re.search(r"^\s*(server|pool|peer)\s+", clean_line):
                                server_defined = True
                                break
                    if not server_defined:
                        remediation_script_blocks.append(f"echo 'server time.bora.net iburst' >> {chrony_conf} && systemctl restart chronyd")
                except Exception:
                    pass

        elif "ntp" in active_daemon:
            ntp_conf = "/etc/ntp.conf"
            if os.path.exists(ntp_conf):
                config_checked_paths.append(ntp_conf)
                try:
                    with open(ntp_conf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            clean_line = line.strip()
                            if clean_line.startswith("#") or not clean_line:
                                continue
                            if re.search(r"^\s*(server|pool)\s+", clean_line):
                                server_defined = True
                                break
                    if not server_defined:
                        remediation_script_blocks.append(f"echo 'server time.bora.net' >> {ntp_conf} && systemctl restart ntpd")
                except Exception:
                    pass

    if server_defined:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시각 동기화 데몬({', '.join(active_daemons)})이 정상 활성화되어 있으며 관련 동기화 설정이 존재합니다. (참조: {', '.join(config_checked_paths)})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 시간 동기화 서비스({', '.join(active_daemons)})가 구동 중이나, 설정 파일 내에 유효한 동기화 서버(server/pool)가 누락되어 있습니다."
        banner = "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
        if remediation_script_blocks:
            result["remediation_cmd"] = banner + " && ".join(remediation_script_blocks)
        else:
            result["remediation_cmd"] = banner + "echo 'server time.bora.net iburst' >> /etc/chrony.conf && systemctl restart chronyd"

    return result
