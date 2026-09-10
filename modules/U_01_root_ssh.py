# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import glob
import os
import re

def Check():
    result = {
        "item_id": "U-01",
        "item_Level": "High",
        "title": "root 계정 원격 접속 제한",
        "status": "Vulnerable",
        "description": "시스템 정책에 root 계정의 원격터미널 접속 차단 설정이 되어있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "# [주의] && 로 이어진 명령입니다. \x27sudo -i\x27로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\nsed -i \x27s/^#*PermitRootLogin.*/PermitRootLogin no/g\x27 /etc/ssh/sshd_config && systemctl restart sshd",
        "exception_guide": "[양호] 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
    }

    config_path = "/etc/ssh/sshd_config"
    include_dir = "/etc/ssh/sshd_config.d"

    if not os.path.exists(config_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/ssh/sshd_config 파일이 존재하지 않습니다. OpenSSH 서버 미설치 또는 비표준 경로를 사용하는지 확인이 필요합니다."
        return result

    config_files = [config_path]
    if os.path.isdir(include_dir):
        config_files.extend(sorted(glob.glob(os.path.join(include_dir, "*.conf"))))

    permit_root_login_val = None
    detected_file = None

    for cfile in config_files:
        try:
            with open(cfile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    match = re.match(r"^\s*PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
                    if match:
                        permit_root_login_val = match.group(1).lower()
                        detected_file = os.path.basename(cfile)
        except Exception:
            continue

    if permit_root_login_val in ["no", "prohibit-password", "without-password"]:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"PermitRootLogin 설정이 \x27{permit_root_login_val}\x27로 안전하게 설정되어 있습니다. (적용 파일: {detected_file})"
    elif permit_root_login_val == "yes":
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] PermitRootLogin 설정이 \x27yes\x27로 되어 있어 root 직접 접속이 가능합니다. (적용 파일: {detected_file})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = "PermitRootLogin 설정이 주석처리 되어있거나, 명시적으로 비활성화(no)되지 않았습니다."

    return result
