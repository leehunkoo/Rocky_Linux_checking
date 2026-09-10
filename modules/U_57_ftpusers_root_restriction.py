# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import subprocess

def Check():
    result = {
        "item_id": "U-57",
        "item_Level": "Medium",
        "title": "Ftpusers 파일 설정",
        "status": "Vulnerable",
        "description": "FTP 서비스를 통한 슈퍼유저(root) 계정의 직접 로그인을 차단하기 위해 ftpusers 파일 내 root 계정 등록 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] FTP 서비스를 사용하지 않거나, 사용 시 ftpusers 파일에 root 계정이 등록되어 접속이 차단된 경우"
    }

    ftp_active = False
    for svc in ["vsftpd", "proftpd"]:
        if subprocess.call(["systemctl", "is-active", "--quiet", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            ftp_active = True
            break

    # Rocky Linux vsftpd 계정 제한 파일
    target_files = [
        "/etc/vsftpd/ftpusers",
        "/etc/vsftpd/user_list",
        "/etc/ftpusers"
    ]

    existing_files = [f for f in target_files if os.path.exists(f)]

    if not ftp_active and not existing_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] FTP 서비스를 사용하지 않으며 관련 차단 파일도 존재하지 않습니다. (N/A)"
        return result

    root_blocked_files = []
    root_missing_files = []

    for file_path in existing_files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]
                if "root" in lines:
                    root_blocked_files.append(os.path.basename(file_path))
                else:
                    root_missing_files.append(file_path)
        except Exception:
            continue

    if root_blocked_files and not root_missing_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] FTP 차단 목록 파일({', '.join(root_blocked_files)})에 root 계정이 정상 등록되어 차단되어 있습니다."
    elif not existing_files:
        result["status"] = "Vulnerable"
        result["current_setting"] = "[WARN] FTP 서비스 차단 파일(ftpusers 등)이 존재하지 않아 root 직접 로그인이 허용될 수 있습니다."
        result["remediation_cmd"] = "mkdir -p /etc/vsftpd && echo 'root' >> /etc/vsftpd/ftpusers"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] FTP 차단 목록 파일 중 root 계정이 누락된 파일이 있습니다 -> {', '.join(root_missing_files)}"
        remediation_cmds = [f"echo 'root' >> {f}" for f in root_missing_files]
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result
