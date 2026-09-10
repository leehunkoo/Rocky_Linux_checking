# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import stat
import subprocess

def Check():
    result = {
        "item_id": "U-56",
        "item_Level": "Medium",
        "title": "FTP 서비스 접근 제어 설정",
        "status": "Vulnerable",
        "description": "FTP 서비스 접속 제한 대상 계정 목록 파일(ftpusers, user_list)의 소유자(root) 및 권한(640 이하) 설정을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] FTP 서비스를 사용하지 않거나, 사용 시 ftpusers 파일의 소유자가 root이고 권한이 640 이하인 경우"
    }

    ftp_active = False
    for svc in ["vsftpd", "proftpd"]:
        if subprocess.call(["systemctl", "is-active", "--quiet", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            ftp_active = True
            break

    # Rocky Linux vsftpd 계정 제한 파일 경로
    target_files = [
        "/etc/vsftpd/ftpusers",
        "/etc/vsftpd/user_list",
        "/etc/ftpusers"
    ]

    existing_files = [f for f in target_files if os.path.exists(f)]

    if not ftp_active and not existing_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] FTP 서비스를 사용하지 않으며 관련 계정 목록 파일도 존재하지 않습니다. (N/A)"
        return result

    if not existing_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 점검 대상 FTP 접근 제어 파일이 존재하지 않습니다."
        return result

    vulnerable_files = []
    remediation_cmds = []

    for file_path in existing_files:
        try:
            f_stat = os.stat(file_path)
            owner_uid = f_stat.st_uid
            mode = stat.S_IMODE(f_stat.st_mode)
            perm_oct = oct(mode)[2:]

            excess_mask = 0o037
            if owner_uid != 0 or (mode & excess_mask) != 0:
                vulnerable_files.append(f"{os.path.basename(file_path)}(권한:{perm_oct}, UID:{owner_uid})")
                remediation_cmds.append(f"chown root {file_path} && chmod 640 {file_path}")
        except Exception:
            continue

    if not vulnerable_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] FTP 접근 제어 파일({', '.join(existing_files)})의 소유자(root) 및 권한(640 이하)이 기준을 충족합니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] FTP 접근 제어 파일의 소유자 또는 권한이 미흡합니다 -> {', '.join(vulnerable_files)}"
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result
