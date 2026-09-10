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
        "item_id": "U-53",
        "item_Level": "Low",
        "title": "FTP 서비스 정보 노출 제한",
        "status": "Vulnerable",
        "description": "FTP 서비스 접속 시 시스템 제원 및 버전 정보가 노출되어 공격자에게 표적 공격 빌미를 제공하는 것을 차단하기 위해 배너 제한 설정을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] FTP 서비스를 사용하지 않거나, 사용 시 배너에 서버 버전이나 운영체제 정보가 노출되지 않도록 설정된 경우"
    }

    ftp_active = False
    for svc in ["vsftpd", "proftpd"]:
        if subprocess.call(["systemctl", "is-active", "--quiet", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
            ftp_active = True
            break

    if not ftp_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] FTP 서비스가 활성화되어 있지 않아 정보 노출 위험이 없습니다. (N/A)"
        return result

    # Rocky Linux vsftpd 표준 경로
    vsftpd_conf = "/etc/vsftpd/vsftpd.conf"
    if not os.path.exists(vsftpd_conf) and os.path.exists("/etc/vsftpd.conf"):
        vsftpd_conf = "/etc/vsftpd.conf"

    banner_configured = False
    if os.path.exists(vsftpd_conf):
        try:
            with open(vsftpd_conf, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if re.match(r"^ftpd_banner\s*=", line):
                        banner_configured = True
                        break
        except Exception:
            pass

    if banner_configured:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] FTP 서비스 배너 정보 제한 설정(ftpd_banner)이 적용되어 있습니다. ({vsftpd_conf})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] FTP 배너에 기본 정보나 버전이 노출될 수 있습니다. ({vsftpd_conf})"
        result["remediation_cmd"] = (
            f"echo 'ftpd_banner=WARNING: Authorized users only.' >> {vsftpd_conf} && systemctl restart vsftpd"
        )

    return result
