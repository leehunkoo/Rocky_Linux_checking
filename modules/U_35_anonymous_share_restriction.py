# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re

def Check():
    result = {
        "item_id": "U-35",
        "item_Level": "High",
        "title": "공공/공유 서비스에 대한 익명 접근 제한 설정",
        "status": "Vulnerable",
        "description": "NFS, Samba, FTP 등 공유 서비스의 익명(Anonymous) 접근 허용으로 인한 중요 정보 노출 및 악성 코드 유포 위험을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] FTP, NFS, Samba 서비스를 사용하지 않거나, 사용 시 익명 계정 및 익명 접근 옵션이 철저히 차단(NO/no)된 경우"
    }

    passwd_path = "/etc/passwd"
    vsftpd_paths = ["/etc/vsftpd/vsftpd.conf", "/etc/vsftpd.conf"]
    proftpd_paths = ["/etc/proftpd.conf", "/etc/proftpd/proftpd.conf"]
    exports_path = "/etc/exports"
    samba_path = "/etc/samba/smb.conf"

    vulnerable_details = []
    remediation_cmds = []
    services_found = False

    # [Step 1] 기본 FTP 익명 계정 검사 (/etc/passwd)
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if parts:
                        username = parts[0].strip()
                        if username == "anonymous":
                            vulnerable_details.append(f"기본 FTP 익명 계정 존재({username})")
                            remediation_cmds.append(f"userdel {username} 2>/dev/null")
                            services_found = True
        except Exception:
            pass

    # [Step 2] vsFTPd 익명 허용 검사 (Rocky Linux 표준 경로: /etc/vsftpd/vsftpd.conf)
    for path in vsftpd_paths:
        if os.path.exists(path):
            services_found = True
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.strip().startswith("#") or not line.strip():
                            continue
                        if "anonymous_enable" in line:
                            match = re.search(r"^\s*anonymous_enable\s*=\s*(YES|yes)", line)
                            if match:
                                vulnerable_details.append("vsFTPd(익명 접속 활성화: anonymous_enable=YES)")
                                remediation_cmds.append(f"sed -i 's/^\\s*anonymous_enable.*/anonymous_enable=NO/g' {path}")
                                break
            except Exception:
                pass

    # [Step 3] ProFTPd 익명 접속 블록 검사
    for path in proftpd_paths:
        if os.path.exists(path):
            services_found = True
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if re.search(r"<\s*Anonymous\b[^>]*>", content, re.IGNORECASE):
                        vulnerable_details.append("ProFTPd(익명 설정 블록 <Anonymous> 존재)")
                        remediation_cmds.append(f"# [조치] {path} 파일 내 <Anonymous> ... </Anonymous> 블록을 주석 처리 또는 제거하십시오.")
            except Exception:
                pass

    # [Step 4] NFS exports 익명/비인가 공유 검사
    if os.path.exists(exports_path):
        try:
            with open(exports_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith("#"):
                        continue
                    services_found = True
                    if "all_squash" in clean_line and "anonuid" in clean_line:
                        vulnerable_details.append("NFS(all_squash 익명 매핑 식별)")
                        remediation_cmds.append(f"# [조치] {exports_path} 파일 내 all_squash/anonuid 설정을 확인하고 필요 시 root_squash로 전환하십시오.")
                        break
        except Exception:
            pass

    # [Step 5] Samba smb.conf 익명 공유 검사
    if os.path.exists(samba_path):
        try:
            with open(samba_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean_line = line.strip()
                    if not clean_line or clean_line.startswith(("#", ";")):
                        continue
                    if "guest ok" in clean_line and re.search(r"guest\s+ok\s*=\s*yes", clean_line, re.IGNORECASE):
                        services_found = True
                        vulnerable_details.append("Samba(게스트 익명 접속 허용: guest ok = yes)")
                        remediation_cmds.append(f"sed -i 's/guest\\s*ok\\s*=\\s*yes/guest ok = no/gI' {samba_path}")
                        break
        except Exception:
            pass

    if not services_found:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] FTP, NFS, Samba 등 파일 공유 서비스가 구성되어 있지 않아 익명 접근 취약성이 존재하지 않습니다."
    elif not vulnerable_details:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 점검된 모든 파일 공유 서비스(FTP/NFS/Samba)의 익명 접근 제한 설정이 정상적으로 유지되고 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 중요 정보 유출 위험이 있는 익명 접근 허용 설정이 발견되었습니다 -> {', '.join(vulnerable_details)}"
        banner = "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
        result["remediation_cmd"] = banner + "\n".join(remediation_cmds)

    return result
