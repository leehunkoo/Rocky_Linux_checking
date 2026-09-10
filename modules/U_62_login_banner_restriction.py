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
        "item_id": "U-62",
        "item_Level": "Low",
        "title": "로그인 시 경고 메시지 설정",
        "status": "Vulnerable",
        "description": "서버 및 주요 네트워크 서비스(SSH, FTP, SMTP, DNS 등) 접속 시 불필요한 버전 정보 유출을 차단하고 비인가자 무단 접근 경고 배너 출력 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 기본 로컬 배너 및 가동 중인 네트워크 서비스(SSH, FTP, SMTP, DNS 등) 설정에 시스템 내부 제원 유출이 배제되고 비인가자 경고 메시지가 매핑된 경우"
    }

    vulnerable_services = []
    remediation_cmds = []
    warning_banner_text = "WARNING: Authorized users only. All activities may be monitored and recorded."

    # [Step 1] 기본 서버 로컬 터미널 배너 점검 (/etc/motd, /etc/issue, /etc/issue.net)
    # Rocky Linux / RHEL 기본 배너 유출 속성 지시어(Rocky, Red Hat, Kernel, escape code)
    local_banners = ["/etc/motd", "/etc/issue", "/etc/issue.net"]
    for banner_path in local_banners:
        if os.path.exists(banner_path):
            try:
                with open(banner_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    if any(kw in content for kw in ["Rocky", "Red Hat", "CentOS", "Kernel", "\\r", "\\m", "\\s"]) or len(content.strip()) == 0:
                        vulnerable_services.append(f"Server({os.path.basename(banner_path)} 버전유출 위험)")
                        remediation_cmds.append(f"echo '{warning_banner_text}' > {banner_path}")
            except Exception:
                pass
        else:
            vulnerable_services.append(f"Server({os.path.basename(banner_path)} 배너 유실)")
            remediation_cmds.append(f"echo '{warning_banner_text}' > {banner_path}")

    # [Step 2] SSH 배너 지시어 검증 (/etc/ssh/sshd_config)
    sshd_config = "/etc/ssh/sshd_config"
    if os.path.exists(sshd_config):
        try:
            banner_mapped = False
            with open(sshd_config, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    clean_line = line.strip()
                    if clean_line.startswith("#") or not clean_line:
                        continue
                    if "Banner" in clean_line and re.search(r"^\s*Banner\s+\S+", clean_line):
                        banner_mapped = True
                        break
            if not banner_mapped:
                vulnerable_services.append("SSH(Banner 설정 누락)")
                remediation_cmds.extend([
                    f"if grep -q '^\\s*#\\s*Banner' {sshd_config}; then sed -i 's/^\\s*#\\s*Banner.*/Banner \\/etc\\/issue.net/g' {sshd_config}; else echo 'Banner /etc/issue.net' >> {sshd_config}; fi",
                    "systemctl restart sshd 2>/dev/null"
                ])
        except Exception:
            pass

    # [Step 3] 가동 중인 메일 서비스 (Postfix / Sendmail)
    if subprocess.call(["systemctl", "is-active", "--quiet", "postfix"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        postfix_cf = "/etc/postfix/main.cf"
        if os.path.exists(postfix_cf):
            try:
                with open(postfix_cf, "r", encoding="utf-8", errors="ignore") as f:
                    if not re.search(r"^\s*smtpd_banner\s*=\s*", f.read(), re.MULTILINE):
                        vulnerable_services.append("Postfix(smtpd_banner 누락)")
                        remediation_cmds.extend([f"echo 'smtpd_banner = {warning_banner_text}' >> {postfix_cf}", "postfix reload 2>/dev/null"])
            except Exception:
                pass

    # [Step 4] 가동 중인 FTP 서비스 (vsftpd)
    if subprocess.call(["systemctl", "is-active", "--quiet", "vsftpd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
        vsftpd_conf = "/etc/vsftpd/vsftpd.conf"
        if not os.path.exists(vsftpd_conf):
            vsftpd_conf = "/etc/vsftpd.conf"
        if os.path.exists(vsftpd_conf):
            try:
                with open(vsftpd_conf, "r", encoding="utf-8", errors="ignore") as f:
                    if "ftpd_banner" not in f.read():
                        vulnerable_services.append("vsFTPd(ftpd_banner 누락)")
                        remediation_cmds.extend([f"echo 'ftpd_banner={warning_banner_text}' >> {vsftpd_conf}", "systemctl restart vsftpd 2>/dev/null"])
            except Exception:
                pass

    if not vulnerable_services:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 기본 터미널 및 가동 중인 네트워크 서비스 접근 정보 제어(보안 배너 설정) 정책이 안전하게 충족되었습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 일부 로컬 배너 또는 활성 네트워크 서비스 접속 지점에서 기본 배너가 방치되어 정보 노출 우려가 있습니다: {', '.join(vulnerable_services)}"
        banner = ["# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요."]
        result["remediation_cmd"] = "\n".join(banner + list(dict.fromkeys(remediation_cmds)))

    return result
