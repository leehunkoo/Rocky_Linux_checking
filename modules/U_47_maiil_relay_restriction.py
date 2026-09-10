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
        "item_id": "U-47",
        "item_Level": "High",
        "title": "스팸 메일 릴레이 제한",
        "status": "Vulnerable",
        "description": "SMTP 메일 서버가 스팸 메일 유포기지 또는 DoS 공격 경유지로 악용되는 것을 차단하기 위해 메일 릴레이 제한 및 접근제어 정책 수립 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 메일 서비스를 사용하지 않아 데몬이 비활성화되어 있거나(N/A), 사용 시 릴레이 통제 정책(mynetworks 격리 또는 promiscuous_relay 제거)이 정상 반영된 경우"
    }

    mail_daemons = ["postfix", "sendmail"]
    active_services = []

    for daemon in mail_daemons:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                active_services.append(daemon)
        except Exception:
            continue

    if not active_services:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 메일 서비스(Postfix, Sendmail)가 활성화되어 있지 않아 스팸 릴레이 취약성에 노출되지 않습니다. (N/A)"
        return result

    vulnerable_details = []
    remediation_cmds = []

    for active_svc in active_services:
        if active_svc == "postfix":
            main_cf = "/etc/postfix/main.cf"
            if os.path.exists(main_cf):
                try:
                    mynetworks_open = False
                    with open(main_cf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("#") or not line.strip():
                                continue
                            if "mynetworks" in line:
                                if "0.0.0.0" in line or "::/0" in line:
                                    mynetworks_open = True
                                    break
                    if mynetworks_open:
                        vulnerable_details.append("Postfix(mynetworks 과도한 광역 개방)")
                        remediation_cmds.extend([
                            f"sed -i 's/^\\s*mynetworks.*/mynetworks = 127.0.0.1\\/8 [::1]\\/128/g' {main_cf}",
                            "postfix reload 2>/dev/null"
                        ])
                except Exception:
                    pass
            else:
                vulnerable_details.append("Postfix(main.cf 유실)")

        elif active_svc == "sendmail":
            sendmail_mc = "/etc/mail/sendmail.mc"
            if os.path.exists(sendmail_mc):
                try:
                    with open(sendmail_mc, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("dnl") or not line.strip():
                                continue
                            if "promiscuous_relay" in line:
                                vulnerable_details.append("Sendmail(promiscuous_relay 활성화)")
                                remediation_cmds.extend([
                                    f"sed -i '/promiscuous_relay/d' {sendmail_mc}",
                                    f"m4 {sendmail_mc} > /etc/mail/sendmail.cf 2>/dev/null || true",
                                    "systemctl restart sendmail 2>/dev/null"
                                ])
                                break
                except Exception:
                    pass

    if not vulnerable_details:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 현재 실행 중인 메일 서비스({', '.join(active_services)})의 릴레이 제한 정책이 정상 가동 중입니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 외부 스팸 경유지로 악용될 수 있는 메일 릴레이 설정이 식별되었습니다: {', '.join(vulnerable_details)}"
        banner = ["# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요."]
        result["remediation_cmd"] = "\n".join(banner + list(dict.fromkeys(remediation_cmds)))

    return result
