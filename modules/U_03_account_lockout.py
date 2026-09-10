# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re

def Check():
    result = {
        "item_id": "U-03",
        "item_Level": "High",
        "title": "계정 잠금 임계값 설정",
        "status": "Vulnerable",
        "description": "비밀번호 입력 실패 시 계정 잠금 임계값 및 잠금 시간 정책이 적절히 설정되어 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] Rocky Linux 8/9 표준 faillock 정책 설정\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "authselect select sssd with-faillock --force 2>/dev/null || true && \n"
            "if [ -f /etc/security/faillock.conf ]; then\n"
            "  sed -i 's/^#*\\s*deny\\s*=.*/deny = 5/g' /etc/security/faillock.conf\n"
            "  grep -q '^deny\\s*=' /etc/security/faillock.conf || echo 'deny = 5' >> /etc/security/faillock.conf\n"
            "  sed -i 's/^#*\\s*unlock_time\\s*=.*/unlock_time = 120/g' /etc/security/faillock.conf\n"
            "  grep -q '^unlock_time\\s*=' /etc/security/faillock.conf || echo 'unlock_time = 120' >> /etc/security/faillock.conf\n"
            "fi"
        ),
        "exception_guide": "[양호] 계정 잠금 임계값이 5회 이하 및 잠금 시간이 설정된 경우 (faillock.conf 또는 PAM 설정)"
    }

    faillock_conf = "/etc/security/faillock.conf"
    pam_targets = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]

    deny_val = None
    unlock_time_val = None
    detection_module = None

    if os.path.exists(faillock_conf):
        try:
            with open(faillock_conf, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    m_deny = re.match(r"^\s*deny\s*=\s*(\d+)", line)
                    if m_deny:
                        deny_val = int(m_deny.group(1))
                        detection_module = "faillock.conf"
                    m_unlock = re.match(r"^\s*unlock_time\s*=\s*(\d+)", line)
                    if m_unlock:
                        unlock_time_val = int(m_unlock.group(1))
                        detection_module = "faillock.conf"
        except Exception:
            pass

    for pam_file in pam_targets:
        if not os.path.exists(pam_file):
            continue
        try:
            with open(pam_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "pam_faillock.so" in line:
                        if detection_module is None:
                            detection_module = "pam_faillock (PAM)"
                        m_deny = re.search(r"deny=(\d+)", line)
                        if m_deny and deny_val is None:
                            deny_val = int(m_deny.group(1))
                        m_unlock = re.search(r"unlock_time=(\d+)", line)
                        if m_unlock and unlock_time_val is None:
                            unlock_time_val = int(m_unlock.group(1))
        except Exception:
            pass

    if detection_module is not None:
        deny_str = str(deny_val) if deny_val is not None else "미설정"
        unlock_str = str(unlock_time_val) if unlock_time_val is not None else "미설정"
        summary = f"감지: {detection_module} | deny(실패 횟수): {deny_str} | unlock_time(잠금 시간): {unlock_str}초"

        if deny_val is not None and deny_val <= 5:
            if unlock_time_val is not None and unlock_time_val >= 120:
                result["status"] = "PASS(양호)"
                result["current_setting"] = f"[양호] {summary} 규정에 따라 계정 잠금 기준을 만족합니다."
            else:
                result["status"] = "Vulnerable"
                result["current_setting"] = f"[WARN] {summary} 잠금 유지시간이 120초 보다 짧거나 누락되어 있습니다."
        else:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] {summary} 계정 잠금 임계값이 5회를 초과했거나 누락되어 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = "Rocky Linux PAM(system-auth/password-auth) 및 faillock.conf 내에 계정 잠금 모듈(pam_faillock)이 비활성화되어 있습니다."

    return result
