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
        "item_id": "U-66",
        "item_Level": "Medium",
        "title": "정책에 따른 시스템 로깅 설정",
        "status": "Vulnerable",
        "description": "보안 사고 발생 시 원인 규명 및 침해 사실 확인을 위해 조직의 보안 정책에 부합하는 시스템 로깅(rsyslog) 수립 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] rsyslog 로깅 서비스가 가동 중이며, 설정 파일(/etc/rsyslog.conf 등)에 인증(authpriv), 예약(cron), 전역(info) 등 핵심 감사 설정이 수립된 경우"
    }

    rsyslog_service = "rsyslog"
    rsyslog_active = False

    try:
        exit_code = subprocess.call(["systemctl", "is-active", "--quiet", rsyslog_service], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if exit_code == 0:
            rsyslog_active = True
    except Exception:
        pass

    # Rocky Linux / RHEL 표준 rsyslog 정책 주입 스크립트
    remediation_script = (
        "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
        "# Rocky Linux / RHEL 표준 로깅 정책을 /etc/rsyslog.conf에 주입\n"
        "if [ -f /etc/rsyslog.conf ]; then\n"
        "  echo '*.info;mail.none;authpriv.none;cron.none                /var/log/messages' >> /etc/rsyslog.conf\n"
        "  echo 'authpriv.*                                              /var/log/secure' >> /etc/rsyslog.conf\n"
        "  echo 'mail.*                                                  -/var/log/maillog' >> /etc/rsyslog.conf\n"
        "  echo 'cron.*                                                  /var/log/cron' >> /etc/rsyslog.conf\n"
        "  echo '*.emerg                                                 :omusrmsg:*' >> /etc/rsyslog.conf\n"
        "  systemctl restart rsyslog 2>/dev/null\n"
        "fi"
    )

    if not rsyslog_active:
        result["status"] = "Vulnerable"
        result["current_setting"] = "[WARN] 시스템 로깅 데몬(rsyslog) 서비스가 비활성화되어 있거나 동작하지 않습니다."
        result["remediation_cmd"] = remediation_script
        return result

    config_paths = ["/etc/rsyslog.conf"]
    rsyslog_d = "/etc/rsyslog.d"
    if os.path.isdir(rsyslog_d):
        try:
            for f_name in os.listdir(rsyslog_d):
                if f_name.endswith(".conf"):
                    config_paths.append(os.path.join(rsyslog_d, f_name))
        except Exception:
            pass

    has_auth_logging = False
    has_cron_logging = False
    has_info_logging = False
    has_emerg_logging = False

    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        clean_line = line.strip()
                        if not clean_line or clean_line.startswith("#"):
                            continue
                        if re.search(r"auth(priv)?\.\*", clean_line):
                            has_auth_logging = True
                        if re.search(r"cron\.\*", clean_line):
                            has_cron_logging = True
                        if re.search(r"\*\.info", clean_line):
                            has_info_logging = True
                        if re.search(r"\*\.emerg", clean_line):
                            has_emerg_logging = True
            except Exception:
                continue

    missing_policies = []
    if not has_auth_logging: missing_policies.append("authpriv.* 누락")
    if not has_cron_logging: missing_policies.append("cron.* 누락")
    if not has_info_logging: missing_policies.append("*.info 누락")
    if not has_emerg_logging: missing_policies.append("*.emerg 누락")

    if not missing_policies:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 정책에 따른 시스템 로깅 설정이 rsyslog 구성을 통해 적절히 반영되어 가동 중입니다. (/var/log/messages, secure, maillog, cron 등)"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 법적 요구사항 및 보안 준수 정책에 필요한 일부 로깅 설정 항목이 누락되었습니다 -> ({', '.join(missing_policies)})"
        result["remediation_cmd"] = remediation_script

    return result
