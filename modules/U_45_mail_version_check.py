# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import subprocess

def Check():
    result = {
        "item_id": "U-45",
        "item_Level": "High",
        "title": "메일 서비스 버전 점검",
        "status": "Vulnerable",
        "description": "버퍼 오버플로우 공격에 의한 시스템 권한 탈취 및 정보 노출을 예방하기 위해 실행 중인 메일 서비스(Postfix, Sendmail)의 취약 버전 여부 및 서비스 필요성을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 메일 서비스를 사용하지 않아 데몬이 모두 정지되어 있거나(N/A에 준함), 사용 시 최신 패치 버전이 적용된 상태인 경우"
    }

    # Rocky Linux 표준 메일 데몬 (Postfix 기본)
    mail_daemons = ["postfix", "sendmail"]
    active_services = []
    version_details = []

    for daemon in mail_daemons:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                active_services.append(daemon)
        except Exception:
            continue

    if not active_services:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 Postfix, Sendmail 등 메일 서비스가 활성화되어 있지 않습니다. (메일 서비스 미사용으로 해당없음 N/A 처리)"
        return result

    for active_svc in active_services:
        if active_svc == "postfix":
            try:
                version_out = subprocess.check_output(["postconf", "mail_version"], text=True, stderr=subprocess.DEVNULL)
                if version_out:
                    version_details.append(f"Postfix({version_out.strip()})")
            except Exception:
                version_details.append("Postfix(버전 획득 실패)")

        elif active_svc == "sendmail":
            try:
                proc = subprocess.Popen(["sendmail", "-d0.1", "-bt"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                stdout, _ = proc.communicate(input="exit\n")
                version_match = None
                for line in stdout.splitlines():
                    if "Version" in line:
                        version_match = line.strip()
                        break
                if version_match:
                    version_details.append(f"Sendmail({version_match})")
                else:
                    version_details.append("Sendmail(활성화됨)")
            except Exception:
                version_details.append("Sendmail(활성화됨)")

    result["status"] = "Manual Check"
    result["current_setting"] = f"[확인필요] 현재 메일 서비스가 실행 중입니다. 최신 보안 패치 적용 여부를 검토하십시오 -> (가동 데몬: {', '.join(version_details)})"

    result["remediation_cmd"] = (
        "# [방법 1] 메일 서비스를 사용하지 않는 경우: 데몬 일괄 정지 및 비활성화\n"
        "for mail_svc in postfix sendmail; do\n"
        "  if systemctl is-active --quiet $mail_svc 2>/dev/null; then\n"
        "    systemctl stop $mail_svc 2>/dev/null\n"
        "    systemctl disable $mail_svc 2>/dev/null\n"
        "  fi\n"
        "done\n"
        "\n"
        "# [방법 2] 메일 서비스가 필요한 경우: dnf를 통한 최신 보안 패치 적용\n"
        "dnf update -y postfix sendmail"
    )

    return result
