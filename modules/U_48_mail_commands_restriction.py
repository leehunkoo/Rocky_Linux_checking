# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-48",
        "item_Level": "Medium",
        "title": "expn, vrfy 명령어 제한",
        "status": "Vulnerable",
        "description": "SMTP 서비스를 통한 특정 계정 존재 여부 추적 및 정보 유출을 원천 방지하기 위해 expn, vrfy 명령어 사용 금지 설정 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 메일 서비스를 사용하지 않아 데몬이 모두 비활성화되어 있거나(N/A), 사용 시 각 메일 시스템별 명령어 통제 정책(goaway, noexpn/novrfy 적용 또는 disable_vrfy_command 활성화)이 완료된 경우"
    }

    mail_daemons = ["sendmail", "postfix", "exim4"]
    active_services = []

    # [Step 1] systemd API 기법을 활용한 메일 서비스 실시간 구동 상태 체크
    for daemon in mail_daemons:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                active_services.append(daemon)
        except Exception:
            continue

    # 메일 서비스를 일절 사용하지 않는 환경인 경우 해당없음(N/A)을 내포한 PASS 처리
    if not active_services:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 메일 서비스(Sendmail, Postfix, Exim)가 활성화되어 있지 않아 정보 유출 취약성에 노출되지 않습니다. (N/A)"
        return result

    vulnerable_details = []
    remediation_cmds = []

    # [Step 2] 가동 중인 메일 시스템별 세부 보안 옵션 상태 전수 점검
    for active_svc in active_services:
        if active_svc == "sendmail":
            sendmail_cf = "/etc/mail/sendmail.cf"
            if os.path.exists(sendmail_cf):
                try:
                    privacy_options_ok = False
                    with open(sendmail_cf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("#") or not line.strip():
                                continue
                            # PrivacyOptions 옵션 구조 매칭 검사
                            if "PrivacyOptions" in line:
                                # goaway가 설정되어 있거나, noexpn과 novrfy가 동시에 충족되는지 검증
                                has_goaway = "goaway" in line
                                has_noexpn_novrfy = "noexpn" in line and "novrfy" in line
                                if re.search(r"^\s*O\s+PrivacyOptions\s*=\s*", line) and (has_goaway or has_noexpn_novrfy):
                                    privacy_options_ok = True
                                    break
                    
                    if not privacy_options_ok:
                        vulnerable_details.append("Sendmail(PrivacyOptions 내 expn/vrfy 제한 미흡)")
                        remediation_cmds.extend([
                            f"# [조치] {sendmail_cf} 파일의 PrivacyOptions 설정에 noexpn, novrfy 또는 goaway를 바인딩하십시오.",
                            "systemctl restart sendmail 2>/dev/null"
                        ])
                except Exception:
                    pass
            else:
                vulnerable_details.append("Sendmail(config 미식별)")

        elif active_svc == "postfix":
            main_cf = "/etc/postfix/main.cf"
            if os.path.exists(main_cf):
                try:
                    disable_vrfy_ok = False
                    with open(main_cf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("#") or not line.strip():
                                continue
                            if "disable_vrfy_command" in line:
                                if re.search(r"^\s*disable_vrfy_command\s*=\s*(yes|YES)", line):
                                    disable_vrfy_ok = True
                                    break
                    
                    if not disable_vrfy_ok:
                        vulnerable_details.append("Postfix(disable_vrfy_command 옵션 미설정)")
                        remediation_cmds.extend([
                            f"if grep -q '^\\s*disable_vrfy_command' {main_cf}; then sed -i 's/^\\s*disable_vrfy_command.*/disable_vrfy_command = yes/g' {main_cf}; else echo 'disable_vrfy_command = yes' >> {main_cf}; fi",
                            "postfix reload 2>/dev/null"
                        ])
                except Exception:
                    pass
            else:
                vulnerable_details.append("Postfix(main.cf 유실)")

        elif active_svc == "exim4":
            exim_paths = ["/etc/exim4/exim4.conf", "/etc/exim4/exim4.conf.template"]
            exim_vuln_found = False
            
            for path in exim_paths:
                if os.path.exists(path):
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            for line in f:
                                if line.strip().startswith("#") or not line.strip():
                                    continue
                                # acl_smtp_vrfy 나 acl_smtp_expn 가 주석 없이 accept 형태로 방치되어 있는지 검사
                                if re.search(r"^\s*acl_smtp_(vrfy|expn)\s*=\s*accept", line):
                                    exim_vuln_found = True
                                    break
                    except Exception:
                        pass
            
            if exim_vuln_found:
                vulnerable_details.append("Exim4(acl_smtp_vrfy 또는 expn 접근 무제한 허용 정책 존재)")
                remediation_cmds.extend([
                    "# [조치] Exim 설정 파일 내 acl_smtp_vrfy = accept 및 acl_smtp_expn = accept 정의행을 삭제하거나 주석 처리하십시오.",
                    "systemctl restart exim4 2>/dev/null"
                ])

    # KISA 가이드  최종 판정
    if not vulnerable_details:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 현재 실행 중인 메일 서비스({', '.join(active_services)})의 expn 및 vrfy 정보 유출 명령어 정보 보호 수립이 적절히 작동하고 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] SMTP 명령어를 통한 원격 사용자 계정 사전 추출 공격에 노출된 설정이 존재합니다: {', '.join(vulnerable_details)}"
        
        # 중복 명령어 정돈 처리
        unique_cmds = []
        for cmd in remediation_cmds:
            if cmd not in unique_cmds:
                unique_cmds.append(cmd)
        banner = ["# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 실행하세요."]
        result["remediation_cmd"] = "\n".join(banner + unique_cmds)

    return result