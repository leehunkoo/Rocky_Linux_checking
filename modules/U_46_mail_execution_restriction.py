# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat
import re
import subprocess

def Check():
    result = {
        "item_id": "U-46",
        "item_Level": "High",
        "title": "일반 사용자의 메일 서비스 실행 방지",
        "status": "Vulnerable",
        "description": "비인가자에 의한 메일 큐 강제 드롭 및 SMTP 서비스 오류 유발을 방지하기 위해 일반 사용자의 메일 큐 제어 옵션(q 옵션 등) 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 메일 서비스를 사용하지 않아 데몬이 모두 비활성화되어 있거나, 사용 시 각 메일 시스템별 권한 제어 설정(restrictqrun 적용 또는 바이너리 타인 실행 권한 제거)이 완수된 경우"
    }

    mail_daemons = ["sendmail", "postfix", "exim4"]
    active_services = []

    # [Step 1] systemd 기반 메일 서비스 실시간 구동 상태 체크
    for daemon in mail_daemons:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                active_services.append(daemon)
        except Exception:
            continue

    # 가이드라인 조치 사항 반영: 메일 서비스를 일절 사용하지 않는 경우 자동으로 PASS(양호) 처리
    if not active_services:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에서 메일 서비스(Sendmail, Postfix, Exim)가 활성화되어 있지 않아 일반 사용자의 악의적인 큐 조작 취약점에 노출되지 않습니다. (N/A)"
        return result

    vulnerable_details = []
    remediation_cmds = []

    # [Step 2] 가동 중인 메일 시스템별 세부 권한 격리 상태 전수 점검
    for active_svc in active_services:
        if active_svc == "sendmail":
            sendmail_cf = "/etc/mail/sendmail.cf"
            if os.path.exists(sendmail_cf):
                try:
                    restrictqrun_found = False
                    with open(sendmail_cf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            if line.strip().startswith("#") or not line.strip():
                                continue
                            if "PrivacyOptions" in line and "restrictqrun" in line:
                                # 주석 없는 PrivacyOptions 지시어 내에 restrictqrun 바인딩 검증
                                if re.search(r"^\s*O\s+PrivacyOptions\s*=\s*.*restrictqrun", line):
                                    restrictqrun_found = True
                                    break
                    
                    if not restrictqrun_found:
                        vulnerable_details.append("Sendmail(PrivacyOptions 내 restrictqrun 설정 누락)")
                        remediation_cmds.extend([
                            f"# [조치] {sendmail_cf} 파일의 PrivacyOptions 설정에 restrictqrun 인자를 주입하십시오.",
                            "systemctl restart sendmail 2>/dev/null"
                        ])
                except Exception:
                    vulnerable_details.append("Sendmail(설정 파일 파싱 실패)")
            else:
                vulnerable_details.append("Sendmail(config 미식별)")

        elif active_svc == "postfix":
            postsuper_path = "/usr/sbin/postsuper"
            if os.path.exists(postsuper_path):
                try:
                    p_stat = os.stat(postsuper_path)
                    permission_int = stat.S_IMODE(p_stat.st_mode)
                    permission_oct = oct(permission_int)[2:]
                    
                    # 가이드라인 기준: 일반 사용자 실행 권한 제거 (chmod o-x)
                    # 타인 실행 권한 비트(stat.S_IXOTH)가 활성화되어 있다면 취약
                    if (permission_int & stat.S_IXOTH) != 0:
                        vulnerable_details.append(f"Postfix({postsuper_path} 타인 실행 권한 허용: {permission_oct})")
                        remediation_cmds.append(f"chmod o-x {postsuper_path}")
                except Exception:
                    vulnerable_details.append("Postfix(바이너리 속성 획득 실패)")
            else:
                vulnerable_details.append("Postfix(postsuper 경로 미식별)")

        elif active_svc == "exim4":
            exiqgrep_path = "/usr/sbin/exiqgrep"
            if os.path.exists(exiqgrep_path):
                try:
                    e_stat = os.stat(exiqgrep_path)
                    permission_int = stat.S_IMODE(e_stat.st_mode)
                    permission_oct = oct(permission_int)[2:]
                    
                    # 가이드라인 기준: 일반 사용자 실행 권한 제거 (chmod o-x)
                    if (permission_int & stat.S_IXOTH) != 0:
                        vulnerable_details.append(f"Exim4({exiqgrep_path} 타인 실행 권한 허용: {permission_oct})")
                        remediation_cmds.append(f"chmod o-x {exiqgrep_path}")
                except Exception:
                    vulnerable_details.append("Exim4(바이너리 속성 획득 실패)")
            else:
                vulnerable_details.append("Exim4(exiqgrep 경로 미식별)")

    # KISA 가이드 최종 판정
    if not vulnerable_details:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 현재 가동 중인 메일 서비스({', '.join(active_services)})에 대해 일반 사용자의 메일 큐 관리 및 제어 명령 실행 권한이 완전하게 통제되어 안전합니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 일반 사용자의 비인가 메일 서비스 통제가 미흡한 설정이 발견되었습니다: {', '.join(vulnerable_details)}"
        
        # 중복 명령어 정돈 처리
        unique_cmds = []
        for cmd in remediation_cmds:
            if cmd not in unique_cmds:
                unique_cmds.append(cmd)
        banner = ["# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 실행하세요."]
        result["remediation_cmd"] = "\n".join(banner + unique_cmds)

    return result