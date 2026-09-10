# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import stat

def Check():
    result = {
        "item_id": "U-37",
        "item_Level": "High",
        "title": "crontab 설정파일 권한 설정 미흡",
        "status": "Vulnerable",
        "description": "관리자 외 일반 사용자가 crontab/at 명령어 및 관련 설정 파일을 통해 불법적인 예약 작업을 등록/실행하지 못하도록 명령어 및 관련 파일의 소유자·권한 설정을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] crontab/at 명령어에 일반 사용자(Others) 실행 권한이 없고, cron/at 관련 설정·작업 파일의 소유자가 root이며 권한이 640 이하인 경우"
    }

    findings = []
    remediation_cmds = []
    checked_count = 0

    # 1. crontab/at 명령어 자체 권한 점검 (Others 실행 제한)
    for cmd_path in ["/usr/bin/crontab", "/usr/bin/at"]:
        if not os.path.exists(cmd_path):
            continue
        try:
            checked_count += 1
            mode = stat.S_IMODE(os.stat(cmd_path).st_mode)
            perm_oct = oct(mode)[2:]
            if mode & (stat.S_IXOTH | stat.S_IROTH):
                findings.append(f"{cmd_path}(권한:{perm_oct}, 일반 사용자 실행/조회 권한 존재)")
                remediation_cmds.append(f"chmod o-rx {cmd_path}")
        except Exception:
            continue

    # 2. cron 관련 설정 파일 점검: /etc/crontab, /etc/cron.d/*, /etc/cron.allow, /etc/cron.deny
    cron_targets = []
    if os.path.isfile("/etc/crontab"):
        cron_targets.append("/etc/crontab")
    cron_d_dir = "/etc/cron.d"
    if os.path.isdir(cron_d_dir):
        try:
            for name in os.listdir(cron_d_dir):
                full = os.path.join(cron_d_dir, name)
                if os.path.isfile(full):
                    cron_targets.append(full)
        except Exception:
            pass
    for name in ["/etc/cron.allow", "/etc/cron.deny", "/etc/at.allow", "/etc/at.deny"]:
        if os.path.isfile(name):
            cron_targets.append(name)

    # 3. Rocky Linux / RHEL 표준 crontab 스풀 디렉터리 (/var/spool/cron/*)
    for c_dir in ["/var/spool/cron", "/var/spool/cron/crontabs"]:
        if os.path.isdir(c_dir):
            try:
                for name in os.listdir(c_dir):
                    full = os.path.join(c_dir, name)
                    if os.path.isfile(full):
                        cron_targets.append(full)
            except Exception:
                pass

    # 4. at 작업 목록 스풀 디렉터리
    for at_spool in ["/var/spool/at", "/var/spool/cron/atjobs"]:
        if os.path.isdir(at_spool):
            try:
                for name in os.listdir(at_spool):
                    full = os.path.join(at_spool, name)
                    if os.path.isfile(full):
                        cron_targets.append(full)
            except Exception:
                pass

    excess_mask = 0o037  # 그룹 쓰기/실행 + 타인 전체 권한 차단 마스크
    for target in cron_targets:
        try:
            checked_count += 1
            file_stat = os.stat(target)
            owner_uid = file_stat.st_uid
            mode = stat.S_IMODE(file_stat.st_mode)
            perm_oct = oct(mode)[2:]

            is_owner_bad = owner_uid != 0
            is_perm_bad = (mode & excess_mask) != 0

            if is_owner_bad or is_perm_bad:
                reasons = []
                if is_owner_bad:
                    reasons.append(f"소유자 부적절(UID:{owner_uid})")
                if is_perm_bad:
                    reasons.append(f"권한 초과({perm_oct})")
                findings.append(f"{target}({', '.join(reasons)})")

                cmd_parts = []
                if is_owner_bad:
                    cmd_parts.append(f"chown root {target}")
                if is_perm_bad:
                    cmd_parts.append(f"chmod 640 {target}")
                remediation_cmds.append(" && ".join(cmd_parts))
        except Exception:
            continue

    if not findings:
        result["status"] = "PASS(양호)"
        if checked_count == 0:
            result["current_setting"] = "[양호] crontab/at 명령어 및 관련 설정 파일이 시스템에 존재하지 않아 점검 대상이 없습니다."
        else:
            result["current_setting"] = f"[양호] 점검된 총 {checked_count}개의 crontab/at 명령어 및 관련 파일의 소유자·권한 설정이 모두 기준을 충족합니다."
    else:
        max_display = 5
        displayed = findings[:max_display]
        total = len(findings)
        summary_msg = f"권한 설정 미흡 총 {total}건 발견 -> " + ", ".join(displayed)
        if total > max_display:
            summary_msg += f" 외 {total - max_display}개 추가 점검 필요"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] crontab/at 명령어 또는 관련 파일의 소유자·권한 설정이 미흡합니다:\n{summary_msg}"

        banner = [
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.",
            "# crontab/at 명령어 파일은 SGID 비트를 보존하기 위해 symbolic 모드(o-rx)로 변경하십시오.",
        ]
        result["remediation_cmd"] = "\n".join(banner + remediation_cmds)

    return result
