# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re

def Check():
    result = {
        "item_id": "U-30",
        "item_Level": "Medium",
        "title": "UMASK 설정 관리",
        "status": "Vulnerable",
        "description": "신규 파일 및 디렉터리 생성 시 과도한 기본 권한이 부여되어 무단 수정 및 데이터 유출이 발생하는 것을 차단하기 위해 전역 UMASK 설정 상태를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "# 1. /etc/login.defs 내 UMASK 설정 수정\n"
            "if [ -f /etc/login.defs ]; then\n"
            "  if grep -q '^\\s*UMASK' /etc/login.defs; then\n"
            "    sed -i 's/^\\s*UMASK.*/UMASK           022/g' /etc/login.defs\n"
            "  else\n"
            "    echo 'UMASK           022' >> /etc/login.defs\n"
            "  fi\n"
            "fi &&\n"
            "# 2. /etc/profile 및 /etc/bashrc 내 umask 설정 수정\n"
            "if [ -f /etc/profile ]; then\n"
            "  if grep -q 'umask' /etc/profile; then\n"
            "    sed -i 's/^\\s*umask.*/umask 022/g' /etc/profile\n"
            "  else\n"
            "    echo '' >> /etc/profile\n"
            "    echo '# KISA U-30 UMASK 정책 적용' >> /etc/profile\n"
            "    echo 'umask 022' >> /etc/profile\n"
            "  fi\n"
            "fi &&\n"
            "if [ -f /etc/bashrc ]; then\n"
            "  if grep -q 'umask' /etc/bashrc; then\n"
            "    sed -i 's/^\\s*umask.*/umask 022/g' /etc/bashrc\n"
            "  fi\n"
            "fi"
        ),
        "exception_guide": "[양호] 전역 설정 파일(/etc/profile, /etc/bashrc, /etc/login.defs)의 UMASK 값이 022 이상(022 또는 027 등)으로 강제된 경우"
    }

    profile_path = "/etc/profile"
    bashrc_path = "/etc/bashrc"
    defs_path = "/etc/login.defs"

    if not os.path.exists(profile_path) and not os.path.exists(defs_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "전역 환경 변수 정책 파일(/etc/profile 및 /etc/login.defs)이 모두 존재하지 않아 수동 확인이 필요합니다."
        return result

    detected_settings = []
    profile_umask = None
    defs_umask = None

    if os.path.exists(profile_path):
        try:
            with open(profile_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    match = re.search(r"^\s*umask\s+(\d+)", line, re.IGNORECASE)
                    if match:
                        profile_umask = match.group(1)
                        detected_settings.append(f"profile:umask {profile_umask}")
        except Exception:
            pass

    if os.path.exists(bashrc_path):
        try:
            with open(bashrc_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    match = re.search(r"^\s*umask\s+(\d+)", line, re.IGNORECASE)
                    if match and profile_umask is None:
                        profile_umask = match.group(1)
                        detected_settings.append(f"bashrc:umask {profile_umask}")
        except Exception:
            pass

    if os.path.exists(defs_path):
        try:
            with open(defs_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    match = re.search(r"^\s*UMASK\s+(\d+)", line)
                    if match:
                        defs_umask = match.group(1)
                        detected_settings.append(f"login.defs:UMASK {defs_umask}")
        except Exception:
            pass

    def is_secure_umask(umask_str):
        if not umask_str or not umask_str.isdigit():
            return False
        val = umask_str.zfill(3)[-3:]
        group_bit = int(val[1])
        others_bit = int(val[2])
        return group_bit >= 2 and others_bit >= 2

    profile_ok = is_secure_umask(profile_umask) if profile_umask else True
    defs_ok = is_secure_umask(defs_umask) if defs_umask else True

    if profile_umask is None and defs_umask is None:
        profile_ok = False
        defs_ok = False

    summary_msg = ", ".join(detected_settings) if detected_settings else "UMASK 설정 정책 누락"

    if profile_ok and defs_ok:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시스템 전역 환경변수의 UMASK 값이 권고 기준(022 이상)에 부합하여 신규 파일 권한 오남용을 제한하고 있습니다. ({summary_msg})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] UMASK 값이 022 미만으로 완화되어 있거나 필수 설정 정책이 유실되었습니다. ({summary_msg})"

    return result
