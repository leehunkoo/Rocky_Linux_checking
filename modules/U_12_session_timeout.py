# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re

def Check():
    result = {
        "item_id": "U-12",
        "item_Level": "Low",
        "title": "세션 종료 시간 설정",
        "status": "Vulnerable",
        "description": "사용자 유휴 시간 방치로 인한 비인가자 접근을 차단하기 위해 Session Timeout(방산업체 기준 300초 이하) 설정 여부 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] if/then/fi 블록이 포함되어 있어 맨 앞에 sudo만 붙이면 문법 오류/권한 거부가 납니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤(다시 sudo 붙이지 말고) 아래 전체를 그대로 붙여넣어 실행하세요.\n"
            "# 1. Bourne/Bash 쉘 계열 세션 타임아웃 중복 방지 안전 조치\n"
            "if [ -f /etc/profile ]; then\n"
            "  if grep -q 'TMOUT=' /etc/profile; then\n"
            "    sed -i 's/^\\s*TMOUT\\s*=.*/TMOUT=300/g' /etc/profile\n"
            "  else\n"
            "    echo '' >> /etc/profile\n"
            "    echo '# KISA U-12 Session Timeout 정책 적용' >> /etc/profile\n"
            "    echo 'TMOUT=300' >> /etc/profile\n"
            "    echo 'export TMOUT' >> /etc/profile\n"
            "  fi\n"
            "fi &&\n"
            "# 2. C쉘 계열 세션 타임아웃 안전 조치\n"
            "if [ -f /etc/csh.cshrc ]; then\n"
            "  if grep -q 'autologout=' /etc/csh.cshrc; then\n"
            "    sed -i 's/^\\s*set\\s\\+autologout\\s*=.*/set autologout=5/g' /etc/csh.cshrc\n"
            "  else\n"
            "    echo 'set autologout=5' >> /etc/csh.cshrc\n"
            "  fi\n"
            "fi"
        ),
        "exception_guide": "[양호] Session Timeout 정책이 300초(5분) 이하로 설정되어 유휴 세션이 자동 차단되는 경우 (※ 모니터링 전용 계정은 업무 영향도에 따라 예외 처리 가능)"
    }

    target_files = ["/etc/profile", "/etc/bashrc", "/etc/csh.cshrc"]

    tmout_val = None
    autologout_val = None
    detected_setting = []

    # 파일 존재 여부 검증
    for file_path in target_files:
        if not os.path.exists(file_path):
            continue

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    # Rocky Linux (Bourne/bash 계열) | ** kali(Debian)의 경우 Zsh 사용
                    tmout_match = re.search(r"^\s*TMOUT\s*=\s*(\d+)", line)
                    if tmout_match:
                        tmout_val = int(tmout_match.group(1))
                        detected_setting.append(f"{os.path.basename(file_path)}:TMOUT={tmout_val}초")

                    # Cshell 계열(set autologout = 10 구조 파싱)
                    csh_match = re.search(r"^\s*set\s+autologout\s*=\s*(\d+)", line)
                    if csh_match:
                        autologout_val = int(csh_match.group(1))
                        detected_setting.append(f"{os.path.basename(file_path)}:autologout={autologout_val}분")

        except Exception:
            pass

    
    is_bash_ok = False
    is_csh_ok = True
    csh_exists = os.path.exists("/etc/csh.cshrc") or os.path.exists("/etc/csh.login")

    # KISA 가이드 최종 판정 (600초 이하 권고) | 방산업체 (300초 이하 권고)
    if tmout_val is not None and 0 < tmout_val <= 300:
        is_bash_ok = True

    if csh_exists:
        if autologout_val is not None and 0 < autologout_val <= 5:
            is_csh_ok = True
        else:
            is_csh_ok = False

    summary_msg = ", ".join(detected_setting) if detected_setting else "Timeout 정책 설정 누락"

    if is_bash_ok and is_csh_ok:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 기준 시간(300초/5분) 이하로 세션 자동 종료 정책이 수립되어 있습니다. ({summary_msg})"

    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 세션 종료 제한 시간이 300초를 초과 하였거나, 설정이 누락되어 있습니다. ({summary_msg})"

        # 이 시스템에 실제로 존재하는 쉘 계열만 골라 조치 명령을 구성 (Bash/C쉘 자동 판별)
        cmd_blocks = []
        if not is_bash_ok:
            cmd_blocks.append(
                "if [ -f /etc/profile ]; then\n"
                "  if grep -q 'TMOUT=' /etc/profile; then\n"
                "    sed -i 's/^\\s*TMOUT\\s*=.*/TMOUT=300/g' /etc/profile\n"
                "  else\n"
                "    echo '' >> /etc/profile\n"
                "    echo '# KISA U-12 Session Timeout 정책 적용' >> /etc/profile\n"
                "    echo 'TMOUT=300' >> /etc/profile\n"
                "    echo 'export TMOUT' >> /etc/profile\n"
                "  fi\n"
                "fi"
            )
        if csh_exists and not is_csh_ok:
            cmd_blocks.append(
                "if [ -f /etc/csh.cshrc ]; then\n"
                "  if grep -q 'autologout=' /etc/csh.cshrc; then\n"
                "    sed -i 's/^\\s*set\\s\\+autologout\\s*=.*/set autologout=5/g' /etc/csh.cshrc\n"
                "  else\n"
                "    echo 'set autologout=5' >> /etc/csh.cshrc\n"
                "  fi\n"
                "fi"
            )

        shell_note = "C쉘(csh) 설치 확인됨 - 두 계열 모두" if csh_exists else "Bash/Bourne 계열만 사용 중"
        header = (
            "# [주의] if/then/fi 블록이 포함되어 있어 맨 앞에 sudo만 붙이면 문법 오류/권한 거부가 납니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤(다시 sudo 붙이지 말고) 아래 전체를 그대로 붙여넣어 실행하세요.\n"
            f"# (이 시스템은 {shell_note} 조치 대상입니다)\n"
        )
        result["remediation_cmd"] = header + " &&\n".join(cmd_blocks)

    return result
