# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-34",
        "item_Level": "High",
        "title": "Finger 서비스 비활성화",
        "status": "Vulnerable",
        "description": "네트워크 외부에서 사용자 정보(이름, 홈 디렉터리, 로그인 정보 등) 유출을 방지하기 위해 Finger 서비스 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] if/fi 와 && 로 이어진 스크립트입니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤\n"
            "# (다시 sudo를 붙이지 말고) 전체를 붙여넣어 실행하세요.\n"
            "# 1. 레거시 inetd.conf 내 Finger 서비스 주석 처리 및 안전 가드 적용\n"
            "if [ -f /etc/inetd.conf ]; then\n"
            "  sed -i 's/^\\s*finger/#finger/g' /etc/inetd.conf\n"
            "fi &&\n"
            "# 2. xinetd.d/finger 서비스 강제 비활성화 (disable = yes)\n"
            "if [ -f /etc/xinetd.d/finger ]; then\n"
            "  if grep -q 'disable' /etc/xinetd.d/finger; then\n"
            "    sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/finger\n"
            "  else\n"
            "    sed -i '/}/i \\\\tdisable = yes' /etc/xinetd.d/finger\n"
            "  fi\n"
            "  systemctl restart xinetd 2>/dev/null || true\n"
            "fi &&\n"
            "# 3. 시스템 독립 실행형 finger 데몬 정지 및 비활성화\n"
            "for daemon in fingerd cfingerd efingerd; do\n"
            "  if systemctl is-active --quiet $daemon 2>/dev/null; then\n"
            "    systemctl stop $daemon\n"
            "    systemctl disable $daemon\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] Finger 서비스가 비활성화되어 있거나 시스템 내에 관련 서비스 데몬 및 패키지가 설치되지 않은 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_path = "/etc/xinetd.d/finger"
    
    finger_active = False
    detected_locations = []

    # [Step 1] /etc/inetd.conf 내 활성화 여부 파싱
    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if re.search(r"^\s*finger\s+", line):
                        finger_active = True
                        detected_locations.append("inetd.conf")
                        break
        except Exception:
            pass

    # [Step 2] /etc/xinetd.d/finger 내 disable 옵션 파싱 (기본값은 무조건 안전하게 시작)
    if os.path.exists(xinetd_path):
        try:
            is_disabled = False
            with open(xinetd_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # 주석 처리되지 않은 disable 세팅 추적
                disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                if disable_match:
                    if disable_match.group(1).lower() == "yes":
                        is_disabled = True
                
                # 만약 명시적으로 disable = yes 가 설정되어 있지 않다면 활성으로 간주
                if not is_disabled:
                    finger_active = True
                    detected_locations.append("xinetd.d/finger")
        except Exception:
            pass

    # [Step 3] 현대 Rocky Linux 독립 데몬(systemd 호환 패키지) 동작 여부 크로스체크
    target_daemons = ["fingerd", "cfingerd", "efingerd"]
    for daemon in target_daemons:
        try:
            # systemctl 상태 확인 코드로 백그라운드 활성 스캔
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", daemon], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                finger_active = True
                detected_locations.append(f"systemd:{daemon}")
        except Exception:
            pass

    # KISA 가이드 최종 판정
    if not finger_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] Finger 서비스가 비활성화되어 있거나 시스템 내에 설치되지 않아 외부 사용자 정보 유출 취약점이 존재하지 않습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 외부 주소 조회가 허용된 Finger 서비스가 탐지되었습니다 -> (활성 경로: {', '.join(detected_locations)})"

    return result