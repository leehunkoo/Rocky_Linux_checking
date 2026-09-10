# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-42",
        "item_Level": "High",
        "title": "불필요한 RPC 서비스 비활성화",
        "status": "Vulnerable",
        "description": "버퍼 오버플로우, 원격 명령 실행 등 취약점이 다수 존재하는 불필요한 RPC 서비스의 활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] if/for/&& 로 이어진 스크립트입니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤\n"
            "# (다시 sudo를 붙이지 말고) 전체를 붙여넣어 실행하세요.\n"
            "# 1. 레거시 inetd.conf 내 취약한 RPC 서비스 주석 처리\n"
            "if [ -f /etc/inetd.conf ]; then\n"
            "  for rpc_svc in rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd; do\n"
            "    sed -i \"s/^\\s*$rpc_svc/#$rpc_svc/g\" /etc/inetd.conf\n"
            "  done\n"
            "fi &&\n"
            "# 2. xinetd.d 내 취약한 RPC 관련 서비스 강제 비활성화\n"
            "if [ -d /etc/xinetd.d ]; then\n"
            "  for xfile in $(ls /etc/xinetd.d/ 2>/dev/null); do\n"
            "    if echo \"$xfile\" | grep -qE \"(cmsd|ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|nisd|rexd|pcnfsd|statd|ypupdated|rquotad|kcms|cachefs)\"; then\n"
            "      if grep -q 'disable' /etc/xinetd.d/$xfile; then\n"
            "        sed -i 's/^\\s*disable\\s*=.*/disable = yes/g' /etc/xinetd.d/$xfile\n"
            "      else\n"
            "        sed -i '/}/i \\\\tdisable = yes' /etc/xinetd.d/$xfile\n"
            "      fi\n"
            "    fi\n"
            "  done\n"
            "  systemctl restart xinetd 2>/dev/null || true\n"
            "fi &&\n"
            "# 3. systemd 독립 구동형 RPC 서비스 일괄 영구 정지\n"
            "for s_unit in rpc-statd rpc-rquotad; do\n"
            "  if systemctl is-active --quiet $s_unit.service 2>/dev/null; then\n"
            "    systemctl stop $s_unit.service 2>/dev/null\n"
            "    systemctl disable $s_unit.service 2>/dev/null\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] 가이드라인에 명시된 불필요한 취약 RPC 서비스가 모두 비활성화되어 있거나 시스템 내에 설치되지 않은 경우"
    }

    inetd_path = "/etc/inetd.conf"
    xinetd_dir = "/etc/xinetd.d"
    
    # KISA 가이드라인 명시 불필요한 RPC 서비스 식별 키워드 목록
    rpc_keywords = [
        "cmsd", "ttdbserverd", "sadmind", "rusersd", "walld", "sprayd", 
        "rstatd", "nisd", "rexd", "pcnfsd", "statd", "ypupdated", "rquotad", 
        "kcms_server", "cachefsd"
    ]
    
    # 현대 배포판 기준 매핑되는 주요 systemd 서비스 명칭.
    # [주의] rpcbind(포트매퍼)는 가이드가 명시한 "불필요한 RPC 서비스" 목록(rpc.cmsd, rpc.statd,
    # rpc.rquotad 등 특정 레거시 데몬들)에 포함되지 않는 범용 기반 서비스라 대상에서 제외함.
    # rpcbind를 정지하면 이 목록과 무관한 다른 정상 RPC 의존 기능까지 함께 끊길 수 있음.
    systemd_rpc_units = ["rpc-statd", "rpc-rquotad"]

    rpc_active = False
    detected_locations = []

    # [Step 1] /etc/inetd.conf 내 활성화 여부 파싱
    if os.path.exists(inetd_path):
        try:
            with open(inetd_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    for kw in rpc_keywords:
                        if kw in line:
                            rpc_active = True
                            detected_locations.append(f"inetd.conf:{kw}")
        except Exception:
            pass

    # [Step 2] /etc/xinetd.d/ 디렉터리 내 설정 파일 전수 검사
    if os.path.exists(xinetd_dir) and os.path.isdir(xinetd_dir):
        try:
            for filename in os.listdir(xinetd_dir):
                for kw in rpc_keywords:
                    if kw in filename.lower():
                        target_file = os.path.join(xinetd_dir, filename)
                        if os.path.exists(target_file):
                            with open(target_file, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()
                                disable_match = re.search(r"^\s*disable\s*=\s*(yes|no)", content, re.MULTILINE | re.IGNORECASE)
                                is_disabled = False
                                if disable_match and disable_match.group(1).lower() == "yes":
                                    is_disabled = True
                                
                                if not is_disabled:
                                    rpc_active = True
                                    detected_locations.append(f"xinetd.d/{filename}")
        except Exception:
            pass

    # [Step 3] systemd 기반 핵심 RPC 서비스 구동 상태 실시간 스캔
    for unit in systemd_rpc_units:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", f"{unit}.service"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                rpc_active = True
                detected_locations.append(f"systemd:{unit}")
        except Exception:
            pass

    # KISA 가이드 최종 판정
    if not rpc_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 취약점 유발 우려가 있는 불필요한 RPC 서비스들이 안전하게 비활성화되어 있거나 설치되지 않았습니다."
    else:
        # 중복 식별 문자 정돈
        unique_locations = sorted(list(set(detected_locations)))
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 보안에 취약한 불필요한 RPC 서비스가 가동 중인 것으로 식별되었습니다 -> (활성 경로: {', '.join(unique_locations)})"

    return result