# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import subprocess

def Check():
    result = {
        "item_id": "U-41",
        "item_Level": "High",
        "title": "불필요한 automountd 제거",
        "status": "Vulnerable",
        "description": "RPC 취약점을 악용한 권한 상승 및 비인가 명령어 원격 실행 위험을 차단하기 위해 automount 및 autofs 서비스의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 실행하세요.\n"
            "# [조치 시 영향 - 가이드 원문] NFS/Samba 홈 디렉터리를 autofs로 자동 마운트하는 환경(NIS/LDAP\n"
            "# 연동 등)이라면 이 조치로 사용자 홈 접근이 끊길 수 있습니다. 적용 전 /etc/auto.* , /etc/auto_*\n"
            "# 파일이 실제로 쓰이고 있는지 먼저 확인하십시오. 또한 적용 후에는 CD-ROM 등 이동식 미디어의\n"
            "# 자동 마운트도 되지 않습니다.\n"
            "# 1. systemd 기반 활성 구동형 자동 마운트 서비스 데몬 일괄 영구 정지 및 비활성화\n"
            "for auto_svc in autofs automount; do\n"
            "  if systemctl is-active --quiet $auto_svc 2>/dev/null; then\n"
            "    systemctl stop $auto_svc 2>/dev/null\n"
            "    systemctl disable $auto_svc 2>/dev/null\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] automountd 또는 autofs 서비스가 비활성화 상태이거나 시스템 내에 관련 서비스 패키지가 설치되지 않은 경우"
    }

    # KISA 가이드 최종 판정
    auto_target_services = ["autofs", "automount"]
    
    auto_active = False
    detected_active_daemons = []

    # [Step 1] systemd API 매커니즘을 활용하여 실시간 활성 상태 검증 및 격리 진단
    for service_name in auto_target_services:
        try:
            # systemctl is-active 실행 결과 코드가 0이면 현재 동작 중인 프로세스로 판정
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                auto_active = True
                detected_active_daemons.append(service_name)
        except Exception:
            continue

    # [Step 2] 2026 KISA 상세 가이드라인 판단 기준 분기 조율 및 리포트 데이터 바인딩
    if not auto_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 권한 상승 공격에 취약한 automountd 및 autofs 서비스 데몬이 안전하게 비활성화되어 있거나 설치되지 않았습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 불필요한 RPC 취약점 노출 위험이 있는 자동 마운트 서비스가 가동 중입니다 -> (활성 유닛: {', '.join(detected_active_daemons)})"

    return result