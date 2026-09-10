# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import subprocess

def Check():
    result = {
        "item_id": "U-43",
        "item_Level": "High",
        "title": "NIS, NIS+ 점검",
        "status": "Vulnerable",
        "description": "네트워크 평문 전송 및 취약한 인증 구조를 가진 불필요한 NIS 서비스(ypserv, ypbind 등)의 구동을 차단하여 원격 권한 탈취 위협을 예방하는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 실행하세요.\n"
            "# 1. 명세표에 기재된 systemd 기반 활성 구동형 NIS 관련 데몬 일괄 영구 정지 및 비활성화\n"
            "for nis_svc in ypserv ypbind rpc.yppasswdd ypxfrd rpc.ypupdated nis; do\n"
            "  if systemctl is-active --quiet $nis_svc 2>/dev/null; then\n"
            "    systemctl stop $nis_svc 2>/dev/null\n"
            "    systemctl disable $nis_svc 2>/dev/null\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] NIS 관련 서비스 데몬들이 비활성화 상태이거나 시스템 내에 관련 서비스 패키지가 설치되지 않은 경우"
    }

    # KISA 상세 가이드라인 및 상세 명세표에 명시된 NIS/YP 제어 데몬군 매핑
    nis_target_services = [
        "ypserv",          # master와 slave 서버에서 실행되며 클라이언트로부터의 ypbind 요청에 응답
        "ypbind",          # 모든 NIS 시스템에서 실행되며 클라이언트와 서버를 바인딩하고 초기화함
        "rpc.yppasswdd",   # 사용자들이 비밀번호를 변경하기 위해 사용
        "ypxfrd",          # NIS 마스터 서버에서만 실행되며 고속으로 NIS 맵 전송
        "rpc.ypupdated",   # NIS 마스터 서버에서만 실행되며 고속으로 암호화하여 NIS 맵 전송
        "nis"              # 리눅스 배포판 통합 서비스 유닛
    ]
    
    nis_active = False
    detected_active_daemons = []

    # [Step 1] systemd API 메커니즘을 활용하여 명세표 데몬들의 실시간 활성 상태 검증 및 격리 진단
    for service_name in nis_target_services:
        try:
            # systemctl is-active 실행 결과 코드가 0이면 현재 동작 중인 프로세스로 판정
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                nis_active = True
                detected_active_daemons.append(service_name)
        except Exception:
            continue

    # KISA 가이드 최종 판정
    if not nis_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 보안에 취약한 평문 기반 NIS 서비스 데몬이 안전하게 비활성화되어 있거나 설치되지 않았습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 무단 정보 변조 및 타 시스템 권한 탈취 위험이 있는 NIS 서비스 데몬이 가동 중입니다 -> (활성 유닛: {', '.join(detected_active_daemons)})"

    return result