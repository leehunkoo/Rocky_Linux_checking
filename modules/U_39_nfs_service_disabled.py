# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import subprocess

def Check():
    result = {
        "item_id": "U-39",
        "item_Level": "High",
        "title": "불필요한 NFS 서비스 비활성화",
        "status": "Vulnerable",
        "description": "불필요한 파일 공유로 인한 무단 데이터 유출 및 외부 침해사고 위험을 차단하기 위해 NFS 서비스(nfs-server 등)의 비활성화 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.\n"
            "# Rocky Linux NFS 서비스 영구 정지 및 비활성화\n"
            "for nfs_svc in nfs-server nfs nfs-lock nfs-idmapd; do\n"
            "  if systemctl is-active --quiet $nfs_svc 2>/dev/null; then\n"
            "    systemctl stop $nfs_svc 2>/dev/null\n"
            "    systemctl disable $nfs_svc 2>/dev/null\n"
            "  fi\n"
            "done"
        ),
        "exception_guide": "[양호] 원격 파일 시스템 마운트용 NFS 관련 서비스 데몬들이 비활성화 상태이거나 시스템 내에 설치되지 않은 경우"
    }

    # Rocky Linux / Enterprise Linux NFS 서비스 유닛
    nfs_target_services = ["nfs-server", "nfs", "nfs-kernel-server", "nfs-lock"]
    nfs_active = False
    detected_active_daemons = []

    for service_name in nfs_target_services:
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                nfs_active = True
                detected_active_daemons.append(service_name)
        except Exception:
            continue

    if not nfs_active:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 침해사고 위험성이 높은 NFS 서비스 데몬이 안전하게 비활성화되어 있거나 설치되지 않았습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 불필요하거나 접근 제어가 미비할 수 있는 NFS 데몬이 가동 중입니다 -> (활성 유닛: {', '.join(detected_active_daemons)})"

    return result
