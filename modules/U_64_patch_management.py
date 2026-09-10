# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import subprocess

def Check():
    result = {
        "item_id": "U-64",
        "item_Level": "High",
        "title": "주기적 보안 패치 및 벤더 권고사항 적용",
        "status": "Vulnerable",
        "description": "알려진 취약점을 악용한 시스템 침해사고를 차단하기 위해 운영체제(OS) 및 커널의 주기적인 패치 관리 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# 1. Rocky Linux DNF 패키지 관리자를 통한 보안 패치 및 커널 최신화\n"
            "# (서비스 영향도를 고려하여 사전 승인된 정비 시간대에 실행 권장)\n"
            "# dnf check-update --security\n"
            "# dnf upgrade --security -y\n"
            "# 또는 전체 최신화:\n"
            "# dnf update -y"
        ),
        "exception_guide": "[양호] 패치 적용 정책을 수립하여 주기적으로 패치 관리를 수행하고 있으며, 최신 패치 배포 내용을 확인하고 커널 및 OS 버전에 유기적으로 적용한 경우"
    }

    os_info = "Unknown Rocky/RHEL OS"
    kernel_info = "Unknown Kernel"

    # [Step 1] hostnamectl을 활용한 OS 및 커널 정보 수집
    try:
        out = subprocess.check_output(["hostnamectl"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if "Operating System" in line:
                os_info = line.split(":", 1)[1].strip()
            elif "Kernel" in line:
                kernel_info = line.split(":", 1)[1].strip()
    except Exception:
        pass

    # [Step 2] /etc/rocky-release, /etc/redhat-release 교차 확인
    if os_info == "Unknown Rocky/RHEL OS":
        for rel_file in ["/etc/rocky-release", "/etc/redhat-release", "/etc/os-release"]:
            if os.path.exists(rel_file):
                try:
                    with open(rel_file, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read().strip()
                        if content:
                            os_info = content.splitlines()[0]
                            break
                except Exception:
                    pass

    if kernel_info == "Unknown Kernel":
        try:
            kernel_info = subprocess.check_output(["uname", "-r"], text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            pass

    # KISA 가이드 최종 판정: 관리자의 패치 정책 및 이력 수동 검토 필요
    result["status"] = "Manual Check"
    result["current_setting"] = f"[확인필요] 시스템 제원 -> OS: {os_info} | Kernel: {kernel_info}. Rocky Linux 보안 패치 정책 및 주기적 패치 관리 현황을 수동 검토하십시오."

    return result
