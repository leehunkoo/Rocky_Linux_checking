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
            "# [수동 점검 절차 및 명령어]\n"
            "# 1. 적용 가능한 보안 업데이트 존재 여부 확인:\n"
            "dnf check-update --security\n"
            "# -> 출력 결과에 패키지 목록이 없으면 최신 보안 패치가 모두 적용된 양호 상태입니다.\n\n"
            "# 2. 최근 패키지 및 커널 업데이트 이력 확인:\n"
            "dnf history list\n"
            "# -> 정기적으로(월/분기별) 시스템 패치를 수행한 이력이 있는지 확인합니다.\n\n"
            "# 3. 보안 패치 적용 정책 수립 확인:\n"
            "# -> 조직 내 '보안 패치 관리 지침' 또는 정기 점검 계획이 수립되어 운영 중인지 검토합니다.\n\n"
            "# [미흡 시 조치: 보안 업데이트 일괄 적용]\n"
            "# (운영 서비스 영향도를 고려하여 사전 승인된 정비 시간에 실행 권장)\n"
            "sudo dnf upgrade --security -y"
        ),
        "exception_guide": "[양호] 패치 적용 정책을 수립하여 주기적으로 패치 관리를 수행하고 있으며, 최신 패치 배포 내용을 확인하고 커널 및 OS 버전에 유기적으로 적용한 경우"
    }

    os_info = "Unknown Rocky/RHEL OS"
    kernel_info = "Unknown Kernel"

    # [Step 1] hostnamectl을 활용한 OS 및 커널 정보 수집
    try:
        out = subprocess.check_output(["hostnamectl"], universal_newlines=True, stderr=subprocess.DEVNULL)
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
            kernel_info = subprocess.check_output(["uname", "-r"], universal_newlines=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            pass

    # KISA 가이드 최종 판정: 관리자의 패치 정책 및 이력 수동 검토 필요
    result["status"] = "Manual Check"
    result["current_setting"] = f"[확인필요] 시스템 제원 -> OS: {os_info} | Kernel: {kernel_info}. Rocky Linux 보안 패치 정책 및 주기적 패치 관리 현황을 수동 검토하십시오."

    return result
