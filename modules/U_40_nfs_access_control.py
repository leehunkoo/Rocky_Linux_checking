# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat
import re

def Check():
    result = {
        "item_id": "U-40",
        "item_Level": "High",
        "title": "NFS 접근 통제",
        "status": "Vulnerable",
        "description": "인증 절차 없는 비인가자의 무단 파일 마운트 및 중요 데이터 변조/유출을 방지하기 위해 /etc/exports 파일의 권한 규격(644 이하)과 접근 통제 정책 적절성을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] NFS 서비스를 사용하지 않거나(설정 파일 미존재), 불가피하게 사용 시 /etc/exports 파일의 소유자가 root이고 권한이 644 이하이며 접근 통제 정책(전역 오픈 '*' 없음)이 안전하게 수립된 경우"
    }

    file_path = "/etc/exports"

    # 1. 가이드라인 기준: NFS 공유 설정 파일 자체가 없다면 서비스 미사용으로 간주하여 PASS(양호) 처리
    if not os.path.exists(file_path):
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 NFS 공유 설정 파일(/etc/exports)이 존재하지 않아 잠재적 취약성이 유실된 안전한 상태입니다."
        return result

    try:
        # 2. 파일 메타데이터(소유자 UID, 권한 비트) 조회 및 검증
        file_stat = os.stat(file_path)
        owner_uid = file_stat.st_uid
        mode = file_stat.st_mode
        permission_int = stat.S_IMODE(mode)
        permission_oct = oct(permission_int)[2:]

        # 가이드라인 판단 기준 1: 권한이 644 이하인지 확인 (그룹/타인의 쓰기 또는 실행 권한 허용 여부 마스킹)
        # 0o644를 초과하는 비트 권한(소유자 실행 0o100, 그룹 쓰기/실행 0o030, 타인 쓰기/실행 0o003) 검사
        excess_mask = stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IWOTH | stat.S_IXOTH
        has_excess_permission = (permission_int & excess_mask) != 0

        # 3. /etc/exports 파일 내 접근 통제 설정(와일드카드 및 옵션) 정밀 파싱
        has_wildcard_open = False
        vulnerable_lines = []

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line_content = line.strip()
                if not line_content or line_content.startswith("#"):
                    continue

                # 공백 또는 탭을 기준으로 경로와 접근 호스트 정책 분할
                tokens = line_content.split()
                if len(tokens) >= 2:
                    # 호스트 정의 부분에 '*' 와일드카드가 포함되어 무차별 허용을 수행하는지 검사
                    # 예: /shared_dir *(rw,sync) 또는 /data *
                    for token in tokens[1:]:
                        if token.startswith("*"):
                            has_wildcard_open = True
                            vulnerable_lines.append(f"{line_num}행:전역개방('{line_content}')")
                            break

        summary_msg = f"소유자 UID: {owner_uid} | 파일 권한: {permission_oct}"
        
        # KISA 가이드 최종 판정
        sudo_banner = (
            "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
        )
        if owner_uid != 0:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/exports 파일의 소유자가 root가 아닙니다. ({summary_msg})"
            result["remediation_cmd"] = sudo_banner + "chown root /etc/exports && chmod 644 /etc/exports"
        elif has_excess_permission:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/exports 파일의 권한 설정이 권고 기준(644 이하)을 초과했습니다. ({summary_msg})"
            result["remediation_cmd"] = sudo_banner + "chown root /etc/exports && chmod 644 /etc/exports"
        elif has_wildcard_open:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/exports 내 특정 호스트가 아닌 전체 개방 와일드카드(*) 설정이 식별되었습니다. ({', '.join(vulnerable_lines)})"
            result["remediation_cmd"] = (
                sudo_banner +
                "# [조치] /etc/exports 파일 권한 고정 및 파일 내 와일드카드(*) 설정을 제거하고 특정 신뢰 호스트 IP만 매핑하십시오.\n"
                "chown root /etc/exports && chmod 644 /etc/exports"
            )
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] NFS 접근 통제 설정 파일의 소유권(root), 접근 제한 비트({permission_oct}) 및 세부 공유 타깃이 안전하게 통제되고 있습니다."

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"/etc/exports 속성 해석 및 파싱 중 예외 발생: {str(e)}"

    return result