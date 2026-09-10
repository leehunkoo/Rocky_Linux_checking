# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-63",
        "item_Level": "Medium",
        "title": "sudo 명령어 접근 관리",
        "status": "Vulnerable",
        "description": "비인가 사용자의 관리자 권한 남용 및 불법적인 시스템 설정을 차단하기 위해 /etc/sudoers 파일의 소유권(root)과 접근 권한 규격(640)의 적절성을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] /etc/sudoers 파일의 소유자가 root이고, 파일 권한이 640 이하(또는 440)로 설정되어 일반 사용자 및 불필요한 그룹의 쓰기/실행 권한이 완벽히 차단된 경우"
    }

    file_path = "/etc/sudoers"

    # [Step 1] /etc/sudoers 파일의 물리적 존재 유무 선제 필터링
    if not os.path.exists(file_path):
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 sudo 명령어 설정 파일(/etc/sudoers)이 존재하지 않아 권한 남용 취약성에 노출되지 않습니다."
        return result

    try:
        # [Step 2] 파일 메타데이터 및 비트 플래그 연산 추출
        f_stat = os.stat(file_path)
        owner_uid = f_stat.st_uid
        mode = f_stat.st_mode
        permission_int = stat.S_IMODE(mode)
        permission_oct = oct(permission_int)[2:]

        # 가이드라인 권고 수치: 소유자(root), 권한(640 이하)
        # 640을 초과하는 위험 비트 차단 마스킹 검증 연산 구동
        # 소유자의 실행(0o100), 그룹의 쓰기/실행(0o030), 타인(Others)의 모든 권한(0o007) 허용 여부 조사
        excess_mask = stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH
        has_excess_permission = (permission_int & excess_mask) != 0

        summary_msg = f"소유자 UID: {owner_uid}, 현재 권한: {permission_oct}"

        # KISA 가이드 최종 판정
        if owner_uid != 0:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/sudoers 파일의 소유권이 root 관리자가 아닙니다. ({summary_msg})"
            result["remediation_cmd"] = (
                "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
                "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
                "chown root /etc/sudoers && chmod 640 /etc/sudoers"
            )
        elif has_excess_permission:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] /etc/sudoers 파일의 권한 범위가 가이드라인 규격(640 이하)을 초과하여 개방되어 있습니다. ({summary_msg})"
            result["remediation_cmd"] = (
                "# [주의] && 로 이어진 명령입니다. 맨 앞에 sudo 하나만 붙이면 chmod 부분은 권한 미적용됩니다.\n"
                "# 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
                "chown root /etc/sudoers && chmod 640 /etc/sudoers"
            )
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] /etc/sudoers 파일의 소유자(root) 및 보안 격리 권한({permission_oct}) 사양이 완벽하게 통제 중입니다."

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"[확인필요] 파일 속성 획득 도중 예외가 발생했습니다: {str(e)}"

    return result