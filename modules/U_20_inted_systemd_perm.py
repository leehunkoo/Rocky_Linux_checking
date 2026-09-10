# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat
import glob

def Check():
    result = {
        "item_id": "U-20",
        "item_Level": "High",
        "title": "/etc/(x)inetd.conf 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "슈퍼데몬 및 systemd 서비스 관리 설정 파일의 임의 변조를 통한 악의적인 서비스 등록을 차단하기 위해 파일 소유자(root)와 권한(600 이하)을 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 존재하는 핵심 서비스 설정 파일들의 소유자가 root이고, 권한이 600 이하인 경우 (존재하지 않는 서비스 규격은 자동 제외)"
    }

    # 점검 대상: (x)inetd 계열 + systemd 전역 설정(system.conf) + 시스템 단위 서비스 유닛 전체(/etc/systemd/system/**)
    # 주의: /etc/systemd/user/**는 root가 아니라 로그인한 사용자의 systemd --user 세션이 직접
    # 읽어야 하는 파일이라 이 항목(root 전용 600) 대상에서 의도적으로 제외함
    target_groups = {
        "inetd_conf": ["/etc/inetd.conf"],
        "xinetd_conf": ["/etc/xinetd.conf"],
        "xinetd_d": ["/etc/xinetd.d/*"],
        "systemd_system_conf": ["/etc/systemd/system.conf"],
        "systemd_system_dir": ["/etc/systemd/system/**"],
    }

    vulnerable_elements = []
    vulnerable_groups = set()
    checked_files_count = 0

    for group_name, patterns in target_groups.items():
        for pattern in patterns:
            matches = glob.glob(pattern, recursive=True) if "**" in pattern else glob.glob(pattern)
            for file_path in matches:
                if not os.path.isfile(file_path):
                    continue

                try:
                    checked_files_count += 1
                    file_stat = os.stat(file_path)
                    owner_uid = file_stat.st_uid
                    mode = file_stat.st_mode
                    permission_int = stat.S_IMODE(mode)
                    permission_oct = format(permission_int, "03o")

                    # KISA 가이드 판단 기준: 600 이하 (소유자 읽기/쓰기 외에 그룹 및 타인의 모든 권한 거부)
                    excess_mask = 0o177 | stat.S_IXUSR
                    has_excess_permission = (permission_int & excess_mask) != 0

                    # 소유자가 root(UID 0)가 아니거나 600 권한을 만족하지 못할 경우 취약 항목 적재
                    if owner_uid != 0 or has_excess_permission:
                        filename = os.path.basename(file_path)
                        parent_dir = os.path.basename(os.path.dirname(file_path))
                        display_name = f"{parent_dir}/{filename}" if parent_dir else filename
                        vulnerable_elements.append(f"{display_name}(권한:{permission_oct}, UID:{owner_uid})")
                        vulnerable_groups.add(group_name)

                except Exception:
                    continue

    # KISA 가이드 최종 판정
    if checked_files_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 점검 대상이 되는 레거시 슈퍼데몬 및 표준 systemd 환경 설정 파일이 식별되지 않습니다."
        return result

    if not vulnerable_elements:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 존재하는 총 {checked_files_count}개의 서비스 제어 파일 소유권(root) 및 접근 제어 정책(600 이하)이 완벽히 준수되고 있습니다."
    else:
        # 가독성을 고려한 최대 5개 요약 노출 알고리즘 적용
        max_display = 5
        displayed_items = vulnerable_elements[:max_display]
        total_vuln_count = len(vulnerable_elements)

        summary_msg = f"미흡 파일 총 {total_vuln_count}건 발견 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 설정 미흡"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 관리자 외에 접근 및 수정이 가능한 취약한 서비스 설정 파일이 존재합니다:\n{summary_msg}"

        # 실제로 취약점이 발견된 카테고리에 대해서만 조치 명령을 구성
        # (예전 코드는 경로가 '존재하기만' 하면 무관한 카테고리까지 통째로 chmod -R 하던 버그가 있었음)
        # 디렉터리는 chmod -R 600 대신 find로 파일만 골라 처리 -> 디렉터리 탐색(실행) 비트 보존
        cmd_blocks = []
        if "inetd_conf" in vulnerable_groups:
            cmd_blocks.append("chown root /etc/inetd.conf && chmod 600 /etc/inetd.conf")
        if "xinetd_conf" in vulnerable_groups:
            cmd_blocks.append("chown root /etc/xinetd.conf && chmod 600 /etc/xinetd.conf")
        if "xinetd_d" in vulnerable_groups:
            cmd_blocks.append(
                "find /etc/xinetd.d -type f -exec chown root {} \\; -exec chmod 600 {} \\;"
            )
        if "systemd_system_conf" in vulnerable_groups:
            cmd_blocks.append("chown root /etc/systemd/system.conf && chmod 600 /etc/systemd/system.conf")
        if "systemd_system_dir" in vulnerable_groups:
            cmd_blocks.append(
                "find /etc/systemd/system -type f -exec chown root {} \\; -exec chmod 600 {} \\;"
            )

        header = (
            "# [주의] 여러 명령/조건문이 포함되어 있어 맨 앞에 sudo만 붙이면 뒤쪽 명령은 권한 미적용됩니다.\n"
            "# 'sudo -i'로 root 셸에 먼저 진입한 뒤(다시 sudo 붙이지 말고) 아래 전체를 실행하세요.\n"
            "# /etc/systemd/user/**는 로그인 사용자의 systemd --user 세션이 읽어야 하므로 의도적으로 제외했습니다.\n"
            "# [조치 시 영향 - 실측 확인] systemctl status/start/stop/restart/enable/disable 등 실제 서비스\n"
            "# 관리 명령은 systemd 데몬(root)이 대신 읽어 응답하므로 영향 없습니다. 다만 'systemctl cat <서비스>'로\n"
            "# sudo 없이 유닛 파일 내용을 직접 조회하던 경우 적용 후 Permission denied가 발생하니, 필요 시\n"
            "# 'sudo systemctl cat <서비스>'로 실행하십시오.\n"
        )
        result["remediation_cmd"] = header + "\n".join(cmd_blocks)

    return result
