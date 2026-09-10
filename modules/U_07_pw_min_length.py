# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-07",
        "item_Level": "low",
        "title": "불필요한 계정 제거",
        "status": "Vulnerable",
        "description": "퇴직, 전직, 휴직 등의 사유로 장기간 사용하지 않는 계정 및 불필요한 기본 시스템 계정의 존재 여부 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "#[user 잠금 명령어]\n sudo usermod -s /sbin/nologin\n#[미사용 계정 삭제(퇴직자 등)]\n sudo userdel <username>\n#[불필요 계정 완전 삭제]\n sudo userdel -r <username>",
        "exception_guide": "[양호] 로그인이 가능한 미사용 일반 계정이 없고, uucp/nuucp 등 불필요한 기본 계정이 제거되었거나 쉘이 차단된 경우"
    }

    passwd_path = "/etc/passwd"

    # 존재 여부 확인
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 파일이 존재하지 않아 수동 확인이 필요합니다."
        return result
    
    # 안전하게 계정을 삭제(userdel) 해도 되는 계정 패턴 정의
    excat_delete_targets = ["uucp", "nuucp", "lp", "games", "test", "tester", "exam", "guest", "temp", "tmp"]

    # 삭제되면 안 되며, 로그인만 차단(nologin)해야 하는 핵심 시스템 계정 정의
    protect_block_targets = ["nobody", "sync", "shutdown", "halt", "gdm", "gnome", "mail", "postfix", "rpc", "rpcuser"]

    detected_to_delete = []     # userdel 대상
    detected_to_block = []      # login shell 차단 대상
    vulnerable_active_user = [] # 장기 미사용자(취약 계정)

    active_shells = ["/bin/bash", "/bin/sh", "/usr/bin/bash", "/usr/bin/sh"]

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 7:
                    username = parts[0]
                    uid = parts[2]
                    login_shell = parts[6]

                    if not uid.isdigit():
                        continue
                    uid = int(uid)

                    # 삭제 대상 검사 로직 (user1, user2 같은 임시 테스트 계정만 좁게 매칭 - userkim 등 실계정 오탐 방지)
                    is_temp_pattern = re.match(r'^user\d+$', username) is not None
                    if (username in excat_delete_targets or is_temp_pattern) and login_shell in active_shells:
                        detected_to_delete.append(username)
                        continue

                    # 로그인 차단이 필요한 핵심 시스템 계정
                    if username in protect_block_targets:
                        if login_shell in active_shells:
                            detected_to_block.append(username)
                        continue

                    # 장기 미사용 & 일반 사용자 계정 추적(UID 1000 이상)
                    if uid >= 1000 and login_shell in active_shells:
                        try:
                            out = subprocess.check_output(
                                ["last", "-n", "1", username],
                                text=True, stderr=subprocess.DEVNULL
                            )
                            # last는 tty 출력 시 계정명을 8자로 잘라 표시하므로
                            # username 문자열 포함 여부로 판단하지 않고, 실제 로그인, 레코드 라인이 있는지(꼬리의 "wtmp begins.." 문구 제외)로 판단
                            login_lines = [
                                l for l in out.splitlines()
                                if l.strip() and not l.strip().startswith("wtmp")
                            ]
                            if not login_lines:
                                vulnerable_active_user.append(username)
                        except Exception:
                            # last 명령 실행 자체가 실패한 경우(권한 부족/미설치 등)는
                            # 정상 계정을 오탐으로 삭제 권고하지 않도록 취약 처리하지 않음
                            pass
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{passwd_path} 분석 중 오류 발생: {str(e)}"
        return result
    
    # 조치 명령어 생성(remediation_cmd)
    remediation_cmds = []
    summary_elements = []

    if detected_to_delete:
        summary_elements.append(f"불필요 계정(삭제 권장): {', '.join(detected_to_delete)}")
        for u in detected_to_delete:
            remediation_cmds.append(f"userdel -r {u}")  # 서버의 사용자의 정보를 완전히 삭제

    if detected_to_block:
        summary_elements.append(f"차단 필요 시스템 계정(nologin): {', '.join(detected_to_block)}")
        for u in detected_to_block:
            remediation_cmds.append(f"sudo usermod -s /sbin/nologin {u}")

    if vulnerable_active_user:
        summary_elements.append(f"장기 미사용 일반 계정(퇴직자 등): {', '.join(vulnerable_active_user)}")
        for u in vulnerable_active_user:
            remediation_cmds.append(f"userdel {u}") # 계정 정보만 삭제하고 디렉토리 파일 등은 그대로 서버에 남음(퇴직자 발생시)

    # KISA 가이드 최종 판정
    if not summary_elements:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 불필요한 임시 계정이 없으며, 주요 핵심 시스템 계정의 원격/로컬 로그인 쉘이 안전하게 차단되어 있습니다."
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 계정 관리 보완 필요 -> {' / '.join(summary_elements) }"
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result