# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re

_NOLOGIN_SHELLS = {"nologin", "false", "sync", "shutdown", "halt"}


def _is_nologin_shell(shell_path):
    return os.path.basename(shell_path.strip()) in _NOLOGIN_SHELLS


def Check():
    result = {
        "item_id": "U-32",
        "item_Level": "Medium",
        "title": "홈 디렉토리로 지정한 디렉토리의 존재 관리",
        "status": "Vulnerable",
        "description": "/etc/passwd에 설정된 홈 디렉터리가 유실 및 미존재하여 로그인 시 루트(/) 경로로 임시 할당되는 보안 위험 계정이 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 시스템 내 모든 사용자 계정에 지정된 홈 디렉터리 경로가 물리적으로 정상 존재하고 있는 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 검증 
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/passwd 파일이 존재하지 않아 홈 디렉터리 존재 여부 조사를 진행할 수 없습니다."
        return result

    # /etc/login.defs UID_MIN(기본 1000) 기준으로 base-passwd 표준 시스템 계정을 제외.
    # lp/news/uucp/list/irc 등은 base-passwd가 항상 미리 만들어두는 nologin 계정이며, 해당
    # 패키지(cups, news 서버, uucp 등)를 실제로 설치하지 않으면 홈으로 지정된 스풀 디렉터리
    # (/var/spool/lpd 등) 자체가 애초에 생성되지 않는 것이 기본 Rocky Linux 환경의 정상 상태.
    # 이 계정들은 로그인 자체가 불가능(/usr/sbin/nologin)해 가이드가 우려하는 "로그인 시 홈이
    # 루트로 할당" 위협이 성립하지 않으므로, 걸러내지 않으면 모든 기본 Rocky Linux에서 대량 오탐 발생.
    uid_min = 1000
    try:
        with open("/etc/login.defs", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                m = re.match(r"^UID_MIN\s+(\d+)", line)
                if m:
                    uid_min = int(m.group(1))
                    break
    except Exception:
        pass

    missing_home_accounts = []
    remediation_cmds = []
    checked_count = 0

    try:
        # /etc/passwd 파일을 순차적으로 읽어 모든 계정명과 지정 홈 디렉터리 경로 분석
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 7:
                    username = parts[0].strip()
                    uid = int(parts[2].strip())
                    home_dir = parts[5].strip()
                    shell = parts[6].strip()

                    # base-passwd 표준 시스템 계정(0 < UID < UID_MIN) 제외 — root와 일반
                    # 사용자(UID >= UID_MIN)만 실제 로그인 위험이 있는 점검 대상으로 삼음.
                    # UID_MIN만으로는 nobody(65534)처럼 Rocky Linux의 "동적 할당 시스템 UID"(6만번대)
                    # 계정을 못 걸러내므로, 로그인 셸이 nologin류인 경우도 함께 제외.
                    if (uid != 0 and uid < uid_min) or _is_nologin_shell(shell):
                        continue

                    # 시스템 기본 분기 필터링 예외 처리
                    # 홈 디렉터리가 비어 있거나 지정 경로 자체가 없는 특이 케이스 대응
                    if not home_dir:
                        missing_home_accounts.append(f"{username}(설정 경로 없음)")
                        remediation_cmds.append(f"# 계정 '{username}'의 홈 디렉토리 경로가 설정되지 않았습니다. 환경에 맞는 홈 디렉토리를 생성 및 매핑하십시오.")
                        continue

                    checked_count += 1
                    
                    # 물리적으로 디렉터리가 실재하는지 확인
                    if not os.path.isdir(home_dir):
                        missing_home_accounts.append(f"{username}({home_dir})")
                        
                        # 가이드라인 표준 조치 사례(Step 2, Step 3) 기반 안내 명령어 빌드
                        remediation_cmds.append(f"# [조치선택 1] 불필요한 계정일 경우 삭제: userdel {username}")
                        remediation_cmds.append(f"# [조치선택 2] 사용 중인 계정일 경우 홈 디렉토리 물리 생성: mkdir -p {home_dir} && chown {username} {home_dir}")

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"사용자 계정 정보 파싱 중 예외 발생: {str(e)}"
        return result

    # KISA 가이드 최종 판정
    if not missing_home_accounts:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 점검 대상이 되는 총 {checked_count}개 계정의 지정 홈 디렉터리가 시스템 내에 모두 정상적으로 존재합니다."
    else:
        # 대시보드 UI 칸 깨짐 방지 및 정렬 가독성 보장을 위한 최대 5개 노출 필터 적용
        max_display = 5
        displayed_items = missing_home_accounts[:max_display]
        total_vuln_count = len(missing_home_accounts)

        summary_msg = f"홈 디렉터리 미존재 계정 총 {total_vuln_count}건 발견 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 계정 추가 점검 필요"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 설정된 홈 디렉터리가 유실되어 무단 권한 액세스 위험이 있는 계정이 감지되었습니다:\n{summary_msg}"
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result