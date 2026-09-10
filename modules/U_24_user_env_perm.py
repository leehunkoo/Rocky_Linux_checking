# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

def Check():
    result = {
        "item_id": "U-24",
        "item_Level": "High",
        "title": "사용자, 시스템 환경변수 파일 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "비인가자의 환경변수 조작 및 변조로 인한 정상 서비스 악영향을 방지하기 위해 각 홈 디렉터리 내 환경변수 파일의 소유자 권한과 쓰기 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 홈 디렉터리 환경변수 파일 소유자가 root 또는 해당 계정이고, 소유자 외에 타인(Others)의 쓰기 권한이 부여되지 않은 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 존재 여부 검증
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/passwd 파일이 존재하지 않아 계정 기반 홈 디렉터리 추적이 불가합니다."
        return result
    
    # 가이드라인에 명시된 주요 점검 대상 환경변수 파일 종류 목록
    env_targets = [
        ".profile", ".bashrc", ".bash_profile", ".bash_login", 
        ".kshrc", ".cshrc", ".login", ".exrc", ".netrc"
    ]

    vulnerable_files = []
    remediation_cmds = []
    checked_files_count = 0

    try:
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                
                parts = line.split(":")
                if len(parts) >= 6:
                    username = parts[0].strip()
                    uid = int(parts[2].strip())
                    home_dir = parts[5].strip()

                    # 가상 경로이거나 존재하지 않는 홈 디렉터리는 제외
                    if not home_dir or not os.path.isdir(home_dir):
                        continue

                    # 3. 해당 사용자의 홈 디렉터리 내부 환경변수 파일 전수 탐색
                    for env_file in env_targets:
                        full_path = os.path.join(home_dir, env_file)
                        if not os.path.exists(full_path) or not os.path.isfile(full_path):
                            continue

                        try:
                            checked_files_count += 1
                            file_stat = os.stat(full_path)
                            file_uid = file_stat.st_uid
                            mode = file_stat.st_mode
                            permission_int = stat.S_IMODE(mode)
                            permission_oct = oct(permission_int)[2:]

                            is_owner_ok = (file_uid == 0 or file_uid == uid)
                            is_others_writable = (permission_int & stat.S_IWOTH) != 0

                            if not is_owner_ok or is_others_writable:
                                relative_display = f"{username}/{env_file}(권한:{permission_oct}, UID:{file_uid})"
                                vulnerable_files.append(relative_display)
                                
                                # 가이드라인 조치 사례(chown, chmod o-w)에 완전히 밀착된 자동 조치 구문 빌드
                                if not is_owner_ok:
                                    remediation_cmds.append(f"chown {username} {full_path}")
                                if is_others_writable:
                                    remediation_cmds.append(f"chmod o-w {full_path}")

                        except Exception:
                            continue

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"계정 홈 디렉터리 분석 중 예외 발생: {str(e)}"
        return result
    
    # KISA 가이드 최종 판정
    if checked_files_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 각 사용자 홈 디렉터리 내에 점검 대상이 되는 환경변수 파일이 존재하지 않습니다."
        return result

    if not vulnerable_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 탐지된 {checked_files_count}개의 사용자 환경변수 파일의 소유권 및 권한 설정 상태가 모두 안전합니다."
    else:
        max_display = 5
        displayed_items = vulnerable_files[:max_display]
        total_vuln_count = len(vulnerable_files)

        summary_msg = f"보안 미흡 파일 총 {total_vuln_count}건 발견 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 추가 점검 필요"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 타 사용자가 변조 가능한 부적절한 사용자 환경변수 파일이 방치되어 있습니다:\n{summary_msg}"
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result