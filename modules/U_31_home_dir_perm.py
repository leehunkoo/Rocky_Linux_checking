# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import stat

_NOLOGIN_SHELLS = {"nologin", "false", "sync", "shutdown", "halt"}


def _is_nologin_shell(shell_path):
    return os.path.basename(shell_path.strip()) in _NOLOGIN_SHELLS


def Check():
    result = {
        "item_id": "U-31",
        "item_Level": "Medium",
        "title": "홈디렉토리 소유자 및 권한 설정",
        "status": "Vulnerable",
        "description": "비인가자의 사용자 홈 디렉터리 내 설정 파일 변조 및 정상 서비스 차단을 예방하기 위해 각 홈 디렉터리의 소유자 매핑 상태와 타인 쓰기 권한 제한 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 존재하는 모든 사용자 홈 디렉터리의 소유자가 해당 계정 명의로 일치하고, 타인(Others)의 쓰기 권한이 제거된 경우"
    }

    passwd_path = "/etc/passwd"

    # 파일 존재 여부 검증
    if not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/passwd 파일이 식별되지 않아 홈 디렉터리 추적 진단을 진행할 수 없습니다."
        return result
    
    system_shared_dirs = ["/", "/dev", "/var/run/sshd", "/run/sshd", "/nonexistent"]

    # /etc/login.defs의 UID_MIN(일반 사용자 최소 UID, 기본 1000) 기준으로 daemon/bin/sync/games/
    # mail/lp/news/uucp/list/irc 등 base-passwd 표준 시스템 계정을 제외.
    # 이 계정들은 /usr/sbin, /bin, /var/mail 등 다수 패키지가 공유하는 root 소유 시스템 디렉터리를
    # "홈"으로 갖는 것이 Rocky Linux 기본 설계이며 로그인 불가(nologin) 계정이라 가이드가 말하는
    # "홈 디렉터리 변조로 인한 서비스 이용 제한" 위협 자체가 적용되지 않음. 이를 걸러내지 않으면
    # 모든 기본 우분투 시스템에서 대량 오탐이 발생하고, 그대로 조치하면 chown daemon /usr/sbin 처럼
    # 시스템을 손상시키는 명령이 생성됨.
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

    vulnerable_dirs = []
    remediation_cmds = []
    checked_count = 0

    try:
        # 2. /etc/passwd 파일을 읽어 실제 사용자 계정명, UID, 홈 디렉터리 경로 추출
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

                    # base-passwd 표준 시스템 계정(0 < UID < UID_MIN) 제외 — root(UID 0)와
                    # 일반 사용자(UID >= UID_MIN)만 실제 점검 대상으로 삼음.
                    # UID_MIN만으로는 nobody(65534), libvirt-qemu(64055)처럼 Rocky Linux의 "동적
                    # 할당 시스템 UID"(6만번대) 계정을 못 걸러내므로, 로그인 셸이 nologin류인
                    # 경우도 함께 제외(로그인 자체가 불가능해 가이드가 우려하는 위협이 성립 안 함).
                    if (uid != 0 and uid < uid_min) or _is_nologin_shell(shell):
                        continue

                    # 일반 사용자가 생성한 디렉터리 및 물리적으로 실재하는 홈 디렉터리만 필터링
                    if not home_dir or not os.path.isdir(home_dir) or home_dir in system_shared_dirs:
                        continue

                    try:
                        checked_count += 1
                        dir_stat = os.stat(home_dir)
                        dir_uid = dir_stat.st_uid
                        mode = dir_stat.st_mode
                        permission_int = stat.S_IMODE(mode)
                        permission_oct = oct(permission_int)[2:]

                        # KISA 가이드 최종 판정
                        is_owner_correct = (dir_uid == uid)
                        is_others_writable = (permission_int & stat.S_IWOTH) != 0

                        if not is_owner_correct or is_others_writable:
                            reasons = []
                            if not is_owner_correct:
                                reasons.append(f"소유주 불일치(UID:{dir_uid})")
                                remediation_cmds.append(f"chown {username} {home_dir}")
                            if is_others_writable:
                                reasons.append("타인 쓰기 허용")
                                remediation_cmds.append(f"chmod o-w {home_dir}")

                            vulnerable_dirs.append(f"{username}:{home_dir}(권한:{permission_oct}, 사유:{'/'.join(reasons)})")

                    except Exception:
                        continue

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"사용자 정보 수집 중 분석 장애 발생: {str(e)}"
        return result

    # 3. 2026 KISA 상세 가이드라인 준수 기준 종합 판단
    if checked_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 검증 대상이 되는 독립된 계정별 홈 디렉터리가 존재하지 않거나 모두 공용 시스템 경로입니다."
        return result

    if not vulnerable_dirs:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 점검된 총 {checked_count}개의 사용자 홈 디렉터리 소유권 및 권한 격리 설정이 모두 완벽히 준수되고 있습니다."
    else:
        # 대시보드 스크롤 정렬 가독성을 유지하기 위한 최대 5개 노출 제한 및 축약 필터 작동
        max_display = 5
        displayed_items = vulnerable_dirs[:max_display]
        total_vuln_count = len(vulnerable_dirs)

        summary_msg = f"보안 미흡 홈 디렉터리 총 {total_vuln_count}건 감지 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개의 유저 디렉터리 설정 미흡"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 소유자가 부적절하거나 타인의 무단 수정이 허용된 취약한 홈 디렉터리가 방치되어 있습니다:\n{summary_msg}"
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result