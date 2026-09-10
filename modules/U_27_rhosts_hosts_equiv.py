# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat

# r-command(rlogin/rsh/rexec) 서비스를 실제로 제공하는 데몬 바이너리 후보 경로.
# 이 중 하나도 존재하지 않으면 관련 config/inetd/systemd 설정과 무관하게 서비스 자체가
# 구조적으로 동작 불가능하므로, 가이드의 "서비스를 사용하지 않으면 양호" 기준을 안전하게
# 판단할 수 있는 근거가 됨 (subprocess로 systemctl 등을 호출하지 않아 환경 의존성이 없음).
_RCOMMAND_DAEMON_PATHS = [
    "/usr/sbin/in.rlogind", "/usr/sbin/in.rshd", "/usr/sbin/in.rexecd",
    "/usr/sbin/rlogind", "/usr/sbin/rshd", "/usr/sbin/rexecd",
    "/usr/bin/rlogind", "/usr/bin/rshd", "/usr/bin/rexecd",
]


def _rcommand_service_present():
    return any(os.path.exists(p) for p in _RCOMMAND_DAEMON_PATHS)


def Check():
    result = {
        "item_id": "U-27",
        "item_Level": "High",
        "title": "$HOME/.rhosts, hosts.equiv 사용 금지",
        "status": "Vulnerable",
        "description": "인증 없는 원격 접속(r-command)을 악용한 무단 권한 상승 및 백도어 활용을 차단하기 위해 hosts.equiv 및 .rhosts 파일의 소유자, 권한, '+' 설정 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] r-command 서비스(rlogin, rsh 등)를 사용하지 않거나, 파일 소유자가 root/해당 계정이며 권한이 600 이하이고 내용 중 '+' 옵션이 없는 경우"
    }

    passwd_path = "/etc/passwd"
    global_equiv = "/etc/hosts.equiv"

    vulnerable_files = []
    remediation_cmds = []
    checked_files_count = 0

    if os.path.exists(global_equiv) and os.path.isfile(global_equiv):
        try:
            checked_files_count += 1
            file_stat = os.stat(global_equiv)
            owner_uid = file_stat.st_uid
            mode = file_stat.st_mode
            permission_int = stat.S_IMODE(mode)
            permission_oct = oct(permission_int)[2:]

            # 소유자가 root(0)여야 하며, 권한이 600 이하여야 함 (소유자 R/W 외 모든 권한 허용 비트 마스킹 검사)
            excess_mask = 0o177 | stat.S_IXUSR
            is_owner_bad = (owner_uid != 0)
            is_perm_bad = (permission_int & excess_mask) != 0

            has_plus_sign = False
            with open(global_equiv, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if not line.strip() or line.strip().startswith("#"):
                        continue
                    if "+" in line:
                        has_plus_sign = True
                        break

            if is_owner_bad or is_perm_bad or has_plus_sign:
                reasons = []
                if is_owner_bad: reasons.append(f"소유자 부적절(UID:{owner_uid})")
                if is_perm_bad: reasons.append(f"권한 초과({permission_oct})")
                if has_plus_sign: reasons.append("'+' 취약 옵션 발견")
                vulnerable_files.append(f"/etc/hosts.equiv ({', '.join(reasons)})")
                
                # 조치 명령어 자동 바인딩
                remediation_cmds.append(f"chown root {global_equiv} && chmod 600 {global_equiv}")
                if has_plus_sign:
                    remediation_cmds.append(f"# [주의] {global_equiv} 파일 내의 '+' 설정을 제거하고 허용할 특정 호스트/계정만 등록하십시오.")

        except Exception:
            pass
    
    if os.path.exists(passwd_path):
        try:
            with open(passwd_path, "r", encoding="utf-8") as f:
                passwd_lines = f.readlines()
        except Exception as e:
            # /etc/passwd 자체를 읽지 못한 경우에만 전체를 Manual Check로 처리.
            # (이미 위에서 찾은 /etc/hosts.equiv 취약점이 있다면 그 결과는 보존하지 않고
            #  더 안전한 쪽인 Manual Check로 안내 — passwd 미해석 시 .rhosts 전수 점검이 불가하므로)
            result["status"] = "Manual Check"
            result["current_setting"] = f"/etc/passwd 파일을 읽지 못해 계정별 .rhosts 점검이 불가합니다: {str(e)}"
            return result

        for line in passwd_lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 개별 계정 라인 파싱 실패(형식 이상 등)는 해당 라인만 건너뛰고 나머지 계정/이미 찾은
            # hosts.equiv 결과는 계속 보존 — 한 줄의 이상 형식 때문에 전체 판정이 Manual Check로
            # 밀려 이미 발견한 취약점이 묻히는(미탐) 것을 방지.
            try:
                parts = line.split(":")
                if len(parts) < 6:
                    continue
                username = parts[0].strip()
                uid = int(parts[2].strip())
                home_dir = parts[5].strip()
            except Exception:
                continue

            # 홈 디렉터리 경로가 정상이 아닌 경우 제외
            if not home_dir or not os.path.isdir(home_dir):
                continue

            rhosts_path = os.path.join(home_dir, ".rhosts")
            if os.path.exists(rhosts_path) and os.path.isfile(rhosts_path):
                try:
                    checked_files_count += 1
                    file_stat = os.stat(rhosts_path)
                    file_uid = file_stat.st_uid
                    mode = file_stat.st_mode
                    permission_int = stat.S_IMODE(mode)
                    permission_oct = oct(permission_int)[2:]

                    excess_mask = 0o177 | stat.S_IXUSR
                    is_owner_bad = (file_uid != 0 and file_uid != uid)
                    is_perm_bad = (permission_int & excess_mask) != 0

                    # Condition 3: '+' 포함 여부 체크
                    has_plus_sign = False
                    with open(rhosts_path, "r", encoding="utf-8", errors="ignore") as rf:
                        for r_line in rf:
                            if not r_line.strip() or r_line.strip().startswith("#"):
                                continue
                            if "+" in r_line:
                                has_plus_sign = True
                                break

                    if is_owner_bad or is_perm_bad or has_plus_sign:
                        reasons = []
                        if is_owner_bad: reasons.append(f"소유자 부적절(UID:{file_uid})")
                        if is_perm_bad: reasons.append(f"권한 초과({permission_oct})")
                        if has_plus_sign: reasons.append("'+' 취약 옵션 발견")
                        vulnerable_files.append(f"~{username}/.rhosts ({', '.join(reasons)})")

                        # 사용자별 조치 명령어 매핑
                        remediation_cmds.append(f"chown {username} {rhosts_path} && chmod 600 {rhosts_path}")
                        if has_plus_sign:
                            remediation_cmds.append(f"# [주의] {rhosts_path} 파일 내의 '+' 설정을 제거하고 허용할 특정 호스트/계정만 등록하십시오.")

                except Exception:
                    continue
        
    # KISA 가이드 최종 판정
    if checked_files_count == 0:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 시스템 내에 r-command 인증 관련 파일(hosts.equiv 또는 .rhosts)이 존재하지 않아 안전합니다."
        return result

    if not vulnerable_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 감출된 총 {checked_files_count}개의 원격 인증 릴레이 설정 파일의 소유권, 권한 및 옵션 정책이 완벽히 만족합니다."
        return result

    # 가독성을 고려한 최대 5개 노출 제한 및 축약 필터 적용
    max_display = 5
    displayed_items = vulnerable_files[:max_display]
    total_vuln_count = len(vulnerable_files)

    summary_msg = f"보안 규격 미흡 파일 총 {total_vuln_count}건 발견 -> " + ", ".join(displayed_items)
    if total_vuln_count > max_display:
        summary_msg += f" 외 {total_vuln_count - max_display}개 추가 점검 필요"

    service_present = _rcommand_service_present()

    if not service_present:
        # 가이드 판단기준: "r-command 서비스를 사용하지 않으면 무조건 양호".
        # in.rlogind/in.rshd/in.rexecd 등 서비스 데몬 자체가 시스템에 없어 관련 파일 설정과
        # 무관하게 원격 공격 표면이 존재하지 않으므로 PASS 처리하되, 감사 추적성을 위해
        # 발견된 파일 미흡 사항은 참고 정보로 그대로 노출함(서비스 재설치 시 조치 필요).
        result["status"] = "PASS(양호)"
        result["current_setting"] = (
            "[양호] r-command 데몬(in.rlogind/in.rshd/in.rexecd 등)이 시스템에 설치되어 있지 않아 "
            "서비스 자체가 사용 불가능합니다(가이드 판단기준: 서비스 미사용 시 양호).\n"
            f"[참고] 다만 다음 설정 미흡 파일이 남아있어, 추후 r-command 관련 패키지를 설치/활성화할 "
            f"경우 반드시 조치가 필요합니다: {summary_msg}"
        )
        return result

    result["status"] = "Vulnerable"
    result["current_setting"] = f"[WARN] r-command 서비스가 설치되어 있으며, 무차별 원격 명령어 실행권한 변조 우려가 있는 취약한 인증 파일이 존재합니다:\n{summary_msg}"

    banner = [
        "# [주의] chown/chmod 는 root 권한이 필요합니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤",
        "# (다시 sudo를 붙이지 말고) 전체를 붙여넣어 실행하세요.",
    ]
    result["remediation_cmd"] = "\n".join(banner + remediation_cmds)

    return result