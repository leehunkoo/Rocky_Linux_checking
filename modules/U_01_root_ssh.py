# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import glob
import os
import re

def Check():
    result = {
        "item_id": "U-01",
        "item_Level": "High",
        "title": "root 계정 원격 접속 제한",
        "status": "Vulnerable",
        "description": "시스템 정책에 root 계정의 원격터미널 접속 차단 설정이 되어있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 원격터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우"
    }

    config_path = "/etc/ssh/sshd_config"
    include_dir = "/etc/ssh/sshd_config.d"

    # 1. 시스템 내 wheel 그룹 구성원 확인
    wheel_members = set()
    if os.path.exists("/etc/group"):
        try:
            with open("/etc/group", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4 and parts[0] == "wheel":
                        wheel_members = set(m.strip() for m in parts[3].split(",") if m.strip())
                        break
        except Exception:
            pass

    # 2. 시스템 내 원격/로컬 로그인 가능한 일반 사용자 계정(UID >= 1000) 점검
    invalid_shells = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/sync", "/sbin/halt", "/sbin/shutdown"]
    normal_users = []
    if os.path.exists("/etc/passwd"):
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        uname, uid, gid, shell = parts[0], parts[2], parts[3], parts[6]
                        if uid.isdigit() and int(uid) >= 1000 and uname != "nobody":
                            if shell not in invalid_shells and not any(shell.endswith(x) for x in ["nologin", "false"]):
                                has_wheel = (uname in wheel_members) or (gid == "10")
                                normal_users.append({"username": uname, "has_wheel": has_wheel})
        except Exception:
            pass

    if not os.path.exists(config_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/etc/ssh/sshd_config 파일이 존재하지 않습니다. OpenSSH 서버 미설치 또는 비표준 경로를 사용하는지 확인이 필요합니다."
        return result

    config_files = [config_path]
    if os.path.isdir(include_dir):
        config_files.extend(sorted(glob.glob(os.path.join(include_dir, "*.conf"))))

    permit_root_login_val = None
    detected_file = None

    for cfile in config_files:
        try:
            with open(cfile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    match = re.match(r"^\s*PermitRootLogin\s+(\S+)", line, re.IGNORECASE)
                    if match:
                        permit_root_login_val = match.group(1).lower()
                        detected_file = os.path.basename(cfile)
        except Exception:
            continue

    # 계정 상태 안내 텍스트 구성
    if normal_users:
        user_desc_list = [
            f"{u['username']}(wheel 권한 보유)" if u['has_wheel'] else f"{u['username']}(일반 계정)"
            for u in normal_users
        ]
        user_info = f"확인된 일반 로그인 계정: [{', '.join(user_desc_list)}]"
        has_wheel_admin = any(u['has_wheel'] for u in normal_users)
        if not has_wheel_admin:
            user_info += " ※ 주의: 일반 계정에 wheel(sudo) 관리 권한이 없습니다. root 차단 전 관리 계정에 sudo 권한을 부여해야 합니다."
    else:
        user_info = "[CRITICAL] 시스템에 로그인 가능한 일반 계정이 없습니다! root 접속 차단 시 원격 접속이 완전히 차단(Lockout)됩니다."

    # 조치 명령어(remediation_cmd) 동적 구성
    remediation_notes = [
        "# [주의] && 로 이어진 명령입니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.",
        "# [주의] 로그인 가능한 일반 계정이 없는 상태에서 root 원격 접속을 차단하면 SSH 접속이 완전히 차단(Lockout)됩니다!",
        "# [주의] 관리자 계정이 wheel(또는 sudo) 그룹에 속하는 것은 2단계 인증(일반계정 로그인 -> sudo 관리자 승격)을 위한 정상적이고 필수적인 보안 구성입니다. (취약점이 아님)",
        "# [주의] 조치 적용 후 기존 접속 창을 절대 닫지 마시고, 새 터미널 창을 열어 일반 계정 로그인 및 sudo su 승격 테스트를 반드시 성공한 후 기존 창을 종료하세요."
    ]

    if not normal_users:
        remediation_notes.append("# [조치 가이드] 로그인 가능한 일반 계정이 없으므로, 먼저 관리용 일반 계정을 생성하고 wheel 그룹에 추가한 후 SSH root 차단을 적용합니다.")
        cmd_str = (
            "\n".join(remediation_notes) + "\n"
            "# 1. 관리용 일반 계정 생성 및 wheel(sudo) 그룹 지정\n"
            "useradd -m -G wheel <username> && "
            "passwd <username> && "
            "# 2. SSH PermitRootLogin 차단 설정 및 서비스 재시작\n"
            "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config && systemctl restart sshd"
        )
    else:
        wheel_users = [u['username'] for u in normal_users if u['has_wheel']]
        if not wheel_users:
            first_user = normal_users[0]['username']
            remediation_notes.append(f"# [조치 가이드] 기존 계정 '{first_user}'에 wheel(sudo) 관리 권한을 부여하거나, 새 관리 계정을 생성(useradd -m -G wheel <username>)한 후 root를 차단하세요.")
            cmd_str = (
                "\n".join(remediation_notes) + "\n"
                f"usermod -aG wheel {first_user} && "
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config && systemctl restart sshd"
            )
        else:
            remediation_notes.append(f"# [조치 가이드] 확인된 관리 계정: {', '.join(wheel_users)} | 신규 관리 계정 추가 필요 시: useradd -m -G wheel <username> && passwd <username>")
            cmd_str = (
                "\n".join(remediation_notes) + "\n"
                "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config && systemctl restart sshd"
            )

    result["remediation_cmd"] = cmd_str

    # 상태 판정
    if permit_root_login_val in ["no", "prohibit-password", "without-password"]:
        if not normal_users:
            result["status"] = "Manual Check"
            result["current_setting"] = f"PermitRootLogin은 '{permit_root_login_val}'이나, 로그인 가능한 일반 계정이 없어 Lockout 위험이 있습니다. ({user_info}, 적용 파일: {detected_file})"
        else:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] PermitRootLogin 설정이 '{permit_root_login_val}'로 안전하게 설정되어 있습니다. ({user_info}, 적용 파일: {detected_file})"
    elif permit_root_login_val == "yes":
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] PermitRootLogin 설정이 'yes'로 되어 있어 root 직접 원격 접속이 허용된 상태입니다. ({user_info}, 적용 파일: {detected_file})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] PermitRootLogin 설정이 주석처리 되어있거나 명시적으로 차단(no)되지 않았습니다. ({user_info})"

    return result
