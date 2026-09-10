# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re


def _get_gid_min(default=1000):
    """/etc/login.defs의 GID_MIN을 읽어 '일반 사용자 그룹' 시작 GID를 확인.
    (Rocky Linux/RHEL 기본값 1000 미만은 패키지가 만드는 시스템 예약 그룹 구간)"""
    login_defs = "/etc/login.defs"
    if not os.path.exists(login_defs):
        return default
    try:
        with open(login_defs, "r", encoding="utf-8") as f:
            for line in f:
                m = re.match(r'^\s*GID_MIN\s+(\d+)', line)
                if m:
                    return int(m.group(1))
    except Exception:
        pass
    return default


def Check():
    result = {
        "item_id": "U-09",
        "item_Level": "Low",
        "title": "계정이 존재하지 않는 GID 금지",
        "status": "Vulnerable",
        "description": "그룹 설정 파일(/etc/group)을 점검하여 소속된 사용자가 존재하지 않는 불필요한 그룹이 방치되어 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "#[수동 검사 경로]\n/etc/group or /etc/gshadow\n#[불필요 계정 삭제 명령어]\ngroupdel <group name>\n\n**주의**\n해당 결과는 root권한으로 검사해야 정확한 결과를 받을 수 있습니다.",
        "exception_guide": "[양호] 시스템 관리나 데몬 운용에 필요한 그룹 외에 계정이 존재하지 않는 불필요한 그룹이 제거된 경우"
    }

    group_path = "/etc/group"
    gshadow_path = "/etc/gshadow"
    passwd_path = "/etc/passwd"

    # 파일 존재 여부 확인
    if not os.path.exists(group_path) or not os.path.exists(gshadow_path) or not os.path.exists(passwd_path):
        result["status"] = "Manual Check"
        result["current_setting"] = f"필수 그룹 파일({group_path}, {gshadow_path} 또는 {passwd_path})이 존재하지 않아 수동으로 점검이 필요합니다."
        return result
    
    empty_groups = []
    group_to_gid = {}  # 그룹명 -> GID (기본 그룹 사용 여부 교차검증용)
    gid_min = _get_gid_min()
    skipped_system_groups = 0  # GID < gid_min 이라 점검 범위에서 제외한 개수

    # Rocky Linux 기본 내장 및 주요 서비스 예약 그룹 목록(오탐 방지 확보 목적) ** 주의 ** 타 서비스 운영시 주요 서비스 있을 수 있음으로 참고바람
    system_reserved_groups = [
        "root", "daemon", "bin", "sys", "adm", "tty", "disk", "lp", "mail", "news",
        "uucp", "proxy", "kmem", "dialout", "fax", "voice", "cdrom", "floppy", "tape",
        "wheel", "audio", "dip", "www-data", "backup", "operator", "list", "irc",
        "src", "gnupg", "shadow", "utmp", "video", "sasl", "plugdev", "staff", "games",
        "users", "nogroup", "systemd-journal", "systemd-network", "systemd-resolve",
        "systemd-timesync", "chrony", "polkitd", "sssd", "rpc", "rpcuser", "messagebus", "input", "kvm", "render", "gdm", "ssh",
        "man", "lpadmin", "sambashare", "libvirt-qemu", "libvirt-dnsmasq", "lxd", "sgx"
    ]

    try:
        with open(group_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 4:
                    group_name = parts[0]
                    gid = parts[2].strip()
                    members_str = parts[3].strip()

                    if gid.isdigit():
                        group_to_gid[group_name] = gid

                    # 소속 사용자가 완전히 비어 있는 그룹 추출
                    members = [m.strip() for m in members_str.split(",") if m.strip()]

                    if not members:
                        if group_name in system_reserved_groups:
                            continue
                        # GID < gid_min(기본 1000)은 패키지가 만드는 시스템/서비스
                        # 예약 구간이라 "비어있음 = 불필요"로 자동 판단할 수 없어 점검 제외
                        if gid.isdigit() and int(gid) < gid_min:
                            skipped_system_groups += 1
                            continue
                        if group_name not in empty_groups:
                            empty_groups.append(group_name)

        # /etc/passwd의 GID 필드(기본 그룹)로 사용 중인 그룹은 제외
        # /etc/group의 members 필드는 보조 그룹만 기록하므로, 사용자 개인 기본
        # 그룹(예: Rocky Linux / RHEL 1:1 UPG 방식)은 members가 비어있어도 실제로 사용 중임
        used_gids = set()
        with open(passwd_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 4:
                    used_gids.add(parts[3].strip())

        empty_groups = [
            g for g in empty_groups
            if group_to_gid.get(g) not in used_gids
        ]

        with open(gshadow_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 4:
                    group_name = parts[0]
                    gshadow_members_str = parts[3].strip()
                    gshadow_members = [m.strip() for m in gshadow_members_str.split(",") if m.strip()]

                    # gshadow 파일 쪽에 소속 사용자가 기재되어 있다면, 빈 그룹 목록에서 최종 제외
                    if gshadow_members and group_name in empty_groups:
                        empty_groups.remove(group_name)
    
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"그룹 정책 파일 해석 중 오류 발생: {str(e)}"
        return result
    
    scope_note = f" (GID<{gid_min} 시스템/패키지 예약 그룹 {skipped_system_groups}개는 자동 판단 불가로 점검 범위 제외, 수동 확인 권장)" if skipped_system_groups else ""

    # KISA 가이드 최종 판정
    if not empty_groups:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] ({group_path} 또는 {gshadow_path} 파일 내에 계정이 존재하지 않는 불필요한 누락 그룹이 발견되지 않았습니다.){scope_note}"

    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 소속 계정이 식별되지 않는 관리 외 유형 그룹이 방치되어 있습니다: {', '.join(empty_groups)}{scope_note}"

        remmediation_cmds = [
            f"# [주의] 아래는 GID {gid_min} 이상의 일반 사용자 그룹 중",
            "# 소속 계정도 없고 누구의 기본 그룹도 아닌 것들입니다.",
            "# 삭제 전 find / -gid <GID> 등으로 소유 파일이 남아있지 않은지 확인하세요.",
        ] + [f"groupdel {g}" for g in empty_groups]
        result["remediation_cmd"] = "\n".join(remmediation_cmds)

    return result