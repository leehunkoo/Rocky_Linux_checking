# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import stat
import subprocess

_KNOWN_SUID_REQUIRED_BASENAMES = {
    "chrome-sandbox": "Chrome/Chromium 계열 브라우저의 렌더러 샌드박스 격리에 SUID가 필수입니다.",
    "Xorg.wrap": "X 서버가 직접 그래픽 하드웨어에 접근할 때 SUID/SGID가 필요합니다.",
}

def _known_suid_required_reason(file_path):
    return _KNOWN_SUID_REQUIRED_BASENAMES.get(os.path.basename(file_path))

def Check():
    result = {
        "item_id": "U-23",
        "item_Level": "High",
        "title": "SUID, SGID, Sticky bit 설정 파일 점검",
        "status": "Vulnerable",
        "description": "권한 상승 공격에 악용될 수 있는 불필요하거나 악의적인 SUID/SGID 설정 파일의 방치 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] OS 기본 필수 명령어를 제외하고 불필요하거나 의심스러운 파일에 SUID, SGID 설정이 부여되어 있지 않은 경우"
    }

    # Rocky Linux / Enterprise Linux 시스템 표준 화이트리스트 SUID/SGID 파일 목록
    standard_whitelist = [
        "/usr/bin/passwd", "/usr/bin/sudo", "/usr/bin/su", "/bin/su", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/gpasswd", "/usr/bin/newgrp", "/usr/bin/pkexec", "/usr/bin/chage", "/usr/bin/expiry",
        "/usr/bin/mount", "/bin/mount", "/usr/bin/umount", "/bin/umount",
        "/usr/bin/ping", "/bin/ping", "/usr/bin/ping6", "/bin/ping6",
        "/usr/bin/crontab", "/usr/bin/write", "/usr/bin/wall",
        "/usr/sbin/unix_chkpwd", "/usr/sbin/pam_timestamp_check", "/usr/sbin/userhelper", "/usr/sbin/usernetctl",
        "/usr/libexec/dbus-1/dbus-daemon-launch-helper",
        "/usr/libexec/polkit-1/polkit-agent-helper-1",
        "/usr/libexec/openssh/ssh-keysign",
        "/usr/bin/fusermount", "/usr/bin/fusermount3",
        "/usr/bin/locate", "/usr/bin/at",
        "/usr/libexec/cockpit-session",
        "/usr/libexec/sssd/krb5_child", "/usr/libexec/sssd/ldap_child",
        "/usr/libexec/sssd/selinux_child", "/usr/libexec/sssd/proxy_child",
        "/usr/bin/staprun",
    ]

    cmd = [
        "find", "/", "-xdev",
        "(",
            "-path", "*/overlay2/*",
            "-o", "-path", "*/var/lib/docker/*",
            "-o", "-path", "*/var/lib/containerd/*",
            "-o", "-path", "*/var/lib/containers/*",
            "-o", "-path", "*/run/containerd/*",
        ")",
        "-prune",
        "-o",
        "(",
            "-user", "root", "-type", "f",
            "(", "-perm", "-04000", "-o", "-perm", "-02000", ")",
        ")",
        "-print",
    ]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        found_files = [line.strip() for line in stdout.splitlines() if line.strip()]
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"SUID/SGID 파일 탐색 중 예외 발생: {str(e)}"
        return result

    suspicious_files = []
    for file_path in found_files:
        if file_path not in standard_whitelist:
            try:
                file_stat = os.stat(file_path)
                mode = file_stat.st_mode
                permission_oct = oct(stat.S_IMODE(mode))[2:]
                suspicious_files.append(f"{file_path}(권한:{permission_oct})")
            except Exception:
                suspicious_files.append(file_path)

    if not suspicious_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시스템 내 권한 상승 위험이 있는 비표준 SUID/SGID 파일이 발견되지 않았습니다. (총 {len(found_files)}개의 표준 명령어 제어됨)"
    else:
        max_display = 5
        displayed_items = suspicious_files[:max_display]
        total_vuln_count = len(suspicious_files)

        summary_msg = f"의심스러운 특수 권한 파일 총 {total_vuln_count}건 발견 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 더 존재함"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 인가되지 않은 임의 생성 파일 또는 무단 SUID/SGID 설정 파일이 존재합니다:\n{summary_msg}"

        remediation_cmds = [
            "# [주의] 아래 명령들은 모두 root 권한이 필요합니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.",
            "# [필수 확인] 실행 전 'rpm -qf <파일경로>' 명령으로 소속 패키지 여부를 먼저 확인하십시오.",
            "# 1. 불필요/의심스러운 파일에서 SUID/SGID 권한 박탈",
        ]
        for item in suspicious_files:
            clean_path = item.split("(")[0]
            reason = _known_suid_required_reason(clean_path)
            if reason:
                remediation_cmds.append(f"# [경고] {clean_path}")
                remediation_cmds.append(f"#   -> {reason}")
            else:
                remediation_cmds.append(f"chmod -s {clean_path}")

        remediation_cmds.extend([
            "\n# 2. 만약 해당 업무용 애플리케이션 파일에 특수 권한 유지가 필수적인 경우,",
            "# 특정 관리 그룹(wheel 등)에만 할당하고 일반 사용자의 접근을 차단 조치",
            "# chgrp wheel <파일경로> && chmod 4750 <파일경로>"
        ])

        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result
