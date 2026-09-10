# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re
import subprocess

def Check():
    result = {
        "item_id": "U-28",
        "item_Level": "High",
        "title": "접속 IP 및 포트 제한",
        "status": "Vulnerable",
        "description": "외부로부터의 무분별한 불법 접근 및 침해사고를 방지하기 위해 방화벽(firewalld, nftables, iptables) 또는 TCP Wrapper를 통한 접속 IP 및 포트 제한 설정 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] firewalld 방화벽이 활성화되어 정책이 존재하거나, TCP Wrapper(/etc/hosts.deny)에서 기본 차단 후 hosts.allow에 허용 IP가 정의된 경우"
    }

    hosts_allow_path = "/etc/hosts.allow"
    hosts_deny_path = "/etc/hosts.deny"

    firewalld_active = False
    nftables_has_rules = False
    iptables_has_rules = False
    tcp_wrapper_ok = False

    detection_details = []
    remediation_cmds = []

    _c_env = dict(os.environ)
    _c_env["LANG"] = "C"
    _c_env["LC_ALL"] = "C"

    # [Step 1] Rocky Linux 표준 방화벽 firewalld 활성화 및 정책 검증
    try:
        fw_state = subprocess.check_output(["firewall-cmd", "--state"], text=True, stderr=subprocess.DEVNULL, env=_c_env).strip()
        if fw_state == "running":
            firewalld_active = True
            # 활성 zone 정보 확인
            fw_zones = subprocess.check_output(["firewall-cmd", "--get-active-zones"], text=True, stderr=subprocess.DEVNULL, env=_c_env)
            if fw_zones.strip():
                detection_details.append("firewalld 방화벽 활성화 및 활성 존 식별됨")
            else:
                detection_details.append("firewalld 방화벽이 가동 중이나 활성 존이 비어있음")
    except Exception:
        # systemctl로 firewalld 동작 확인
        try:
            exit_code = subprocess.call(["systemctl", "is-active", "--quiet", "firewalld"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if exit_code == 0:
                firewalld_active = True
                detection_details.append("firewalld 서비스 활성화 상태")
        except Exception:
            pass

    # [Step 2] nftables / iptables 검증 (firewalld 대신 사용되는 환경)
    try:
        nft_out = subprocess.check_output(["nft", "list", "ruleset"], text=True, stderr=subprocess.DEVNULL, env=_c_env)
        if "chain" in nft_out and ("accept" in nft_out.lower() or "drop" in nft_out.lower()):
            nftables_has_rules = True
            detection_details.append("nftables 접근 제어 룰셋 활성화 식별됨")
    except Exception:
        pass

    try:
        iptables_output = subprocess.check_output(["iptables", "-L", "INPUT", "-n"], text=True, stderr=subprocess.DEVNULL, env=_c_env)
        rules = [l.strip() for l in iptables_output.splitlines() if l.strip()]
        if len(rules) > 2:
            iptables_has_rules = True
            detection_details.append("iptables INPUT 체인 내 접근 제어 규칙 존재함")
    except Exception:
        pass

    # [Step 3] TCP Wrapper (/etc/hosts.allow, /etc/hosts.deny) 교차 파싱
    deny_all_configured = False
    allow_rules_exist = False

    if os.path.exists(hosts_deny_path):
        try:
            with open(hosts_deny_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if re.search(r"^\s*ALL\s*:\s*ALL", line, re.IGNORECASE):
                        deny_all_configured = True
                        break
        except Exception:
            pass

    if os.path.exists(hosts_allow_path):
        try:
            with open(hosts_allow_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if ":" in line and not line.startswith(":"):
                        allow_rules_exist = True
                        break
        except Exception:
            pass

    if deny_all_configured and allow_rules_exist:
        tcp_wrapper_ok = True
        detection_details.append("TCP Wrapper 정책 수립 완료(hosts.deny 차단 및 allow 허용)")

    # KISA 가이드 최종 판정
    if firewalld_active or nftables_has_rules or iptables_has_rules or tcp_wrapper_ok:
        result["status"] = "PASS(양호)"
        status_summary = " / ".join(detection_details) if detection_details else "호스트 방화벽 활성화 상태"
        result["current_setting"] = f"[양호] 네트워크 접속 IP 및 포트 제한 정책이 정상 가동 중입니다. ({status_summary})"
    else:
        result["status"] = "Vulnerable"
        status_summary = " / ".join(detection_details) if detection_details else "호스트 방화벽 및 접근 제어 정책 전무"
        result["current_setting"] = f"[WARN] 인바운드 트래픽을 통제하는 보안 접근 제어 정책이 수립되어 있지 않습니다. ({status_summary})"

        # Rocky Linux firewalld 조치 가이드
        remediation_cmds.extend([
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 실행하세요.",
            "# [방법 1] Rocky Linux 권고 - firewalld 방화벽 활성화 및 원격 접근 제어",
            "# 1. 원격 세션 차단을 방지하기 위해 firewalld 기동 전 SSH 기본 서비스 허용 확인",
            "systemctl enable --now firewalld",
            "firewall-cmd --permanent --add-service=ssh",
            "# 2. 특정 신뢰 IP/대역만 SSH를 허용하고자 할 경우(Rich Rule 예시):",
            "# firewall-cmd --permanent --zone=public --add-rich-rule='rule family=\"ipv4\" source address=\"192.168.1.0/24\" service name=\"ssh\" accept'",
            "# 3. 방화벽 룰 즉시 적용",
            "firewall-cmd --reload",
            "",
            "# [방법 2] TCP Wrapper 레거시 호스트 차단 구성 (지원 환경인 경우)",
            "if [ -f /etc/hosts.deny ]; then",
            "  grep -q '^ALL:ALL' /etc/hosts.deny || echo 'ALL:ALL' >> /etc/hosts.deny",
            "fi",
            "if [ -f /etc/hosts.allow ]; then",
            "  echo '# KISA U-28 원격 서비스 허용 가이드' >> /etc/hosts.allow",
            "  echo '# 예시: sshd : 192.168.1.10' >> /etc/hosts.allow",
            "fi"
        ])
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result
