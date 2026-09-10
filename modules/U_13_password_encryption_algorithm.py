# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.
# Rocky Linux Edition

import os
import re

def Check():
    result = {
        "item_id": "U-13",
        "item_Level": "Medium",
        "title": "안전한 비밀번호 암호화 알고리즘 사용",
        "status": "Vulnerable",
        "description": "시스템 정책 및 실제 계정 암호 정보에 SHA-2 이상의 안전한 비밀번호 암호화 알고리즘(SHA-512, YESCRYPT 등)이 적용되어 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# 1. /etc/login.defs 파일 내 ENCRYPT_METHOD 설정 수정\n"
            "if [ -f /etc/login.defs ]; then\n"
            "  if grep -q '^\\s*ENCRYPT_METHOD' /etc/login.defs; then\n"
            "    sed -i 's/^\\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs\n"
            "  else\n"
            "    echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs\n"
            "  fi\n"
            "fi &&\n"
            "# 2. Rocky Linux PAM authselect 암호화 정책 강화\n"
            "authselect select sssd with-pwquality --force 2>/dev/null || true"
        ),
        "exception_guide": "[양호] login.defs 설정이 SHA-2(SHA-256/512) 또는 YESCRYPT 이상이며, /etc/shadow 내 암호화 해시 식별자가 $5, $6 또는 $y(yescrypt)인 경우"
    }

    shadow_path = "/etc/shadow"
    login_defs_path = "/etc/login.defs"
    pam_targets = ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]

    if not os.path.exists(shadow_path) or not os.path.exists(login_defs_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "필수 암호 설정 파일(/etc/shadow 또는 /etc/login.defs)이 유실되어 수동 점검이 필요합니다."
        return result

    encrypt_method_val = "설정 누락"
    pam_algo_found = "설정 누락"
    vulnerable_accounts = []

    secure_hash_prefixes = ("$5$", "$6$", "$y$")

    try:
        with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parts = line.split(":")
                if len(parts) >= 2:
                    username = parts[0]
                    enc_passwd = parts[1]

                    if enc_passwd and not enc_passwd.startswith(("*", "!", "!!", "x")):
                        if not enc_passwd.startswith(secure_hash_prefixes):
                            vulnerable_accounts.append(username)

        with open(login_defs_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                match = re.match(r"^ENCRYPT_METHOD\s+(\S+)", line)
                if match:
                    encrypt_method_val = match.group(1).upper()
                    break

        for pam_file in pam_targets:
            if not os.path.exists(pam_file):
                continue
            with open(pam_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "pam_unix.so" in line and ("password" in line or line.startswith("password")):
                        if "yescrypt" in line:
                            pam_algo_found = "yescrypt 강제화"
                        elif "sha512" in line:
                            pam_algo_found = "SHA-512 강제화"
                        elif "sha256" in line:
                            pam_algo_found = "SHA-256 강제화"
                        elif "md5" in line.lower():
                            pam_algo_found = "MD5 (취약)"
                        else:
                            pam_algo_found = "기본 보안 알고리즘(SHA-512/yescrypt)"
                        break
            if pam_algo_found != "설정 누락":
                break

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"설정 파일 파싱 중 오류 발생: {str(e)}"
        return result

    is_shadow_clean = len(vulnerable_accounts) == 0
    is_defs_ok = encrypt_method_val.replace("-", "") in ["SHA256", "SHA512", "YESCRYPT"]
    is_pam_ok = "MD5" not in pam_algo_found and pam_algo_found != "설정 누락"

    summary_msg = f"login.defs: {encrypt_method_val} | PAM 정책: {pam_algo_found} | 취약한 계정 수: {len(vulnerable_accounts)}개"

    if is_shadow_clean and is_defs_ok and is_pam_ok:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시스템 및 정책이 모두 SHA-2 또는 yescrypt 이상의 안전한 암호화 알고리즘으로 구성되어 있습니다. ({summary_msg})"
    else:
        result["status"] = "Vulnerable"
        error_details = []
        if not is_shadow_clean:
            error_details.append(f"취약한 알고리즘 계정 발견 ({', '.join(vulnerable_accounts)})")
        if not is_defs_ok or not is_pam_ok:
            error_details.append("시스템 암호화 강제화 정책 미비")

        result["current_setting"] = f"[WARN] {', '.join(error_details)} ({summary_msg}) 알고리즘 정책 변경 후 기존 계정은 패스워드를 재설정해야 적용됩니다."

        cmd_blocks = []
        if not is_defs_ok:
            cmd_blocks.append(
                "if [ -f /etc/login.defs ]; then\n"
                "  if grep -q '^\\s*ENCRYPT_METHOD' /etc/login.defs; then\n"
                "    sed -i 's/^\\s*ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs\n"
                "  else\n"
                "    echo 'ENCRYPT_METHOD SHA512' >> /etc/login.defs\n"
                "  fi\n"
                "fi"
            )

        if vulnerable_accounts:
            cmd_blocks.append(
                "# 취약한 해시 계정은 다음 로그인 시 비밀번호를 재설정하도록 처리\n"
                + "\n".join(f"chage -d 0 {u}" for u in vulnerable_accounts)
            )

        header = "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
        result["remediation_cmd"] = header + " &&\n".join(cmd_blocks)

    return result
