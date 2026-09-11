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
        "item_id": "U-02",
        "item_Level": "High",
        "title": "패스워드 복잡성 설정",
        "status": "Vulnerable",
        "description": "시스템 정책에 패스워드 복잡성(최소길이, 문자 혼용, Root 적용) 및 사용 기간 정책이 적절히 설정되어 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# [주의] && 로 이어진 여러 명령입니다. 'sudo -i'로 root 셸에 먼저 진입한 뒤 아래를 실행하세요.\n"
            "# [주의] /etc/login.defs 설정은 '신규 계정' 생성 시에만 기본값으로 적용됩니다.\n"
            "# [주의] 이미 존재하는 계정(root 및 기존 일반 사용자)은 login.defs 변경이 소급 적용되지 않으므로 반드시 'chage' 명령어로 적용해야 합니다.\n"
            "# Step 1: pwquality.conf 설정 수정\n"
            "sed -i 's/^#*\\s*minlen.*/minlen = 8/g' /etc/security/pwquality.conf && "
            "sed -i 's/^#*\\s*dcredit.*/dcredit = -1/g' /etc/security/pwquality.conf && "
            "sed -i 's/^#*\\s*ucredit.*/ucredit = -1/g' /etc/security/pwquality.conf && "
            "sed -i 's/^#*\\s*lcredit.*/lcredit = -1/g' /etc/security/pwquality.conf && "
            "sed -i 's/^#*\\s*ocredit.*/ocredit = -1/g' /etc/security/pwquality.conf && "
            "if ! grep -q '^enforce_for_root' /etc/security/pwquality.conf; then "
            "  if grep -q '^#\\s*enforce_for_root' /etc/security/pwquality.conf; then "
            "    sed -i 's/^#\\s*enforce_for_root/enforce_for_root/g' /etc/security/pwquality.conf; "
            "  else "
            "    echo 'enforce_for_root' >> /etc/security/pwquality.conf; "
            "  fi; "
            "fi && "
            "# Step 2: PAM authselect 설정 (Rocky Linux 표준)\n"
            "authselect select sssd with-pwquality --force 2>/dev/null || true && "
            "# Step 3: login.defs 설정 수정 및 기존 계정(root, 일반유저) 패스워드 만료 정책 소급 적용\n"
            "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/g' /etc/login.defs && "
            "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   1/g' /etc/login.defs && "
            "chage -M 90 -m 1 -W 7 root && "
            "awk -F: '$3 >= 1000 && $7 !~ /(nologin|false)/ {print $1}' /etc/passwd | while read u; do chage -M 90 -m 1 -W 7 \"$u\"; done"
        ),
        "exception_guide": "[양호] pwquality 복잡성(Root 적용 포함) 설정 완료, PAM(system-auth/password-auth) 모듈 순서 정상, login.defs 및 기존 계정 shadow 기간 정책이 준수된 경우"
    }

    pwq_path = "/etc/security/pwquality.conf"
    pwq_dir = "/etc/security/pwquality.conf.d"
    pam_targets = ["/etc/pam.d/password-auth", "/etc/pam.d/system-auth"]
    defs_path = "/etc/login.defs"

    if not os.path.exists(pwq_path) or not os.path.exists(defs_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "필수 설정 파일(pwquality.conf 또는 login.defs)이 존재하지 않아 수동 확인이 필요합니다."
        return result

    step1_ok = False
    enforce_root = False
    policies = {"minlen": None, "dcredit": None, "ucredit": None, "lcredit": None, "ocredit": None}

    pwq_files = [pwq_path]
    if os.path.isdir(pwq_dir):
        pwq_files.extend(sorted(glob.glob(os.path.join(pwq_dir, "*.conf"))))

    try:
        for pfile in pwq_files:
            with open(pfile, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "enforce_for_root" in line:
                        enforce_root = True
                    match = re.match(r"^\s*([a-zA-Z0-9_]+)\s*=\s*(-?\d+)", line)
                    if match:
                        key, val = match.group(1).lower(), int(match.group(2))
                        if key in policies:
                            policies[key] = val
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"pwquality 설정 파싱 오류: {str(e)}"
        return result

    minlen = policies.get("minlen")
    credits = [policies[k] for k in ["dcredit", "lcredit", "ocredit", "ucredit"]]
    credits_ok = all(v is not None and v <= -1 for v in credits)

    if minlen is not None and minlen >= 8 and credits_ok and enforce_root:
        step1_ok = True

    step2_ok = False
    pam_file_found = False
    try:
        for pam_file in pam_targets:
            if not os.path.exists(pam_file):
                continue
            pam_file_found = True
            with open(pam_file, "r", encoding="utf-8", errors="ignore") as f:
                pam_lines = [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

            idx_pwq, idx_unix = -1, -1
            for i, line in enumerate(pam_lines):
                if "pam_pwquality.so" in line:
                    idx_pwq = i
                elif "pam_unix.so" in line and ("password" in line or line.startswith("password")):
                    idx_unix = i

            if idx_pwq != -1 and (idx_unix == -1 or idx_pwq <= idx_unix):
                step2_ok = True
                break
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"PAM 설정 파싱 오류: {str(e)}"
        return result

    if not pam_file_found:
        result["status"] = "Manual Check"
        result["current_setting"] = "Rocky Linux PAM 인증 설정 파일(password-auth / system-auth)이 존재하지 않습니다."
        return result

    step3_ok = False
    max_days, min_days = None, None
    defs_ok = False
    try:
        with open(defs_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or not line:
                    continue
                match_max = re.match(r"^PASS_MAX_DAYS\s+(\d+)", line)
                match_min = re.match(r"^PASS_MIN_DAYS\s+(\d+)", line)
                if match_max:
                    max_days = int(match_max.group(1))
                if match_min:
                    min_days = int(match_min.group(1))

        if max_days is not None and max_days <= 90 and min_days is not None and min_days >= 1:
            defs_ok = True
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"login.defs 파싱 오류: {str(e)}"
        return result

    # shadow 파일 기반 기존 계정(root 및 일반 계정) 패스워드 만료 정책 점검
    shadow_path = "/etc/shadow"
    shadow_unapplied = []
    shadow_checked = False

    target_accounts = ["root"]
    invalid_shells = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin", "/bin/sync", "/sbin/halt", "/sbin/shutdown"]
    if os.path.exists("/etc/passwd"):
        try:
            with open("/etc/passwd", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 7:
                        uname, uid, shell = parts[0], parts[2], parts[6]
                        if uid.isdigit() and int(uid) >= 1000 and uname != "nobody":
                            if shell not in invalid_shells and not any(shell.endswith(x) for x in ["nologin", "false"]):
                                target_accounts.append(uname)
        except Exception:
            pass

    if os.path.exists(shadow_path):
        try:
            with open(shadow_path, "r", encoding="utf-8", errors="ignore") as f:
                shadow_checked = True
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 5:
                        user = parts[0]
                        pw_hash = parts[1]
                        if user in target_accounts:
                            # 패스워드가 잠겨있지 않거나 실제 로그인 가능한 계정
                            if not pw_hash.startswith("*") and not pw_hash.startswith("!"):
                                sp_min_str = parts[3]
                                sp_max_str = parts[4]
                                sp_min = int(sp_min_str) if sp_min_str.isdigit() else 0
                                sp_max = int(sp_max_str) if sp_max_str.isdigit() else 99999

                                if sp_max > 90 or sp_min < 1:
                                    shadow_unapplied.append(f"{user}(최대={sp_max}일, 최소={sp_min}일)")
        except (PermissionError, Exception):
            shadow_checked = False

    if defs_ok:
        if shadow_checked:
            if not shadow_unapplied:
                step3_ok = True
                step3_desc = f"양호 (login.defs MAX={max_days}/MIN={min_days}, 기존계정 shadow 적용 완료)"
            else:
                step3_ok = False
                step3_desc = f"미달 (login.defs는 정상이나 기존계정 shadow 미적용: {', '.join(shadow_unapplied)} -> chage 적용 필요)"
        else:
            step3_ok = True
            step3_desc = f"양호 (login.defs MAX={max_days}/MIN={min_days} / ※ shadow 확인 권한필요)"
    else:
        step3_ok = False
        step3_desc = f"미달 (login.defs MAX={max_days}, MIN={min_days})"

    s1_lbl = "양호" if step1_ok else "미달"
    s2_lbl = "양호" if step2_ok else "미달"
    s3_lbl = "양호" if step3_ok else "미달"
    summary_text = (
        f"[Step 1 pwquality]: {s1_lbl} (minlen={minlen}, enforce_for_root={enforce_root}) | "
        f"[Step 2 PAM순서]: {s2_lbl} | "
        f"[Step 3 기간정책]: {step3_desc}"
    )

    if step1_ok and step2_ok and step3_ok:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 모든 단계 보안 가이드 만족: {summary_text}"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 일부 보안설정 기준 미달: {summary_text}"

    return result
