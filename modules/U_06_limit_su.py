# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re
import stat

def Check():
    result = {
        "item_id": "U-06",
        "item_Level": "High",
        "title": "사용자 계정 su 기능 제한",
        "status": "Vulnerable",
        "description": "su 관련 그룹만 su 명령어 사용 권한이 부여되어 있는지 점검하여 su 그룹에 포함되지 않은 일반 사용자의 su 명령 사용을 원천적으로 차단하는지 확인하기 위함",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "# wheel group에 su 명령 허용 계정 등록 \n usermod -G wheel <username>",
        "exception_guide": "[양호] su 파일 권한이 4750 이하이면서 소유 그룹이 wheel이고, pam_wheel.so 설정이 활성화된 경우"
    }
    
    group_path = "/etc/group"
    pam_su_path = "/etc/pam.d/su"
    su_bin_path = "/usr/bin/su"

    # su 명령어 존재 여부 검증
    if not os.path.exists(su_bin_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/usr/bin/su 명령어가 존재하지 않는 특이 시스템 입니다. 확인이 필요합니다."
        return result
    
    # 기본 시스템 정보 수집
    wheel_group_exists = False
    pam_file_exists = os.path.exists(pam_su_path)
    pam_wheel_configured = False
    su_group_name = "unknown"
    su_permission_ok = False

    # wheel 그룹 존재 점검 (/etc/group)
    if os.path.exists(group_path):
        try:
            with open(group_path, "r", encoding='utf-8') as f:
                for line in f:
                    if line.startswith("wheel:"):
                        wheel_group_exists = True
                        break
        except Exception as e:
            result["status"] = "Manual Check"
            result["current_setting"] = f"{group_path} 읽기 실패: {str(e)}"
            return result
        
    # Pam 모듈 적용 설정 확인 (/etc/pam.d/su)
    if pam_file_exists:
        try:
            with open(pam_su_path, "r", encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    if "pam_wheel.so" in line and ("use_uid" in line or "group=" in line):
                        pam_wheel_configured = True
                        break
        except Exception as e:
            result["status"] = "Manual Check"
            result["current_setting"] = f"{pam_su_path} 읽기 실패: {str(e)}"
            return result
        
    # /usr/bin/su 파일 권한 및 소유 그룹 정보 파싱
    try:
        su_stat = os.stat(su_bin_path)
        mode = su_stat.st_mode
        permission_oct = oct(stat.S_IMODE(mode))[2:]

        # 인가되지 않는 사용자 실행 권한(others Execute) 제한 여부 검증
        others_executable = (mode & stat.S_IXOTH) != 0
        if not others_executable:
            su_permission_ok = True

        import grp
        try:
            su_group_name = grp.getgrgid(su_stat.st_gid).gr_name
        except KeyError:
            su_group_name = str(su_stat.st_gid)

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"{su_bin_path} 속성 읽기 실패: {str(e)}"
        return result
    
    # KISA 가이드 최종 판정

    # PAM 모듈을 사용 중인 경우
    if pam_file_exists:
        summary_msg = f"PAM 사용 환경 | pam_wheel 설정: {'적용' if pam_wheel_configured else '누락'} | su 소유 그룹: {su_group_name} | su 권한: {permission_oct}"

        if pam_wheel_configured and su_group_name == "wheel" and su_permission_ok:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] PAM 제어 및 wheel 그룹 통제를 통해 su 권한이 제한되어 있습니다. ({summary_msg})"
            return result
        else:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] PAM 기반 su 기능 제한 설정이 누락되었거나, 불완전합니다. ({summary_msg})"
            
            # PAM 전용 타겟 조치 명령어
            remediation_cmds = []
            if not wheel_group_exists:
                remediation_cmds.append("sudo groupadd wheel 2>/dev/null || true")
            if su_group_name != "wheel":
                remediation_cmds.append("sudo chgrp wheel /usr/bin/su")
            if not su_permission_ok:
                remediation_cmds.append("sudo chmod 4750 /usr/bin/su")

            remediation_cmds.append(
                "# 활성화된 pam_wheel.so use_uid 설정이 없으면 추가\n"
                "if ! grep -qE '^[^#].*pam_wheel\\.so.*use_uid' /etc/pam.d/su; then\n"
                "  echo 'auth       required   pam_wheel.so use_uid' | sudo tee -a /etc/pam.d/su > /dev/null\n"
                "fi"
            )
            result["remediation_cmd"] = "\n".join(remediation_cmds)

    # PAM 모듈을 이용 중이지 않는 경우(구형 또는 특이 시스템 환경의 경우)
    else:
        summary_msg = f"Non-PAM 환경 | wheel 그룹 존재: {wheel_group_exists} | su 소유그룹: {su_group_name} | su 권한: {permission_oct}" 

        if wheel_group_exists and su_group_name == "wheel" and su_permission_ok:
            result["status"] = "PASS(양호)"
            result["current_setting"] = f"[양호] Non-PAM 환경에서 wheel 그룹 지정을 통해 su 사용 권한이 정상 제한되어 있습니다. ({summary_msg})"
        else:
            result["status"] = "Vulnerable"
            result["current_setting"] = f"[WARN] Non-PAM 환경에서 su 사용 제한 설정(wheel 지정 및 4750 권한)이 미비합니다. ({summary_msg})"

            # Non-PAM 전용 타겟 조치 명령어
            remediation_cmds = []
            if not wheel_group_exists:
                remediation_cmds.append("sudo groupadd wheel 2>/dev/null || true")
            remediation_cmds.append("sudo chgrp wheel /usr/bin/su")
            remediation_cmds.append("sudo chmod 4750 /usr/bin/su")
            remediation_cmds.append("# su 명령어 사용 권한을 부여할 사용자를 추가 등록하십시오.: \n# usermod -G wheel <username>")

            result["remediation_cmd"] = "\n".join(remediation_cmds)
    
    return result