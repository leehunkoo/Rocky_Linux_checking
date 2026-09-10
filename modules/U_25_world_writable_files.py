# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat
import subprocess

def Check():
    result = {
        "item_id": "U-25",
        "item_Level": "High",
        "title": "world writable 파일 점검",
        "status": "Vulnerable",
        "description": "일반 사용자 및 비인가자가 중요 시스템 파일을 임의로 수정하여 발생하는 악의적인 코드 실행을 방지하기 위해 world writable 파일 존재 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 시스템 내에 불필요한 world writable 파일이 존재하지 않거나, 존재하는 파일의 설정 이유를 명확히 인지하여 관리 중인 경우"
    }

    # KISA 상세 가이드라인 find 기반 탐색 표준 명령어 실행
    # Docker/Podman/containerd 오버레이 스토리지는 컨테이너 이미지 레이어 내부 파일을 그대로
    # 포함하며 -xdev(같은 파일시스템)만으로는 걸러지지 않아, U-23과 동일하게 대량 오탐 및
    # "컨테이너 내부 저장소 파일에 chmod/rm" 같은 위험한 조치로 이어질 수 있어 명시적으로 제외.
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
        "(", "-type", "f", "-perm", "-2", ")",
        "-print",
    ]

    standard_whitelist_dirs = [
        "/tmp", "/var/tmp", "/var/lock", "/run/lock"
    ]

    try:
        # find 명령어 수행하여 일반 사용자 쓰기 비트(Others Write)가 활성화된 파일 추출
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate()
        
        found_files = [line.strip() for line in stdout.splitlines() if line.strip()]

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"world writable 파일 시스템 조사 중 예외 발생: {str(e)}"
        return result

    suspicious_files = []

    # 임시 디렉터리(/tmp 등) 하위의 정상 유휴 파일을 제외한 잠재적 취약 위험 파일 격리
    for file_path in found_files:
        is_whitelisted = False
        for wl_dir in standard_whitelist_dirs:
            if file_path.startswith(wl_dir):
                is_whitelisted = True
                break
                
        if not is_whitelisted:
            try:
                file_stat = os.stat(file_path)
                mode = file_stat.st_mode
                permission_oct = oct(stat.S_IMODE(mode))[2:]
                suspicious_files.append(f"{file_path}(권한:{permission_oct})")
            except Exception:
                suspicious_files.append(file_path)

    # KISA 가이드 최종 판정
    if not suspicious_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] 임시 경로 이외의 중요 시스템 영역 내에 불필요하게 방치된 world writable 파일이 존재하지 않습니다."
    else:
        # 칸 정렬 깨짐 방지 및 가독성을 유지하기 위해 최대 5개 노출 및 축약 알고리즘 적용
        max_display = 5
        displayed_items = suspicious_files[:max_display]
        total_vuln_count = len(suspicious_files)

        summary_msg = f"위험한 world writable 파일 총 {total_vuln_count}건 검출 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개 추가 검토 필요"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 일반 사용자가 임의로 수정/제거 가능한 world writable 파일이 존재합니다:\n{summary_msg}"

        # 가이드라인 조치 사례(chmod o-w 또는 rm)를 적용한 동적 명령어 바인딩
        remediation_cmds = [
            "# 1. 검출된 중요 파일들의 일반 사용자 쓰기(Others Write) 권한을 안전하게 박탈",
            "# 가이드라인 규격 기본 조치: chmod o-w <파일_이름>"
        ]
        
        for item in suspicious_files:
            clean_path = item.split("(")[0]
            remediation_cmds.append(f"chmod o-w {clean_path}")

        remediation_cmds.extend([
            "\n# 2. 검토 후 시스템 운영에 완전히 불필요하다고 판단되는 악의적 생성 파일은 영구 제거",
            "# rm <파일_이름>"
        ])
        
        result["remediation_cmd"] = "\n".join(remediation_cmds)

    return result