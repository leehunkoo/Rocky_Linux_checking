# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import re


def _has_unsafe_dot(path_value):
    """PATH 문자열에서 '.' 또는 빈 경로(::)가 맨 마지막이 아닌 위치에 있으면 True.
    (KISA 가이드 기준: 맨 마지막에 위치하거나 없으면 양호. 단, PATH가 '.'/빈 경로
    뿐이거나 그것들로만 구성된 경우는 실질적으로 전체가 위험하므로 예외적으로 취약 처리)"""
    if not path_value:
        return False
    parts = path_value.split(":")
    if len(parts) == 1:
        return parts[0] in (".", "")
    # 맨 끝에 연속된 '.'/빈 경로는 정책상 안전하므로 모두 제거한 뒤 나머지만 검사
    trimmed = list(parts)
    while trimmed and trimmed[-1] in (".", ""):
        trimmed.pop()
    if not trimmed:
        return True  # 전부 '.'/빈 경로뿐이었던 경우
    return any(p in (".", "") for p in trimmed)


def Check():
    result = {
        "item_id": "U-14",
        "item_Level": "High",
        "title": "root 홈, 패스 디렉터리 권한 및 패스 설정",
        "status": "Vulnerable",
        "description": "root 계정 및 전역 환경설정 파일의 PATH 변수에 현재 디렉터리('.')가 맨 앞이나 중간에 포함되어 변조된 명령어가 우선 실행되는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": (
            "# 전역 및 root 설정 파일 내 PATH 설정 중 맨 앞이나 중간에 위치한 '.' 제거 또는 맨 뒤로 이동 조치\n"
            "# 예시: PATH=./$PATH 와 같이 맨 앞에 지정된 설정을 지우거나 맨 뒤로 이동하도록 해당 파일 수정 권고"
        ),
        "exception_guide": "[양호] PATH 환경변수에 '.' 또는 '::'이 맨 앞이나 중간에 포함되지 않은 경우 (맨 마지막에 위치하거나 없는 경우 양호)"
    }

    target_files = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/csh.cshrc",
        "/root/.bash_profile",
        "/root/.bashrc"
    ]

    path_violations = []

    # PATH 환경 변수 점검 (맨 앞/중간에 '.' 또는 빈 경로(::)가 있으면 취약, 맨 마지막이면 양호)
    current_path = os.environ.get("PATH", "")
    if current_path and _has_unsafe_dot(current_path):
        path_violations.append(f"실시간 PATH 변수의 맨 앞/중간에 '.' 또는 빈 경로가 존재함 (PATH={current_path})")

    # 파일 검증
    for file_path in target_files:
        if not os.path.exists(file_path):
            continue
            
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    
                    # PATH=... 할당문 탐색 정규표현식
                    match = re.search(r"^\s*export\s+PATH\s*=\s*(.*)", line) or re.search(r"^\s*PATH\s*=\s*(.*)", line)
                    if match:
                        path_value = match.group(1).strip('"\'')

                        # 파일 내 선언 구조 분석 (맨 앞/중간에 '.' 또는 빈 경로면 취약, 맨 마지막이면 양호)
                        if _has_unsafe_dot(path_value):
                            path_violations.append(f"{os.path.basename(file_path)} 파일 내 위험한 PATH 구조 발견({path_value})")
        except Exception:
            pass

    # KISA 가이드 최종 판정
    summary_msg = f"실시간 PATH: {current_path}"

    if not path_violations:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 환경변수 및 설정 파일 내에 현재 디렉터리('.') 경로가 안전하게 통제되어 있습니다. ({summary_msg})"
    else:
        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 위협적인 명령어 검색 경로가 감지되었습니다 -> { ' / '.join(path_violations) }"
        
        # 탐지된 취약 파일들에 대해 맞춤형 주석 안내 가이드 동적 생성
        cmds = ["# 아래 탐지된 파일들의 PATH 선언문에서 맨 앞/중간의 '.' 또는 공백(:)을 제거하거나 맨 뒤로 이동하십시오."]
        for violation in path_violations:
            if "파일" in violation:
                filename = violation.split(" ")[0]
                cmds.append(f"# 대상 파일 수정 필요: {filename}")
        result["remediation_cmd"] = "\n".join(cmds)

    return result
