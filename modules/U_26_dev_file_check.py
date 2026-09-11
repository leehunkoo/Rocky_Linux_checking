# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import stat
import subprocess

def Check():
    result = {
        "item_id": "U-26",
        "item_Level": "High",
        "title": "/dev에 존재하지 않는 device 파일 점검",
        "status": "Vulnerable",
        "description": "/dev 디렉터리 내에 일반 파일 형태로 위장하여 숨겨진 악의적인 루트킷 및 불필요한 장치 위장 파일의 방치 여부를 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] /dev 디렉터리 내 장치 파일 규격(Block/Character)이 아닌 불필요한 일반 파일이 존재하지 않는 경우 (※ mqueue, shm 경로는 예외 적용)"
    }

    dev_path = "/dev"

    # /dev 디렉터리 존재 여부 검증
    if not os.path.exists(dev_path) or not os.path.isdir(dev_path):
        result["status"] = "Manual Check"
        result["current_setting"] = "/dev 디렉터리가 식별되지 않는 특이 시스템 환경입니다."
        return result
    
    # 경로 접두사 기준 예외 디렉터리 (부분 문자열 매칭 금지: "/dev/fake_mqueue_x", "/dev/xshmz" 같은
    # 위장 파일명이 "mqueue"/"shm" 문자열을 포함한다는 이유로 화이트리스트를 통과해버리는 우회를 방지)
    standard_whitelist_prefixes = [
        os.path.join(dev_path, "mqueue"),
        os.path.join(dev_path, "shm"),
        os.path.join(dev_path, ".udev"),
        os.path.join(dev_path, ".initramfs"),
    ]

    vulnerable_files = []
    remediation_cmds = []
    checked_files_count = 0

    try:
        # KISA 표준 진단 기법인 find /dev -type f 규격 구현 (-xdev로 /dev 자체 파일시스템 경계 내로 제한)
        cmd = ["find", dev_path, "-xdev", "-type", "f"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        stdout, _ = process.communicate()

        found_files = [line.strip() for line in stdout.splitlines() if line.strip()]

    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"/dev 파일 시스템 조사 중 장치 탐색 예외 발생: {str(e)}"
        return result

    # 수집된 일반 파일 중 화이트리스트 차단 및 실제 취약 파일 필터링
    for file_path in found_files:
        is_whitelisted = False
        for prefix in standard_whitelist_prefixes:
            if file_path == prefix or file_path.startswith(prefix + os.sep):
                is_whitelisted = True
                break

        if not is_whitelisted:
            try:
                checked_files_count += 1
                file_stat = os.stat(file_path)
                mode = file_stat.st_mode

                if stat.S_ISREG(mode):
                    vulnerable_files.append(file_path)
                    # [주의] rm은 되돌릴 수 없으므로 바로 삭제하지 않고 먼저 상세 정보를 확인시킴
                    # (일부 드라이버/데몬이 부팅 중 생성하는 정상 파일일 가능성 배제 위함)
                    remediation_cmds.append(f"ls -l {file_path}")
            except Exception:
                continue

    # KISA 가이드 최종 판정
    if not vulnerable_files:
        result["status"] = "PASS(양호)"
        result["current_setting"] = "[양호] /dev 디렉터리 내에 루트킷 등으로 위장된 의심스러운 일반 파일이 존재하지 않습니다."
    else:
        # 화면 출력 정렬이 깨지는 현상을 차단하고 가독성을 보장하기 위해 최대 5개 축약 필터 작동
        max_display = 5
        displayed_items = vulnerable_files[:max_display]
        total_vuln_count = len(vulnerable_files)

        summary_msg = f"의심스러운 위장 일반 파일 총 {total_vuln_count}건 검출 -> " + ", ".join(displayed_items)
        if total_vuln_count > max_display:
            summary_msg += f" 외 {total_vuln_count - max_display}개의 위장 파일 발견"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] /dev 디렉터리 내에 장치 번호(Major/Minor)가 없는 일반 위장 파일이 방치되어 있습니다:\n{summary_msg}"

        banner = [
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤 (다시 sudo를 붙이지 말고) 실행하세요.",
            "# 1. 아래 명령으로 각 파일의 상세 정보(소유자/시각/크기)를 먼저 확인하십시오.",
            "#    일부 드라이버/애플리케이션이 부팅 중 생성하는 정상 파일일 수 있습니다.",
        ]
        footer = [
            "",
            "# 2. 확인 결과 불필요/의심스러운 파일로 판단되는 경우에만 개별적으로 제거",
            "# 예시: rm <파일_이름>",
        ]
        result["remediation_cmd"] = "\n".join(banner + remediation_cmds + footer)

    return result