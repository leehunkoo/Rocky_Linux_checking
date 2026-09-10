# -*- coding: utf-8 -*-
# Copyright 2026. leehunkoo. All rights reserved.
# This tool was developed with AI assistance (Claude, Gemini) and thoroughly verified in a dedicated local environment.
# Licensed under the AGPL-3.0.

import os
import subprocess

def Check():
    result = {
        "item_id": "U-15",
        "item_Level": "High",
        "title": "파일 및 디렉터리 소유자 설정",
        "status": "Vulnerable",
        "description": "퇴직자 자료 또는 무단 생성 파일 등 소유자나 소유 그룹이 존재하지 않는 파일 및 디렉터리가 시스템 내에 방치되어 있는지 점검",
        "current_setting": "",
        "remediation_type": "Command",
        "remediation_cmd": "",
        "exception_guide": "[양호] 소유자나 소유 그룹이 존재하지 않는(정상 계정과 매핑되지 않는) 파일 및 디렉터리가 존재하지 않는 경우"
    }

    # 취약점 진단 명령어 (2026 KISA 가이드: find / \( -nouser -o -nogroup \) -xdev -ls 2>/dev/null)
    # Docker/Podman/containerd 오버레이 스토리지 안의 파일은 컨테이너 이미지 내부 UID/GID로 소유되어
    # 있어 호스트의 /etc/passwd·/etc/group에는 대응 계정이 없는 경우가 흔함(예: 컨테이너 이미지가
    # 만드는 UID 1000 "app" 계정 등) — 이는 실제 "소유자 없는 유령 파일"이 아니라 정상적인 컨테이너
    # 이미지 레이어일 뿐이므로, U-23/U-25와 동일하게 이 경로들은 순회에서 명시적으로 제외.
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
        "(", "-nouser", "-o", "-nogroup", ")",
        "-ls",
    ]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, _ = process.communicate(timeout=120)

        lines = [line.strip() for line in stdout.splitlines() if line.strip()]

    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        result["status"] = "Manual Check"
        result["current_setting"] = "find / 전체 스캔이 120초 내에 끝나지 않아 시간 초과되었습니다. 수동 점검이 필요합니다."
        return result
    except Exception as e:
        result["status"] = "Manual Check"
        result["current_setting"] = f"find 명령어를 통한 소유자 미존재 파일 탐색 중 장애 발생: {str(e)}"
        return result

    # root 권한이 아니면 /root, 타 사용자 홈 등 접근 불가 디렉터리가 누락되어 결과가
    # 불완전할 수 있음 (오탐이 아니라 미탐 위험이므로 반드시 안내)
    is_root = (os.geteuid() == 0)
    priv_note = "" if is_root else " (※ root 권한으로 실행되지 않아 접근 불가 디렉터리가 스캔에서 누락되었을 수 있습니다. sudo로 재실행 권장)"
    
    # KISA 가이드 최종 판정
    if not lines:
        result["status"] = "PASS(양호)"
        result["current_setting"] = f"[양호] 시스템 내에 소유자 또는 소유 그룹이 존재하지 않는 파일/디렉터리가 발견되지 않았습니다.{priv_note}"
    else:
        # 발견된 유령 파일의 개수가 많을 수 있으므로 최대 5개까지만 축약 요약 노출 처리하여 리포트 가독성 보장
        max_display = 5
        displayed_files = lines[:max_display]
        total_count = len(lines)
        
        summary_msg = f"총 {total_count}개의 유령 파일 검출됨\n" + "\n".join(displayed_files)
        if total_count > max_display:
            summary_msg += f"\n... 외 {total_count - max_display}개 더 존재함"

        result["status"] = "Vulnerable"
        result["current_setting"] = f"[WARN] 소유자(UID) 또는 소유 그룹(GID)이 누락된 파일이 방치되어 있습니다:\n{summary_msg}{priv_note}"

        # 가이드라인 조치 명령어 시각화(rm 또는 chown/chgrp) — 둘 다 사람이 직접 대상을 골라야
        # 하는 작업이라 실행형 명령이 아니라 예시 주석으로만 제공(U-05/U-10과 동일한 안전 원칙)
        result["remediation_cmd"] = (
            "# [주의] 'sudo -i'로 root 셸에 먼저 진입한 뒤, 위에서 발견된 각 파일/디렉터리에 대해\n"
            "# 실제로 불필요한지 사용 중인지 먼저 확인한 후 아래 중 해당하는 조치를 선택해 실행하십시오.\n"
            "# 1. 불필요한 파일인 경우 안전성 검토 후 삭제 처리\n"
            "# 예시: rm <파일_이름>  또는  rm -r <디렉터리_이름>\n\n"
            "# 2. 사용 중인 파일인 경우 정상적인 관리자/그룹으로 소유권 재할당\n"
            "# 예시: chown <사용자_이름> <파일_또는_디렉터리_이름>\n"
            "# 예시: chgrp <그룹_이름> <파일_또는_디렉터리_이름>"
        )

    return result