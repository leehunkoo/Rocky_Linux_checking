import html
import importlib
import os
import re
import sys
import textwrap
import urllib.parse

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

def parse_remediation_info(raw_cmd):
    """
    raw_cmd 문자열을 지능적으로 분석하여 분리:
    - has_cmd: 유효한 명령어나 가이드가 존재하는지 여부
    - notes: [설명 및 주의사항 목록 (HTML escaped)]
    - clean_cmd: 터미널에 직접 실행할 순수 명령어 (HTML escaped)
    - clean_cmd_raw: 터미널에 직접 실행할 순수 명령어 원본
    - has_placeholder: <username>, <UID> 등 사용자가 직접 입력/수정해야 하는 값이 있는지 여부
    - is_guide_only: 실행 명령어가 없고 순수 가이드/설명문만 있는지 여부
    """
    if not raw_cmd or not str(raw_cmd).strip():
        return {
            "has_cmd": False,
            "notes": [],
            "clean_cmd": "",
            "clean_cmd_raw": "",
            "has_placeholder": False,
            "is_guide_only": False,
        }

    raw = textwrap.dedent(str(raw_cmd)).strip()

    # Split inline comments on && or ||
    normalized_lines = []
    for line in raw.split("\n"):
        if "&& #" in line:
            parts = line.split("&& #", 1)
            normalized_lines.append(parts[0].rstrip() + " &&")
            normalized_lines.append("# " + parts[1].strip())
        elif "|| #" in line:
            parts = line.split("|| #", 1)
            normalized_lines.append(parts[0].rstrip() + " ||")
            normalized_lines.append("# " + parts[1].strip())
        else:
            normalized_lines.append(line)

    notes = []
    cmd_lines = []

    for line in normalized_lines:
        stripped = line.strip()
        if not stripped:
            continue

        if any(stripped.startswith(prefix) for prefix in ["# [주의]", "#[주의]", "**주의**", "# [조치 시 영향", "# [인프라 보완", "# [참고]", "※", "[수동 점검"]):
            notes.append(stripped.lstrip("#*※ ").strip())
        elif "sudo -i" in stripped and "root 셸" in stripped:
            notes.append(stripped.lstrip("# ").strip())
        elif stripped.startswith("#") and any(k in stripped for k in ["가이드", "지침", "권고", "영향", "확인하십시오", "경로"]):
            notes.append(stripped.lstrip("# ").strip())
        elif stripped.startswith("**") and stripped.endswith("**"):
            notes.append(stripped.strip("* ").strip())
        elif stripped.startswith("#") and re.match(r"^#\s*\d+\.\s+.*(조치|가이드|설정|점검|제거|비활성화|적용)", stripped):
            notes.append(stripped.lstrip("# ").strip())
        elif re.match(r"^\d+\.\s+(sudo\s+)?[a-zA-Z0-9_./-]+", stripped):
            cmd = re.sub(r"^\d+\.\s*", "", stripped)
            cmd_lines.append(cmd)
        elif stripped.startswith("#"):
            clean_test = re.sub(r"^#\s*", "", stripped)
            if re.match(r"^(sudo\s+)?(usermod|userdel|groupdel|chmod|chown|systemctl|cat|echo|sed|ls|find|dnf|yum)\s+", clean_test):
                cmd_lines.append(clean_test)
            else:
                notes.append(stripped.lstrip("# ").strip())
        else:
            cmd_lines.append(stripped)

    clean_cmd_raw = "\n".join(cmd_lines).strip()
    has_placeholder = bool(re.search(r"<[^>]+>", clean_cmd_raw))
    is_guide_only = len(cmd_lines) == 0 and len(notes) > 0

    return {
        "has_cmd": bool(clean_cmd_raw or is_guide_only),
        "notes": [html.escape(n) for n in notes],
        "clean_cmd": html.escape(clean_cmd_raw),
        "clean_cmd_raw": clean_cmd_raw,
        "has_placeholder": has_placeholder,
        "is_guide_only": is_guide_only,
    }

def render_final_remediation_html(parsed):
    """최종 보고서 상세 행에 삽입될 조치 가이드 & 터미널 명령어 박스 HTML 생성"""
    if not parsed["has_cmd"]:
        return """
        <div class="remediation-empty-box">
            이 항목은 별도의 자동 조치 명령어가 제공되지 않습니다. 상단의 <strong>[판단 기준]</strong> 및 보안 운영 가이드에 따라 수동 점검 및 설정을 진행하세요.
        </div>"""

    parts = ['<div class="remediation-container">']

    # 1. 조치 전 확인 및 주의사항 (Notes)
    if parsed["notes"]:
        li_items = "".join(f"<li>{n}</li>" for n in parsed["notes"])
        parts.append(f"""
        <div class="remediation-notes-box">
            <div class="notes-header">
                <strong>[조치 전 확인 및 주의사항]</strong>
            </div>
            <ul class="notes-list">{li_items}</ul>
        </div>""")

    # 2. 사용자 입력 필요 경고 (Placeholder Alert)
    if parsed["has_placeholder"]:
        parts.append("""
        <div class="remediation-placeholder-box">
            <strong>[사용자 설정 필요]</strong> 명령어에 <code>&lt;username&gt;</code>, <code>&lt;UID&gt;</code> 등 사용자가 직접 입력해야 하는 값이 포함되어 있습니다. 복사 후 실제 서버 환경 값으로 변경하여 실행하세요.
        </div>""")

    # 3. 터미널 실행 명령어 창
    if parsed["clean_cmd_raw"]:
        encoded_cmd = urllib.parse.quote(parsed["clean_cmd_raw"])
        parts.append(f"""
        <div class="terminal-box">
            <div class="terminal-bar">
                <div class="terminal-dots">
                    <span class="terminal-dot dot-red"></span>
                    <span class="terminal-dot dot-yellow"></span>
                    <span class="terminal-dot dot-green"></span>
                    <span class="terminal-title">터미널 실행 명령어 (Bash)</span>
                    <span class="terminal-auth-tag">root 권한 (sudo -i) 필요</span>
                </div>
                <div class="terminal-actions">
                    <button type="button" class="copy-cmd-btn" data-encoded="{encoded_cmd}" onclick="copyTerminalCmd(this)">
                        <svg class="copy-icon" viewBox="0 0 24 24" width="13" height="13" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                        </svg>
                        <span>명령어 복사</span>
                    </button>
                </div>
            </div>
            <pre class="terminal-pre"><code>{parsed['clean_cmd']}</code></pre>
        </div>""")

    parts.append("</div>")
    return "\n".join(parts)

def load_all_modules():
    """modules/ 디렉토리에서 U_로 시작하는 .py 파일을 정렬 순으로 자동 로드"""
    modules_dir = os.path.join(current_dir, "modules")
    module_files = sorted(
        f for f in os.listdir(modules_dir)
        if f.startswith("U_") and f.endswith(".py")
    )

    loaded = []
    for filename in module_files:
        module_name = filename[:-3]  # .py 제거
        try:
            mod = importlib.import_module(f"modules.{module_name}")
            if hasattr(mod, "Check"):
                loaded.append((module_name, mod))
            else:
                print(f"[경고] {module_name}: Check() 함수 없음 — 건너뜀")
        except Exception as e:
            print(f"[오류] {module_name} 임포트 실패: {e}")

    return loaded

def build_html_report(results):
    template_path = os.path.join(current_dir, "templates", "report.html")
    output_path = os.path.join(current_dir, "report_result.html")

    if not os.path.exists(template_path):
        print(f"[오류] 템플릿 파일이 없습니다: {template_path}")
        return

    card_items = ""
    for item in results:
        status_val = item["status"]

        if "PASS" in status_val:
            status_class = "PASS(양호)"
            badge_class = "badge-pass"
        elif "Vulnerable" in status_val or "취약" in status_val:
            status_class = "Vulnerable"
            badge_class = "badge-vulnerable"
        elif "Manual" in status_val or "확인" in status_val:
            status_class = "Manual Check"
            badge_class = "badge-manual"
        else:
            status_class = "N/A"
            badge_class = "badge-na"

        item_id = html.escape(str(item["item_id"]))
        title = html.escape(str(item["title"]))
        item_level = html.escape(str(item.get("item_Level", "상")))
        status_text = html.escape(str(status_val))
        description = html.escape(str(item["description"]))
        current_setting = html.escape(str(item["current_setting"]))
        exception_guide = html.escape(str(item["exception_guide"]))
        search_key = html.escape(f"{item['item_id']} {item['title']}".lower())

        parsed = parse_remediation_info(item.get("remediation_cmd", ""))
        
        cmd_section = ""
        if parsed["clean_cmd_raw"]:
            encoded_clean = urllib.parse.quote(parsed["clean_cmd_raw"])
            cmd_section = f"""
                    <div class="cmd-toolbar">
                        <span style="font-size: 11px; color: var(--ios-text-muted); font-weight: 600;">※ 불필요한 주석 없이 실행할 터미널 명령어만 복사됩니다</span>
                        <button class="copy-btn" onclick="copyCmd(this, '{encoded_clean}')">명령어 복사</button>
                    </div>
                    <div class="cmd-wrap">
                        <div class="cmd-block">{parsed['clean_cmd']}</div>
                        <div class="cmd-fade"></div>
                        <button class="more-btn"></button>
                    </div>"""
            if parsed["notes"]:
                notes_li = "".join(f"<li>{n}</li>" for n in parsed["notes"])
                cmd_section += f"""
                    <div style="margin-top: 8px; font-size: 11.5px; background: #f2f2f7; padding: 8px 12px; border-radius: 8px; color: #3a3a3c;">
                        <strong>[조치 전 확인 및 주의사항]</strong>
                        <ul style="margin: 4px 0 0; padding-left: 16px;">{notes_li}</ul>
                    </div>"""
            if parsed["has_placeholder"]:
                cmd_section += """
                    <div style="margin-top: 6px; font-size: 11.5px; background: #fff8e6; padding: 6px 10px; border-radius: 6px; color: #873800; border: 1px solid #ffd666;">
                        <strong>[사용자 설정 필요]</strong> 명령어 내 <code>&lt;...&gt;</code> 표시는 사용자가 실제 환경에 맞게 수정한 후 실행해야 합니다.
                    </div>"""
        elif parsed["has_cmd"] and parsed["notes"]:
            notes_li = "".join(f"<li>{n}</li>" for n in parsed["notes"])
            cmd_section = f"""
                    <div style="font-size: 12px; background: #f2f2f7; padding: 10px 14px; border-radius: 8px; color: #3a3a3c;">
                        <strong>[조치 가이드]</strong>
                        <ul style="margin: 6px 0 0; padding-left: 18px;">{notes_li}</ul>
                    </div>"""
        else:
            cmd_section = '<div class="setting-box" style="color: var(--ios-text-muted);">해당 없음 (수동 점검 필요)</div>'

        card_items += f"""
        <div class="list-item" data-status="{status_class}" data-search="{search_key}">
            <div class="item-header">
                <div class="item-title-box">
                    <span class="item-id">{item_id}</span>
                    <span class="item-title">{title}</span>
                    <span class="item-level">중요도: {item_level}</span>
                </div>
                <span class="badge {badge_class}">{status_text}</span>
            </div>

            <div class="item-body">
                <div class="info-section">
                    <span class="section-label">점검 및 현황</span>
                    <div class="section-content" style="font-weight: 600; color: #3a3a3c;">{description}</div>
                    <div class="setting-box">{current_setting}</div>
                </div>

                <div class="info-section">
                    <span class="section-label">조치 가이드</span>
                    {cmd_section}
                    <div class="guide-box">※ {exception_guide}</div>
                </div>
            </div>
        </div>
        """

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        final_html = html_content.replace("<!-- REPORT_ITEMS_PLACEHOLDER -->", card_items)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_html)

        print(f"\n[성공] 리포트 생성 완료: {output_path}")
    except Exception as e:
        print(f"[오류] HTML 리포트 생성 실패: {str(e)}")

def build_final_report(results):
    """인쇄/바인딩용 최종 서버 점검 보고서 생성 (기존 report_result.html과 별개의 산출물).
    항목별 '최종판정'/'비고'는 브라우저에서 수기로 편집·저장(localStorage)하는 구조라
    여기서는 자동판정 결과를 초기값으로 채운 뼈대만 만든다."""
    template_path = os.path.join(current_dir, "templates", "final_report.html")
    output_path = os.path.join(current_dir, "final_report_result.html")

    if not os.path.exists(template_path):
        print(f"[오류] 최종 보고서 템플릿 파일이 없습니다: {template_path}")
        return

    rows = ""
    for idx, item in enumerate(results, 1):
        status_val = item["status"]

        if "PASS" in status_val:
            auto_value, badge_class, auto_label = "PASS", "badge-pass", "양호"
        elif "Vulnerable" in status_val or "취약" in status_val:
            auto_value, badge_class, auto_label = "Vulnerable", "badge-vuln", "취약"
        elif "Manual" in status_val or "확인" in status_val:
            auto_value, badge_class, auto_label = "Manual Check", "badge-manual", "수동확인"
        else:
            auto_value, badge_class, auto_label = "Manual Check", "badge-manual", status_val

        item_id = html.escape(str(item["item_id"]))
        title = html.escape(str(item["title"]))
        item_level = html.escape(str(item.get("item_Level", "상")))
        description = html.escape(str(item["description"]))
        current_setting = html.escape(str(item["current_setting"]))
        exception_guide = html.escape(str(item["exception_guide"]))

        parsed = parse_remediation_info(item.get("remediation_cmd", ""))
        remediation_html = render_final_remediation_html(parsed)
        clean_cmd_encoded = urllib.parse.quote(parsed["clean_cmd_raw"]) if parsed["clean_cmd_raw"] else ""

        options = "".join(
            f'<option value="{val}"{" selected" if val == auto_value else ""}>{label}</option>'
            for val, label in [
                ("PASS", "양호"), ("Vulnerable", "취약"),
                ("Manual Check", "수동확인"), ("Exception", "예외처리(오탐)"),
            ]
        )

        rows += f"""
        <tr class="main-row" data-item-id="{item_id}" data-auto-status="{auto_value}" data-title="{title}" data-has-cmd="{'true' if parsed['clean_cmd_raw'] else 'false'}" data-has-placeholder="{'true' if parsed['has_placeholder'] else 'false'}" data-clean-cmd="{clean_cmd_encoded}">
            <td class="col-no">{idx}</td>
            <td class="col-id">{item_id}</td>
            <td class="col-title">{title}<span class="lvl">{item_level}</span>
                <button class="toggle-detail-btn" onclick="toggleDetail(this)">상세정보 보기 ▾</button>
            </td>
            <td class="col-auto"><span class="badge-mini {badge_class}">{auto_label}</span></td>
            <td class="col-final">
                <div class="col-final-wrap">
                    <select class="final-status" autocomplete="off" onchange="onFinalStatusChange(this)">{options}</select>
                    <span class="print-only-text"></span>
                </div>
            </td>
            <td class="col-remark"><textarea class="remark" oninput="scheduleSave()" placeholder="특이사항/예외 사유 입력"></textarea></td>
        </tr>
        <tr class="detail-row" data-item-id="{item_id}">
            <td colspan="6">
                <div class="detail-content-wrap">
                    <div class="finding-group">
                        <div class="finding-card">
                            <div class="finding-label">점검 내용</div>
                            <div class="finding-val">{description}</div>
                        </div>
                        <div class="finding-card">
                            <div class="finding-label">점검 및 현황</div>
                            <div class="finding-val">{current_setting}</div>
                        </div>
                        <div class="finding-card">
                            <div class="finding-label">판단 기준</div>
                            <div class="finding-val">{exception_guide}</div>
                        </div>
                    </div>
                    {remediation_html}
                </div>
            </td>
        </tr>
        """

    try:
        with open(template_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        final_html = html_content.replace("<!-- FINAL_REPORT_ITEMS_PLACEHOLDER -->", rows)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(final_html)

        print(f"[성공] 최종 점검 보고서 생성 완료: {output_path}")
    except Exception as e:
        print(f"[오류] 최종 보고서 생성 실패: {str(e)}")

def run():
    print("=== KISA 주요정보통신기반시설 취약점 분석 ===\n")

    modules = load_all_modules()
    if not modules:
        print("[오류] 실행할 모듈이 없습니다.")
        return

    all_results = []
    for module_name, mod in modules:
        print(f"[실행] {module_name} ...")
        try:
            result = mod.Check()
            all_results.append(result)
            print(f"  → {result['item_id']} {result['title']}: {result['status']}")
        except Exception as e:
            print(f"  → [오류] Check() 실행 실패: {e}")

    print(f"\n총 {len(all_results)}개 항목 진단 완료")
    build_html_report(all_results)
    build_final_report(all_results)

if __name__ == "__main__":
    run()
