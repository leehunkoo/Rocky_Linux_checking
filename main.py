import html
import importlib
import os
import sys
import textwrap
import urllib.parse

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.append(current_dir)

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
        remediation_cmd_raw = textwrap.dedent(item["remediation_cmd"]).strip()
        remediation_cmd = html.escape(remediation_cmd_raw)
        remediation_cmd_encoded = urllib.parse.quote(remediation_cmd_raw)
        exception_guide = html.escape(str(item["exception_guide"]))
        search_key = html.escape(f"{item['item_id']} {item['title']}".lower())

        cmd_section = ""
        if remediation_cmd_raw:
            cmd_section = f"""
                    <div class="cmd-toolbar">
                        <button class="copy-btn" onclick="copyCmd(this, '{remediation_cmd_encoded}')">복사</button>
                    </div>
                    <div class="cmd-wrap">
                        <div class="cmd-block">{remediation_cmd}</div>
                        <div class="cmd-fade"></div>
                        <button class="more-btn"></button>
                    </div>"""
        else:
            cmd_section = '<div class="setting-box" style="color: var(--ios-text-muted);">해당 없음</div>'

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
        remediation_cmd_raw = textwrap.dedent(item["remediation_cmd"]).strip()
        remediation_cmd = html.escape(remediation_cmd_raw)
        exception_guide = html.escape(str(item["exception_guide"]))

        options = "".join(
            f'<option value="{val}"{" selected" if val == auto_value else ""}>{label}</option>'
            for val, label in [
                ("PASS", "양호"), ("Vulnerable", "취약"),
                ("Manual Check", "수동확인"), ("Exception", "예외처리(오탐)"),
            ]
        )

        cmd_block = f'<div class="cmd-mini">{remediation_cmd}</div>' if remediation_cmd_raw else ""

        rows += f"""
        <tr class="main-row" data-item-id="{item_id}">
            <td class="col-no">{idx}</td>
            <td class="col-id">{item_id}</td>
            <td class="col-title">{title}<span class="lvl">{item_level}</span>
                <button class="toggle-detail-btn" onclick="toggleDetail(this)">상세정보 보기 ▾</button>
            </td>
            <td class="col-auto"><span class="badge-mini {badge_class}">{auto_label}</span></td>
            <td class="col-final">
                <select class="final-status" onchange="onFinalStatusChange(this)">{options}</select>
                <span class="print-only-text"></span>
            </td>
            <td class="col-remark"><textarea class="remark" oninput="scheduleSave()" placeholder="특이사항/예외 사유 입력"></textarea></td>
        </tr>
        <tr class="detail-row">
            <td colspan="6">
                <div class="finding-text"><strong>점검 내용:</strong> {description}</div>
                <div class="finding-text"><strong>점검 및 현황:</strong> {current_setting}</div>
                <div class="finding-text"><strong>판단 기준:</strong> {exception_guide}</div>
                {cmd_block}
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
