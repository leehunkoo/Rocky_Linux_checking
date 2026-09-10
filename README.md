# Rocky Linux Vulnerability Scanner (KISA 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드 기반)

2026년 KISA(한국인터넷진흥원) 「주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드」의 Unix/Linux 항목(U-01 ~ U-67)을 기준으로, **Rocky Linux / RHEL(Red Hat Enterprise Linux 8, 9) 계열** 서버를 자동 점검하는 전문 보안 진단 도구입니다.

> ⚠️ **주의사항**: 이 도구는 실제 운영 서버에서 점검 명령을 실행합니다. 반드시 아래 [주의사항](#주의사항)을 먼저 확인하시고, 운영 환경에 적용하기 전 테스트 환경에서 검증하시기 바랍니다.

---

## 📌 주요 특징

- **U-01 ~ U-67 전 항목 자동 진단**: 계정 관리, 파일/디렉터리 권한, 서비스 관리, 패치 및 로그 관리 등 총 67개 KISA 점검 항목 완전 구현
- **Rocky Linux / RHEL 아키텍처 완벽 대응**:
  - 패키지 관리: `dnf` 및 `rpm` 기반 패키지 검증 (`rpm -qf`) 및 조치 스크립트 제공
  - PAM 및 계정 인증: Rocky Linux 표준 PAM 구성(`/etc/pam.d/system-auth`, `/etc/pam.d/password-auth`), `authselect`, `/etc/security/faillock.conf`, `/etc/security/pwquality.conf` 대응
  - 관리자 권한 및 그룹: Rocky Linux의 기본 관리자 그룹 `wheel` 및 `pam_wheel.so` su 제한 점검
  - 방화벽: `firewalld`(`firewall-cmd`), `nftables`, `iptables` 다중 보안 스택 탐지
  - 시간 동기화: RHEL/Rocky 표준 `chronyd.service` 및 `/etc/chrony.conf` 점검
  - 서비스 데몬 및 설정 경로: BIND(`named.service`, `/etc/named.conf`), vsftpd(`/etc/vsftpd/vsftpd.conf`), OpenSSH(`sshd.service`, `/etc/ssh/sshd_config.d/*.conf`) 등 RHEL 표준 경로 완벽 적용
  - 시스템 로깅: Rocky Linux 표준 로그 시설(`/var/log/messages`, `/var/log/secure`, `/var/log/maillog`, `/var/log/cron`) 점검
- **오탐(False Positive) 방지**: 컨테이너 가상 파일시스템(Docker, Podman overlayfs), 특수 파일시스템(/proc, /sys, /dev), 시스템 예약 계정(UID < 1000) 등 예외 처리 로직 내장
- **안전한 조치 가이드**: 서비스 중단 및 설정 파괴 위험이 있는 항목은 일방적 자동 변경이 아닌 주석과 안전한 권고 조치 명령어(`remediation_cmd`) 제공
- **듀얼 리포트 시스템**:
  1. `report_result.html`: 대시보드형 인터랙티브 웹 리포트 (카테고리/결과별 필터, 키워드 검색, 조치 명령어 원클릭 복사)
  2. `final_report_result.html`: 인쇄/결재용 최종 보안 점검 보고서 (표지, 결재란, 항목별 결과 브라우저 상 수기 편집, `localStorage` 자동 임시저장, JSON 내보내기/불러오기)

---

## 🛠️ 요구 사항 및 호환성

- **OS**: Rocky Linux 8.x / 9.x (RHEL, AlmaLinux, CentOS Stream 8/9 호환)
- **Python**: Python 3.6 이상 (Python 표준 라이브러리만 사용하므로 별도 pip 패키지 설치 불필요)
- **권한**: `root` 또는 `sudo` 권한 권장 (일부 보안 설정 파일 및 `/etc/shadow`, PAM 설정 등은 root 권한이 없을 경우 수동 점검(`Manual Check`)으로 분류될 수 있습니다.)

---

## 🚀 사용법

```bash
# 1. 저장소 복제 및 이동
git clone https://github.com/leehunkoo/Rocky_Linux_checking.git
cd Rocky_Linux_checking

# 2. 보안 점검 실행 (가급적 root/sudo 권한으로 실행)
sudo python3 main.py
```

### 점검 결과 확인

점검이 완료되면 작업 디렉터리에 다음 두 리포트 파일이 생성됩니다:

1. **`report_result.html`**:
   - 웹 브라우저로 열어 전체 점검 통계, 취약 항목 목록, 상세 로그 및 조치 명령어를 직관적으로 확인합니다.
2. **`final_report_result.html`**:
   - 실무 감사 및 결재용 A4 규격 인쇄 보고서입니다.
   - 브라우저 상에서 담당자 의견, 예외 사유 입력 및 판정 결과(양호/취약/해당없음)를 직접 수정한 후 인쇄(PDF 저장)할 수 있습니다.

> 🔒 **보안 안내**: 생성된 리포트 파일에는 시스템의 계정명, 파일 경로, 설치 소프트웨어 정보 등 민감한 시스템 정보가 포함될 수 있으므로, 원격 저장소에 커밋하거나 외부에 무단 반출되지 않도록 유의하시기 바랍니다.

---

## 📂 프로젝트 구조

```
Rocky_checking/
├── main.py                     # 모듈 자동 로드, 진단 오케스트레이션 및 보고서 렌더링
├── config.json                 # 점검 설정 및 임계치 정의
├── modules/                    # U-01 ~ U-67 점검 모듈
│   ├── __init__.py
│   ├── U_01_root_remote_login.py
│   ├── U_02_password_complexity.py
│   ├── U_03_account_lockout.py
│   └── ... (총 67개 점검 모듈)
├── templates/
│   ├── report.html             # 대시보드형 인터랙티브 리포트 템플릿
│   └── final_report.html       # 인쇄/결재용 최종 보고서 템플릿
├── 주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf
├── LICENSE
└── README.md
```

---

## ⚠️ 주의사항

1. **조치 명령어 사전 검증**:
   각 점검 항목에서 제공하는 조치 명령어(`remediation_cmd`)는 운영 환경에 따라 영향도가 다를 수 있습니다. 운영 중인 핵심 서비스에 적용하기 전 반드시 테스트 환경에서 사전 검증하십시오.
2. **SUID/SGID 및 미식별 파일 조치**:
   시스템 바이너리(예: `passwd`, `sudo`, `su`, `/usr/libexec/*`)의 권한을 무차별 해제할 경우 시스템 정상 동작이 불가능해질 수 있으므로 주석 안내에 따라 신중히 검토 후 조치하십시오.

---

## 📄 라이선스

본 프로젝트의 라이선스는 [LICENSE](./LICENSE) 파일을 참고하십시오.

## 🛡️ 면책 조항 (Disclaimer)

본 도구는 보안 점검 및 가이드 준수 진단을 지원하기 위한 목적의 참고용 도구이며, 실제 보안 조치 및 시스템 변경에 대한 최종 책임은 사용자 및 시스템 운영 관리자에게 있습니다.
