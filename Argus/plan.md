# Argus 개선 계획

## 문제 진단

### 근본 원인
`collector.py`의 `fetch_recent_cves()`가 CVEProject/cvelistV5 GitHub 레포의 **커밋 기반**으로 CVE를 수집함.
cve.org가 날짜/시간 형식 표준화 패치를 하면 하루에 ~20,000건의 CVE 파일이 커밋에 포함되지만,
실제 취약점 내용(description, CVSS, affected 등)은 변경되지 않음.

현재 로직은 "어떤 파일이 수정되었는가"만 확인하고, "무엇이 변경되었는가"를 확인하지 않음.
→ 모든 수정된 CVE가 전체 파이프라인(enrichment + AI 분석 + Slack 알림)을 거치며 API 할당량 소진.

---

## Task 1: CVE 콘텐츠 해시 기반 필터링

### 접근 방식: 3단계 방어 레이어

#### Layer 1: 커밋 레벨 사전 필터링 (collector.py)
- GitHub API의 커밋 상세 정보에서 `patch` (diff) 크기를 활용
- **대량 벌크 커밋 감지**: 단일 커밋에 100개 이상 파일이 수정되면 벌크 패치로 간주
- 벌크 커밋의 경우 파일의 `patch` diff를 확인하여 의미있는 변경인지 판별
- 커밋 메시지에 "format", "standardize", "date", "metadata", "batch update" 등 패턴이 있으면 벌크로 분류

#### Layer 2: 콘텐츠 해시 비교 (collector.py + database.py)
- CVE JSON에서 **의미있는 필드만** 추출하여 SHA-256 해시 생성:
  - `description`, `affected` (vendor/product/versions), `metrics` (CVSS), `problemTypes` (CWE), `references`
  - 날짜/시간 필드(`datePublished`, `dateUpdated`, `dateReserved` 등) **제외**
  - 메타데이터 필드(`state`, `assignerOrgId`, `serial` 등) **제외**
- DB에 `content_hash` 필드 추가
- 해시가 동일하면 → 스킵 (메타데이터만 변경된 것)
- 해시가 다르면 → 실제 콘텐츠 변경이므로 전체 파이프라인 진행

#### Layer 3: 스마트 배치 제한 (main.py)
- 한 번의 실행에서 처리할 최대 CVE 수를 설정 (기본 50건)
- 우선순위: 신규 CVE (DB에 없는 것) > 고위험 변경 > 일반 변경
- 할당량 소진 방지를 위한 안전장치

### 수정 파일 및 변경 내용

#### `src/collector.py`
1. `fetch_recent_cves()` → `fetch_recent_cves_smart()` 로 개선
   - 커밋별 파일 수 체크 (벌크 감지)
   - 벌크 커밋은 diff 기반 필터링 적용
   - 경량 사전 검사 (raw JSON만 가져와서 해시 비교)
2. `_compute_content_hash(json_data)` 신규 메서드 추가
   - 의미있는 필드만 정규화하여 해시 생성
3. `_is_bulk_commit(commit_data)` 신규 메서드 추가
   - 벌크 메인테넌스 커밋 감지
4. `_has_meaningful_change(file_info)` 신규 메서드 추가
   - diff에서 의미있는 변경 확인

#### `src/database.py`
1. `get_content_hash(cve_id)` 메서드 추가
2. `update_content_hash(cve_id, hash)` 메서드 추가
3. DB 테이블에 `content_hash` 컬럼 추가 (upsert로 자연 마이그레이션)

#### `src/main.py`
1. `main()` 함수에 스마트 배치 제한 로직 추가
2. CVE 목록을 우선순위별 정렬 후 상위 N건만 처리

#### `src/config.py`
1. `MAX_CVES_PER_RUN` 설정 추가 (기본 50)
2. `BULK_COMMIT_THRESHOLD` 설정 추가 (기본 100)

---

## Task 2: GitHub Pages 대시보드

### 아키텍처 결정

**데이터 소스: 하이브리드 (GitHub Actions에서 JSON 생성)**
- Supabase free tier 제한 걱정 해결: 클라이언트가 직접 Supabase를 호출하지 않음
- GitHub Actions 실행 시 Supabase에서 데이터를 조회하여 JSON 파일로 export
- 이 JSON 파일을 GitHub Pages에 배포
- 고위험 CVE의 상세 리포트는 기존 GitHub Issues 링크로 연결
- 블랙리스트 IP도 동일한 방식으로 JSON export

**기술 스택: 순수 HTML/CSS/JS (빌드 도구 없음)**
- 외부 의존성 최소화: CDN으로 최소한의 라이브러리만 사용
- Jekyll 등 SSG 불필요 - 데이터는 JSON으로 제공되므로 클라이언트 렌더링
- 모바일 반응형 CSS

### 페이지 구조

```
docs/
├── index.html          # 메인 대시보드 (CVE 목록 + 통계)
├── blacklist.html      # 블랙리스트 IP 대시보드
├── css/
│   └── style.css       # 공통 스타일
├── js/
│   ├── app.js          # CVE 대시보드 로직
│   ├── blacklist.js    # 블랙리스트 IP 로직
│   └── common.js       # 공통 유틸리티
└── data/
    ├── cves.json       # CVE 데이터 (Actions에서 생성)
    ├── blacklist.json  # 블랙리스트 IP (Actions에서 생성)
    └── stats.json      # 통계 데이터 (Actions에서 생성)
```

### 대시보드 기능

#### CVE 대시보드 (index.html)
- **통계 카드**: 전체 CVE 수, 고위험 수, KEV 등재 수, 최근 24시간 신규
- **트렌드 차트**: 일별/주별 CVE 발견 추이 (간단한 bar chart)
- **CVE 테이블**: 검색, 필터(심각도/벤더/제품), 정렬
- **심각도 컬러 코딩**: Critical(빨강), High(주황), Medium(노랑), Low(초록)
- **상세 보기**: 클릭 시 모달/확장으로 상세 정보 + GitHub Issue 링크

#### 블랙리스트 IP 대시보드 (blacklist.html)
- **IP 테이블**: 검색, 필터(위험도/카테고리/소스)
- **카테고리별 분류**: 악성 봇, 스캐너, C2 서버 등
- **위험도 표시**: 점수 기반 컬러 코딩

### 수정/신규 파일

#### `src/export_dashboard_data.py` (신규)
- Supabase에서 CVE 데이터 조회 → `docs/data/cves.json` 생성
- 블랙리스트 IP 데이터 → `docs/data/blacklist.json` 생성
- 통계 집계 → `docs/data/stats.json` 생성

#### `docs/` 디렉토리 (신규)
- 위 페이지 구조대로 정적 파일 생성

#### GitHub Actions 워크플로우
- 기존 Argus 실행 후 `export_dashboard_data.py` 실행
- `docs/data/` 디렉토리의 JSON 파일을 커밋/푸시
- GitHub Pages는 `docs/` 디렉토리에서 자동 배포

---

## 구현 순서

1. **DB 스키마 확장** - `content_hash` 필드 추가 (database.py)
2. **콘텐츠 해시 로직** - `_compute_content_hash()` 구현 (collector.py)
3. **벌크 커밋 감지** - `_is_bulk_commit()` 구현 (collector.py)
4. **스마트 CVE 수집** - `fetch_recent_cves()` 개선 (collector.py)
5. **배치 제한 및 우선순위** - main.py 개선
6. **대시보드 데이터 Export** - export_dashboard_data.py
7. **GitHub Pages 프론트엔드** - docs/ 디렉토리
8. **테스트 및 검증**
