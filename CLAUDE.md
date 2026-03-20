# CLAUDE.md — K-SecGuide 프로젝트 지침

## 프로젝트 소개
주요정보통신기반시설 취약점 분석·평가 가이드(관리/물리/기술) 웹 레퍼런스 사이트.
Jekyll + GitHub Pages로 구축. 보안 실무자가 499개 점검항목과 관계법규를 쉽게 검색·참조할 수 있게 함.

## 절대 원칙
1. **공공누리 제4유형 준수**: 출처표시+상업적이용금지+변경금지. 모든 페이지 Footer에 표기.
2. **환각 금지**: PDF 원문에 없는 내용 절대 추가하지 않음. 불확실하면 TBD로 남김.
3. **원문 변경 금지**: 오탈자도 수정하지 않음. PDF 텍스트 그대로 사용.
4. **단계적 작업**: 한 번에 전체 만들지 않음. 단계 완료 후 사용자 검수.

## 개발 환경
- 사용자는 로컬 개발환경이 없음. 브라우저(github.dev)만 사용.
- Claude Code가 GitHub 레포에 브랜치를 생성하고 직접 코드를 작성·커밋·푸시한다.
- 사용자가 GitHub에서 브랜치 확인 후 main에 merge한다.
- PDF 원본은 레포의 `source-pdf/` 폴더에 있음. Claude Code는 여기서 읽는다.
- Jekyll 미리보기 없음 — merge 후 GitHub Pages 자동 빌드로 확인.

## 기술 스택
- Jekyll + just-the-docs 테마
- 데이터: _data/ 폴더 YAML
- GitHub Pages 배포
- Python + pymupdf(fitz) (PDF 파싱용)

## 파일 구조
- `source-pdf/` — 원본 PDF (레포에 포함, Claude Code가 파싱에 사용)
  - 취약점 가이드 PDF 2개 + `laws/` 하위에 법령 PDF 14개
- `_data/` — 파싱된 YAML 데이터
- `docs/` — Markdown 페이지
- `scripts/` — PDF 파싱 스크립트 (Jekyll 빌드에 미포함)

## 브랜치 전략
- 각 Step마다 별도 브랜치 생성: `step-1-init`, `step-2-parse`, ...
- 사용자가 확인 후 main에 merge
- main 브랜치 push 시 GitHub Pages 자동 배포

## 커밋 컨벤션
- `feat: Step N - 설명` (새 기능)
- `fix: 수정 내용` (버그 수정)
- `data: 데이터 업데이트 내용` (YAML 데이터 변경)

## 주의사항
- 한국어 인코딩 주의 (UTF-8)
- 법령 URL: https://www.law.go.kr/법령/[법령명] 형식
- 법령 데이터는 사용자가 별도 제공한 것만 사용. API 호출하지 않음.
- 기술↔관리 크로스레퍼런스는 Claude가 양쪽 PDF 텍스트 근거로 초안 생성 → 각 매핑에 근거+확신도+매핑유형 기록 → 사용자 검수 후 확정. 확신도 "낮음"은 사이트에 바로 반영하지 않음.
