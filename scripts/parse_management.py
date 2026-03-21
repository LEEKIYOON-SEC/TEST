#!/usr/bin/env python3
"""관리·물리적 취약점 가이드 PDF → YAML 파싱 스크립트"""

import fitz
import re
import yaml
import sys
import os

PDF_PATH = os.path.join(os.path.dirname(__file__), '..', 'source-pdf',
    '주요정보통신기반시설 관리·물리적 취약점 분석·평가 방법 안내서.pdf')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '_data')

# 카테고리 매핑 (관리적 분야)
ADMIN_CATEGORIES = {
    '1. 정보보호 정책': {'id': 'policy', 'name': '정보보호 정책'},
    '2. 정보보호 조직': {'id': 'organization', 'name': '정보보호 조직'},
    '3. 자산분류': {'id': 'asset', 'name': '자산분류'},
    '4. 위험관리': {'id': 'risk', 'name': '위험관리'},
    '5. 감사': {'id': 'audit', 'name': '감사'},
    '6. 인적보안': {'id': 'hr_security', 'name': '인적보안'},
    '7. 외부자보안': {'id': 'external_security', 'name': '외부자보안'},
    '8. 교육 및 훈련': {'id': 'training', 'name': '교육 및 훈련'},
    '9. 인증 및 권한관리': {'id': 'auth', 'name': '인증 및 권한관리'},
    '10. 접근통제': {'id': 'access_control', 'name': '접근통제'},
    '11. 운영관리': {'id': 'operation', 'name': '운영관리'},
    '12. 보안관리': {'id': 'security_mgmt', 'name': '보안관리'},
    '13. 사고대응': {'id': 'incident', 'name': '사고대응'},
    '14. 업무 연속성': {'id': 'continuity', 'name': '업무 연속성'},
}

PHYSICAL_CATEGORIES = {
    '1. 물리보안': {'id': 'physical_security', 'name': '물리보안'},
}


def find_detail_items(doc, start_page, end_page, code_prefix):
    """상세 항목의 시작 위치(페이지, 코드)를 찾는다."""
    items = []
    for pg in range(start_page, end_page):
        text = doc[pg].get_text()
        # 항목 코드가 단독 줄에 있는 패턴 (목차 테이블이 아닌 상세 페이지)
        # 상세 페이지에서는 코드 뒤에 카테고리 경로가 따라옴
        pattern = rf'^({code_prefix}-\d+)\s*$'
        for match in re.finditer(pattern, text, re.MULTILINE):
            code = match.group(1)
            # 목차 테이블 페이지인지 확인 (같은 페이지에 여러 코드가 있으면 목차)
            all_codes = re.findall(pattern, text, re.MULTILINE)
            if len(all_codes) <= 2:  # 상세 페이지는 보통 1~2개 항목
                items.append((code, pg))
    return items


def extract_item_text(doc, items, idx):
    """항목의 전체 텍스트를 추출한다."""
    code, start_pg = items[idx]
    if idx + 1 < len(items):
        end_pg = items[idx + 1][1]
    else:
        end_pg = start_pg + 3  # 마지막 항목은 최대 3페이지

    text = ''
    for pg in range(start_pg, min(end_pg + 1, doc.page_count)):
        page_text = doc[pg].get_text()
        text += page_text + '\n'

    # 다음 항목의 코드 이전까지만 추출
    if idx + 1 < len(items):
        next_code = items[idx + 1][0]
        # 다음 항목 코드 위치를 찾아 거기까지만 사용
        next_pattern = rf'\n{re.escape(next_code)}\s*\n'
        next_match = re.search(next_pattern, text)
        if next_match:
            text = text[:next_match.start()]

    return text


def parse_category(text, code):
    """카테고리 경로를 파싱한다."""
    if code.startswith('P-'):
        # 물리적 분야
        pattern = r'(?:관리적 분야|물리적 분야)\s*>\s*(\d+\.\s*\S+)'
        # P 항목은 "관리적 분야 > 1. 물리보안" 형태로 나옴 (PDF 내)
        match = re.search(pattern, text)
        if match:
            cat_key = match.group(1).strip()
            for key, val in PHYSICAL_CATEGORIES.items():
                if key in cat_key or cat_key in key:
                    return 'physical', val
        return 'physical', {'id': 'physical_security', 'name': '물리보안'}
    else:
        # 관리적 분야
        pattern = r'관리적 분야\s*>\s*(\d+\.\s*[^\n]+)'
        match = re.search(pattern, text)
        if match:
            cat_key = match.group(1).strip()
            for key, val in ADMIN_CATEGORIES.items():
                if cat_key.startswith(key.split('.')[0] + '.'):
                    return 'admin', val
                if key in cat_key:
                    return 'admin', val
        return 'admin', {'id': 'unknown', 'name': 'TBD'}


def parse_sections(text, code):
    """항목 텍스트에서 각 섹션을 파싱한다."""
    result = {'code': code}

    # 제목: 코드 다음 줄의 카테고리 경로 다음 줄
    # 패턴: code\n카테고리경로\n제목
    title_pattern = rf'{re.escape(code)}\s*\n(?:관리적 분야|물리적 분야)\s*>\s*[^\n]+\n(.+?)(?:\n|$)'
    title_match = re.search(title_pattern, text)
    if title_match:
        result['title'] = title_match.group(1).strip()
    else:
        result['title'] = 'TBD'

    # 카테고리
    field, cat = parse_category(text, code)
    result['field'] = field
    result['category_id'] = cat['id']
    result['category_name'] = cat['name']

    # 관련 조직
    org_match = re.search(r'관련 조직\s*\n(.+?)(?:\n|세부 설명)', text, re.DOTALL)
    if org_match:
        result['related_org'] = org_match.group(1).strip()

    # 세부 설명
    detail_match = re.search(r'세부 설명\s*\n(.*?)(?=고려 사항|관계 법규|확인 대상)', text, re.DOTALL)
    if detail_match:
        lines = []
        for line in detail_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not re.match(r'^\d+$', line) and '주요정보통신기반시설' not in line and '한국인터넷진흥원' not in line:
                line = re.sub(r'^§\s*', '', line)
                if line:
                    lines.append(line)
        result['description'] = lines

    # 고려 사항
    consider_match = re.search(r'고려 사항\s*\n(.*?)(?=관계 법규|확인 대상)', text, re.DOTALL)
    if consider_match:
        lines = []
        for line in consider_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not re.match(r'^\d+$', line) and '주요정보통신기반시설' not in line and '한국인터넷진흥원' not in line:
                line = re.sub(r'^§\s*', '', line)
                if line:
                    lines.append(line)
        result['considerations'] = lines

    # 관계 법규
    law_match = re.search(r'관계 법규\s*\n(.*?)(?=확인 대상|$)', text, re.DOTALL)
    if law_match:
        law_text = law_match.group(1).strip()
        laws = {}
        current_group = None
        for line in law_text.split('\n'):
            line = line.strip()
            if not line or re.match(r'^\d+$', line) or '주요정보통신기반시설' in line or '한국인터넷진흥원' in line:
                continue
            if line in ('공통', '공공기관', '금융회사', 'ICT기업'):
                current_group = line
                laws[current_group] = []
            elif current_group:
                laws[current_group].append(line)
        if laws:
            result['related_laws'] = laws

    # 확인 대상(예시)
    check_match = re.search(r'확인 대상\(예시\)\s*\n(.*?)(?=$|\n[A-Z]-\d+)', text, re.DOTALL)
    if check_match:
        lines = []
        for line in check_match.group(1).strip().split('\n'):
            line = line.strip()
            if line and not re.match(r'^\d+$', line) and '주요정보통신기반시설' not in line and '한국인터넷진흥원' not in line:
                line = re.sub(r'^☐\s*', '', line)
                if line:
                    lines.append(line)
        result['check_targets'] = lines

    return result


def main():
    doc = fitz.open(PDF_PATH)

    # 관리적 항목 (A-1 ~ A-118): 상세는 p.17(idx 16) ~ p.214(idx 213)
    admin_items = find_detail_items(doc, 16, 214, 'A')
    # 물리적 항목 (P-1 ~ P-18): 상세는 p.217(idx 216) ~ p.242(idx 241)
    physical_items = find_detail_items(doc, 216, 243, 'P')

    print(f"관리적 항목 발견: {len(admin_items)}개")
    print(f"물리적 항목 발견: {len(physical_items)}개")

    all_parsed = []

    for items_list in [admin_items, physical_items]:
        for i, (code, pg) in enumerate(items_list):
            text = extract_item_text(doc, items_list, i)
            parsed = parse_sections(text, code)
            parsed['page'] = pg + 1  # 1-indexed
            all_parsed.append(parsed)
            print(f"  파싱 완료: {code} - {parsed.get('title', 'TBD')[:40]}")

    doc.close()

    # YAML 출력
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 관리적 항목
    admin_data = [item for item in all_parsed if item['field'] == 'admin']
    # 물리적 항목
    physical_data = [item for item in all_parsed if item['field'] == 'physical']

    # 카테고리별 그룹화
    categories = {}
    for item in all_parsed:
        cat_id = item['category_id']
        if cat_id not in categories:
            categories[cat_id] = {
                'id': cat_id,
                'name': item['category_name'],
                'field': item['field'],
                'items': []
            }
        categories[cat_id]['items'].append(item)

    # YAML 저장 - 전체 항목
    yaml_path = os.path.join(OUTPUT_DIR, 'management_items.yml')

    # PyYAML 한국어 출력 설정
    class KoreanDumper(yaml.SafeDumper):
        pass

    def str_representer(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    KoreanDumper.add_representer(str, str_representer)

    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(all_parsed, f, allow_unicode=True, default_flow_style=False,
                  Dumper=KoreanDumper, sort_keys=False)

    print(f"\n총 {len(all_parsed)}개 항목 → {yaml_path}")

    # 카테고리 목록도 저장
    cat_list = []
    for cat_id, cat_data in categories.items():
        cat_list.append({
            'id': cat_data['id'],
            'name': cat_data['name'],
            'field': cat_data['field'],
            'count': len(cat_data['items']),
            'codes': [item['code'] for item in cat_data['items']]
        })

    cat_path = os.path.join(OUTPUT_DIR, 'management_categories.yml')
    with open(cat_path, 'w', encoding='utf-8') as f:
        yaml.dump(cat_list, f, allow_unicode=True, default_flow_style=False,
                  Dumper=KoreanDumper, sort_keys=False)

    print(f"카테고리 {len(cat_list)}개 → {cat_path}")


if __name__ == '__main__':
    main()
