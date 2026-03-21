#!/usr/bin/env python3
"""기술적 취약점 가이드 PDF → YAML 파싱 스크립트"""

import fitz
import re
import yaml
import os
from collections import defaultdict

PDF_PATH = os.path.join(os.path.dirname(__file__), '..', 'source-pdf',
    '주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드.pdf')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), '..', '_data')

# 섹션(대분류) 매핑: 코드 접두사 → 섹션 정보
SECTION_MAP = {
    'U': {'id': 'unix', 'name': 'UNIX 서버', 'order': 1},
    'W': {'id': 'windows', 'name': 'Windows 서버', 'order': 2},
    'WEB': {'id': 'web_service', 'name': '웹 서비스', 'order': 3},
    'S': {'id': 'security_device', 'name': '보안 장비', 'order': 4},
    'N': {'id': 'network', 'name': '네트워크 장비', 'order': 5},
    'C': {'id': 'control_system', 'name': '제어시스템', 'order': 6},
    'PC': {'id': 'pc', 'name': 'PC', 'order': 7},
    'D': {'id': 'dbms', 'name': 'DBMS', 'order': 8},
    'M': {'id': 'mobile', 'name': '이동통신', 'order': 9},
    'HV': {'id': 'virtualization', 'name': '가상화 장비', 'order': 10},
    'CA': {'id': 'cloud', 'name': '클라우드', 'order': 11},
}

# 각 항목 코드 접두사와 섹션 이름 매핑 (카테고리 경로에서 사용)
CODE_TO_SECTION_NAME = {
    'U': 'UNIX',
    'W': 'Windows 서버',  # W-xx는 Windows
    'S': '보안 장비',       # S-xx는 보안 장비
    'N': '네트워크 장비',
    'C': '제어시스템',       # C-xx는 제어시스템
    'PC': 'PC',
    'D': 'DBMS',
    'M': '이동통신',
    'WEB': '웹(Web)',
    'HV': '가상화 장비',
    'CA': '클라우드',
}

# 노이즈 라인 필터
NOISE_PATTERNS = [
    r'^\d+\s*$',
    r'한국인터넷진흥원',
    r'주요정보통신기반시설.*가이드',
    r'^\d+\.\s*(Unix|Windows|웹|보안|네트워크|제어|PC|DBMS|이동|가상|클라우드)',
]


def is_noise(line):
    for p in NOISE_PATTERNS:
        if re.search(p, line):
            return True
    return False


def find_all_detail_items(doc):
    """모든 상세 항목의 (코드, 중요도, 시작페이지) 목록을 반환."""
    items = []
    # 기술적 가이드 코드 패턴: U-01, W-01, S-01, N-01, C-01, PC-01, D-01, M-01, WEB-01, HV-01, CA-01
    code_pattern = re.compile(r'^((?:PC|WEB|HV|CA|U|W|S|N|C|D|M)-\d+)\s*$', re.MULTILINE)
    severity_pattern = re.compile(r'^\((상|중|하)\)\s*$', re.MULTILINE)

    for pg in range(doc.page_count):
        text = doc[pg].get_text()
        codes_on_page = code_pattern.findall(text)

        # 목차 테이블 페이지는 항목이 많이 나열됨 (3개 이상이면 목차)
        if len(codes_on_page) > 2:
            continue

        for code in codes_on_page:
            # 중요도 찾기
            severity = None
            # 코드 다음 줄에 (상), (중), (하)가 있음
            sev_match = re.search(rf'{re.escape(code)}\s*\n\((상|중|하)\)', text)
            if sev_match:
                severity = sev_match.group(1)

            items.append((code, severity, pg))

    return items


def extract_item_text(doc, items, idx):
    """항목의 전체 텍스트를 추출."""
    code, sev, start_pg = items[idx]
    if idx + 1 < len(items):
        end_pg = items[idx + 1][2]
    else:
        end_pg = min(start_pg + 5, doc.page_count - 1)

    text = ''
    for pg in range(start_pg, min(end_pg + 1, doc.page_count)):
        text += doc[pg].get_text() + '\n'

    # 다음 항목 코드 이전까지만
    if idx + 1 < len(items):
        next_code = items[idx + 1][0]
        next_pattern = rf'\n{re.escape(next_code)}\s*\n'
        next_match = re.search(next_pattern, text)
        if next_match:
            text = text[:next_match.start()]

    return text


def parse_technical_item(text, code, severity):
    """기술적 항목 텍스트를 파싱."""
    result = {
        'code': code,
        'severity': severity,
    }

    # 섹션 정보 (코드 접두사에서)
    prefix = code.rsplit('-', 1)[0]
    if prefix in SECTION_MAP:
        result['section_id'] = SECTION_MAP[prefix]['id']
        result['section_name'] = SECTION_MAP[prefix]['name']
    else:
        result['section_id'] = prefix.lower()
        result['section_name'] = prefix

    # 카테고리 경로: "UNIX > 1. 계정 관리" 등
    cat_pattern = rf'{re.escape(code)}\s*\n(?:\((상|중|하)\)\s*\n)?(.+?)\s*>\s*(\d+\.\s*[^\n]+)\n(.+?)(?:\n|$)'
    cat_match = re.search(cat_pattern, text)
    if cat_match:
        result['category'] = cat_match.group(3).strip()
        result['title'] = cat_match.group(4).strip()
    else:
        # 대체 패턴
        title_lines = text.split('\n')
        for i, line in enumerate(title_lines):
            if line.strip() == code:
                # 중요도 건너뛰고 카테고리 > 서브카테고리 패턴 찾기
                for j in range(i+1, min(i+5, len(title_lines))):
                    if '>' in title_lines[j]:
                        parts = title_lines[j].split('>')
                        result['category'] = parts[-1].strip()
                        if j+1 < len(title_lines):
                            result['title'] = title_lines[j+1].strip()
                        break
                break
        if 'title' not in result:
            result['title'] = 'TBD'

    # 개요 섹션 내 필드들
    fields_map = {
        '점검 내용': 'check_content',
        '점검 목적': 'check_purpose',
        '보안 위협': 'security_threat',
        '참고': 'reference',
    }

    for label, key in fields_map.items():
        pattern = rf'{label}\s*\n(.*?)(?=점검 내용|점검 목적|보안 위협|참고\s*\n|점검 대상|대상\s*\n|판단 기준|$)'
        match = re.search(pattern, text, re.DOTALL)
        if match:
            val = match.group(1).strip()
            # 노이즈 제거
            lines = [l.strip() for l in val.split('\n') if l.strip() and not is_noise(l.strip())]
            if lines:
                result[key] = '\n'.join(lines)

    # 점검 대상 및 판단 기준
    target_match = re.search(r'대상\s*\n(.+?)(?:\n|$)', text)
    if target_match:
        result['target'] = target_match.group(1).strip()

    # 판단 기준 (양호/취약)
    good_match = re.search(r'양호\s*[:：]\s*(.+?)(?:\n|$)', text)
    bad_match = re.search(r'취약\s*[:：]\s*(.+?)(?:\n|$)', text)
    if good_match:
        result['good_criteria'] = good_match.group(1).strip()
    if bad_match:
        result['bad_criteria'] = bad_match.group(1).strip()

    # 조치 방법
    action_match = re.search(r'조치 방법\s*\n(.*?)(?=조치 시 영향|점검 및 조치|$)', text, re.DOTALL)
    if action_match:
        val = action_match.group(1).strip()
        lines = [l.strip() for l in val.split('\n') if l.strip() and not is_noise(l.strip())]
        if lines:
            result['action_method'] = '\n'.join(lines)

    # 조치 시 영향
    impact_match = re.search(r'조치 시 영향\s*\n(.*?)(?=점검 및 조치|$)', text, re.DOTALL)
    if impact_match:
        val = impact_match.group(1).strip()
        lines = [l.strip() for l in val.split('\n') if l.strip() and not is_noise(l.strip())]
        if lines:
            result['action_impact'] = '\n'.join(lines)

    # 점검 및 조치 사례 (전체 텍스트로 보존)
    case_match = re.search(r'점검 및 조치 사례\s*\n(.*)', text, re.DOTALL)
    if case_match:
        val = case_match.group(1).strip()
        lines = [l.strip() for l in val.split('\n') if l.strip() and not is_noise(l.strip())]
        if lines:
            result['remediation_cases'] = '\n'.join(lines)

    return result


def main():
    doc = fitz.open(PDF_PATH)

    items = find_all_detail_items(doc)
    print(f"기술적 항목 발견: {len(items)}개")

    # 코드별 그룹
    by_prefix = defaultdict(list)
    for code, sev, pg in items:
        prefix = code.rsplit('-', 1)[0]
        by_prefix[prefix].append((code, sev, pg))

    for prefix in sorted(by_prefix.keys()):
        codes = by_prefix[prefix]
        print(f"  {prefix}: {len(codes)}개 ({codes[0][0]}~{codes[-1][0]})")

    all_parsed = []
    for i, (code, sev, pg) in enumerate(items):
        text = extract_item_text(doc, items, i)
        parsed = parse_technical_item(text, code, sev)
        parsed['page'] = pg + 1  # 1-indexed
        all_parsed.append(parsed)

        if i % 50 == 0:
            print(f"  파싱 중... {i+1}/{len(items)} ({code})")

    doc.close()

    print(f"파싱 완료: {len(all_parsed)}개")

    # YAML 출력
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    class KoreanDumper(yaml.SafeDumper):
        pass

    def str_representer(dumper, data):
        if '\n' in data:
            return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
        return dumper.represent_scalar('tag:yaml.org,2002:str', data)

    KoreanDumper.add_representer(str, str_representer)

    yaml_path = os.path.join(OUTPUT_DIR, 'technical_items.yml')
    with open(yaml_path, 'w', encoding='utf-8') as f:
        yaml.dump(all_parsed, f, allow_unicode=True, default_flow_style=False,
                  Dumper=KoreanDumper, sort_keys=False)

    print(f"총 {len(all_parsed)}개 항목 → {yaml_path}")

    # 카테고리 목록
    categories = {}
    for item in all_parsed:
        section_id = item.get('section_id', 'unknown')
        cat_name = item.get('category', 'TBD')
        key = f"{section_id}_{cat_name}"
        if key not in categories:
            categories[key] = {
                'section_id': section_id,
                'section_name': item.get('section_name', 'TBD'),
                'category': cat_name,
                'items': []
            }
        categories[key]['items'].append(item['code'])

    cat_list = []
    for key, cat_data in categories.items():
        cat_list.append({
            'section_id': cat_data['section_id'],
            'section_name': cat_data['section_name'],
            'category': cat_data['category'],
            'count': len(cat_data['items']),
            'codes': cat_data['items']
        })

    cat_path = os.path.join(OUTPUT_DIR, 'technical_categories.yml')
    with open(cat_path, 'w', encoding='utf-8') as f:
        yaml.dump(cat_list, f, allow_unicode=True, default_flow_style=False,
                  Dumper=KoreanDumper, sort_keys=False)

    print(f"카테고리 {len(cat_list)}개 → {cat_path}")


if __name__ == '__main__':
    main()
