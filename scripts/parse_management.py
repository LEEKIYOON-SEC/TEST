#!/usr/bin/env python3
"""관리·물리 PDF에서 A-항목 상세를 추출하는 스크립트"""
import fitz
import re
import yaml
import sys

PDF_PATH = "source-pdf/주요정보통신기반시설 관리·물리적 취약점 분석·평가 방법 안내서.pdf"

# 도메인 정의
DOMAINS = {
    6: {"name": "6. 인적보안", "items": list(range(21, 27))},
    7: {"name": "7. 외부자보안", "items": list(range(27, 34))},
    8: {"name": "8. 교육 및 훈련", "items": list(range(34, 39))},
    9: {"name": "9. 인증 및 권한관리", "items": list(range(39, 43))},
    10: {"name": "10. 접근통제", "items": list(range(43, 58))},
    11: {"name": "11. 운영관리", "items": list(range(58, 73))},
    12: {"name": "12. 보안관리", "items": list(range(73, 104))},
    13: {"name": "13. 사고대응", "items": list(range(104, 114))},
    14: {"name": "14. 업무연속성", "items": list(range(114, 119))},
}

def find_item_pages(doc):
    """각 A-N 항목이 시작되는 페이지 인덱스를 찾는다"""
    item_pages = {}
    for i in range(16, len(doc)):
        text = doc[i].get_text()
        # A-N\n 패턴으로 항목 시작 찾기 (상세 페이지에서)
        for m in re.finditer(r'\nA-(\d+)\n', text):
            num = int(m.group(1))
            if num not in item_pages:
                # 목차가 아닌 상세 페이지인지 확인 (세부 설명이 있는지)
                if '세부 설명' in text or '관련 조직' in text:
                    item_pages[num] = i
    return item_pages

def extract_item_text(doc, item_num, item_pages):
    """항목의 전체 텍스트를 추출 (시작 페이지 + 다음 페이지까지)"""
    if item_num not in item_pages:
        return ""
    start_page = item_pages[item_num]
    texts = [doc[start_page].get_text()]
    # 다음 페이지도 포함 (법규/확인대상이 다음 페이지에 있을 수 있음)
    if start_page + 1 < len(doc):
        next_text = doc[start_page + 1].get_text()
        # 다음 페이지가 다른 항목의 시작이 아니면 포함
        if not re.search(r'\nA-\d+\n.*관리적 분야', next_text):
            texts.append(next_text)
        elif '관계 법규' in next_text or '확인 대상' in next_text or '확인대상' in next_text:
            texts.append(next_text)
    return '\n'.join(texts)

def parse_item(text, item_num):
    """텍스트에서 항목 정보를 파싱"""
    result = {"id": f"A-{item_num}"}

    # 제목 추출
    title_match = re.search(rf'A-{item_num}\n관리적 분야 > \d+\. .+?\n(.+?)(?:\n관련 조직|\n관련조직)', text, re.DOTALL)
    if title_match:
        result["title"] = title_match.group(1).strip().replace('\n', ' ')
    else:
        result["title"] = "TBD"

    # 관련 조직
    org_match = re.search(r'관련 ?조직\n(.+?)\n세부 설명', text, re.DOTALL)
    if org_match:
        result["related_org"] = org_match.group(1).strip()
    else:
        result["related_org"] = "TBD"

    # 세부 설명
    desc_match = re.search(r'세부 설명\n(.*?)(?:\n고려 사항|\n관계 법규)', text, re.DOTALL)
    descriptions = []
    if desc_match:
        for line in desc_match.group(1).strip().split('\n'):
            line = line.strip()
            if line.startswith('§'):
                line = line[1:].strip()
            if line and not line.startswith('[그림'):
                descriptions.append(line)
    result["description"] = descriptions

    # 고려 사항
    cons_match = re.search(r'고려 사항\n(.*?)(?:\n관계 법규|\n\[그림|\n확인 대상|\n확인대상)', text, re.DOTALL)
    considerations = []
    if cons_match:
        for line in cons_match.group(1).strip().split('\n'):
            line = line.strip()
            if line.startswith('§'):
                line = line[1:].strip()
            if line.startswith('※'):
                considerations.append(line)
            elif line and not line.startswith('-') and not line.startswith('[그림') and len(line) > 5:
                considerations.append(line)
    result["considerations"] = considerations

    # 관계 법규
    laws = {"common": [], "public": [], "finance": [], "ict": []}
    law_match = re.search(r'관계 법규\n(.*?)(?:\n확인 대상|\n확인대상)', text, re.DOTALL)
    if law_match:
        law_text = law_match.group(1)
        current_sector = None
        for line in law_text.strip().split('\n'):
            line = line.strip()
            if line in ['공통', '공통\n']:
                current_sector = 'common'
            elif line in ['공공기관', '공공기관\n']:
                current_sector = 'public'
            elif line in ['금융회사', '금융회사\n']:
                current_sector = 'finance'
            elif line.startswith('ICT') or line == 'ICT기업':
                current_sector = 'ict'
            elif current_sector and line and not line.startswith('번호') and not line.startswith('취약점'):
                laws[current_sector].append(line)
    result["laws"] = laws

    # 확인 대상
    checklist = []
    check_match = re.search(r'(?:확인 대상|확인대상)\(예시\)\n(.*?)$', text, re.DOTALL)
    if check_match:
        for line in check_match.group(1).strip().split('\n'):
            line = line.strip()
            if line.startswith('☐'):
                checklist.append(line[1:].strip())
    result["checklist"] = checklist

    return result

def main():
    doc = fitz.open(PDF_PATH)
    item_pages = find_item_pages(doc)

    domain_num = int(sys.argv[1]) if len(sys.argv) > 1 else 6

    if domain_num not in DOMAINS:
        print(f"도메인 {domain_num} 없음")
        return

    domain = DOMAINS[domain_num]
    items = []

    for item_num in domain["items"]:
        text = extract_item_text(doc, item_num, item_pages)
        if text:
            parsed = parse_item(text, item_num)
            parsed["domain"] = domain["name"]
            items.append(parsed)
            print(f"  A-{item_num}: {parsed['title'][:50]}... (설명{len(parsed['description'])} 고려{len(parsed['considerations'])} 법규{sum(len(v) for v in parsed['laws'].values())} 확인{len(parsed['checklist'])})")
        else:
            print(f"  A-{item_num}: 페이지 미발견!")

    # YAML 출력
    output = {
        "domain": domain["name"],
        "domain_number": domain_num,
        "category": "관리적 분야",
        "items": items
    }

    filename = f"_data/management/{domain_num:02d}_{domain['name'].split('. ')[1].replace(' ', '')}.yml"
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"\n저장: {filename}")

if __name__ == "__main__":
    main()
