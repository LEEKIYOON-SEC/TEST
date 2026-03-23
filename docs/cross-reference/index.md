---
layout: default
title: 크로스레퍼런스
nav_order: 5
has_children: false
permalink: /cross-reference/
---

# 크로스레퍼런스

관리적 점검항목과 기술적 점검항목(UNIX/Windows/Web) 간의 매핑 현황입니다.

각 관리 항목의 상세 페이지에서 **관련 기술 항목** 섹션을 통해 직접 확인할 수 있습니다.

---

## 매핑 현황

<table>
  <thead>
    <tr><th>확신도</th><th>관리 항목 수</th><th>기술 매핑 수</th><th>상태</th></tr>
  </thead>
  <tbody>
    <tr>
      <td><span class="mapping-type mapping-type-direct">높음</span></td>
      <td>{{ site.data.cross_ref_confirmed.mappings.size }}개</td>
      <td>{% assign total_confirmed = 0 %}{% for m in site.data.cross_ref_confirmed.mappings %}{% assign total_confirmed = total_confirmed | plus: m.tech_ids.size %}{% endfor %}{{ total_confirmed }}개</td>
      <td>확인 완료 — 각 항목에 표시</td>
    </tr>
    <tr>
      <td><span class="mapping-type mapping-type-related">중간</span></td>
      <td>{{ site.data.cross_ref_review.mappings.size }}개</td>
      <td>{% assign total_review = 0 %}{% for m in site.data.cross_ref_review.mappings %}{% assign total_review = total_review | plus: m.tech_ids.size %}{% endfor %}{{ total_review }}개</td>
      <td>검토 필요 — 각 항목에 (검토중) 표시</td>
    </tr>
    <tr>
      <td>낮음</td>
      <td>{{ site.data.cross_ref_uncertain.mappings.size }}개</td>
      <td>{% assign total_uncertain = 0 %}{% for m in site.data.cross_ref_uncertain.mappings %}{% assign total_uncertain = total_uncertain | plus: m.tech_ids.size %}{% endfor %}{{ total_uncertain }}개</td>
      <td>미반영 — 간접적 연관만 존재</td>
    </tr>
  </tbody>
</table>

---

## 매핑된 관리 항목 목록

### 확인 완료 (높음)

{% for mapping in site.data.cross_ref_confirmed.mappings %}
- **{{ mapping.admin_id }}** {{ mapping.admin_title | xml_escape }} → {{ mapping.tech_ids | map: "id" | join: ", " }}
{% endfor %}

### 검토 필요 (중간)

{% for mapping in site.data.cross_ref_review.mappings %}
- **{{ mapping.admin_id }}** {{ mapping.admin_title | xml_escape }} → {{ mapping.tech_ids | map: "id" | join: ", " }}
{% endfor %}
