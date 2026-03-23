---
layout: default
title: 크로스레퍼런스
nav_order: 5
has_children: false
permalink: /cross-reference/
---

# 크로스레퍼런스

관리적 점검항목과 기술적 점검항목(UNIX/Windows/Web) 간의 매핑입니다.

각 관리 항목이 어떤 기술적 점검항목으로 구현되는지 확인할 수 있습니다.

---

## 확인된 매핑 (확신도: 높음)

사이트에 반영 가능한 매핑입니다.

{% for mapping in site.data.cross_ref_confirmed.mappings %}
<details class="admin-item" id="xref-{{ mapping.admin_id | downcase }}">
  <summary>
    <strong>{{ mapping.admin_id }}</strong> — {{ mapping.admin_title | xml_escape }}
    <span style="margin-left:auto; font-size:0.8rem; color:#888;">{{ mapping.tech_ids.size }}개 기술항목</span>
  </summary>
  <div class="item-body">
    {% for tech in mapping.tech_ids %}
    <div class="crossref-mapping">
      <strong>{{ tech.id }}</strong> {{ tech.title | xml_escape }}
      {% if tech.mapping_type == "직접구현" %}
      <span class="mapping-type mapping-type-direct">{{ tech.mapping_type }}</span>
      {% elsif tech.mapping_type == "관련" %}
      <span class="mapping-type mapping-type-related">{{ tech.mapping_type }}</span>
      {% else %}
      <span class="mapping-type mapping-type-indirect">{{ tech.mapping_type }}</span>
      {% endif %}
      <div class="crossref-evidence">{{ tech.evidence | xml_escape }}</div>
    </div>
    {% endfor %}
  </div>
</details>
{% endfor %}

---

## 검토 필요 (확신도: 중간)

사용자 검수 후 확정 또는 삭제할 매핑입니다.

{% for mapping in site.data.cross_ref_review.mappings %}
<details class="admin-item" id="review-{{ mapping.admin_id | downcase }}">
  <summary>
    <strong>{{ mapping.admin_id }}</strong> — {{ mapping.admin_title | xml_escape }}
    <span style="margin-left:auto; font-size:0.8rem; color:#888;">{{ mapping.tech_ids.size }}개 기술항목</span>
  </summary>
  <div class="item-body">
    {% for tech in mapping.tech_ids %}
    <div class="crossref-mapping">
      <strong>{{ tech.id }}</strong> {{ tech.title | xml_escape }}
      {% if tech.mapping_type == "직접구현" %}
      <span class="mapping-type mapping-type-direct">{{ tech.mapping_type }}</span>
      {% elsif tech.mapping_type == "관련" %}
      <span class="mapping-type mapping-type-related">{{ tech.mapping_type }}</span>
      {% else %}
      <span class="mapping-type mapping-type-indirect">{{ tech.mapping_type }}</span>
      {% endif %}
      <div class="crossref-evidence">{{ tech.evidence | xml_escape }}</div>
    </div>
    {% endfor %}
  </div>
</details>
{% endfor %}
