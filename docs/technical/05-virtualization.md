---
layout: default
title: 가상화 장비
parent: 기술적 분야
nav_order: 5
---

# 가상화 장비

{{ site.data.technical['05_virtualization'].items.size }}개 점검항목 (HV-01 ~ HV-25)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['05_virtualization'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['05_virtualization'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['05_virtualization'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['05_virtualization'].items %}
{% include technical_item.html item=item %}
{% endfor %}
