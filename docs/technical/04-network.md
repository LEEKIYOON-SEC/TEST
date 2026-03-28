---
layout: default
title: 네트워크 장비
parent: 기술적 분야
nav_order: 4
---

# 네트워크 장비

{{ site.data.technical['04_network'].items.size }}개 점검항목 (N-01 ~ N-38)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['04_network'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['04_network'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['04_network'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['04_network'].items %}
{% include technical_item.html item=item %}
{% endfor %}
