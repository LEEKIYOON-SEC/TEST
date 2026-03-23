---
layout: default
title: 웹 서비스
parent: 기술적 분야
nav_order: 3
---

# 웹 서비스 (보안설정)

{{ site.data.technical['03_web'].items.size }}개 점검항목 (WEB-01 ~ WEB-26)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['03_web'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['03_web'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['03_web'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['03_web'].items %}
{% include technical_item.html item=item %}
{% endfor %}
