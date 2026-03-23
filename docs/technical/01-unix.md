---
layout: default
title: UNIX 서버
parent: 기술적 분야
nav_order: 1
---

# UNIX 서버

{{ site.data.technical['01_unix'].items.size }}개 점검항목 (U-01 ~ U-67)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['01_unix'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['01_unix'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['01_unix'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['01_unix'].items %}
{% include technical_item.html item=item %}
{% endfor %}
