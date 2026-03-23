---
layout: default
title: Windows 서버
parent: 기술적 분야
nav_order: 2
---

# Windows 서버

{{ site.data.technical['02_windows'].items.size }}개 점검항목 (W-01 ~ W-64)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['02_windows'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['02_windows'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['02_windows'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['02_windows'].items %}
{% include technical_item.html item=item %}
{% endfor %}
