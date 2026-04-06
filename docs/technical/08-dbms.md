---
layout: default
title: DBMS
parent: 기술적 분야
nav_order: 8
---

# DBMS

{{ site.data.technical['08_dbms'].items.size }}개 점검항목 (26종)

| 중요도 | 항목 수 |
|:-------|:--------|
| 상 | {% assign high = site.data.technical['08_dbms'].items | where: "severity", "상" %}{{ high.size }}개 |
| 중 | {% assign med = site.data.technical['08_dbms'].items | where: "severity", "중" %}{{ med.size }}개 |
| 하 | {% assign low = site.data.technical['08_dbms'].items | where: "severity", "하" %}{{ low.size }}개 |

---

{% for item in site.data.technical['08_dbms'].items %}
{% include technical_item.html item=item %}
{% endfor %}
