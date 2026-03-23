---
layout: default
title: 물리적 분야
nav_order: 3
has_children: false
permalink: /physical/
---

# 물리적 분야

주요정보통신기반시설 **물리적 취약점 분석·평가** 점검항목입니다.

총 **{{ site.data.physical['01_physical'].items.size }}개** 항목으로 구성되어 있습니다.

---

{% for item in site.data.physical['01_physical'].items %}
{% include admin_item.html item=item %}
{% endfor %}
