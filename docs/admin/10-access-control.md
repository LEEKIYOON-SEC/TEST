---
layout: default
title: 10. 접근통제
parent: 관리적 분야
nav_order: 10
---

# {{ site.data.management['10_접근통제'].domain }}

{% for item in site.data.management['10_접근통제'].items %}
{% include admin_item.html item=item %}
{% endfor %}
