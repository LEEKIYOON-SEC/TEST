---
layout: default
title: 10. 접근통제
parent: 관리적 분야
nav_order: 10
---

# {{ site.data.management['10_access_control'].domain }}

{% for item in site.data.management['10_access_control'].items %}
{% include admin_item.html item=item %}
{% endfor %}
