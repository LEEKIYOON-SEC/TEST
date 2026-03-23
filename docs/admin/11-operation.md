---
layout: default
title: 11. 운영관리
parent: 관리적 분야
nav_order: 11
---

# {{ site.data.management['11_operation'].domain }}

{% for item in site.data.management['11_operation'].items %}
{% include admin_item.html item=item %}
{% endfor %}
