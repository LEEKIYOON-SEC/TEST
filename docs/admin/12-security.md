---
layout: default
title: 12. 보안관리
parent: 관리적 분야
nav_order: 12
---

# {{ site.data.management['12_security'].domain }}

{% for item in site.data.management['12_security'].items %}
{% include admin_item.html item=item %}
{% endfor %}
