---
layout: default
title: 4. 위험관리
parent: 관리적 분야
nav_order: 4
---

# {{ site.data.management['04_risk'].domain }}

{% for item in site.data.management['04_risk'].items %}
{% include admin_item.html item=item %}
{% endfor %}
