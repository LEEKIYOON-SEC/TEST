---
layout: default
title: 6. 인적보안
parent: 관리적 분야
nav_order: 6
---

# {{ site.data.management['06_hr_security'].domain }}

{% for item in site.data.management['06_hr_security'].items %}
{% include admin_item.html item=item %}
{% endfor %}
