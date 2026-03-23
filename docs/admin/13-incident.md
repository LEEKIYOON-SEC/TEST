---
layout: default
title: 13. 사고대응
parent: 관리적 분야
nav_order: 13
---

# {{ site.data.management['13_incident'].domain }}

{% for item in site.data.management['13_incident'].items %}
{% include admin_item.html item=item %}
{% endfor %}
