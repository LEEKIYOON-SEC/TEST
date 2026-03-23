---
layout: default
title: 7. 외부자보안
parent: 관리적 분야
nav_order: 7
---

# {{ site.data.management['07_external'].domain }}

{% for item in site.data.management['07_external'].items %}
{% include admin_item.html item=item %}
{% endfor %}
