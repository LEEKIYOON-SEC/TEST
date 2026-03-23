---
layout: default
title: 2. 정보보호 조직
parent: 관리적 분야
nav_order: 2
---

# {{ site.data.management['02_organization'].domain }}

{% for item in site.data.management['02_organization'].items %}
{% include admin_item.html item=item %}
{% endfor %}
