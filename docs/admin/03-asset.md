---
layout: default
title: 3. 자산분류
parent: 관리적 분야
nav_order: 3
---

# {{ site.data.management['03_asset'].domain }}

{% for item in site.data.management['03_asset'].items %}
{% include admin_item.html item=item %}
{% endfor %}
