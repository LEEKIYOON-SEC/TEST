---
layout: default
title: 1. 정보보호 정책
parent: 관리적 분야
nav_order: 1
---

# {{ site.data.management['01_policy'].domain }}

{% for item in site.data.management['01_policy'].items %}
{% include admin_item.html item=item %}
{% endfor %}
