---
layout: default
title: 9. 인증 및 권한관리
parent: 관리적 분야
nav_order: 9
---

# {{ site.data.management['09_auth'].domain }}

{% for item in site.data.management['09_auth'].items %}
{% include admin_item.html item=item %}
{% endfor %}
