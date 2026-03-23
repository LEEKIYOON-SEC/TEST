---
layout: default
title: 8. 교육 및 훈련
parent: 관리적 분야
nav_order: 8
---

# {{ site.data.management['08_education'].domain }}

{% for item in site.data.management['08_education'].items %}
{% include admin_item.html item=item %}
{% endfor %}
