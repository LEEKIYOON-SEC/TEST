---
layout: default
title: 관리적 분야
nav_order: 2
has_children: true
permalink: /admin/
---

# 관리적 분야

주요정보통신기반시설 **관리적 취약점 분석·평가** 점검항목입니다.

총 **118개** 항목이 14개 도메인으로 구성되어 있습니다.

| 도메인 | 항목 범위 | 항목 수 |
|:-------|:---------|:--------|
{% for file in site.data.management %}
| {{ file[1].domain }} | {% assign first = file[1].items | first %}{% assign last = file[1].items | last %}{{ first.id }} ~ {{ last.id }} | {{ file[1].items.size }}개 |
{% endfor %}
