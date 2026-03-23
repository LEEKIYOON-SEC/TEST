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

<table>
  <thead>
    <tr><th>도메인</th><th>항목 범위</th><th>항목 수</th></tr>
  </thead>
  <tbody>
  {% for file in site.data.management %}
    {% assign first = file[1].items | first %}
    {% assign last = file[1].items | last %}
    <tr>
      <td>{{ file[1].domain }}</td>
      <td>{{ first.id }} ~ {{ last.id }}</td>
      <td>{{ file[1].items.size }}개</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
