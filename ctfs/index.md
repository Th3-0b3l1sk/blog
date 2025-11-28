---
title: CTFs
layout: default
nav_order: 10
has_children: true
has_toc: false
permalink: /ctfs/
---

# CTFs

{% assign children = site.pages | where: "parent", page.title | sort: "nav_order" %}
{% if children.size > 0 %}
<ul>
  {% for child in children %}
  <li><a href="{{ child.url | relative_url }}">{{ child.title }}</a></li>
  {% endfor %}
</ul>
{% endif %}
