---
title: "CyCTF"
parent: 2025
layout: default
has_children: true
has_toc: false
nav_order: 1
permalink: /ctfs/2025/cyctf/
---

# CyCTF

Writeups for the 2025 CyCTF event.

{% assign children = site.pages | where: "parent", page.title | sort: "nav_order" %}
{% if children.size > 0 %}
<ul>
  {% for child in children %}
  <li><a href="{{ child.url | relative_url }}">{{ child.title }}</a></li>
  {% endfor %}
</ul>
{% endif %}
