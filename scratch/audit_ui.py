import re
from collections import Counter

with open("index.html", "r", encoding="utf-8") as f:
    html = f.read()

# 1. Check duplicate IDs
ids = re.findall(r'id="([^"]+)"', html)
counts = Counter(ids)
dups = {k: v for k, v in counts.items() if v > 1}
print("Duplicate IDs:", dups)

# 2. Check for missing elements referenced in document.getElementById
js_get_ids = set(re.findall(r'getElementById\([\'"]([^\'"]+)[\'"]\)', html))
html_id_set = set(ids)
missing_in_html = [gid for gid in js_get_ids if gid not in html_id_set]
print("getElementById targets missing in HTML:", missing_in_html)

# 3. Check for syntax issues in JS blocks
script_blocks = re.findall(r'<script>(.*?)</script>', html, re.DOTALL)
print(f"Total script blocks found: {len(script_blocks)}")
