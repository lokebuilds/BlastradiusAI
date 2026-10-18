import re

with open("index.html", "r", encoding="utf-8") as f:
    content = f.read()

ids = set(re.findall(r"getElementById\(['\"]([^'\"]+)['\"]\)", content))
for i in sorted(list(ids)):
    print(i)
