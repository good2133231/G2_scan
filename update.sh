#!/bin/bash

# 添加需要跟踪的文件
git add start.py
git add ./file/cdn_动态添加_一年清一次.txt
git add ./file/filter-domain.txt

# 如果有改动则提交
if ! git diff --cached --quiet; then
  git commit -m "update start.py and supporting files"
else
  echo "No changes to commit"
fi

# 推送改动
git push
