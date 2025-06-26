git add start.py
if ! git diff --cached --quiet; then
  git commit -m "update start.py"
else
  echo "No changes to commit"
fi
git push

