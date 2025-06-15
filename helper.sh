!/bin/bash
# If for whatever reason the site doesn't work in GitHub Pages run this script.

rm -rf public/
hugo --cleanDestinationDir
git add .
git commit -m "changes"
git push hugo main
