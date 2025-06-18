!/bin/bash
# If for whatever reason the site doesn't work in GitHub Pages run this script.

rm -rf public/
hugo --cleanDestinationDir
git add .
git commit -m "Changes made and pushed by the helper script."
git push hugo main
