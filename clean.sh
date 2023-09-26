find . -type d -name '__pycache__' -exec rm -rf {} \;
rm -rf src/build
rm -rf src/dist
rm -rf src/*.egg-info