#!/bin/sh

echo "[+] Duplicating reputation files with spaces to replace them with '_'..."

find /var/db/darwin/ -regex ".* .*" -exec sh -c '
filename="$1";
new_filename=$(echo $filename | tr " " "_");
echo "$filename -> $new_filename"
cp -np "$filename" "$new_filename"' shell {} \;

echo "[-] done"