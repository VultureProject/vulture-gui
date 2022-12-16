#!/bin/sh

echo "[+] Duplicating reputation files with spaces to replace them with '_'..."
# for f in *; do mv "$f" `echo $f | tr ' ' '_'`; done
for x in /var/db/darwin/*\ *; do
    new_filename="$(echo $x | tr ' ' '_')"
    echo "$x -> $new_filename"
    cp -np "$x" "$new_filename"
done
echo "[-] done"
