#!/bin/sh

# Start the cron daemon in the background.
# The "-f" flag keeps it in the foreground, and "&" backgrounds the process.
cron -f &

#Start fnetd
exec /fnetd/build/fnetd -p 1337 -u pwn -lt 2 -lm 536870912 ./vuln
