#!/bin/bash
[ "$PAM_SERVICE" = "sshd" ] || exit 0
[ "$PAM_TYPE" = "open_session" ] || exit 0
exec /usr/bin/python3 /opt/karaul/karaul.py record
