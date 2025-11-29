#!/usr/bin/env bash
# Show CMDS README in a scrollable dialog box

dialog --backtitle "CMDS-Deployment Server" \
       --title "CMDS Hybrid Catalyst-to-Meraki README" \
       --no-collapse \
       --textbox ./read.me 30 120