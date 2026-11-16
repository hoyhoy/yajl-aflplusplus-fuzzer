#!/usr/bin/env bash

running=true
trap 'running=false' INT TERM

# \u  = 4 hex digits (BMP, up to U+FFFF)
# \U  = up to 8 hex digits (full range, up to U+10FFFF)
bmp=$'\u2713'               # ✓  U+2713
frames=( $'\U0001F311' $'\U0001F312' $'\U0001F313' $'\U0001F314'
         $'\U0001F315' $'\U0001F316' $'\U0001F317' $'\U0001F318' )  # 🌑🌒🌓🌔🌕🌖🌗🌘

i=0
while $running; do
    printf '\r%s working... %s' "${frames[i % ${#frames[@]}]}" "$bmp"
    ((i++))
    sleep 0.2 &
    wait $!
done

printf '\n\U0001F44B Clean exit\n'   # 👋
