#!/bin/sh
set -eu

SINCE="${1:-24 hours ago}"

echo "Top blocked hosts since: $SINCE"
echo

{
  journalctl -k --since "$SINCE" | grep 'nft-threat IN ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-SRC ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-DST ' \
    | sed -n 's/.*DST=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat OUT ' \
    | sed -n 's/.*DST=\([0-9.]*\).*/\1/p'
} \
  | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -50

echo
echo "Top blocked direction/IP/port since: $SINCE"
echo

{
  journalctl -k --since "$SINCE" | grep 'nft-threat IN ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*DPT=\([0-9]*\).*/IN \1 \2/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-SRC ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*DPT=\([0-9]*\).*/FWD-SRC \1 \2/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-DST ' \
    | sed -n 's/.*DST=\([0-9.]*\).*DPT=\([0-9]*\).*/FWD-DST \1 \2/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat OUT ' \
    | sed -n 's/.*DST=\([0-9.]*\).*DPT=\([0-9]*\).*/OUT \1 \2/p'
} \
  | awk '$2 ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ { print }' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -100

echo
echo "Top /24 networks since: $SINCE"
echo

{
  journalctl -k --since "$SINCE" | grep 'nft-threat IN ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-SRC ' \
    | sed -n 's/.*SRC=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat FWD-DST ' \
    | sed -n 's/.*DST=\([0-9.]*\).*/\1/p'

  journalctl -k --since "$SINCE" | grep 'nft-threat OUT ' \
    | sed -n 's/.*DST=\([0-9.]*\).*/\1/p'
} \
  | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$' \
  | awk -F. '{ print $1 "." $2 "." $3 ".0/24" }' \
  | sort \
  | uniq -c \
  | sort -nr \
  | head -30
