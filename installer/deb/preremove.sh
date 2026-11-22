#!/bin/sh
set -e
systemctl stop omenwatch.service || true
systemctl disable omenwatch.service || true
