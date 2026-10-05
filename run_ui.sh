#!/usr/bin/env bash
# Conservé pour compatibilité : l'UI se lance désormais via ./fortilog.sh (portable).
exec "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/fortilog.sh" ui "$@"
