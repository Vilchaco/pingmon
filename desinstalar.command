#!/bin/bash
# Detiene pingmon y quita el arranque automático. Los datos quedan en ~/pingmon/data.
cd "$HOME/pingmon" 2>/dev/null || cd "$(dirname "$0")"
/usr/bin/python3 pingmon.py uninstall
read -r -p "Pulsa Enter para cerrar." _
