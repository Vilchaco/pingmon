#!/bin/bash
# Instalador de pingmon para el Mac mini de la oficina.
# Copia el monitor a ~/pingmon, configura el servidor RTMP y lo deja arrancando solo.
# Uso: bash instalar.command [host[:puerto]]
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/pingmon"

echo "== Instalando pingmon en $DEST =="

# Python 3 del sistema (viene con las Command Line Tools de Xcode).
if ! /usr/bin/python3 -c 'import sys' >/dev/null 2>&1; then
  echo
  echo "Falta Python 3. macOS va a abrir el instalador de las Command Line Tools."
  echo "Acepta la instalación y, cuando termine, vuelve a ejecutar este instalador."
  xcode-select --install >/dev/null 2>&1 || true
  exit 1
fi

# Se instala fuera de Descargas/Escritorio/Documentos: macOS no deja que los
# procesos en segundo plano lean esas carpetas.
if [ "$SRC" != "$DEST" ]; then
  mkdir -p "$DEST"
  if [ -f "$DEST/config.json" ]; then
    cp "$DEST/config.json" "$DEST/config.json.bak"   # conserva la config si ya estaba instalado
  fi
  cp "$SRC/pingmon.py" "$SRC/dashboard.html" "$SRC/README.md" "$SRC/desinstalar.command" "$DEST/"
  if [ -f "$DEST/config.json.bak" ]; then
    mv "$DEST/config.json.bak" "$DEST/config.json"
    echo "Se ha conservado la config.json que ya había."
  else
    cp "$SRC/config.json" "$DEST/"
  fi
  xattr -dr com.apple.quarantine "$DEST" 2>/dev/null || true
fi
cd "$DEST"

# Pregunta al usuario solo si hay terminal: con `curl | bash` la entrada estándar
# es el propio script, así que se lee de /dev/tty.
ask() {
  REPLY=""
  if [ -r /dev/tty ] && [ -w /dev/tty ]; then
    read -r -p "$1" REPLY < /dev/tty || REPLY=""
  fi
}

# Servidor RTMP actual: como argumento (host o host:puerto), por PINGMON_SERVER o preguntando.
CURRENT=$(/usr/bin/python3 -c 'import json;s=[t for t in json.load(open("config.json"))["targets"] if t["id"]=="server"][0];print("%s:%s"%(s["host"],s["port"]))')
SERVER="${1:-${PINGMON_SERVER:-}}"
echo
echo "Servidor RTMP en config.json: $CURRENT"
if [ -z "$SERVER" ]; then
  ask "Servidor RTMP como host o host:puerto (Enter para dejarlo como está): "
  SERVER="$REPLY"
fi
if [ -n "$SERVER" ]; then
  HOST="${SERVER%%:*}"
  PORT=1935
  case "$SERVER" in *:*) PORT="${SERVER##*:}";; esac
  /usr/bin/python3 - "$HOST" "$PORT" <<'EOF'
import json, sys
host, port = sys.argv[1], int(sys.argv[2])
src = open("config.json").read()
srv = [t for t in json.loads(src)["targets"] if t["id"] == "server"][0]
src = src.replace('"host": "%s", "port": %d' % (srv["host"], srv["port"]),
                  '"host": "%s", "port": %d' % (host, port), 1)
json.loads(src)  # valida que sigue siendo JSON correcto
open("config.json", "w").write(src)
EOF
  echo "Servidor configurado: $HOST:$PORT"
fi

echo
/usr/bin/python3 pingmon.py install
echo
echo "Comprobando las primeras mediciones (30 s)..."
sleep 30
/usr/bin/python3 - <<'EOF'
import sqlite3, time
db = sqlite3.connect("data/pingmon.db")
rows = db.execute("SELECT target, COUNT(*), SUM(rtt_ms IS NOT NULL) FROM samples "
                  "WHERE ts > ? GROUP BY target", (time.time() - 60,)).fetchall()
if not rows:
    print("  Aún no hay muestras. Revisa el log: ~/pingmon/data/pingmon.log")
for target, n, ok in rows:
    print("  %-14s %s" % (target, "OK" if ok else "SIN RESPUESTA"))
bad = {t for t, n, ok in rows if not ok}
if "gateway" in bad:
    print()
    print("  El router no responde. Casi siempre es el permiso de Red local de macOS:")
    print("  Ajustes del Sistema > Privacidad y seguridad > Red local > activa python3 (y Terminal).")
    print("  Después ejecuta de nuevo este instalador.")
if "server" in bad:
    print()
    print("  El servidor RTMP no responde en el puerto configurado desde este equipo.")
    print("  Revisa que el Security Group permita la IP pública de la oficina.")
EOF
echo
echo "Listo. El monitor ya está corriendo, arranca solo al iniciar sesión y evita que el Mac mini se duerma."
echo "Si macOS pregunta si Python puede aceptar conexiones entrantes, pulsa Permitir (es para ver el dashboard desde otros equipos)."
