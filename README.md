# pingmon: latencia de la oficina a AWS

Mide continuamente la latencia y la pérdida desde la oficina hacia las regiones de AWS y hacia el servidor RTMP. Así podéis decidir con datos a qué región moveros y si mover el servidor servirá de algo.

## Qué mide y por qué

| Objetivo | Cómo | Para qué |
|---|---|---|
| Regiones AWS | Tiempo de conexión TCP a `dynamodb.<región>.amazonaws.com:443` | Comparar regiones. Los endpoints de AWS no suelen responder a ICMP, y RTMP va por TCP, así que el RTT de TCP es la medida que importa |
| Servidor RTMP actual | Tiempo de conexión TCP a `host:1935` | Medir el camino real de la señal |
| Router de la oficina | ICMP al gateway por defecto (se detecta solo) | **Control**: si el lag aparece aquí, el problema está en la LAN o el Wi-Fi |
| Internet (1.1.1.1) | ICMP | **Control**: si aparece aquí y no en el router, el problema es la línea o el ISP |

Cada sonda que no responde en 1 s cuenta como **pérdida**. Si se pierde un SYN, TCP lo reenvía al cabo de ~1 s, y para una emisión en directo eso ya es un corte.

El dashboard cruza los episodios de lag hacia AWS con los controles:

- **Coinciden con lag en el router o en internet** → el problema es la red de la oficina, casi siempre porque la subida se satura durante la emisión (*bufferbloat*). Cambiar de región no lo arregla.
- **Solo aparecen hacia AWS** → el problema está en el camino hacia AWS, y ahí sí tiene sentido comparar regiones.

## Instalación (una línea)

En el Mac mini de la oficina, abre Terminal y pega esta línea, cambiando el final por el host de vuestro servidor RTMP (el de la URL del encoder: en `rtmp://ingest.midominio.com/live` es `ingest.midominio.com`; si no es el 1935, añade `:puerto`):

```bash
curl -fsSL https://raw.githubusercontent.com/Vilchaco/pingmon/main/install.sh | bash -s -- ingest.midominio.com
```

Sin el host (`… | bash`) también funciona: te lo pregunta, o si pulsas Enter mide solo las regiones.

El instalador:
- copia todo a `~/pingmon`;
- lo deja corriendo y arrancando solo, e impide que el Mac mini se duerma mientras corre;
- te dice la dirección del dashboard, que se abre desde cualquier equipo de la oficina en `http://<nombre-del-mac-mini>.local:8787`. Si macOS pregunta si Python puede aceptar conexiones entrantes, pulsa **Permitir**.

Para actualizar, vuelve a ejecutar la misma línea: descarga la última versión y conserva tu `config.json`.

Al terminar, el instalador espera 30 s y comprueba que cada destino responde. Si el **router sale «SIN RESPUESTA»**, casi siempre es el permiso de Red local de macOS: ve a **Ajustes del Sistema → Privacidad y seguridad → Red local**, activa python3 (y Terminal) y vuelve a ejecutar el instalador.

Para que sobreviva a cortes de luz y reinicios, en el Mac mini:
- **Ajustes del Sistema → Energía** → activa «Arrancar automáticamente tras un corte de luz».
- **Ajustes del Sistema → Usuarios y grupos** → activa el inicio de sesión automático. El monitor arranca al iniciar sesión.

Para cambiar el servidor o las regiones más adelante, edita `~/pingmon/config.json` y reinicia con `python3 ~/pingmon/pingmon.py install`. Para quitarlo: `bash ~/pingmon/desinstalar.command`. Los datos se conservan en `~/pingmon/data`.

Informe rápido por terminal:
```bash
python3 ~/pingmon/pingmon.py report --window 7d
```

## Recomendaciones

- **Sin VPN, proxy ni Cloudflare WARP.** Tiene que medir el mismo camino que usa el encoder. Desde Monterrey, lo esperable es que México (mx-central-1) sea la región más rápida. Si no lo es, comprueba por dónde sale el tráfico.
- **Conecta el Mac mini por cable** a la misma red desde la que emite el encoder. Si mides por Wi-Fi, el lag del Wi-Fi contamina la medida.
- **Déjalo varios días, incluyendo días de emisión.** Lo más útil es el mapa de calor por hora del día y comparar las horas con emisión con las horas sin ella.
- El dashboard es accesible desde la red de la oficina (`"bind": "0.0.0.0"`). Para limitarlo al propio Mac mini, pon `"127.0.0.1"`.
- Si el router no responde a ping, el dashboard lo avisa y lo excluye del diagnóstico. Revisa primero el permiso de Red local (ver arriba). Si aun así no responde, puede que el router filtre el ping: prueba con `"method": "tcp", "port": 80` (o 53) en `config.json`.
- La sonda del servidor RTMP abre y cierra una conexión TCP cada 10 s. En los logs del servidor saldrán como conexiones cortas; es normal.

## Configuración (`config.json`)

- `interval_seconds`: cada cuánto se sondea (10 s por defecto).
- `timeout_seconds`: a partir de cuánto se considera pérdida (1 s).
- `retention_days`: cuánto histórico se guarda (30 días).
- `targets`: añade o quita regiones con el mismo formato. `kind` es `control`, `server` o `region`.

## Archivos

- `install.sh`: instalación en una línea (descarga el repo y ejecuta `instalar.command`).
- `instalar.command` / `desinstalar.command`: instalación y desinstalación en el propio Mac.
- `pingmon.py`: sondeo, análisis, servidor web, informe e instalación en launchd. Solo usa la librería estándar.
- `dashboard.html`: el dashboard.
- `data/pingmon.db`: las muestras en bruto (SQLite). `data/pingmon.log`: el log cuando corre con launchd.
