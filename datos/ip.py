import re
from pathlib import Path

CARPETA_ENTRADA = "./datos"  # <-- Cambia aquí
ARCHIVO_SALIDA = "ip_user_pass.txt"
IP_RE = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def extraer(linea):
    ip = IP_RE.search(linea)
    if not ip:
        return None
    ip = ip.group()
    resto = linea.replace(ip, '', 1).strip()
    partes = resto.split(':')
    if len(partes) >= 2:
        user = partes[-2].strip()
        pwd = partes[-1].strip()
        if user and pwd:
            return f"{ip}:{user}:{pwd}"
    return None

with open(ARCHIVO_SALIDA, 'w', encoding='utf-8') as out:
    for arch in Path(CARPETA_ENTRADA).rglob('*.txt'):
        with open(arch, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                res = extraer(line.strip())
                if res:
                    out.write(res + '\n')
print("Listo, revisa", ARCHIVO_SALIDA)