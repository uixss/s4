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
import base64
import importlib.util
import json
from typing import List, Dict, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import ipaddress
import socket

# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

# Configuración por defecto
DEFAULT_CONFIG = {
    'threads': 20,
    'timeout': 10,
    'attempts': 2,
    'default_port': 3389,
    'check_ssh': True,
    'check_rdp': True,
    'full_scan': False,
    'max_pending': 500,
    'update_interval': 100,
    'batch_size': 50,
    'scan_chunk_size': 100,
    'max_concurrent_scans': 200,
}

# Puertos comunes para escaneo rápido
COMMON_PORTS = [21, 22, 23, 80, 443, 3389, 8080, 3306, 445, 139, 135, 53, 1433, 1521]

# Textos de la interfaz
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

# Colores de la interfaz
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
    """Gestor seguro de credenciales con encriptación"""
    
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_create_key(self) -> bytes:
        """Carga o crea una clave de encriptación"""
        key_path = os.path.join(os.path.dirname(__file__), "secret.key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_credentials(self, user: str, password: str) -> str:
        """Encripta las credenciales"""
        cred_str = f"{user}:{password}"
        return self.cipher.encrypt(cred_str.encode()).decode()
    
    def decrypt_credentials(self, encrypted: str) -> Tuple[str, str]:
        """Desencripta las credenciales"""
        decrypted = self.cipher.decrypt(encrypted.encode()).decode()
        return decrypted.split(":")

class ScanResult:
    """Contenedor para resultados de escaneo"""
    
    def __init__(self):
        self.active_ips = []
        self.open_ports = {}
        self.ssh_success = []
        self.rdp_success = []
        self.scan_stats = {
            'ips_scanned': 0,
            'ips_active': 0,
            'ports_found': 0,
            'creds_valid': 0,
            'start_time': None,
            'end_time': None,
        }

class NetworkUtils:
    """Utilidades para operaciones de red"""
    
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Valida si una cadena es una IP válida"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_private_ip(ip_str: str) -> bool:
        """Verifica si la IP es privada"""
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private
        except ValueError:
            return False
    
    @staticmethod
    async def check_port_async(ip: str, port: int, timeout: int = 5) -> bool:
        """Verifica si un puerto está abierto (asíncrono)"""
        try:
            conn = asyncio.open_connection(ip, port)
            _, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    @staticmethod
    def check_port_sync(ip: str, port: int, timeout: int = 5) -> bool:
        """Verifica si un puerto está abierto (síncrono)"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0

# ============================================================================
# LÓGICA PRINCIPAL DE ESCANEO
# ============================================================================

class NetworkScanner:
    """Motor principal de escaneo de red"""
    
    def __init__(self, config: Dict, credential_manager: CredentialManager):
        self.config = config
        self.cred_manager = credential_manager
        self.results = ScanResult()
        self.is_scanning = False
        self.should_stop = False
        
    def load_ips_from_file(self, filepath: str) -> List[str]:
        """Carga IPs desde archivo con validación"""
        ips = []
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and NetworkUtils.is_valid_ip(ip.split('/')[0]):
                            ips.append(ip)
            except UnicodeDecodeError:
                with open(filepath, 'r', encoding='latin-1') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and NetworkUtils.is_valid_ip(ip.split('/')[0]):
                            ips.append(ip)
        return ips
    
    def load_credentials_from_file(self, filepath: str) -> Dict[str, str]:
        """Carga credenciales desde archivo"""
        credentials = {}
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        if ':' in line:
                            user, password = line.strip().split(':', 1)
                            credentials[user] = password
            except UnicodeDecodeError:
                with open(filepath, 'r', encoding='latin-1') as f:
                    for line in f:
                        if ':' in line:
                            user, password = line.strip().split(':', 1)
                            credentials[user] = password
        return credentials
    
    async def scan_ip_range(self, ip_range: str, ports: List[int]) -> List[str]:
        """Escanea un rango de IPs para puertos específicos"""
        active_ips = []
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
            ips_to_scan = [str(ip) for ip in network.hosts()]
        except ValueError:
            # Si no es un rango CIDR, asumir que es una IP individual
            ips_to_scan = [ip_range]
        
        # Limitar concurrencia
        semaphore = asyncio.Semaphore(self.config.get('max_concurrent_scans', 200))
        
        async def check_ip(ip: str) -> Optional[str]:
            async with semaphore:
                if self.should_stop:
                    return None
                
                for port in ports:
                    if await NetworkUtils.check_port_async(ip, port, self.config['timeout']):
                        return ip
                return None
        
        # Escanear en chunks para mejor rendimiento
        chunk_size = self.config.get('scan_chunk_size', 100)
        for i in range(0, len(ips_to_scan), chunk_size):
            if self.should_stop:
                break
                
            chunk = ips_to_scan[i:i + chunk_size]
            tasks = [check_ip(ip) for ip in chunk]
            results = await asyncio.gather(*tasks)
            active_ips.extend([ip for ip in results if ip])
            
            # Pequeña pausa para no saturar
            await asyncio.sleep(0.01)
        
        return active_ips
    
    async def scan_ports_on_ip(self, ip: str, ports_to_scan: List[int]) -> List[int]:
        """Escanea puertos específicos en una IP"""
        open_ports = []
        semaphore = asyncio.Semaphore(self.config.get('max_concurrent_scans', 200))
        
        async def check_port(port: int) -> Tuple[int, bool]:
            async with semaphore:
                if self.should_stop:
                    return port, False
                is_open = await NetworkUtils.check_port_async(ip, port, self.config['timeout'])
                return port, is_open
        
        # Escanear puertos en chunks
        chunk_size = self.config.get('scan_chunk_size', 100)
        for i in range(0, len(ports_to_scan), chunk_size):
            if self.should_stop:
                break
                
            chunk = ports_to_scan[i:i + chunk_size]
            tasks = [check_port(port) for port in chunk]
            results = await asyncio.gather(*tasks)
            open_ports.extend([port for port, is_open in results if is_open])
            
            await asyncio.sleep(0.01)
        
        return open_ports
    
    async def test_ssh_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Prueba conexión SSH con credenciales"""
        if self.should_stop:
            return False
            
        try:
            async with asyncssh.connect(
                host=ip,
                port=port,
                username=username,
                password=password,
                known_hosts=None,
                connect_timeout=self.config['timeout']
            ) as conn:
                await conn.close()
                return True
        except:
            return False
    
    async def test_rdp_connection(self, ip: str, port: int, username: str, password: str) -> bool:
        """Prueba conexión RDP con credenciales (ejecuta en thread separado)"""
        if self.should_stop:
            return False
            
        def try_rdp():
            try:
                cmd = [
                    "xfreerdp",
                    f"/v:{ip}:{port}",
                    f"/u:{username}",
                    f"/p:{password}",
                    "/cert:ignore",
                    f"/timeout:{self.config['timeout'] * 1000}",
                    "/sec:tls"
                ]
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.config['timeout']
                )
                output = result.stdout.decode(errors='ignore') + result.stderr.decode(errors='ignore')
                return "connected to" in output or "Authentication only" in output
            except:
                return False
        
        loop = asyncio.get_event_loop()
        with ThreadPoolExecutor() as executor:
            return await loop.run_in_executor(executor, try_rdp)
    
    async def brute_force_service(self, ip: str, port: int, credentials: Dict[str, str], 
                                service_type: str) -> List[Tuple[str, str]]:
        """Realiza fuerza bruta en un servicio"""
        valid_creds = []
        semaphore = asyncio.Semaphore(self.config.get('batch_size', 50))
        
        async def test_credential(user: str, password: str) -> Tuple[str, str, bool]:
            async with semaphore:
                if self.should_stop:
                    return user, password, False
                
                if service_type == 'ssh':
                    success = await self.test_ssh_connection(ip, port, user, password)
                else:  # rdp
                    success = await self.test_rdp_connection(ip, port, user, password)
                
                return user, password, success
        
        # Probar credenciales en batches
        users = list(credentials.items())
        batch_size = self.config.get('batch_size', 50)
        
        for i in range(0, len(users), batch_size):
            if self.should_stop:
                break
                
            batch = users[i:i + batch_size]
            tasks = [test_credential(user, passwd) for user, passwd in batch]
            results = await asyncio.gather(*tasks)
            
            for user, password, success in results:
                if success:
                    valid_creds.append((user, password))
            
            await asyncio.sleep(0.1)  # Pequeña pausa entre batches
        
        return valid_creds
    
    def stop_scan(self):
        """Detiene el escaneo actual"""
        self.should_stop = True
    
    def reset_scan(self):
        """Reinicia el estado del escaneo"""
        self.results = ScanResult()
        self.is_scanning = False
        self.should_stop = False

# ============================================================================
# INTERFAZ GRÁFICA (GUI)
# ============================================================================

class NetworkScannerApp:
    """Interfaz gráfica principal de la aplicación"""
    
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.setup_style()
        
        # Inicializar componentes
        self.cred_manager = CredentialManager()
        self.network_scanner = NetworkScanner(DEFAULT_CONFIG, self.cred_manager)
        
        # Variables de estado
        self.scanning = False
        self._log_buffer = []
        self._result_queue = Queue()
        self.scan_history = []
        self.config_cache = {}
        self.credentials_cache = {}
        
        # Inicializar variables de widgets
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
        self.progress_chart = None
        
        # Configurar asyncio
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Crear interfaz
        self.create_widgets()
        self.load_default_config()
        self.update_file_counts()
        
        # Configurar actualizaciones periódicas
        self.root.after(100, self._process_results)
        self.root.after(100, self._flush_log_buffer)
        
        # Mostrar ventana de autenticación
        self.show_auth_window()
    
    def setup_window(self):
        """Configura la ventana principal"""
        self.root.title(TEXTS['app_title'])
        self.root.geometry("750x650")
        self.root.overrideredirect(True)
        self.root.wm_attributes('-alpha', 0.95)
        self.root.configure(bg=COLORS['bg_main'])
        self.root.resizable(True, True)
        
        # Manejar movimiento de ventana
        self.x = 0
        self.y = 0
        self.root.bind("<Button-1>", self.start_move)
        self.root.bind("<ButtonRelease-1>", self.stop_move)
        self.root.bind("<B1-Motion>", self.on_motion)
    
    def setup_style(self):
        """Configura los estilos de la interfaz"""
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configurar estilos base
        self.style.configure(".", 
                           background=COLORS['bg_main'],
                           foreground=COLORS['fg_main'],
                           fieldbackground=COLORS['bg_secondary'])
        
        # Configurar componentes específicos
        self.style.configure("TFrame", background=COLORS['bg_main'])
        self.style.configure("TLabel", 
                           background=COLORS['bg_main'],
                           foreground=COLORS['fg_main'])
        self.style.configure("TButton", 
                           background=COLORS['button_bg'],
                           foreground=COLORS['fg_main'],
                           borderwidth=1)
        self.style.map("TButton",
                      background=[('active', COLORS['button_active']),
                                ('disabled', COLORS['bg_main'])],
                      foreground=[('disabled', '#777777')])
        
        self.style.configure("TEntry",
                           fieldbackground=COLORS['bg_secondary'],
                           foreground=COLORS['fg_main'],
                           insertcolor=COLORS['fg_main'])
        
        self.style.configure("TNotebook",
                           background=COLORS['bg_main'],
                           borderwidth=0)
        self.style.configure("TNotebook.Tab",
                           background=COLORS['button_bg'],
                           foreground=COLORS['fg_main'],
                           padding=[5, 3])
        self.style.map("TNotebook.Tab",
                      background=[('selected', COLORS['highlight']),
                                ('active', COLORS['button_active'])])
        
        # Botones de control de ventana
        close_btn = tk.Button(self.root, text="✕", command=self.root.destroy,
                            bg=COLORS['close_bg'], fg="white", bd=0,
                            highlightthickness=0, font=("Arial", 12, "bold"),
                            activebackground=COLORS['close_active'])
        close_btn.place(relx=0.99, rely=0.01, anchor="ne", width=25, height=25)
        
        minimize_btn = tk.Button(self.root, text="–", command=self.root.iconify,
                               bg=COLORS['button_bg'], fg="white", bd=0,
                               highlightthickness=0, font=("Arial", 12, "bold"),
                               activebackground=COLORS['button_active'])
        minimize_btn.place(relx=0.95, rely=0.01, anchor="ne", width=25, height=25)
    
    def show_auth_window(self):
        """Muestra ventana de autenticación"""
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title(TEXTS['auth_title'])
        self.auth_window.geometry("300x200")
        self.auth_window.resizable(False, False)
        self.auth_window.overrideredirect(True)
        self.auth_window.configure(bg=COLORS['bg_main'])
        
        # Centrar ventana
        window_width, window_height = 300, 200
        screen_width = self.auth_window.winfo_screenwidth()
        screen_height = self.auth_window.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.auth_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Contenido de autenticación
        ttk.Label(self.auth_window, text="Acceso al Sistema", 
                 font=("Arial", 12, "bold")).pack(pady=10)
        
        ttk.Label(self.auth_window, text=TEXTS['auth_user']).pack(pady=5)
        self.auth_user = ttk.Entry(self.auth_window)
        self.auth_user.pack(pady=5)
        
        ttk.Label(self.auth_window, text=TEXTS['auth_pass']).pack(pady=5)
        self.auth_pass = ttk.Entry(self.auth_window, show="*")
        self.auth_pass.pack(pady=5)
        
        ttk.Button(self.auth_window, text=TEXTS['auth_button'],
                  command=self.check_credentials).pack(pady=10)
        
        self.root.withdraw()
        self.auth_window.protocol("WM_DELETE_WINDOW", self.root.destroy)
    
    def check_credentials(self):
        """Verifica las credenciales de acceso"""
        user = self.auth_user.get()
        password = self.auth_pass.get()
        
        if user == "admin" and password == "admin123":
            self.auth_window.destroy()
            self.root.deiconify()
            self.center_window()
        else:
            messagebox.showerror("Error", TEXTS['auth_error'])
            self.auth_pass.delete(0, tk.END)
    
    def center_window(self):
        """Centra la ventana en la pantalla"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
    
    def create_widgets(self):
        """Crea todos los widgets de la interfaz"""
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.create_main_tab()
    
    def create_main_tab(self):
        """Crea la pestaña principal"""
        self.main_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.main_frame, text=TEXTS['tab_main'])
        
        # Panel izquierdo (configuración)
        left_panel = ttk.Frame(self.main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_panel.pack_propagate(False)
        
        # Panel derecho (resultados)
        right_panel = ttk.Frame(self.main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configurar paneles
        self._create_config_panel(left_panel)
        self._create_results_panel(right_panel)
    
    def _create_config_panel(self, parent):
        """Crea el panel de configuración"""
        config_frame = ttk.LabelFrame(parent, text=TEXTS['config_section'], padding=5)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Sección de archivos
        file_frame = ttk.LabelFrame(config_frame, text=TEXTS['files_section'], padding=5)
        file_frame.pack(fill=tk.X, padx=5, pady=3)
        
        # Archivo de IPs
        ttk.Label(file_frame, text=TEXTS['ips_file']).pack(anchor=tk.W)
        ip_container = ttk.Frame(file_frame)
        ip_container.pack(fill=tk.X, pady=2)
        
        self.ip_file_entry = ttk.Entry(ip_container)
        self.ip_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ip_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "ip.txt"))
        
        ttk.Button(ip_container, text="...", width=3,
                  command=lambda: self.browse_file(self.ip_file_entry)).pack(side=tk.RIGHT, padx=3)
        
        self.ip_count_label = ttk.Label(file_frame, text="0 IPs cargadas")
        self.ip_count_label.pack(anchor=tk.W)
        
        # Archivo de credenciales
        ttk.Label(file_frame, text=TEXTS['creds_file']).pack(anchor=tk.W, pady=(5,0))
        creds_container = ttk.Frame(file_frame)
        creds_container.pack(fill=tk.X, pady=2)
        
        self.creds_file_entry = ttk.Entry(creds_container)
        self.creds_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.creds_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "creds.txt"))
        
        ttk.Button(creds_container, text="...", width=3,
                  command=lambda: self.browse_file(self.creds_file_entry)).pack(side=tk.RIGHT, padx=3)
        
        self.creds_count_label = ttk.Label(file_frame, text="0 credenciales cargadas")
        self.creds_count_label.pack(anchor=tk.W)
        
        # Sección de parámetros
        params_frame = ttk.LabelFrame(config_frame, text=TEXTS['params_section'], padding=5)
        params_frame.pack(fill=tk.X, padx=5, pady=3)
        
        # Campos de parámetros
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
        
        # Opciones de escaneo
        options_frame = ttk.Frame(params_frame)
        options_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)
        
        self.check_ssh_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="SSH", 
                       variable=self.check_ssh_var).pack(side=tk.LEFT, padx=3)
        
        self.check_rdp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="RDP", 
                       variable=self.check_rdp_var).pack(side=tk.LEFT, padx=3)
        
        self.full_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Escaneo completo", 
                       variable=self.full_scan_var).pack(side=tk.LEFT, padx=3)
        
        # Botón guardar configuración
        ttk.Button(config_frame, text="Guardar Configuración", 
                  command=self.save_config).pack(pady=5)
    
    def _create_results_panel(self, parent):
        """Crea el panel de resultados"""
        # Estadísticas
        stats_frame = ttk.LabelFrame(parent, text=TEXTS['stats_section'], padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)
        
        # Primera fila de estadísticas
        row1 = ttk.Frame(stats_grid)
        row1.pack(fill=tk.X, pady=2)
        
        self.stats_labels['ips'] = ttk.Label(row1, text=TEXTS['stats_ips'].format(count=0))
        self.stats_labels['ips'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        self.stats_labels['activas'] = ttk.Label(row1, text=TEXTS['stats_active'].format(count=0))
        self.stats_labels['activas'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        self.stats_labels['puertos'] = ttk.Label(row1, text=TEXTS['stats_ports'].format(count=0))
        self.stats_labels['puertos'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        # Segunda fila de estadísticas
        row2 = ttk.Frame(stats_grid)
        row2.pack(fill=tk.X, pady=2)
        
        self.stats_labels['creds'] = ttk.Label(row2, text=TEXTS['stats_creds'].format(count=0))
        self.stats_labels['creds'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        self.stats_labels['tiempo'] = ttk.Label(row2, text=TEXTS['stats_time'].format(time="00:00:00"))
        self.stats_labels['tiempo'].pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        # Gráfico de progreso
        self.progress_chart = tk.Canvas(stats_frame, bg=COLORS['text_bg'], height=50)
        self.progress_chart.pack(fill=tk.X, pady=5)
        
        # Controles de escaneo
        self._create_scan_controls(parent)
        
        # Barra de progreso
        self.progress = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=3)
        
        # Pestañas de resultados
        self._create_result_tabs(parent)
        
        # Botones de exportación
        self._create_export_buttons(parent)
    
    def _create_scan_controls(self, parent):
        """Crea los controles de escaneo"""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=5, pady=3)
        
        btn_container = ttk.Frame(control_frame)
        btn_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.start_button = ttk.Button(btn_container, text=TEXTS['scan_start'],
                                      command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=3)
        
        self.stop_button = ttk.Button(btn_container, text=TEXTS['scan_stop'],
                                     state=tk.DISABLED, command=self.stop_scanning)
        self.stop_button.pack(side=tk.LEFT, padx=3)
        
        self.scan_method = ttk.Combobox(control_frame, 
                                       values=TEXTS['scan_methods'], 
                                       state="readonly")
        self.scan_method.set(TEXTS['scan_methods'][1])
        self.scan_method.pack(side=tk.RIGHT, padx=10)
    
    def _create_result_tabs(self, parent):
        """Crea las pestañas de resultados"""
        results_notebook = ttk.Notebook(parent)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Pestaña de logs
        log_frame = ttk.Frame(results_notebook)
        results_notebook.add(log_frame, text=TEXTS['tab_log'])
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD,
                                                 bg=COLORS['text_bg'],
                                                 fg=COLORS['fg_main'],
                                                 insertbackground=COLORS['fg_main'])
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña de IPs
        ip_frame = ttk.Frame(results_notebook)
        results_notebook.add(ip_frame, text=TEXTS['tab_ips'])
        self.ip_text = scrolledtext.ScrolledText(ip_frame, wrap=tk.WORD,
                                                bg=COLORS['text_bg'],
                                                fg=COLORS['fg_main'],
                                                insertbackground=COLORS['fg_main'])
        self.ip_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña de Puertos
        ports_frame = ttk.Frame(results_notebook)
        results_notebook.add(ports_frame, text=TEXTS['tab_ports'])
        self.ports_text = scrolledtext.ScrolledText(ports_frame, wrap=tk.WORD,
                                                   bg=COLORS['text_bg'],
                                                   fg=COLORS['fg_main'],
                                                   insertbackground=COLORS['fg_main'])
        self.ports_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña de SSH
        ssh_frame = ttk.Frame(results_notebook)
        results_notebook.add(ssh_frame, text=TEXTS['tab_ssh'])
        self.ssh_text = scrolledtext.ScrolledText(ssh_frame, wrap=tk.WORD,
                                                 bg=COLORS['text_bg'],
                                                 fg=COLORS['fg_main'],
                                                 insertbackground=COLORS['fg_main'])
        self.ssh_text.pack(fill=tk.BOTH, expand=True)
        
        # Pestaña de RDP
        rdp_frame = ttk.Frame(results_notebook)
        results_notebook.add(rdp_frame, text=TEXTS['tab_rdp'])
        self.rdp_text = scrolledtext.ScrolledText(rdp_frame, wrap=tk.WORD,
                                                 bg=COLORS['text_bg'],
                                                 fg=COLORS['fg_main'],
                                                 insertbackground=COLORS['fg_main'])
        self.rdp_text.pack(fill=tk.BOTH, expand=True)
    
    def _create_export_buttons(self, parent):
        """Crea botones de exportación"""
        export_frame = ttk.Frame(parent)
        export_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Button(export_frame, text=TEXTS['export_ips'],
                  command=lambda: self.export_results("ip_activas.txt")).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(export_frame, text=TEXTS['export_ports'],
                  command=lambda: self.export_results("puertos_abiertos.txt")).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(export_frame, text=TEXTS['export_ssh'],
                  command=lambda: self.export_results("ssh_success.txt")).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(export_frame, text=TEXTS['export_rdp'],
                  command=lambda: self.export_results("rdp_success.txt")).pack(side=tk.LEFT, padx=2)
    
    # ============================================================================
    # MÉTODOS DE LA INTERFAZ
    # ============================================================================
    
    def start_move(self, event):
        """Inicia el movimiento de la ventana"""
        self.x = event.x
        self.y = event.y
    
    def stop_move(self, event):
        """Detiene el movimiento de la ventana"""
        self.x = None
        self.y = None
    
    def on_motion(self, event):
        """Maneja el movimiento de la ventana"""
        if self.x is not None and self.y is not None:
            x = (event.x_root - self.x)
            y = (event.y_root - self.y)
            self.root.geometry(f"+{x}+{y}")
    
    def browse_file(self, entry_widget):
        """Abre diálogo para seleccionar archivo"""
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
            self.update_file_counts()
    
    def update_file_counts(self):
        """Actualiza los contadores de archivos"""
        # Contar IPs
        if self.ip_file_entry:
            ip_file = self.ip_file_entry.get()
            ip_count = 0
            if os.path.exists(ip_file):
                ip_count = len(self.network_scanner.load_ips_from_file(ip_file))
            if self.ip_count_label:
                self.ip_count_label.config(text=f"{ip_count} IPs cargadas")
        
        # Contar credenciales
        if self.creds_file_entry:
            creds_file = self.creds_file_entry.get()
            creds_count = 0
            if os.path.exists(creds_file):
                creds_count = len(self.network_scanner.load_credentials_from_file(creds_file))
            if self.creds_count_label:
                self.creds_count_label.config(text=f"{creds_count} credenciales cargadas")
    
    def load_default_config(self):
        """Carga la configuración por defecto"""
        config_path = os.path.join(os.path.dirname(__file__), "config.cfg")
        config = configparser.ConfigParser()
        
        if os.path.exists(config_path):
            config.read(config_path)
        else:
            config["General"] = {k: str(v) for k, v in DEFAULT_CONFIG.items() 
                               if k in ['threads', 'timeout', 'attempts', 'default_port']}
            config["General"]["CHECK_SSH"] = "True"
            config["General"]["CHECK_RDP"] = "True"
            config["General"]["FULL_SCAN"] = "False"
            
            config["Performance"] = {k: str(v) for k, v in DEFAULT_CONFIG.items() 
                                   if k in ['max_pending', 'update_interval', 'batch_size']}
            
            with open(config_path, 'w') as configfile:
                config.write(configfile)
        
        # Cargar valores en campos si existen
        if self.threads_entry:
            self.threads_entry.delete(0, tk.END)
            self.threads_entry.insert(0, config.get("General", "Threads", 
                                                  fallback=str(DEFAULT_CONFIG['threads'])))
        
        if self.timeout_entry:
            self.timeout_entry.delete(0, tk.END)
            self.timeout_entry.insert(0, config.get("General", "Timeout",
                                                  fallback=str(DEFAULT_CONFIG['timeout'])))
        
        if self.attempts_entry:
            self.attempts_entry.delete(0, tk.END)
            self.attempts_entry.insert(0, config.get("General", "Attempts",
                                                   fallback=str(DEFAULT_CONFIG['attempts'])))
        
        if self.default_port_entry:
            self.default_port_entry.delete(0, tk.END)
            self.default_port_entry.insert(0, config.get("General", "DEFAULTPORT",
                                                       fallback=str(DEFAULT_CONFIG['default_port'])))
        
        # Cargar opciones booleanas
        if self.check_ssh_var:
            self.check_ssh_var.set(config.getboolean("General", "CHECK_SSH", fallback=True))
        
        if self.check_rdp_var:
            self.check_rdp_var.set(config.getboolean("General", "CHECK_RDP", fallback=True))
        
        if self.full_scan_var:
            self.full_scan_var.set(config.getboolean("General", "FULL_SCAN", fallback=False))
        
        # Actualizar configuración del scanner
        if self.threads_entry and self.timeout_entry and self.attempts_entry and self.default_port_entry:
            self.network_scanner.config.update({
                "threads": int(self.threads_entry.get()),
                "timeout": int(self.timeout_entry.get()),
                "attempts": int(self.attempts_entry.get()),
                "default_port": int(self.default_port_entry.get()),
                "check_ssh": self.check_ssh_var.get() if self.check_ssh_var else True,
                "check_rdp": self.check_rdp_var.get() if self.check_rdp_var else True,
                "full_scan": self.full_scan_var.get() if self.full_scan_var else False
            })
    
    def save_config(self):
        """Guarda la configuración actual"""
        config = configparser.ConfigParser()
        
        config["General"] = {
            "Threads": self.threads_entry.get() if self.threads_entry else "20",
            "Timeout": self.timeout_entry.get() if self.timeout_entry else "10",
            "Attempts": self.attempts_entry.get() if self.attempts_entry else "2",
            "DEFAULTPORT": self.default_port_entry.get() if self.default_port_entry else "3389",
            "CHECK_SSH": str(self.check_ssh_var.get()) if self.check_ssh_var else "True",
            "CHECK_RDP": str(self.check_rdp_var.get()) if self.check_rdp_var else "True",
            "FULL_SCAN": str(self.full_scan_var.get()) if self.full_scan_var else "False"
        }
        
        config["Performance"] = {
            "max_pending_tasks": str(DEFAULT_CONFIG['max_pending']),
            "update_interval": str(DEFAULT_CONFIG['update_interval']),
            "batch_size": str(DEFAULT_CONFIG['batch_size'])
        }
        
        config_path = os.path.join(os.path.dirname(__file__), "config.cfg")
        with open(config_path, 'w') as configfile:
            config.write(configfile)
        
        self.load_default_config()
        messagebox.showinfo("Configuración", "Configuración guardada correctamente")
    
    def log_message(self, message):
        """Registra un mensaje en el log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_buffer.append(f"[{timestamp}] {message}\n")
    
    def _flush_log_buffer(self):
        """Vuelca el buffer de logs a la interfaz"""
        if self._log_buffer and self.log_text:
            self.log_text.insert(tk.END, ''.join(self._log_buffer))
            self.log_text.see(tk.END)
            self._log_buffer.clear()
        self.root.after(self.network_scanner.config.get('update_interval', 100), 
                       self._flush_log_buffer)
    
    def _process_results(self):
        """Procesa resultados de la cola"""
        while not self._result_queue.empty():
            result_type, data = self._result_queue.get()
            
            # Actualizar widget correspondiente
            if result_type == "ip" and self.ip_text:
                self.ip_text.insert(tk.END, data + '\n')
                self.ip_text.see(tk.END)
                if 'activas' in self.stats_labels:
                    count = len(self.ip_text.get("1.0", tk.END).splitlines())
                    self.update_stat('activas', count)
            
            elif result_type == "port" and self.ports_text:
                self.ports_text.insert(tk.END, data + '\n')
                self.ports_text.see(tk.END)
                if 'puertos' in self.stats_labels:
                    count = len(self.ports_text.get("1.0", tk.END).splitlines())
                    self.update_stat('puertos', count)
            
            elif result_type == "ssh" and self.ssh_text:
                self.ssh_text.insert(tk.END, data + '\n')
                self.ssh_text.see(tk.END)
                if 'creds' in self.stats_labels:
                    ssh_count = len(self.ssh_text.get("1.0", tk.END).splitlines())
                    rdp_count = len(self.rdp_text.get("1.0", tk.END).splitlines()) if self.rdp_text else 0
                    self.update_stat('creds', ssh_count + rdp_count)
            
            elif result_type == "rdp" and self.rdp_text:
                self.rdp_text.insert(tk.END, data + '\n')
                self.rdp_text.see(tk.END)
                if 'creds' in self.stats_labels:
                    ssh_count = len(self.ssh_text.get("1.0", tk.END).splitlines()) if self.ssh_text else 0
                    rdp_count = len(self.rdp_text.get("1.0", tk.END).splitlines())
                    self.update_stat('creds', ssh_count + rdp_count)
        
        self.root.after(self.network_scanner.config.get('update_interval', 100), 
                       self._process_results)
    
    def update_stat(self, stat, value):
        """Actualiza una estadística en la interfaz"""
        if stat in self.stats_labels:
            text = self.stats_labels[stat].cget("text").split(":")[0]
            self.stats_labels[stat].config(text=f"{text}: {value}")
    
    def start_scan(self):
        """Inicia el escaneo de red"""
        if self.scanning:
            return
        
        self.scanning = True
        self.network_scanner.is_scanning = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        
        # Limpiar resultados anteriores
        if self.log_text:
            self.log_text.delete(1.0, tk.END)
        if self.ip_text:
            self.ip_text.delete(1.0, tk.END)
        if self.ports_text:
            self.ports_text.delete(1.0, tk.END)
        if self.ssh_text:
            self.ssh_text.delete(1.0, tk.END)
        if self.rdp_text:
            self.rdp_text.delete(1.0, tk.END)
        
        # Reiniciar estadísticas
        for stat in self.stats_labels:
            text = self.stats_labels[stat].cget("text").split(":")[0]
            self.stats_labels[stat].config(text=f"{text}: 0")
        
        # Configurar tipo de escaneo
        if self.scan_method:
            method = self.scan_method.get()
            if method == "Rápido":
                self.network_scanner.config["full_scan"] = False
            elif method == "Completo":
                self.network_scanner.config["full_scan"] = True
            else:
                self.network_scanner.config["full_scan"] = DEFAULT_CONFIG['full_scan']
        
        # Actualizar configuración
        if (self.threads_entry and self.timeout_entry and 
            self.attempts_entry and self.default_port_entry and
            self.check_ssh_var and self.check_rdp_var):
            
            self.network_scanner.config.update({
                "threads": int(self.threads_entry.get()),
                "timeout": int(self.timeout_entry.get()),
                "attempts": int(self.attempts_entry.get()),
                "default_port": int(self.default_port_entry.get()),
                "check_ssh": self.check_ssh_var.get(),
                "check_rdp": self.check_rdp_var.get()
            })
        
        # Iniciar temporizador
        self.start_time = datetime.now()
        self.update_timer()
        
        # Ejecutar escaneo en hilo separado
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()
    
    def update_timer(self):
        """Actualiza el temporizador de escaneo"""
        if self.scanning and 'tiempo' in self.stats_labels:
            elapsed = datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]
            self.stats_labels['tiempo'].config(text=f"Tiempo transcurrido: {elapsed_str}")
            self.root.after(1000, self.update_timer)
    
    def stop_scanning(self):
        """Detiene el escaneo en curso"""
        self.network_scanner.stop_scan()
        self.log_message("Deteniendo escaneo...")
    
    async def perform_scan(self):
        """Realiza el escaneo completo"""
        try:
            # Cargar IPs y credenciales
            if not self.ip_file_entry or not self.creds_file_entry:
                self.log_message("Error: Campos de archivos no configurados")
                return
                
            ips = self.network_scanner.load_ips_from_file(self.ip_file_entry.get())
            credentials = self.network_scanner.load_credentials_from_file(self.creds_file_entry.get())
            
            if not ips:
                self.log_message("Error: No se encontraron IPs válidas")
                return
            
            self.log_message(f"Iniciando escaneo de {len(ips)} IPs...")
            
            # Determinar puertos a escanear
            if self.network_scanner.config.get("full_scan", False):
                ports_to_scan = list(range(1, 65536))
            else:
                ports_to_scan = COMMON_PORTS.copy()
                if self.network_scanner.config.get("check_rdp", True):
                    ports_to_scan.append(self.network_scanner.config.get("default_port", 3389))
            
            # Escanear cada rango/IP
            for ip_range in ips:
                if self.network_scanner.should_stop:
                    break
                
                self.log_message(f"Escaneando: {ip_range}")
                active_ips = await self.network_scanner.scan_ip_range(ip_range, ports_to_scan)
                
                for ip in active_ips:
                    if self.network_scanner.should_stop:
                        break
                    
                    self._result_queue.put(("ip", ip))
                    
                    # Escanear puertos en IP activa
                    open_ports = await self.network_scanner.scan_ports_on_ip(ip, ports_to_scan)
                    
                    if open_ports:
                        self._result_queue.put(("port", f"{ip}: {', '.join(map(str, open_ports))}"))
                        
                        # Probar servicios
                        if 22 in open_ports and self.network_scanner.config.get("check_ssh", True):
                            valid_creds = await self.network_scanner.brute_force_service(
                                ip, 22, credentials, 'ssh')
                            for user, password in valid_creds:
                                self._result_queue.put(("ssh", f"{ip}:22 - {user}:{password}"))
                        
                        rdp_port = self.network_scanner.config.get("default_port", 3389)
                        if rdp_port in open_ports and self.network_scanner.config.get("check_rdp", True):
                            valid_creds = await self.network_scanner.brute_force_service(
                                ip, rdp_port, credentials, 'rdp')
                            for user, password in valid_creds:
                                self._result_queue.put(("rdp", f"{ip}:{rdp_port} - {user}:{password}"))
            
            self.log_message("Escaneo completado")
            
        except Exception as e:
            self.log_message(f"Error durante el escaneo: {str(e)}")
    
    def run_scan(self):
        """Ejecuta el escaneo en el loop de asyncio"""
        async def scan_wrapper():
            await self.perform_scan()
            self.scanning = False
            self.network_scanner.is_scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            if not self.network_scanner.should_stop:
                self.log_message("Escaneo finalizado exitosamente")
                self.save_scan_history()
            else:
                self.log_message("Escaneo detenido por el usuario")
                self.network_scanner.reset_scan()
        
        try:
            self.loop.run_until_complete(scan_wrapper())
        except Exception as e:
            self.log_message(f"Error crítico: {str(e)}")
            self.scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
    
    def save_scan_history(self):
        """Guarda el historial del escaneo"""
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'config': self.network_scanner.config.copy(),
            'results': {
                'active_ips': len(self.ip_text.get("1.0", tk.END).splitlines()) if self.ip_text else 0,
                'open_ports': len(self.ports_text.get("1.0", tk.END).splitlines()) if self.ports_text else 0,
                'ssh_creds': len(self.ssh_text.get("1.0", tk.END).splitlines()) if self.ssh_text else 0,
                'rdp_creds': len(self.rdp_text.get("1.0", tk.END).splitlines()) if self.rdp_text else 0,
            }
        }
        self.scan_history.append(history_entry)
    
    def export_results(self, filename):
        """Exporta resultados a archivo"""
        content = ""
        
        # Obtener contenido según el tipo
        if filename == "ip_activas.txt" and self.ip_text:
            content = self.ip_text.get(1.0, tk.END)
        elif filename == "puertos_abiertos.txt" and self.ports_text:
            content = self.ports_text.get(1.0, tk.END)
        elif filename == "ssh_success.txt" and self.ssh_text:
            content = self.ssh_text.get(1.0, tk.END)
        elif filename == "rdp_success.txt" and self.rdp_text:
            content = self.rdp_text.get(1.0, tk.END)
        
        if not content.strip():
            messagebox.showwarning("Exportar", f"No hay datos para exportar a {filename}")
            return
        
        # Pedir ubicación para guardar
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=filename,
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        
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
