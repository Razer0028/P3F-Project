#!/usr/bin/env python3
import os
import re
import subprocess
import threading
import time
from datetime import datetime, timedelta
import fcntl
import traceback
import json

# ==========================================
# 設定
# ==========================================

LOG_FILE = '/opt/serveradmin/logs/player_monitor.log'
PID_FILE = '/tmp/player_monitor.pid'
CONFIG_PATH = '/opt/serveradmin/config/portal_services.json'

# Web公開用に現在の状況を出すJSON
STATUS_JSON = '/opt/serveradmin/status/current_players.json'

# 監視対象のDockerコンテナ名 → 論理名(サーバー名)
CONTAINERS = {
    "minecraft_server":    "minecraft",
    "valheim_server":"valheim",
    "7dtd-server":   "7dtd",
    # 追加する場合はここに "container_name": "logical_name",
}

VALHEIM_JOIN_STRICT = [
    r'Got character ZDO ID',
    r'Got character ZDOID',
    r'Got character',  # "Got character ZDOID from <name>" 系も拾う
]

VALHEIM_JOIN_LOOSE = [
    r'new peer',
    r'New peer connected',
    r'New peer connected,sending global keys',
    r'player connected',
]

patterns = {
    'minecraft': {
        'join': [r'joined the game'],
        'leave': [r'left the game'],
    },
    'valheim': {
        'join': [],
        'leave': [
            r'RPC_Disconnect',
            r'peer disconnected',
            r'closing socket',
            r'Socket closed by peer',
            r'Destroying abandoned non persistent zdo',
        ],
    },
    '7dtd': {
        'join': [
            r"joined the game",
            r"GMSG: Player '.*' joined the game",
            r"Player .* connected",
        ],
        'leave': [
            r"disconnected",
            r"GMSG: Player '.*' left the game",
            r"Player .* disconnected",
        ],
    },
}

def load_enabled_games():
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception:
        return None

    enabled = data.get('enabled')
    services = data.get('services')
    if not isinstance(enabled, list) or not isinstance(services, dict):
        return None

    games = set()
    for service_id in enabled:
        service = services.get(service_id, {})
        if isinstance(service, dict) and service.get('type') == 'game':
            games.add(service_id)
    return games



def load_auto_stop_settings():
    default_enabled = False
    default_minutes = 10
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception:
        return default_enabled, default_minutes

    enabled = data.get('auto_stop_enabled', default_enabled)
    minutes = data.get('auto_stop_minutes', default_minutes)
    try:
        minutes = int(minutes)
    except Exception:
        minutes = default_minutes
    if minutes <= 0:
        minutes = default_minutes
    return bool(enabled), minutes

enabled_games = load_enabled_games()
if enabled_games:
    CONTAINERS = {k: v for k, v in CONTAINERS.items() if v in enabled_games}
    patterns = {k: v for k, v in patterns.items() if k in enabled_games}


# ==========================================
# 状態管理
# ==========================================

class ServerState:
    def __init__(self):
        self.count = 0
        self.zero_time = None
        self.last_event = None
        self.last_event_time = None

state = {srv_name: ServerState() for srv_name in patterns.keys()}
lock = threading.Lock()


# ==========================================
# ログ記録
# ==========================================

def log_event(server: str, event: str, count: int, extra: str = ""):
    """player_monitor.log に1行追記"""
    timestamp = datetime.utcnow().isoformat() + "Z"
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    line = f"{timestamp}, {server}, {event}, {count}"
    if extra:
        line += f", {extra}"
    line += "\n"
    with open(LOG_FILE, 'a') as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line)
        fcntl.flock(f, fcntl.LOCK_UN)


# ==========================================
# JSON出力（公開ポータル用）
# ==========================================

def dump_status_json():
    """
    public_portal.php から読ませる現在ステータスJSONを更新。
    {
      "timestamp": "...Z",
      "servers": {
        "minecraft": { "online": 2, "idle_minutes": 0 },
        "valheim":   { "online": 0, "idle_minutes": 7 },
        "7dtd":      { "online": 1, "idle_minutes": 0 }
      }
    }
    """
    try:
        os.makedirs(os.path.dirname(STATUS_JSON), exist_ok=True)
        now = datetime.utcnow()
        data = {"timestamp": now.isoformat() + "Z", "servers": {}}

        with lock:
            for srv_name, srv_state in state.items():
                if srv_state.count == 0 and srv_state.zero_time is not None:
                    idle_td = now - srv_state.zero_time
                    idle_minutes = int(idle_td.total_seconds() // 60)
                else:
                    idle_minutes = 0
                data["servers"][srv_name] = {
                    "online": srv_state.count,
                    "idle_minutes": idle_minutes,
                }

        tmp_path = STATUS_JSON + ".tmp"
        with open(tmp_path, 'w') as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(data, f, ensure_ascii=False, indent=2)
            fcntl.flock(f, fcntl.LOCK_UN)
        os.replace(tmp_path, STATUS_JSON)

    except Exception as e:
        log_event("system", "dump_status_json_error", 0, extra=str(e))


# ==========================================
# 正規表現準備
# ==========================================

def compile_regex_list(lst): return [re.compile(p, re.IGNORECASE) for p in lst]

compiled_patterns = {
    srv: {
        'join':  compile_regex_list(p['join']),
        'leave': compile_regex_list(p['leave'])
    }
    for srv, p in patterns.items()
}

compiled_valheim_join_strict = compile_regex_list(VALHEIM_JOIN_STRICT)
compiled_valheim_join_loose  = compile_regex_list(VALHEIM_JOIN_LOOSE)


# ==========================================
# ログ解析
# ==========================================

def matches_any(regex_list, text):
    return any(rgx.search(text) for rgx in regex_list)

def handle_line(server_name: str, line: str):
    """ログ1行ごとのjoin/leave検知→状態更新→ログ追記→JSON更新"""
    srv_state = state.get(server_name)
    if not srv_state:
        return

    event = None
    if server_name == 'valheim':
        if matches_any(compiled_valheim_join_strict, line):
            event = 'join'
        elif matches_any(compiled_patterns['valheim']['leave'], line):
            event = 'leave'
        else:
            if matches_any(compiled_valheim_join_loose, line):
                log_event('valheim', 'valheim-conn-setup', srv_state.count, extra=line.strip())
            return
    else:
        if matches_any(compiled_patterns[server_name]['join'], line):
            event = 'join'
        elif matches_any(compiled_patterns[server_name]['leave'], line):
            event = 'leave'
        else:
            return

    now = datetime.utcnow()
    with lock:
        if srv_state.last_event == event and srv_state.last_event_time:
            if (now - srv_state.last_event_time) < timedelta(seconds=1):
                return
        srv_state.last_event = event
        srv_state.last_event_time = now

        if event == 'join':
            srv_state.count += 1
            srv_state.zero_time = None
        elif event == 'leave' and srv_state.count > 0:
            srv_state.count -= 1
            if srv_state.count == 0 and srv_state.zero_time is None:
                srv_state.zero_time = datetime.utcnow()

    log_event(server_name, event, srv_state.count, extra=line.strip())
    dump_status_json()


# ==========================================
# Dockerログ監視
# ==========================================

def docker_logs_follower(container_name: str, server_name: str):
    while True:
        cmd = ['docker', 'logs', '-f', '--tail', '0', container_name]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            while True:
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.1)
                    continue
                handle_line(server_name, line)
        except Exception as e:
            log_event(server_name, 'docker_watch_error',
                      state.get(server_name, ServerState()).count, extra=str(e))
            tb = traceback.format_exc().splitlines()
            for l in tb:
                log_event(server_name, 'traceback', 0, extra=l)
            time.sleep(2)
            continue
        time.sleep(2)


# ==========================================
# 自動停止監視
# ==========================================

def auto_stop_watcher():
    AUTO_STOP_AFTER = timedelta(minutes=10)
    while True:
        now = datetime.utcnow()
        for container_name, server_name in CONTAINERS.items():
            srv_state = state.get(server_name)
            if not srv_state:
                continue
            with lock:
                elapsed = (now - srv_state.zero_time) if (srv_state.count == 0 and srv_state.zero_time) else None
            if auto_stop_enabled and elapsed and elapsed > auto_stop_after:
                try:
                    result = subprocess.run(['docker', 'stop', container_name],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            text=True, timeout=15)
                    if result.returncode == 0:
                        log_event(server_name, 'auto-stop', 0,
                                  extra=f"stopped {container_name}: {result.stdout.strip()}")
                    else:
                        log_event(server_name, 'auto-stop-failed', 0,
                                  extra=f"{container_name}: {result.stderr.strip()}")
                except Exception as e:
                    log_event(server_name, 'auto-stop-failed', 0, extra=f"{container_name}: EXCEPTION {e}")
                with lock:
                    srv_state.zero_time = None
        dump_status_json()
        time.sleep(10)


# ==========================================
# メイン
# ==========================================

def main():
    pid_handle = open(PID_FILE, 'w')
    try:
        fcntl.flock(pid_handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print('player_monitor already running')
        return
    pid_handle.write(str(os.getpid()))
    pid_handle.flush()

    dump_status_json()

    for container_name, server_name in CONTAINERS.items():
        t = threading.Thread(target=docker_logs_follower, args=(container_name, server_name), daemon=True)
        t.start()

    stopper = threading.Thread(target=auto_stop_watcher, daemon=True)
    stopper.start()

    while True:
        time.sleep(5)


if __name__ == '__main__':
    main()
