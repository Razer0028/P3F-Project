<?php
session_save_path('/var/lib/php/portctl-sessions');
session_start();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];

function send_request($data) {
    $sock = @stream_socket_client('unix:///run/portctl.sock', $errno, $errstr, 5);
    if (!$sock) return ['status' => 'error', 'message' => "接続エラー: $errstr"];
    stream_set_timeout($sock, 10);
    fwrite($sock, json_encode($data));
    $response = '';
    while (!feof($sock)) {
        $chunk = fread($sock, 8192);
        if ($chunk === false || $chunk === '') break;
        $response .= $chunk;
    }
    fclose($sock);
    return json_decode($response, true) ?: ['status' => 'error', 'message' => '無効なレスポンス'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['csrf_token']) && hash_equals($csrf_token, $_POST['csrf_token'])) {
    $action = $_POST['action'] ?? '';
    $result = null;
    
    switch ($action) {
        case 'add_forward':
            $result = send_request([
                'action' => 'add_forward',
                'ext_port' => $_POST['ext_port'] ?? '',
                'protocol' => $_POST['protocol'] ?? 'tcp',
                'dest_ip' => $_POST['dest_ip'] ?? '',
                'dest_port' => $_POST['dest_port'] ?? ''
            ]);
            break;
        
        case 'delete_forward':
            $result = send_request(['action' => 'delete_forward', 'id' => $_POST['id'] ?? '']);
            break;
        
        case 'add_ufw':
            $rule_type = $_POST['rule_type'] ?? 'allow';
            $port = trim($_POST['port'] ?? '');
            $proto = $_POST['proto'] ?? '';
            $from_ip = trim($_POST['from_ip'] ?? '');
            $to_ip = trim($_POST['to_ip'] ?? '');
            
            $rule_parts = [$rule_type];
            
            if (!empty($from_ip)) {
                $rule_parts[] = 'from';
                $rule_parts[] = $from_ip;
            }
            
            if (!empty($to_ip)) {
                $rule_parts[] = 'to';
                $rule_parts[] = $to_ip;
            } elseif (!empty($port)) {
                $rule_parts[] = 'to';
                $rule_parts[] = 'any';
            }
            
            if (!empty($port)) {
                $rule_parts[] = 'port';
                $rule_parts[] = $port;
            }
            
            if (!empty($proto) && !empty($port)) {
                $rule_parts[] = 'proto';
                $rule_parts[] = $proto;
            }
            
            $rule = implode(' ', $rule_parts);
            
            if ($rule === $rule_type || $rule === "$rule_type to any") {
                $result = ['status' => 'error', 'message' => 'ポートまたはIPを指定してください'];
            } else {
                $result = send_request(['action' => 'add_ufw', 'rule' => $rule]);
            }
            break;
        
        case 'add_ufw_raw':
            $result = send_request(['action' => 'add_ufw', 'rule' => $_POST['raw_rule'] ?? '']);
            break;
        
        case 'delete_ufw':
            $result = send_request(['action' => 'delete_ufw', 'num' => $_POST['num'] ?? '']);
            break;
    }
    
    if ($result) {
        $_SESSION['flash_message'] = $result['message'] ?? ($result['status'] === 'ok' ? '成功' : 'エラー');
        $_SESSION['flash_type'] = $result['status'] === 'ok' ? 'success' : 'error';
    }
    
    $tab = $_POST['current_tab'] ?? 'forward';
    header("Location: ?tab=" . urlencode($tab));
    exit;
}

$message = $_SESSION['flash_message'] ?? '';
$message_type = $_SESSION['flash_type'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_type']);

$forward_rules = send_request(['action' => 'list_forward']);
$ufw_rules = send_request(['action' => 'list_ufw']);
$tab = $_GET['tab'] ?? 'forward';
$config = [];
if (is_readable('/etc/portctl/config.json')) {
    $decoded = json_decode(file_get_contents('/etc/portctl/config.json'), true);
    if (is_array($decoded)) {
        $config = $decoded;
    }
}
$default_dest_ip = $config['default_dest_ip'] ?? '10.100.0.2';
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Port Forward Manager</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
            background: #1a1a2e; color: #eaeaea; min-height: 100vh; padding: 20px;
        }
        .container { max-width: 900px; margin: 0 auto; }
        h1 { 
            text-align: center; color: #4fc3f7; margin-bottom: 24px; 
            font-size: 1.6rem; font-weight: 500; letter-spacing: 1px;
        }
        .tabs { display: flex; gap: 4px; margin-bottom: 0; }
        .tab {
            flex: 1; padding: 14px 20px; text-align: center; 
            background: #252542; border: 1px solid #3a3a5c; border-bottom: none;
            border-radius: 8px 8px 0 0; cursor: pointer;
            font-size: 0.95rem; color: #9e9eb8; text-decoration: none; 
            transition: all 0.2s;
        }
        .tab:hover { background: #2d2d4a; color: #c5c5dc; }
        .tab.active { background: #2d2d4a; color: #4fc3f7; border-color: #4a4a6a; }
        .card {
            background: #2d2d4a; border: 1px solid #3a3a5c; border-top: none;
            border-radius: 0 0 8px 8px; padding: 24px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        }
        .card h2 {
            font-size: 1rem; color: #b8b8d0; margin-bottom: 16px;
            padding-bottom: 10px; border-bottom: 1px solid #3a3a5c;
            font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .form-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 16px; }
        .form-group { flex: 1; min-width: 140px; }
        .form-group label { 
            display: block; font-size: 0.8rem; color: #8888a8; 
            margin-bottom: 6px; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .form-group input, .form-group select {
            width: 100%; padding: 10px 12px; 
            background: #1a1a2e; border: 1px solid #3a3a5c;
            border-radius: 4px; font-size: 0.95rem; color: #eaeaea;
            transition: border-color 0.2s;
        }
        .form-group input::placeholder { color: #5a5a7a; }
        .form-group input:focus, .form-group select:focus {
            outline: none; border-color: #4fc3f7;
        }
        .form-group select { cursor: pointer; }
        .form-group select option { background: #1a1a2e; }
        .hint { font-size: 0.7rem; color: #6a6a8a; margin-top: 4px; }
        .btn {
            padding: 10px 24px; border: none; border-radius: 4px;
            font-size: 0.9rem; cursor: pointer; transition: all 0.2s;
            text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500;
        }
        .btn-primary { background: #4fc3f7; color: #1a1a2e; }
        .btn-primary:hover { background: #3ba8d8; }
        .btn-danger { 
            background: transparent; color: #f06292; 
            border: 1px solid #f06292; padding: 6px 12px; font-size: 0.8rem; 
        }
        .btn-danger:hover { background: #f06292; color: #1a1a2e; }
        .message { 
            padding: 12px 16px; border-radius: 4px; margin-bottom: 20px; 
            font-size: 0.9rem; border: 1px solid;
        }
        .message.success { background: rgba(76,175,80,0.15); color: #81c784; border-color: #4caf50; }
        .message.error { background: rgba(244,67,54,0.15); color: #e57373; border-color: #f44336; }
        table { width: 100%; border-collapse: collapse; margin-top: 16px; }
        th, td { 
            padding: 12px; text-align: left; 
            border-bottom: 1px solid #3a3a5c; 
        }
        th { 
            background: #252542; font-weight: 500; color: #9e9eb8; 
            text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.5px;
        }
        tr:hover { background: #353560; }
        .empty { text-align: center; color: #6a6a8a; padding: 32px; }
        .section { margin-bottom: 28px; }
        .example { 
            background: #252542; padding: 10px 14px; border-radius: 4px; 
            font-size: 0.8rem; color: #7a7a9a; margin-top: 12px;
            border-left: 3px solid #4fc3f7;
        }
        .example code { color: #9e9eb8; }
    </style>
</head>
<body>
<div class="container">
    <h1>Port Forward Manager</h1>
    
    <?php if ($message): ?>
    <div class="message <?= htmlspecialchars($message_type) ?>"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    
    <div class="tabs">
        <a href="?tab=forward" class="tab <?= $tab === 'forward' ? 'active' : '' ?>">Port Forwarding</a>
        <a href="?tab=ufw" class="tab <?= $tab === 'ufw' ? 'active' : '' ?>">UFW Rules</a>
    </div>
    
    <?php if ($tab === 'forward'): ?>
    <div class="card">
        <h2>Add Forwarding Rule</h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
            <input type="hidden" name="action" value="add_forward">
            <input type="hidden" name="current_tab" value="forward">
            <div class="form-row">
                <div class="form-group">
                    <label>External Port</label>
                    <input type="text" name="ext_port" placeholder="8080 or 8080:8090" required>
                </div>
                <div class="form-group">
                    <label>Protocol</label>
                    <select name="protocol">
                        <option value="tcp">TCP</option>
                        <option value="udp">UDP</option>
                        <option value="both">TCP+UDP</option>
                    </select>
                </div>
                <div class="form-group">
                    <label>Destination IP</label>
                    <input type="text" name="dest_ip" value="<?= htmlspecialchars($default_dest_ip) ?>">
                </div>
                <div class="form-group">
                    <label>Destination Port</label>
                    <input type="text" name="dest_port" placeholder="8080" required>
                </div>
            </div>
            <button type="submit" class="btn btn-primary">Add Rule</button>
        </form>
        
        <h2 style="margin-top: 28px;">Current Rules</h2>
        <?php if (!empty($forward_rules['rules'])): ?>
        <table>
            <tr><th>External Port</th><th>Protocol</th><th>Destination</th><th></th></tr>
            <?php foreach ($forward_rules['rules'] as $rule): ?>
            <tr>
                <td><?= htmlspecialchars($rule['ext_port']) ?></td>
                <td><?= strtoupper(htmlspecialchars($rule['protocol'])) ?></td>
                <td><?= htmlspecialchars($rule['dest_ip']) ?>:<?= htmlspecialchars($rule['dest_port']) ?></td>
                <td>
                    <form method="POST" style="display:inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <input type="hidden" name="action" value="delete_forward">
                        <input type="hidden" name="current_tab" value="forward">
                        <input type="hidden" name="id" value="<?= htmlspecialchars($rule['id']) ?>">
                        <button type="submit" class="btn btn-danger" onclick="return confirm('Delete this rule?')">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        <?php else: ?>
        <div class="empty">No rules configured</div>
        <?php endif; ?>
    </div>
    
    <?php else: ?>
    <div class="card">
        <div class="section">
            <h2>Quick Add</h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="action" value="add_ufw">
                <input type="hidden" name="current_tab" value="ufw">
                <div class="form-row">
                    <div class="form-group">
                        <label>Rule Type</label>
                        <select name="rule_type">
                            <option value="allow">Allow</option>
                            <option value="deny">Deny</option>
                            <option value="limit">Limit</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Port</label>
                        <input type="text" name="port" placeholder="22 or 8080:8090">
                    </div>
                    <div class="form-group">
                        <label>Protocol</label>
                        <select name="proto">
                            <option value="">Any</option>
                            <option value="tcp">TCP</option>
                            <option value="udp">UDP</option>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>From IP (optional)</label>
                        <input type="text" name="from_ip" placeholder="YOUR_ADMIN_CIDR">
                    </div>
                    <div class="form-group">
                        <label>To IP (optional)</label>
                        <input type="text" name="to_ip" placeholder="DEST_IP">
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Add Rule</button>
            </form>
        </div>
        
        <div class="section">
            <h2>Advanced Rule</h2>
            <form method="POST">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                <input type="hidden" name="action" value="add_ufw_raw">
                <input type="hidden" name="current_tab" value="ufw">
                <div class="form-row">
                    <div class="form-group" style="flex: 3;">
                        <label>UFW Command</label>
                        <input type="text" name="raw_rule" placeholder="allow from YOUR_ADMIN_CIDR to any port 22 proto tcp">
                        <div class="hint">Enter arguments after 'ufw'</div>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">Add Rule</button>
                <div class="example">
                    Examples:<br>
                    <code>allow 22/tcp</code><br>
                    <code>allow from YOUR_ADMIN_CIDR</code><br>
                    <code>deny from YOUR_HOST_IP to any port 22</code>
                </div>
            </form>
        </div>
        
        <h2>Current UFW Rules</h2>
        <?php if (!empty($ufw_rules['rules'])): ?>
        <table>
            <tr><th>#</th><th>Rule</th><th></th></tr>
            <?php foreach ($ufw_rules['rules'] as $rule): ?>
            <tr>
                <td><?= htmlspecialchars($rule['num']) ?></td>
                <td><?= htmlspecialchars($rule['rule']) ?></td>
                <td>
                    <form method="POST" style="display:inline">
                        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                        <input type="hidden" name="action" value="delete_ufw">
                        <input type="hidden" name="current_tab" value="ufw">
                        <input type="hidden" name="num" value="<?= htmlspecialchars($rule['num']) ?>">
                        <button type="submit" class="btn btn-danger" onclick="return confirm('Delete this rule?')">Delete</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </table>
        <?php else: ?>
        <div class="empty">No rules configured</div>
        <?php endif; ?>
    </div>
    <?php endif; ?>
</div>
</body>
</html>
