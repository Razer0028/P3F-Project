<?php
session_start();
$_SESSION['admin_auth'] = true;
require_once __DIR__ . '/../public/scripts/portal_config.php';

function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

$portalConfig = portal_load_config();
$games = [];
foreach (portal_enabled_services($portalConfig, 'game') as $service) {
    $id = $service['id'];
    $games[$id] = [
        'label' => $service['label'] ?? $id,
        'container' => $service['container'] ?? $id,
        'supports_cmd' => (bool)($service['supports_cmd'] ?? false),
        'tips' => is_array($service['tips'] ?? null) ? $service['tips'] : [],
    ];
}

$gameKeys = array_keys($games);
$selectedGame = $_GET['game'] ?? ($gameKeys[0] ?? '');
if (!isset($games[$selectedGame])) {
    $selectedGame = $gameKeys[0] ?? '';
}

$statusJson = shell_exec('sudo /opt/serveradmin/bin/docker_manage.sh status 2>&1');
$containers = [];
if ($statusJson) {
    $decoded = json_decode($statusJson, true);
    if (is_array($decoded)) $containers = $decoded;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['mode'] ?? '') === 'send_cmd') {
    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        $_SESSION['flash'] = "CSRFトークンが無効です";
    } else {
        $game = $_POST['game'] ?? '';
        $command = trim($_POST['command'] ?? '');
        $command = preg_replace("/[\\r\\n]+/", '', $command);
        if (!isset($games[$game]) || $game === '') {
            $_SESSION['flash'] = "❌ 不正なゲームが指定されました";
        } elseif (!$games[$game]['supports_cmd']) {
            $_SESSION['flash'] = "⚠️ {$games[$game]['label']} はコンソール操作に未対応です";
        } elseif ($command === '') {
            $_SESSION['flash'] = "❌ コマンドが空です";
        } else {
            $cmd = sprintf(
                'sudo /opt/serveradmin/bin/game_admin.sh cmd %s %s',
                escapeshellarg($game),
                escapeshellarg($command)
            );
            $output = [];
            $exit = 0;
            exec($cmd . ' 2>&1', $output, $exit);
            $outText = trim(implode("\n", $output));
            if ($exit === 0) {
                $_SESSION['flash'] = "✅ コマンドを送信しました";
            } else {
                $_SESSION['flash'] = "❌ 実行に失敗しました (code={$exit})";
            }
            $_SESSION['cmd_output'] = $outText !== '' ? $outText : '(no output)';
        }
    }

    header('Location: ' . basename(__FILE__) . '?game=' . urlencode($selectedGame), true, 303);
    exit;
}

$flash = $_SESSION['flash'] ?? '';
$cmdOutput = $_SESSION['cmd_output'] ?? '';
unset($_SESSION['flash'], $_SESSION['cmd_output']);

$gameMeta = $games[$selectedGame] ?? null;
$status = $gameMeta ? ($containers[$gameMeta['container']]['state'] ?? 'unknown') : 'unknown';
$detail = $gameMeta ? ($containers[$gameMeta['container']]['detail'] ?? '') : '';
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>ゲーム管理コンソール</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Zen+Kaku+Gothic+New:wght@400;500;700&display=swap');

:root{
  --bg:#f3f6fb;
  --bg-grad:radial-gradient(circle at 16% 8%,rgba(14,165,164,.18) 0%,transparent 55%),
            radial-gradient(circle at 86% 6%,rgba(59,130,246,.16) 0%,transparent 55%),
            linear-gradient(180deg,#f8fafc 0%,#eef2ff 100%);
  --surface:#ffffff;
  --surface-2:#f1f5f9;
  --border:#e2e8f0;
  --text:#0f172a;
  --text-dim:#475569;
  --accent:#0f766e;
  --accent-2:#1d4ed8;
  --accent-soft:#ccfbf1;
  --danger:#b42318;
  --danger-soft:#fee2e2;
  --radius-lg:18px;
  --radius-md:12px;
  --radius-sm:8px;
  --shadow:0 16px 40px rgba(15,23,42,.1);
  --shadow-soft:0 8px 20px rgba(15,23,42,.08);
  --space-xs:6px;
  --space-sm:10px;
  --space-md:14px;
  --space-lg:18px;
  --fz-11:11px;
  --fz-12:12px;
  --fz-13:13px;
  --fz-14:14px;
  --font-head:"Space Grotesk","Zen Kaku Gothic New",sans-serif;
  --font-body:"Zen Kaku Gothic New","Space Grotesk",sans-serif;
}

*{box-sizing:border-box;-webkit-font-smoothing:antialiased;}
body{
  margin:0;
  min-height:100vh;
  font-family:var(--font-body);
  color:var(--text);
  background:var(--bg);
  background-image:var(--bg-grad);
  background-attachment:fixed;
}

.page{
  max-width:1100px;
  margin:0 auto;
  padding:18px 16px 40px;
  display:flex;
  flex-direction:column;
  gap:var(--space-md);
}

.nav{display:flex;flex-wrap:wrap;gap:8px;}
.nav a{
  text-decoration:none;
  color:var(--text);
  border:1px solid var(--border);
  padding:8px 12px;
  border-radius:999px;
  background:var(--surface);
  font-size:var(--fz-12);
  box-shadow:var(--shadow-soft);
}
.nav a:hover{border-color:var(--accent);color:var(--accent);} 

.title,.page-title,h1{
  font-family:var(--font-head);
  font-size:20px;
  font-weight:700;
  margin:0;
  color:var(--accent);
}

.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:var(--space-lg);align-items:start;}

.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--radius-lg);
  padding:var(--space-lg);
  box-shadow:var(--shadow);
}

.game-tabs,.file-tabs{display:flex;flex-wrap:wrap;gap:8px;}
.game-tabs a,.file-tabs a{
  text-decoration:none;
  padding:8px 12px;
  border-radius:var(--radius-md);
  border:1px solid var(--border);
  background:var(--surface-2);
  color:var(--text);
  font-size:var(--fz-12);
}
.game-tabs a.active,.file-tabs a.active{
  border-color:var(--accent);
  background:var(--accent-soft);
  color:#0f3d3a;
}

.flash{font-size:var(--fz-12);color:var(--accent);} 

label{font-size:var(--fz-12);color:var(--text-dim);} 
input,select,textarea{
  width:100%;
  padding:10px 12px;
  font-size:var(--fz-12);
  border-radius:var(--radius-md);
  border:1px solid var(--border);
  background:#fff;
  color:var(--text);
}
textarea{min-height:140px;resize:vertical;font-family:"Space Grotesk",ui-monospace,SFMono-Regular,Consolas,monospace;} 

button{
  border:0;
  background:var(--accent);
  color:#fff;
  font-weight:600;
  padding:10px 14px;
  border-radius:var(--radius-md);
  cursor:pointer;
  box-shadow:var(--shadow-soft);
}
button:hover{filter:brightness(1.05);} 

.ghost-btn{background:transparent;color:var(--text);border:1px solid var(--border);box-shadow:none;} 

pre{
  margin:0;
  white-space:pre-wrap;
  word-break:break-word;
  font-family:"Space Grotesk",ui-monospace,SFMono-Regular,Consolas,monospace;
  font-size:12px;
}

.muted{color:var(--text-dim);font-size:var(--fz-12);} 

.wrapper{width:100%;max-width:980px;margin:0 auto;padding:32px 20px 48px;text-align:center;} 
.menu-box{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;} 
.menu-btn{
  display:flex;align-items:center;justify-content:center;gap:8px;
  padding:14px 16px;border-radius:var(--radius-lg);background:var(--surface);border:1px solid var(--border);
  color:var(--text);font-weight:600;text-decoration:none;box-shadow:var(--shadow);transition:.15s ease;
}
.menu-btn:hover{border-color:var(--accent);color:var(--accent);} 

.form-row{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px;} 
.log-box{
  background:#0b1220;color:#e2e8f0;border-radius:var(--radius-md);padding:16px;
  font-family:"Space Grotesk",ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;line-height:1.5;
  max-height:520px;overflow:auto;white-space:pre-wrap;word-break:break-word;
}

.table{width:100%;border-collapse:collapse;font-size:var(--fz-12);} 
.table th,.table td{border-bottom:1px solid var(--border);padding:10px 8px;text-align:left;} 
.table th{color:var(--text);font-weight:600;} 
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:var(--fz-11);background:var(--surface-2);color:var(--text-dim);} 
.result-box{white-space:pre-wrap;font-size:var(--fz-12);color:#0f3d3a;background:var(--accent-soft);border:1px solid rgba(15,118,110,.2);border-radius:var(--radius-md);padding:var(--space-sm) var(--space-md);margin-bottom:16px;} 
.action-row{display:flex;gap:12px;flex-wrap:wrap;align-items:center;margin-top:16px;} 
.save-btn{background:var(--accent-2);color:#fff;} 
.note{font-size:var(--fz-11);color:var(--text-dim);} 

.toggle-card{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 14px;border:1px solid var(--border);border-radius:var(--radius-md);background:var(--surface-2);margin-bottom:8px;} 
.switch{position:relative;display:inline-block;width:46px;height:26px;} 
.switch input{opacity:0;width:0;height:0;} 
.slider{position:absolute;cursor:pointer;top:0;left:0;right:0;bottom:0;background:#cbd5f5;border-radius:999px;transition:.2s;} 
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 6px rgba(15,23,42,.2);} 
.switch input:checked + .slider{background:var(--accent);} 
.switch input:checked + .slider:before{transform:translateX(20px);} 

.stars{display:none;}
</style>
</head>
<body>
  <div class="page">
    <div class="nav">
      <a href="/admin/index.php">管理メニュー</a>
      <a href="/admin/docker_panel.php">コンテナ管理</a>
      <a href="/admin/game_console.php">ゲームコンソール</a>
      <a href="/admin/game_config.php">ゲーム設定</a>
      <a href="/admin/log_viewer.php">ログビューア</a>
    </div>

    <h1 class="title">ゲーム管理コンソール</h1>

    <?php if (empty($games)): ?>
      <div class="card">
        <p class="muted">有効なゲームがありません。portal_services.json を確認してください。</p>
      </div>
    <?php else: ?>
      <div class="game-tabs">
        <?php foreach ($games as $key => $info): ?>
          <a href="?game=<?=h($key)?>" class="<?= $key === $selectedGame ? 'active' : '' ?>">
            <?=h($info['label'])?>
          </a>
        <?php endforeach; ?>
      </div>

      <?php if ($flash): ?>
        <div class="flash"><?=h($flash)?></div>
      <?php endif; ?>

      <div class="grid">
        <div class="card">
          <div class="status-pill">
            <span class="status-dot <?= $status === 'running' ? 'running' : '' ?>"></span>
            <span><?=h($gameMeta['label'] ?? 'unknown')?>: <?=h($status)?></span>
          </div>
          <?php if ($detail): ?>
            <div class="muted" style="margin-top:8px;"><?=h($detail)?></div>
          <?php endif; ?>

          <div style="margin-top:16px;">
            <?php if (!($gameMeta['supports_cmd'] ?? false)): ?>
              <p class="muted">このゲームはコンソール操作に未対応です。設定ファイル編集をご利用ください。</p>
            <?php else: ?>
              <form method="post">
                <input type="hidden" name="mode" value="send_cmd">
                <input type="hidden" name="csrf" value="<?=h($csrf)?>">
                <input type="hidden" name="game" value="<?=h($selectedGame)?>">
                <label>コマンド入力</label>
                <textarea name="command" placeholder="例: <?=h($gameMeta['tips'][0] ?? 'command')?>"></textarea>
                <div class="btn-row">
                  <button type="submit">送信</button>
                </div>
              </form>

              <?php if (!empty($gameMeta['tips'])): ?>
                <div class="btn-row" style="margin-top:12px;">
                  <?php foreach ($gameMeta['tips'] as $tip): ?>
                    <form method="post">
                      <input type="hidden" name="mode" value="send_cmd">
                      <input type="hidden" name="csrf" value="<?=h($csrf)?>">
                      <input type="hidden" name="game" value="<?=h($selectedGame)?>">
                      <input type="hidden" name="command" value="<?=h($tip)?>">
                      <button type="submit" class="ghost-btn"><?=h($tip)?></button>
                    </form>
                  <?php endforeach; ?>
                </div>
              <?php endif; ?>
            <?php endif; ?>
          </div>
        </div>

        <div class="card">
          <label>実行結果</label>
          <pre><?=h($cmdOutput ?: '(no output)')?></pre>
        </div>
      </div>
    <?php endif; ?>
  </div>
</body>
</html>
