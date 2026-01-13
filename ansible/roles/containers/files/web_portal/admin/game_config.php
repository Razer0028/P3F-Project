<?php
session_start();
$_SESSION['admin_auth'] = true;
require_once __DIR__ . '/../public/scripts/portal_config.php';

function h($s) { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

function run_cmd($cmd, $stdin = null) {
    $desc = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $proc = proc_open($cmd, $desc, $pipes);
    if (!is_resource($proc)) {
        return ['code' => 1, 'stdout' => '', 'stderr' => 'proc_open failed'];
    }
    if ($stdin !== null) {
        fwrite($pipes[0], $stdin);
    }
    fclose($pipes[0]);
    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $code = proc_close($proc);
    return ['code' => $code, 'stdout' => $stdout, 'stderr' => $stderr];
}

$portalConfig = portal_load_config();
$games = [];
$configFiles = [];
foreach (portal_enabled_services($portalConfig, 'game') as $service) {
    $id = $service['id'];
    $games[$id] = ['label' => $service['label'] ?? $id];
    $files = $service['config_files'] ?? [];
    $configFiles[$id] = is_array($files) ? $files : [];
}

$gameKeys = array_keys($games);
$selectedGame = $_GET['game'] ?? ($gameKeys[0] ?? '');
if (!isset($games[$selectedGame])) {
    $selectedGame = $gameKeys[0] ?? '';
}

$filesForGame = $selectedGame ? ($configFiles[$selectedGame] ?? []) : [];
$selectedFile = $_GET['file'] ?? array_key_first($filesForGame);
if ($selectedFile === null || $selectedFile === '' || !isset($filesForGame[$selectedFile])) {
    $selectedFile = array_key_first($filesForGame) ?: '';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['mode'] ?? '') === 'save') {
    if (!hash_equals($_SESSION['csrf'], $_POST['csrf'] ?? '')) {
        $_SESSION['flash'] = "CSRFトークンが無効です";
    } else {
        $game = $_POST['game'] ?? '';
        $file = $_POST['file'] ?? '';
        $content = $_POST['content'] ?? '';
        if (!isset($configFiles[$game][$file]) || $game === '' || $file === '') {
            $_SESSION['flash'] = "❌ 不正なファイルが指定されました";
        } elseif (strlen($content) > 524288) {
            $_SESSION['flash'] = "❌ ファイルサイズが大きすぎます";
        } else {
            $cmd = sprintf(
                'sudo /opt/serveradmin/bin/game_admin.sh config-set %s %s',
                escapeshellarg($game),
                escapeshellarg($file)
            );
            $res = run_cmd($cmd, $content);
            if ($res['code'] === 0) {
                $_SESSION['flash'] = "✅ 設定を保存しました";
            } else {
                $err = trim($res['stderr'] ?: $res['stdout']);
                $_SESSION['flash'] = "❌ 保存に失敗しました: " . ($err ?: 'unknown error');
            }
        }
        $selectedGame = $game ?: $selectedGame;
        $selectedFile = $file ?: $selectedFile;
    }

    $redir = basename(__FILE__) . '?game=' . urlencode($selectedGame) . '&file=' . urlencode($selectedFile);
    header('Location: ' . $redir, true, 303);
    exit;
}

$flash = $_SESSION['flash'] ?? '';
unset($_SESSION['flash']);

$fileContent = '';
$fileError = '';
if ($selectedFile && $selectedGame) {
    $cmd = sprintf(
        'sudo /opt/serveradmin/bin/game_admin.sh config-get %s %s',
        escapeshellarg($selectedGame),
        escapeshellarg($selectedFile)
    );
    $res = run_cmd($cmd);
    if ($res['code'] === 0) {
        $fileContent = $res['stdout'];
    } else {
        $fileError = trim($res['stderr'] ?: $res['stdout']);
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="UTF-8">
<title>ゲーム設定エディタ</title>
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

    <h1 class="title">ゲーム設定エディタ</h1>

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

      <div class="file-tabs">
        <?php foreach ($filesForGame as $key => $label): ?>
          <a href="?game=<?=h($selectedGame)?>&file=<?=h($key)?>" class="<?= $key === $selectedFile ? 'active' : '' ?>">
            <?=h($label)?>
          </a>
        <?php endforeach; ?>
      </div>

      <?php if ($flash): ?>
        <div class="flash"><?=h($flash)?></div>
      <?php endif; ?>

      <div class="card">
        <?php if (empty($filesForGame)): ?>
          <p class="muted">編集対象のファイルがありません。</p>
        <?php else: ?>
          <?php if ($fileError): ?>
            <p class="muted">ファイル読み込みエラー: <?=h($fileError)?></p>
          <?php endif; ?>
          <form method="post">
            <input type="hidden" name="mode" value="save">
            <input type="hidden" name="csrf" value="<?=h($csrf)?>">
            <input type="hidden" name="game" value="<?=h($selectedGame)?>">
            <input type="hidden" name="file" value="<?=h($selectedFile)?>">
            <textarea name="content" spellcheck="false"><?=h($fileContent)?></textarea>
            <div style="margin-top:12px;">
              <button type="submit">保存</button>
              <span class="muted" style="margin-left:10px;">保存後はサーバー再起動が必要な場合があります</span>
            </div>
          </form>
        <?php endif; ?>
      </div>
    <?php endif; ?>
  </div>
</body>
</html>
