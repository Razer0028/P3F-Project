<?php
session_start();
header('Content-Type: text/html; charset=UTF-8');
require_once __DIR__ . '/portal_config.php';

/* ===== 設定 ===== */
const WHITELIST_PATH      = '{{ containers_root }}/minecraft/data/whitelist.json';   // ← 修正済み
const PLAYER_STATUS_JSON  = '/opt/serveradmin/status/current_players.json';
const SHOW_WL_DETAILS     = false;
$portalConfig = portal_load_config();
$autoStopEnabled = (bool)($portalConfig['auto_stop_enabled'] ?? false);
$autoStopMinutes = intval($portalConfig['auto_stop_minutes'] ?? 10);
if ($autoStopMinutes <= 0) {
    $autoStopMinutes = 10;
}
$SERVERS = [];
foreach (portal_enabled_services($portalConfig, 'game') as $service) {
    if (!(bool)($service['public'] ?? true)) {
        continue;
    }
    $SERVERS[] = [
        'id'        => $service['id'],
        'label'     => $service['label'] ?? $service['id'],
        'container' => $service['container'] ?? $service['id'],
        'img'       => $service['img'] ?? '/images/soldir.jpg',
        'hostport'  => $service['hostport'] ?? '',
        'howto'     => $service['howto'] ?? '',
        'password'  => $service['password'] ?? null,
        'extra'     => $service['extra'] ?? null,
    ];
}
$minecraftEnabled = false;
foreach ($SERVERS as $srv) {
    if (($srv['id'] ?? '') === 'minecraft') {
        $minecraftEnabled = true;
        break;
    }
}

/* ===== Utility ===== */
function h($s){ return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

/* CSRF */
if (empty($_SESSION['csrf'])) {
    $_SESSION['csrf'] = bin2hex(random_bytes(16));
}
$csrf = $_SESSION['csrf'];

function redirect_self_303(){
    header('Location: '.basename(__FILE__), true, 303);
    exit;
}

function send_discord($msg){
    $webhook = getenv('DISCORD_WEBHOOK_URL');
    if(!$webhook || !filter_var($webhook,FILTER_VALIDATE_URL)){
        return false;
    }
    $ch = curl_init($webhook);
    curl_setopt_array($ch,[
        CURLOPT_POST=>true,
        CURLOPT_POSTFIELDS=>json_encode(['content'=>$msg],JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER=>['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER=>true,
        CURLOPT_TIMEOUT=>6,
    ]);
    curl_exec($ch);
    curl_close($ch);
    return true;
}

/* Mojang UUID 取得 */
function mc_fetch_uuid_hyphenated($name){
    $name = trim($name);
    if(!preg_match('/^[A-Za-z0-9_]{3,16}$/',$name)){
        return [null,'プレイヤー名が不正です（3〜16文字の英数と_）'];
    }

    // Ashcon API（Cloudflare CDN）
    $url = "https://api.ashcon.app/mojang/v2/user/".rawurlencode($name);

    $ch = curl_init($url);
    curl_setopt_array($ch,[
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 6,
        CURLOPT_USERAGENT      => 'public_portal/1.0'
    ]);
    $res = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);

    if($code !== 200 || !$res){
        return [null, 'UUIDを取得できません（ユーザーが存在しない可能性）'];
    }

    $data = json_decode($res, true);
    if(!isset($data['uuid'])){
        return [null, 'UUID取得エラー（データ形式が不正）'];
    }

    // 既にハイフン付きで返ってくるが念のため正規化
    $u = str_replace('-', '', $data['uuid']);
    $hy = substr($u,0,8).'-'.substr($u,8,4).'-'.substr($u,12,4).'-'.substr($u,16,4).'-'.substr($u,20);

    return [$hy, null];
}

/* JSON ロック追記 */
function json_file_lock_append($path,$row){
    $fp=fopen($path,'c+');
    if(!$fp) return false;
    if(!flock($fp,LOCK_EX)){ fclose($fp); return false; }
    $cur=stream_get_contents($fp);
    $arr=$cur?json_decode($cur,true):[];
    if(!is_array($arr)) $arr=[];
    $arr[]=$row;
    ftruncate($fp,0); rewind($fp);
    fwrite($fp,json_encode($arr,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
    fflush($fp); flock($fp,LOCK_UN); fclose($fp);
    return true;
}

/* ホワイトリスト追加 */
function whitelist_add($name,$uuid){
    $fp=fopen(WHITELIST_PATH,'c+');
    if(!$fp) return 'whitelist.jsonを開けません（権限確認）';
    if(!flock($fp,LOCK_EX)){ fclose($fp); return 'whitelist.jsonのロック失敗'; }

    $data=stream_get_contents($fp);
    $arr=$data?json_decode($data,true):[];
    if(!is_array($arr)) $arr=[];

    foreach($arr as $e){
        if(isset($e['name']) && strcasecmp($e['name'],$name)===0){
            flock($fp,LOCK_UN); fclose($fp);
            return 'このプレイヤーは既に登録済みです';
        }
        if(isset($e['uuid']) && strcasecmp($e['uuid'],$uuid)===0){
            flock($fp,LOCK_UN); fclose($fp);
            return 'このUUIDは既に登録済みです';
        }
    }
    $arr[]=['uuid'=>$uuid,'name'=>$name];

    ftruncate($fp,0); rewind($fp);
    fwrite($fp,json_encode($arr,JSON_PRETTY_PRINT|JSON_UNESCAPED_UNICODE));
    fflush($fp); flock($fp,LOCK_UN); fclose($fp);
    return null;
}

/* ホワイトリスト読み込み */
function whitelist_list(){
    if(!is_file(WHITELIST_PATH)) return [];
    $arr=json_decode(@file_get_contents(WHITELIST_PATH),true);
    return is_array($arr)?$arr:[];
}

/* docker コマンド */
function docker_cmd($args){
    $docker = trim((string)shell_exec('command -v docker'));
    if($docker==='') $docker='/usr/bin/docker';

    exec("$docker $args 2>&1",$out,$rc);
    $outStr=implode("\n",$out);

    if($rc!==0 || stripos($outStr,'permission denied')!==false){
        exec("sudo -n $docker $args 2>&1",$out,$rc);
        $outStr=implode("\n",$out);
    }
    return ['out'=>$outStr,'rc'=>$rc];
}

/* dockerコンテナ状態 */
function docker_status($container){
    $c = escapeshellarg($container);
    $run = docker_cmd("inspect -f '{{.State.Running}}' $c");
    $health = docker_cmd("inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' $c");
    return [
        'running' => ($run['rc']===0 && trim($run['out'])==='true'),
        'health'  => ($health['rc']===0 && ($h=trim($health['out']))!=='' && strtolower($h)!=='null') ? $h : null,
    ];
}

/* current players */
function read_current_players(){
    if(!is_file(PLAYER_STATUS_JSON)) return null;
    $data=json_decode(@file_get_contents(PLAYER_STATUS_JSON),true);
    return is_array($data)?$data:null;
}

/* ===== action=status (AJAX) ===== */
if(($_GET['action'] ?? '') === 'status'){
    $list=[];
    foreach($SERVERS as $s){
        $st=docker_status($s['container']);
        $list[$s['id']] = [
            'id'=>$s['id'],
            'label'=>$s['label'],
            'running'=>$st['running'],
            'health'=>$st['health'],
            'hostport'=>$s['hostport'],
        ];
    }
    $players_now=read_current_players();
    echo json_encode([
        'servers'=>$list,
        'players_now'=>$players_now,
        'ts'=>date('Y-m-d H:i:s'),
    ],JSON_UNESCAPED_UNICODE);
    exit;
}

/* ===== POST（whitelist / feedback）===== */
if($_SERVER['REQUEST_METHOD']==='POST'){
    $type = $_POST['type'] ?? '';
    if($type==='whitelist'){
        if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
            $_SESSION['flash'] = ['❌ CSRFトークンが無効です。ページを再読み込みしてやり直してください。', 'error'];
            redirect_self_303();
        }
        if (!$minecraftEnabled) {
            $_SESSION['flash'] = ['❌ Minecraft が公開されていません。', 'error'];
            redirect_self_303();
        }
        $name = trim($_POST['mc_name'] ?? '');
        if($name===''){
            $_SESSION['flash']=['❌ プレイヤー名を入力してください','error'];
        }else{
            [$uuid,$err] = mc_fetch_uuid_hyphenated($name);
            if($err){
                $_SESSION['flash']=["❌ $err",'error'];
            }else{
                $err2=whitelist_add($name,$uuid);
                if($err2){
                    $_SESSION['flash']=["❌ 登録に失敗: $err2",'error'];
                }else{
                    $_SESSION['flash']=['✅ 登録しました。これでサーバーに参加できます。','success'];
                    send_discord("✅ Minecraft ホワイトリスト登録: {$name} ({$uuid})");
                }
            }
        }
        redirect_self_303();
    }

    if($type==='feedback'){
        if (!hash_equals($_SESSION['csrf'] ?? '', $_POST['csrf'] ?? '')) {
            $_SESSION['flash'] = ['❌ CSRFトークンが無効です。ページを再読み込みしてやり直してください。', 'error'];
            redirect_self_303();
        }
        $text=trim($_POST['feedback'] ?? '');
        if($text===''){
            $_SESSION['flash']=['❌ 空のメッセージは送信できません。','error'];
        }else{
            json_file_lock_append(__DIR__.'/feedback.json',[
                'message'=>$text,
                'time'=>date('Y-m-d H:i:s')
            ]);
            send_discord("📮 ご意見/不具合報告:\n".$text);
            $_SESSION['flash']=['✅ ありがとうございました！運営に送信しました。','success'];
        }
        redirect_self_303();
    }
}

/* ===== 初期表示 ===== */
[$flashMsg,$flashType] = $_SESSION['flash'] ?? [null,'success'];
unset($_SESSION['flash']);

$whitelist = whitelist_list();
if (!$minecraftEnabled) {
    $whitelist = [];
}

$initialServers=[];
foreach($SERVERS as $s){
    $initialServers[$s['id']] = docker_status($s['container']);
}
$initialPlayers = read_current_players();

?>
<!DOCTYPE html><html lang="ja"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ゲームサーバー ポータル</title>

<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Zen+Kaku+Gothic+New:wght@400;500;700&display=swap');

:root{
  --bg:#f5f7fb;
  --bg-grad:radial-gradient(circle at 12% 12%,rgba(14,165,164,.18) 0%,transparent 55%),
            radial-gradient(circle at 90% 0%,rgba(59,130,246,.16) 0%,transparent 55%),
            linear-gradient(180deg,#f8fafc 0%,#eef2ff 100%);
  --surface:#ffffff;
  --surface-2:#f1f5f9;
  --border:#e2e8f0;
  --text:#0f172a;
  --muted:#475569;
  --accent:#0f766e;
  --accent-2:#1d4ed8;
  --accent-soft:#ccfbf1;
  --ok:#15803d;
  --ok-soft:#dcfce7;
  --warn:#b54708;
  --warn-soft:#ffedd5;
  --danger:#b42318;
  --danger-soft:#fee2e2;
  --r-lg:18px;
  --r-md:12px;
  --r-sm:8px;
  --shadow:0 16px 40px rgba(15,23,42,.1);
  --shadow-soft:0 8px 20px rgba(15,23,42,.08);
  --fast:.16s ease;
  --font-head:"Space Grotesk","Zen Kaku Gothic New",sans-serif;
  --font-body:"Zen Kaku Gothic New","Space Grotesk",sans-serif;
}
*{box-sizing:border-box;-webkit-font-smoothing:antialiased;}
body{
  margin:0;min-height:100vh;display:flex;flex-direction:column;
  font-family:var(--font-body);
  color:var(--text);
  background:var(--bg);
  background-image:var(--bg-grad);
  background-attachment:fixed;
}
.site-header{
  position:sticky;top:0;z-index:100;
  background:rgba(255,255,255,.9);
  border-bottom:1px solid var(--border);
  backdrop-filter:blur(12px);
  padding:12px 16px;
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  font-size:12px;line-height:1.4;
}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;color:var(--text);font-family:var(--font-head);} 
.brand-icon{
  width:34px;height:34px;border-radius:10px;
  background:linear-gradient(135deg,#0f766e 0%,#14b8a6 100%);
  color:#fff;display:flex;align-items:center;justify-content:center;
  font-size:15px;font-weight:700;box-shadow:var(--shadow-soft);
}
.header-right{color:var(--muted);text-align:right;} 
.status-dot{width:7px;height:7px;border-radius:999px;background:var(--accent);display:inline-block;margin-right:6px;box-shadow:0 0 10px rgba(15,118,110,.5);} 

.main-wrap{
  width:100%;max-width:1200px;margin:18px auto 48px;padding:0 16px 32px;
  display:grid;gap:18px;grid-template-columns:1fr;
}
@media(min-width:960px){
  .main-wrap{grid-template-columns:minmax(0,1.2fr) minmax(0,.8fr);} 
}

.card{
  background:var(--surface);
  border:1px solid var(--border);
  border-radius:var(--r-lg);
  box-shadow:var(--shadow);
  overflow:hidden;
}
.card-header{
  padding:14px 16px;
  display:flex;flex-wrap:wrap;align-items:flex-start;justify-content:space-between;
  border-bottom:1px solid var(--border);
  background:linear-gradient(120deg,rgba(15,118,110,.08),rgba(29,78,216,.06));
  font-size:12px;color:var(--muted);
}
.card-title-main{color:var(--text);font-size:15px;font-weight:700;font-family:var(--font-head);} 
.card-eyebrow{font-weight:500;letter-spacing:.02em;} 
.card-time{font-weight:500;color:var(--muted);} 
.card-body{padding:16px;font-size:14px;line-height:1.5;color:var(--text);} 

.server-grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));} 
.server-tile{
  display:flex;gap:12px;padding:14px;
  background:var(--surface-2);
  border:1px solid var(--border);
  border-radius:var(--r-md);
  box-shadow:var(--shadow-soft);
}
.server-icon img{
  width:54px;height:54px;border-radius:var(--r-md);object-fit:cover;
  border:1px solid var(--border);
}
.server-main{flex:1;min-width:0;display:flex;flex-direction:column;line-height:1.4;} 
.server-name{font-weight:700;font-size:14px;color:var(--text);display:flex;align-items:center;gap:6px;flex-wrap:wrap;} 
.server-addr{
  margin-top:4px;font-family:"Space Grotesk",ui-monospace,Menlo,Consolas,monospace;
  font-size:12px;color:var(--muted);display:flex;flex-wrap:wrap;gap:8px;align-items:center;word-break:break-all;
}
.copy-btn{
  font-size:11px;line-height:1.2;padding:4px 8px;cursor:pointer;
  background:#fff;border:1px solid var(--border);border-radius:var(--r-sm);
  color:var(--accent);transition:var(--fast);
}
.copy-btn:hover{border-color:var(--accent);box-shadow:0 0 8px rgba(15,118,110,.2);} 
.server-players{font-size:12px;color:var(--muted);margin-top:8px;min-height:1.3em;} 
.badge{
  flex-shrink:0;align-self:flex-start;min-width:70px;text-align:center;
  font-size:11px;font-weight:700;line-height:1.3;padding:6px 10px;
  border-radius:999px;border:1px solid var(--border);
  background:var(--ok-soft);color:var(--ok);
}
.badge.ng{background:var(--danger-soft);color:var(--danger);} 
.badge.warn{background:var(--warn-soft);color:var(--warn);} 

.rules-block,.guide-block{color:var(--muted);font-size:13px;line-height:1.6;} 
.guide-block{
  background:var(--surface-2);
  border:1px solid var(--border);
  border-radius:var(--r-md);
  padding:12px 14px;
  margin-bottom:12px;
}
.guide-block code{
  font-family:"Space Grotesk",ui-monospace,Menlo,Consolas,monospace;font-size:12px;
  background:#fff;border:1px solid var(--border);
  border-radius:var(--r-sm);padding:2px 4px;color:var(--accent);
}
.rules-block strong{color:var(--text);font-weight:600;} 

.form-desc{color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:12px;} 
.form-group{display:flex;flex-direction:column;gap:6px;margin-bottom:14px;font-size:13px;color:var(--text);} 
label{font-size:12px;font-weight:600;color:var(--text);} 
input[type=text],textarea{
  width:100%;padding:10px 12px;font-size:13px;line-height:1.4;color:var(--text);
  background:#fff;border:1px solid var(--border);
  border-radius:var(--r-md);outline:none;transition:var(--fast);
}
input[type=text]:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(15,118,110,.12);} 
textarea{min-height:110px;resize:vertical;font-family:"Space Grotesk",ui-monospace,Menlo,Consolas,monospace;} 

.btn-primary{
  appearance:none;border:1px solid transparent;
  cursor:pointer;border-radius:var(--r-md);padding:10px 14px;
  font-size:13px;line-height:1.4;font-weight:700;color:#fff;
  background:linear-gradient(135deg,#0f766e 0%,#14b8a6 100%);
  box-shadow:var(--shadow-soft);transition:var(--fast);
}
.btn-primary[disabled]{opacity:.6;cursor:default;} 
.btn-primary:hover:not([disabled]){filter:brightness(1.05);} 

.wl-stats-row{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;font-size:13px;color:var(--text);} 

.toast{
  position:fixed;right:16px;bottom:16px;z-index:9999;
  max-width:280px;padding:12px 14px;border-radius:var(--r-md);
  background:var(--ok-soft);border:1px solid var(--border);
  box-shadow:var(--shadow);font-size:13px;line-height:1.4;color:var(--ok);
  opacity:0;transform:translateY(8px) scale(.98);transition:all .3s;
}
.toast.show{opacity:1;transform:translateY(0) scale(1);} 
.toast.err{background:var(--danger-soft);color:var(--danger);} 

.ts{font-size:11px;font-weight:500;line-height:1.4;color:var(--muted);} 
.page-bottom-space{height:40px;}
</style>
</head>
<body>

<header class="site-header">
  <div class="brand">
    <div class="brand-icon">🎮</div>
    <div>
      <div style="font-size:13px;line-height:1.3;">ゲームサーバー ポータル</div>
      <div style="font-size:11px;font-weight:400;color:var(--muted);line-height:1.3;">Multiplayer Sandbox / Internal Use</div>
    </div>
  </div>
  <div class="header-right">
    <div><span class="status-dot"></span>online dashboard</div>
    <div style="font-size:11px;">自動停止: <?= $autoStopEnabled ? 'ON' : 'OFF' ?> · whitelist self-service</div>
  </div>
</header>

<main class="main-wrap">
  <!-- LEFT -->
  <section>
    <!-- status -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title-main">サーバーステータス</div>
          <div class="card-eyebrow">現在の稼働状況 / オンライン人数</div>
        </div>
        <div class="card-time" id="ts">最終更新: --:--:--</div>
      </div>

      <div class="card-body">
        <div id="statusGrid" class="server-grid">
          <?php foreach($SERVERS as $srv):
              $sid=$srv['id'];
              $st=$initialServers[$sid] ?? ['running'=>false,'health'=>null];
              $online=$idleMin=null;
              if(is_array($initialPlayers['servers'] ?? null) && isset($initialPlayers['servers'][$sid])){
                  $online  = $initialPlayers['servers'][$sid]['online'] ?? null;
                  $idleMin = $initialPlayers['servers'][$sid]['idle_minutes'] ?? null;
              }

              $badgeClass='badge';
              $badgeText='稼働中';
              if(!$st['running']){ $badgeClass.=' ng'; $badgeText='停止中'; }
              elseif(!empty($st['health']) && $st['health']!=='healthy'){
                  $badgeClass.=' warn';
                  $badgeText.=' / '.h($st['health']);
              }
          ?>
          <div class="server-tile" data-id="<?=h($sid)?>">
            <div class="server-icon">
              <img src="<?=h($srv['img'])?>" alt="<?=h($srv['label'])?>">
            </div>
            <div class="server-main">
              <div class="server-name"><?=h($srv['label'])?></div>
              <?php if($srv['hostport']): ?>
              <div class="server-addr">
                <span><?=h($srv['hostport'])?></span>
                <button class="copy-btn" onclick="copyText(<?=h(json_encode($srv['hostport'], JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE))?>)">コピー</button>
              </div>
              <?php endif; ?>
              <div class="server-players" data-players>
                <?php if($online!==null): ?>
                  現在オンライン: <?=h($online)?>人
                  <?php if($online===0 && $idleMin>0): ?>
                    <?php if($autoStopEnabled): ?>
                    / 無人<?=h($idleMin)?>分（<?=h($autoStopMinutes)?>分で自動停止）
                    <?php else: ?>
                    / 無人<?=h($idleMin)?>分（自動停止は無効）
                    <?php endif; ?>
                  <?php endif; ?>
                <?php else: ?>
                  現在オンライン: 取得中…
                <?php endif; ?>
              </div>
            </div>
            <div class="<?=h($badgeClass)?>" data-badge><?=h($badgeText)?></div>
          </div>
          <?php endforeach; ?>
        </div>

        <div class="rules-block" style="margin-top:16px;">
          ・Valheim / 7DTD の参加パスワードは基本「<strong>changeme1234</strong>」です。<br>
          ・アドレスやパスワードをSNSや不特定多数に拡散しないでください。<br>
        </div>
      </div>
    </div>

    <!-- guide / rules -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title-main">参加ガイド & ルール</div>
          <div class="card-eyebrow">接続方法 / パスワード / 注意事項</div>
        </div>
      </div>

      <div class="card-body">
        <?php foreach($SERVERS as $srv): ?>
          <div class="guide-block">
            <div style="font-size:13px;font-weight:600;color:var(--text);margin-bottom:4px;"><?=h($srv['label'])?></div>
            <div>
              ・接続先: <code><?=h($srv['hostport'])?></code><br>
              ・参加方法: <?=h($srv['howto'])?><br>
              <?php if($srv['password']): ?>
              ・参加パスワード: <strong style="color:var(--text);"><?=h($srv['password'])?></strong><br>
              <?php endif; ?>
              <?php if($srv['extra']): ?>
              <?=nl2br(h($srv['extra']))?><br>
              <?php endif; ?>
            </div>
          </div>
        <?php endforeach; ?>
        <?php if (empty($SERVERS)): ?>
          <div class="rules-block" style="margin-top:10px;">
            現在公開されているサーバーはありません。
          </div>
        <?php endif; ?>

        <div class="rules-block" style="margin-top:20px;">
          <strong>サーバー運営ポリシー</strong><br>
          ・ワールドは予告なくロールバック/ワイプする場合があります。<br>
          ・チート/荒らし/過負荷は禁止です。<br>
          ・他人のID/パスワードを勝手に共有・使用しないでください。<br>
          ・問題行動はホワイトリスト除外・BAN対象になります。<br>
          <?php if ($autoStopEnabled): ?>
          ・0人状態が約<?=h($autoStopMinutes)?>分続くと自動停止します。再起動したい時はDiscordで依頼してください。<br>
          <?php else: ?>
          ・自動停止は現在無効です（プレイヤー数は継続して計測されます）。<br>
          <?php endif; ?>
        </div>

        <div class="rules-block" style="margin-top:16px;">
          ※常時オンラインやデータ永続性は保証できません。<br>
        </div>
      </div>
    </div>
  </section>

  <!-- RIGHT -->
  <section>
    <!-- whitelist -->
    <?php if ($minecraftEnabled): ?>
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title-main">Minecraft ホワイトリスト登録</div>
          <div class="card-eyebrow">Minecraft(Java版) のプレイヤー名で申請</div>
        </div>
      </div>
      <div class="card-body">
        <?php if($flashMsg): ?>
          <div class="toast <?= $flashType==='error'?'err':'' ?> show" id="flash"><?=h($flashMsg)?></div>
          <script>setTimeout(()=>{const f=document.getElementById('flash');if(f)f.classList.remove('show')},4200);</script>
        <?php endif; ?>

        <div class="form-desc">
          Java版プレイヤー名を送信すると、すぐサーバーに入れるよう登録します。<br>
          送信内容は運営に通知されます。荒らし行為があれば解除されます。
        </div>

        <form method="post" onsubmit="return lockSubmit(this)">
          <input type="hidden" name="type" value="whitelist">
          <input type="hidden" name="csrf" value="<?=h($csrf)?>">
          <div class="form-group">
            <label>プレイヤー名（Java版）</label>
            <input type="text" name="mc_name" required placeholder="例: Notch">
          </div>
          <div><button type="submit" class="btn-primary">ホワイトリストに登録する</button></div>
        </form>

        <div style="border-top:1px solid rgba(255,255,255,.05);margin:20px 0 16px;"></div>

        <div class="wl-stats-row">
          <div>現在の登録数: <strong><?=count($whitelist)?></strong> 名</div>
          <button class="btn-primary" style="font-size:12px;padding:8px 12px;" onclick="location.reload()">最新表示</button>
        </div>

        <?php if(SHOW_WL_DETAILS): ?>
        <div style="margin-top:16px;max-height:220px;overflow:auto;border:1px solid rgba(255,255,255,.05);border-radius:var(--r-md);padding:8px 10px;background:rgba(0,0,0,.3);box-shadow:0 20px 40px rgba(0,0,0,.9);font-size:12px;line-height:1.4;">
          <?php foreach($whitelist as $e): ?>
            <div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.05);">
              <div><?=h($e['name']??'-')?></div>
              <div style="font-family:ui-monospace,Menlo,Consolas,monospace;color:var(--muted);"><?=h($e['uuid']??'-')?></div>
            </div>
          <?php endforeach; ?>
          <?php if(empty($whitelist)): ?>
            <div class="rules-block" style="font-size:12px;">まだ登録はありません。</div>
          <?php endif; ?>
        </div>
        <?php endif; ?>
      </div>
    </div>
    <?php endif; ?>

    <!-- feedback -->
    <div class="card">
      <div class="card-header">
        <div>
          <div class="card-title-main">📮 ご意見・不具合報告</div>
          <div class="card-eyebrow">止まってる/ラグい/欲しい機能など</div>
        </div>
      </div>
      <div class="card-body">
        <div class="form-desc">
          サーバーの不具合や「起動してほしい」等あれば教えてください。<br>
          内容は運営のDiscordに送信されます。
        </div>

        <form method="post" onsubmit="return lockSubmit(this)">
          <input type="hidden" name="type" value="feedback">
          <input type="hidden" name="csrf" value="<?=h($csrf)?>">
          <div class="form-group">
            <label>メッセージ</label>
            <textarea name="feedback" ></textarea>
          </div>
          <div><button type="submit" class="btn-primary">送信</button></div>
        </form>
      </div>
    </div>
  </section>
</main>

<div class="page-bottom-space"></div>

<script>
const AUTO_STOP_ENABLED = <?= $autoStopEnabled ? 'true' : 'false' ?>;
const AUTO_STOP_MINUTES = <?= (int)$autoStopMinutes ?>;
function toast(msg,err){
  const d=document.createElement('div');
  d.className='toast'+(err?' err':'')+' show';
  d.textContent=msg;
  document.body.appendChild(d);
  setTimeout(()=>d.classList.remove('show'),3500);
  setTimeout(()=>d.remove(),4200);
}
function copyText(t){
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(t).then(()=>toast('コピーしました: '+t));
  }else{
    const ta=document.createElement('textarea');
    ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand('copy');ta.remove();
    toast('コピーしました: '+t);
  }
}
function lockSubmit(f){
  const btn=f.querySelector('button[type=submit]');
  if(btn){btn.disabled=true;btn.textContent='送信中…';}
  return true;
}

async function refreshStatus(){
  try{
    const r=await fetch('?action=status',{cache:'no-store'});
    const j=await r.json();

    const ts=document.getElementById('ts');
    if(ts) ts.textContent='最終更新: '+j.ts;

    for(const sid in j.servers){
      const info=j.servers[sid];
      const tile=document.querySelector('.server-tile[data-id="'+sid+'"]');
      if(!tile) continue;

      const badge=tile.querySelector('[data-badge]');
      if(badge){
        let cls='badge',text='稼働中';
        if(!info.running){cls+=' ng';text='停止中';}
        else if(info.health && info.health!=='healthy'){cls+=' warn';text+=' / '+info.health;}
        badge.className=cls;
        badge.textContent=text;
      }

      const pbox=tile.querySelector('[data-players]');
      const ps=j.players_now && j.players_now.servers && j.players_now.servers[sid];
      if(pbox && ps){
        let line='現在オンライン: '+ps.online+'人';
        if(ps.online===0 && ps.idle_minutes>0){
          if(AUTO_STOP_ENABLED){
            line+=' / 無人'+ps.idle_minutes+'分（'+AUTO_STOP_MINUTES+'分で自動停止）';
          }else{
            line+=' / 無人'+ps.idle_minutes+'分（自動停止は無効）';
          }
        }
        pbox.textContent=line;
      }
    }
  }catch(e){console.error(e);}
}

document.addEventListener('DOMContentLoaded',()=>{
  refreshStatus();
  setInterval(refreshStatus,30000);
});
</script>

</body></html>
