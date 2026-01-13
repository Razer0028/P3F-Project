<?php
session_start();
require_once __DIR__ . '/../public/scripts/portal_config.php';

if (!($_SESSION['admin_auth'] ?? false)) {
    http_response_code(403);
    die("Forbidden");
}

// POST以外禁止
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo "Method Not Allowed";
    exit;
}

// 入力
$action    = $_POST['action']    ?? '';
$container = $_POST['container'] ?? '';
$csrf      = $_POST['csrf']      ?? '';
$confirm   = trim($_POST['confirm'] ?? '');

if (empty($_SESSION['csrf']) || !hash_equals($_SESSION['csrf'], $csrf)) {
    http_response_code(400);
    $_SESSION['docker_result'] = "❌ CSRFトークンが無効です。";
    header("Location: /admin/docker_panel.php");
    exit;
}

// バリデーション
$valid_actions = ['start', 'stop', 'build', 'delete'];
if (!in_array($action, $valid_actions, true)) {
    $_SESSION['docker_result'] = "❌ 不正な操作が指定されました。";
    header("Location: /admin/docker_panel.php");
    exit;
}

$portalConfig = portal_load_config();
if (in_array($action, ['build', 'delete'], true)) {
    $allowed = portal_all_containers($portalConfig);
} else {
    $allowed = portal_allowed_containers($portalConfig);
}

if (!in_array($container, $allowed, true)) {
    $_SESSION['docker_result'] = "❌ 不正なコンテナが指定されました。";
    header("Location: /admin/docker_panel.php");
    exit;
}

if ($action === 'delete' && $confirm !== '削除') {
    $_SESSION['docker_result'] = "❌ 削除を実行するには確認欄に『削除』と入力してください。";
    header("Location: /admin/docker_panel.php");
    exit;
}

// 監査用
$userEmail = $_SESSION['user_email'] ?? 'unknown';

// 実際のコマンド
$cmd = sprintf(
    'sudo /opt/serveradmin/bin/docker_manage.sh %s %s %s 2>&1',
    escapeshellarg($action),
    escapeshellarg($container),
    escapeshellarg($userEmail)
);

// 実行
exec($cmd, $outputLines, $statusCode);

// 結果を画面表示用にセット
if ($statusCode === 0) {
    $_SESSION['docker_result'] =
        "✅ コンテナ [{$container}] に対して {$action} 実行しました。\n" .
        implode("\n", $outputLines);
} else {
    $_SESSION['docker_result'] =
        "❌ 実行に失敗しました。\n" .
        "コンテナ: {$container}\n" .
        "操作: {$action}\n" .
        "出力:\n" . implode("\n", $outputLines);
}

// リダイレクト
header("Location: /admin/docker_panel.php");
exit;
