<?php
function portal_default_config() {
    return [
        'enabled' => ['minecraft', 'valheim', '7dtd'],
        'monitor_containers' => [],
        'auto_stop_enabled' => false,
        'auto_stop_minutes' => 10,
        'services' => [
            'minecraft' => [
                'type' => 'game',
                'label' => 'Minecraft (Java版)',
                'container' => 'minecraft_server',
                'compose_dir' => '{{ containers_root }}/minecraft',
                'archive' => 'minecraft.tar.gz',
                'img' => '/images/minecraft.png',
                'hostport' => 'yourdomain.com',
                'howto' => 'Minecraft(Java版) → マルチプレイ → サーバー追加 → アドレスに「yourdomain.com」を入力。',
                'password' => null,
                'extra' => null,
                'public' => true,
                'supports_cmd' => true,
                'tips' => ['list', 'save-all', 'whitelist reload'],
                'config_files' => [
                    'server.properties' => 'server.properties',
                    'whitelist.json' => 'whitelist.json',
                    'ops.json' => 'ops.json',
                    'banned-players.json' => 'banned-players.json',
                    'banned-ips.json' => 'banned-ips.json',
                ],
            ],
            'valheim' => [
                'type' => 'game',
                'label' => 'Valheim',
                'container' => 'valheim_server',
                'compose_dir' => '{{ containers_root }}/valheim_server',
                'archive' => 'valheim.tar.gz',
                'img' => '/images/valheim.png',
                'hostport' => 'yourdomain.com:2456',
                'howto' => 'Valheim → アドレス「yourdomain.com:2456」。Steamの「表示→サーバー追加」はポート2457で。',
                'password' => null,
                'extra' => '※ パスワードは他人に無断で拡散しないでください。',
                'public' => true,
                'supports_cmd' => false,
                'tips' => [],
                'config_files' => [
                    'adminlist.txt' => 'adminlist.txt',
                    'permittedlist.txt' => 'permittedlist.txt',
                    'bannedlist.txt' => 'bannedlist.txt',
                ],
            ],
            '7dtd' => [
                'type' => 'game',
                'label' => '7 Days to Die',
                'container' => '7dtd-server',
                'compose_dir' => '{{ containers_root }}/7dtd_server',
                'archive' => '7dtd.tar.gz',
                'img' => '/images/7dtd.png',
                'hostport' => 'yourdomain.com:26900',
                'howto' => '7DTD → 「IPに接続」から「yourdomain.com:26900」。',
                'password' => null,
                'extra' => null,
                'public' => true,
                'supports_cmd' => true,
                'tips' => ['help', 'listplayers', 'saveworld'],
                'config_files' => [
                    'serverconfig.xml' => 'serverconfig.xml',
                    'serveradmin.xml' => 'serveradmin.xml',
                ],
            ],
            'web_portal' => [
                'type' => 'portal',
                'label' => 'Web Portal',
                'container' => 'web_portal',
                'compose_dir' => '{{ containers_root }}/web',
                'public' => false,
            ],
            'player_monitor' => [
                'type' => 'monitor',
                'label' => 'Player Monitor',
                'container' => 'player_monitor',
                'compose_dir' => '{{ containers_root }}/monitor',
                'public' => false,
            ],
        ],
    ];
}

function portal_load_config() {
    $defaults = portal_default_config();
    $path = '/opt/serveradmin/config/portal_services.json';
    if (!is_readable($path)) {
        return $defaults;
    }

    $raw = file_get_contents($path);
    if ($raw === false) {
        return $defaults;
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return $defaults;
    }

    $config = $defaults;
    if (isset($data['enabled']) && is_array($data['enabled'])) {
        $enabled = [];
        foreach ($data['enabled'] as $item) {
            if (is_string($item) && $item !== '') {
                $enabled[] = $item;
            }
        }
        if ($enabled) {
            $config['enabled'] = array_values(array_unique($enabled));
        }
    }

    if (isset($data['monitor_containers']) && is_array($data['monitor_containers'])) {
        $monitor = [];
        foreach ($data['monitor_containers'] as $item) {
            if (is_string($item) && $item !== '') {
                $monitor[] = $item;
            }
        }
        if ($monitor) {
            $config['monitor_containers'] = array_values(array_unique($monitor));
        }
    }

    if (array_key_exists('auto_stop_enabled', $data)) {
        $config['auto_stop_enabled'] = (bool)$data['auto_stop_enabled'];
    }

    if (isset($data['auto_stop_minutes'])) {
        $minutes = intval($data['auto_stop_minutes']);
        if ($minutes > 0) {
            $config['auto_stop_minutes'] = $minutes;
        }
    }

    if (isset($data['services']) && is_array($data['services'])) {
        foreach ($data['services'] as $id => $service) {
            if (!is_array($service) || !is_string($id) || $id === '') {
                continue;
            }
            $config['services'][$id] = array_merge($config['services'][$id] ?? [], $service);
        }
    }

    return $config;
}

function portal_enabled_service_ids(array $config) {
    $enabled = $config['enabled'] ?? [];
    $services = $config['services'] ?? [];
    $ids = [];
    foreach ($enabled as $id) {
        if (is_string($id) && isset($services[$id])) {
            $ids[] = $id;
        }
    }
    return $ids;
}

function portal_enabled_services(array $config, $type = null) {
    $services = $config['services'] ?? [];
    $list = [];
    foreach (portal_enabled_service_ids($config) as $id) {
        $service = $services[$id] ?? null;
        if (!is_array($service)) {
            continue;
        }
        if ($type !== null && ($service['type'] ?? null) !== $type) {
            continue;
        }
        $service['id'] = $id;
        $list[] = $service;
    }
    return $list;
}

function portal_allowed_containers(array $config) {
    $containers = [];
    foreach (portal_enabled_services($config) as $service) {
        $name = $service['container'] ?? '';
        if (is_string($name) && $name !== '') {
            $containers[] = $name;
        }
    }
    return array_values(array_unique($containers));
}

function portal_all_containers(array $config) {
    $containers = [];
    foreach (($config['services'] ?? []) as $service) {
        if (!is_array($service)) {
            continue;
        }
        $name = $service['container'] ?? '';
        if (is_string($name) && $name !== '') {
            $containers[] = $name;
        }
    }
    return array_values(array_unique($containers));
}

function portal_monitor_containers(array $config) {
    $monitor = $config['monitor_containers'] ?? [];
    $known = array_flip(portal_all_containers($config));
    if (is_array($monitor) && count($monitor)) {
        $filtered = [];
        foreach ($monitor as $name) {
            if (is_string($name) && isset($known[$name])) {
                $filtered[] = $name;
            }
        }
        if ($filtered) {
            return array_values(array_unique($filtered));
        }
    }
    return portal_allowed_containers($config);
}
