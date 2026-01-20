const fields = {
  projectName: "project_name",
  timezone: "timezone",
  onpremIp: "onprem_ip",
  vpsIp: "vps_ip",
  ec2Ip: "ec2_ip",
  onpremUser: "onprem_user",
  vpsUser: "vps_user",
  ec2User: "ec2_user",
  onpremKeyName: "onprem_key_name",
  vpsKeyName: "vps_key_name",
  ec2KeyName: "ec2_key_name",
  autoVpsKeyPassphrase: "auto_vps_key_passphrase",
  autoVpsSudoPassword: "auto_vps_sudo_password",
  uploadKeyName: "upload_key_name",
  uploadPassphrase: "upload_passphrase",
  ec2KeyPassphrase: "ec2_key_passphrase",
  backupFullEnabled: "backup_full_enabled",
  backupGamesEnabled: "backup_games_enabled",
  backupGamesCron: "backup_games_cron",
  containersStart: "containers_start",
  containersRoot: "containers_root",
  containersOwner: "containers_owner",
  containersGroup: "containers_group",
  containersManageUser: "containers_manage_user",
  enableWireguard: "enable_wireguard",
  enableFailover: "enable_failover",
  enableFrr: "enable_frr",
  enableSuricata: "enable_suricata",
  enableCloudflared: "enable_cloudflared",
  enablePortctl: "enable_portctl",
  discordWebhook: "discord_webhook",
  ddosNotifyEnable: "ddos_notify_enable",
  ddosNotifyPrimaryIp: "ddos_notify_primary_ip",
  ddosNotifyFallbackIp: "ddos_notify_fallback_ip",
  ddosNotifySignatures: "ddos_notify_signatures",
  webPortalAdminEnable: "web_portal_admin_enable",
  webPortalAdminUser: "web_portal_admin_user",
  webPortalAdminPassword: "web_portal_admin_password",
  webPortalAdminAllowCidrs: "web_portal_admin_allow_cidrs",
  webPortalAdminDenyCidrs: "web_portal_admin_deny_cidrs",
  cfAccountId: "cf_account_id",
  cfZoneName: "cf_zone_name",
  cfZoneMode: "cf_zone_mode",
  cfZonePlan: "cf_zone_plan",
  cfZoneType: "cf_zone_type",
  cfManageFailoverRecord: "cf_manage_failover_record",
  cfFailoverRecordName: "cf_failover_record_name",
  cfFailoverRecordValue: "cf_failover_record_value",
  cfFailoverRecordProxied: "cf_failover_record_proxied",
  cfFailoverRecordTtl: "cf_failover_record_ttl",
  cfManageTunnels: "cf_manage_tunnels",
  cfVpsTunnelName: "cf_vps_tunnel_name",
  cfEc2TunnelName: "cf_ec2_tunnel_name",
  cfVpsHostname: "cf_vps_hostname",
  cfEc2Hostname: "cf_ec2_hostname",
  cfTunnelProxied: "cf_tunnel_proxied",
  cfTunnelTtl: "cf_tunnel_ttl",
  cfVpsTunnelId: "cf_vps_tunnel_id",
  cfEc2TunnelId: "cf_ec2_tunnel_id",
  cfVpsOrigin: "cf_vps_origin",
  cfEc2Origin: "cf_ec2_origin",
  cfVpsCredentials: "cf_vps_credentials",
  cfEc2Credentials: "cf_ec2_credentials",
  cfApiToken: "cf_api_token",
  cfApiTokenFile: "cf_api_token_file",
  awsRegion: "aws_region",
  awsProfile: "aws_profile",
  awsCredentialsFile: "aws_credentials_file",
  vpcMode: "vpc_mode",
  vpcCidr: "vpc_cidr",
  publicSubnetCidr: "public_subnet_cidr",
  publicSubnetAz: "public_subnet_az",
  amiMode: "ami_mode",
  amiId: "ami_id",
  amiOwners: "ami_owners",
  amiNameFilter: "ami_name_filter",
  amiArchitecture: "ami_architecture",
  amiVirtualizationType: "ami_virtualization_type",
  amiRootDeviceType: "ami_root_device_type",
  instanceType: "instance_type",
  keyName: "key_name",
  keyPairMode: "key_pair_mode",
  keyPairPublicKey: "key_pair_public_key",
  instanceName: "instance_name",
  associateEip: "associate_eip",
  sourceDestCheck: "source_dest_check",
  allowedSshCidrs: "allowed_ssh_cidrs",
  allowedUdpPorts: "allowed_udp_ports",
  allowedTcpPorts: "allowed_tcp_ports",
  failoverAccessKeyId: "failover_access_key_id",
  failoverSecretAccessKey: "failover_secret_access_key",
  portGameMinecraft: "port_game_minecraft",
  portGameBedrock: "port_game_bedrock",
  portGameValheim: "port_game_valheim",
  portGame7dtd: "port_game_7dtd",
  portForwardEnable: "port_forward_enable",
  portForwardDestIp: "port_forward_dest_ip",
  portForwardCustom: "port_forward_custom",
  cleanupAuto: "cleanup_auto",
};

const uploadMessages = {
  en: {
    missingFile: "Select a private key file to upload.",
    missingToken: "Paste the upload token from the terminal.",
    missingKeyName: "Enter the key name for this target.",
    uploading: "Uploading key...",
    success: (path) => `Upload complete: ${path}`,
    error: (detail) => `Upload failed: ${detail}`,
    unknownError: "Upload failed. Check the server log.",
  },
  ja: {
    missingFile: "秘密鍵ファイルを選択してください。",
    missingToken: "端末に表示されたトークンを貼り付けてください。",
    missingKeyName: "対象鍵の鍵名を入力してください。",
    uploading: "アップロード中...",
    success: (path) => `アップロード完了: ${path}`,
    error: (detail) => `アップロード失敗: ${detail}`,
    unknownError: "アップロード失敗。サーバーログを確認してください。",
  },
};

const awsCredentialsMessages = {
  en: {
    missingFile: "Select the AWS access key CSV.",
    missingToken: "Paste the portal token.",
    uploading: "Importing AWS credentials...",
    success: (profile) => `AWS credentials saved (profile: ${profile}).`,
    error: (detail) => `Import failed: ${detail}`,
    unknownError: "Import failed. Check the server log.",
  },
  ja: {
    missingFile: "AWSアクセスキーのCSVを選択してください。",
    missingToken: "ポータルトークンを入力してください。",
    uploading: "AWS認証情報を取り込み中...",
    success: (profile) => `AWS認証情報を保存しました（profile: ${profile}）。`,
    error: (detail) => `取り込み失敗: ${detail}`,
    unknownError: "取り込み失敗。サーバーログを確認してください。",
  },
};

const cloudflareTokenMessages = {
  en: {
    missingToken: "Enter the Cloudflare API token or select a token file.",
    missingPortalToken: "Paste the portal token.",
    saving: "Saving Cloudflare token...",
    success: "Cloudflare token saved.",
    error: (detail) => `Save failed: ${detail}`,
    unknownError: "Save failed. Check the server log.",
  },
  ja: {
    missingToken: "Cloudflare APIトークンを入力、またはファイルを選択してください。",
    missingPortalToken: "ポータルトークンを入力してください。",
    saving: "Cloudflareトークンを保存中...",
    success: "Cloudflareトークンを保存しました。",
    error: (detail) => `保存失敗: ${detail}`,
    unknownError: "保存失敗。サーバーログを確認してください。",
  },
};


const saveMessages = {
  en: {
    missingToken: "Enter the portal token.",
    ec2KeyMissing: "EC2 key pair is not ready. Click Generate EC2 key pair or provide an existing key.",
    ec2KeyPublicMissing: "Provide the EC2 public key or switch to Auto (Generate).",
    emptyOutput: "Generate files before saving.",
    saving: "Saving files to server...",
    success: "Saved to server.",
    savedCount: (count) => `${count} file(s) saved.`,
    imported: (count) => `Auto-imported ${count} host vars.`,
    importError: (count) => `Auto-import completed with ${count} error(s).`,
    warningHeader: "Warnings:",
    error: (detail) => `Save failed: ${detail}`,
    unknownError: "Save failed. Check the server log.",
  },
  ja: {
    missingToken: "ポータルトークンを入力してください。",
    ec2KeyMissing: "EC2鍵が未準備です。『EC2鍵を自動生成』を押すか、既存鍵を用意してください。",
    ec2KeyPublicMissing: "EC2公開鍵を入力するか、自動生成モードに切り替えてください。",
    emptyOutput: "先にファイル生成を実行してください。",
    saving: "サーバーへ保存中...",
    success: "サーバーに保存しました。",
    savedCount: (count) => `${count} 件のファイルを保存しました。`,
    imported: (count) => `自動取り込み: ${count} 件のhost_varsを生成しました。`,
    importError: (count) => `自動取り込みで ${count} 件のエラーがあります。`,
    warningHeader: "注意:",
    error: (detail) => `保存失敗: ${detail}`,
    unknownError: "保存失敗。サーバーログを確認してください。",
  },
};

const statusMessages = {
  en: {
    missingToken: "Enter the portal token to run the check.",
    checking: "Checking...",
    ready: "Check complete.",
    error: "Status check failed.",
  },
  ja: {
    missingToken: "チェックにはポータルトークンが必要です。",
    checking: "チェック中...",
    ready: "チェック完了。",
    error: "チェックに失敗しました。",
  },
};

const statusLabels = {
  en: {
    ok: "OK",
    missing: "Missing",
    inventory: "Inventory file",
    groupvars: "Group vars",
    tfvars: "Terraform tfvars",
    tfvarsCloudflare: "Terraform Cloudflare tfvars",
    vaultPass: "Vault password",
    vaultOnprem: "Vault onprem-1.yml",
    vaultVps: "Vault vps-1.yml",
    vaultEc2: "Vault ec2-1.yml",
    cloudflareToken: "Cloudflare token",
    awsCredentials: "AWS credentials",
    awsConfig: "AWS config",
    sshAnsible: "SSH key (on-prem)",
    sshVps: "SSH key (VPS)",
    sshEc2: "SSH key (EC2)",
    toolAnsible: "Tool: ansible-playbook",
    toolAnsibleCli: "Tool: ansible",
    toolTerraform: "Tool: terraform",
    toolSsh: "Tool: ssh",
    toolKeyscan: "Tool: ssh-keyscan",
    toolKeygen: "Tool: ssh-keygen",
    toolPython: "Tool: python3",
  },
  ja: {
    ok: "OK",
    missing: "不足",
    inventory: "Inventoryファイル",
    groupvars: "Group vars",
    tfvars: "Terraform tfvars",
    tfvarsCloudflare: "Terraform Cloudflare tfvars",
    vaultPass: "Vaultパスワード",
    vaultOnprem: "Vault onprem-1.yml",
    vaultVps: "Vault vps-1.yml",
    vaultEc2: "Vault ec2-1.yml",
    cloudflareToken: "Cloudflareトークン",
    awsCredentials: "AWS認証情報",
    awsConfig: "AWS設定",
    sshAnsible: "SSH鍵（オンプレ）",
    sshVps: "SSH鍵（VPS）",
    sshEc2: "SSH鍵（EC2）",
    toolAnsible: "ツール: ansible-playbook",
    toolAnsibleCli: "ツール: ansible",
    toolTerraform: "ツール: terraform",
    toolSsh: "ツール: ssh",
    toolKeyscan: "ツール: ssh-keyscan",
    toolKeygen: "ツール: ssh-keygen",
    toolPython: "ツール: python3",
  },
};


const guidedMessages = {
  en: {
    done: "Done",
    locked: "Complete the previous step",
    waiting: "Waiting",
    saved: "Saved",
    missing: "Missing",
    ok: "OK",
  },
  ja: {
    done: "完了",
    locked: "前の手順を完了してください",
    waiting: "待機",
    saved: "保存済み",
    missing: "不足",
    ok: "OK",
  },
};

const defaultDdosSignatures = [
  "DoS ICMP Flood detected",
  "DoS TCP SYN Flood detected",
  "DoS UDP Flood detected",
  "DDoS ICMP Flood (aggregate)",
  "DDoS UDP Flood (aggregate)",
  "DDoS TCP SYN Flood (aggregate)",
];

let currentLang = "en";
let lastStatusPayload = null;
const DEFAULT_CONFIG_DIR = "~/.config/edge-stack";

function getOutputRoot(payload) {
  if (payload && payload.output_root) {
    return payload.output_root;
  }
  if (lastStatusPayload && lastStatusPayload.output_root) {
    return lastStatusPayload.output_root;
  }
  return DEFAULT_CONFIG_DIR;
}

function outputPath(relPath, payload) {
  return `${getOutputRoot(payload)}/${relPath}`;
}

function inventoryPath(payload) {
  return outputPath("ansible/hosts.ini", payload);
}

function groupVarsPath(payload) {
  return outputPath("ansible/group_vars/all.yml", payload);
}

function hostVarsPath(name, payload) {
  return outputPath(`ansible/host_vars/${name}`, payload);
}

function tfvarsPath(payload) {
  return outputPath("terraform/terraform.tfvars", payload);
}

function tfvarsCfPath(payload) {
  return outputPath("terraform-cloudflare/terraform.tfvars", payload);
}

const guidedState = {
  preflight: false,
  saved: false,
  tfCfApply: false,
  tfApply: false,
  ansibleBase: false,
  ansibleVps: false,
  ansibleCloudflared: false,
  ansiblePortctl: false,
  ansibleEc2: false,
  ansibleOnprem: false,
  validate: false,
};

function value(id) {
  const el = document.getElementById(id);
  if (!el) {
    return "";
  }
  if (el.type === "checkbox") {
    return el.checked;
  }
  return el.value.trim();
}

function containersRootValue() {
  const raw = value(fields.containersRoot);
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return "/srv/edge-stack";
}

const SSH_KEY_DIR = "~/.ssh";

function keyNameValue(fieldId, fallback) {
  const raw = value(fieldId);
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return fallback;
}

function keyPath(keyName) {
  return `${SSH_KEY_DIR}/${keyName}`;
}

function keyNameForTarget(target) {
  if (target === "onprem") {
    return keyNameValue(fields.onpremKeyName, "onprem_ed25519");
  }
  if (target === "vps") {
    return keyNameValue(fields.vpsKeyName, "vps_ed25519");
  }
  if (target === "ec2") {
    return keyNameValue(fields.ec2KeyName, "ec2_key.pem");
  }
  return "";
}

function containersOwnerValue() {
  const raw = value(fields.containersOwner);
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return "edge";
}

function containersGroupValue() {
  const raw = value(fields.containersGroup);
  if (typeof raw === "string" && raw.trim()) {
    return raw.trim();
  }
  return "edge";
}

function parseList(raw, asNumber) {
  if (!raw) {
    return [];
  }
  const parts = raw
    .split(/[\n\r,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
  if (asNumber) {
    return parts
      .map((item) => Number(item))
      .filter((item) => !Number.isNaN(item));
  }
  return parts;
}

const portProfiles = [
  { id: "port_game_minecraft", tcp: [25565], udp: [] },
  { id: "port_game_bedrock", tcp: [], udp: [19132, 19133] },
  { id: "port_game_valheim", tcp: [], udp: [2456, 2457, 2458] },
  { id: "port_game_7dtd", tcp: [], udp: [26900, 26901, 26902] },
];

function normalizePortList(raw) {
  return parseList(raw, true).filter((port) => Number.isInteger(port) && port > 0 && port <= 65535);
}

function addPorts(target, ports) {
  ports.forEach((port) => {
    target.add(port);
  });
}

function parseForwardRules(raw, destIp) {
  if (!raw) {
    return [];
  }
  const rules = [];
  const normalized = normalizeMultiline(raw);
  normalized.split("\n").forEach((line) => {
    const trimmed = line.trim();
    if (!trimmed) {
      return;
    }
    const cleaned = trimmed.replace(/->/g, " ").replace(/,/g, " ");
    const parts = cleaned.split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
      return;
    }
    const protocol = parts[0].toLowerCase();
    if (!["tcp", "udp", "both"].includes(protocol)) {
      return;
    }
    const extPort = parts[1];
    const destPort = parts[2] || extPort;
    rules.push({
      ext_port: extPort,
      dest_port: destPort,
      protocol,
      dest_ip: destIp,
    });
  });
  return rules;
}

function resolveAutoPortForwardDestIp() {
  const status = lastStatusPayload || {};
  const wgIps = status.wg_ips || {};
  if (wgIps.wg0) {
    return wgIps.wg0;
  }
  const setupMode = document.body && document.body.dataset.setupMode;
  if (setupMode === "beginner") {
    return "10.0.0.2";
  }
  return "";
}

function buildPortPlan() {
  const allowedTcp = new Set([22]);
  const allowedUdp = new Set([51820]);
  const forwardRules = [];
  const forwardKeySet = new Set();
  const forwardEnabled = value(fields.portForwardEnable);
  const destIp = value(fields.portForwardDestIp) || resolveAutoPortForwardDestIp() || "";

  portProfiles.forEach((profile) => {
    const input = document.getElementById(profile.id);
    if (!input || !input.checked) {
      return;
    }
    addPorts(allowedTcp, profile.tcp);
    addPorts(allowedUdp, profile.udp);
    if (forwardEnabled) {
      profile.tcp.forEach((port) => {
        const key = `tcp:${port}:${destIp}:${port}`;
        if (forwardKeySet.has(key)) {
          return;
        }
        forwardKeySet.add(key);
        forwardRules.push({
          ext_port: String(port),
          dest_port: String(port),
          protocol: "tcp",
          dest_ip: destIp,
        });
      });
      profile.udp.forEach((port) => {
        const key = `udp:${port}:${destIp}:${port}`;
        if (forwardKeySet.has(key)) {
          return;
        }
        forwardKeySet.add(key);
        forwardRules.push({
          ext_port: String(port),
          dest_port: String(port),
          protocol: "udp",
          dest_ip: destIp,
        });
      });
    }
  });

  const extraTcp = normalizePortList(value(fields.allowedTcpPorts));
  const extraUdp = normalizePortList(value(fields.allowedUdpPorts));
  addPorts(allowedTcp, extraTcp);
  addPorts(allowedUdp, extraUdp);

  if (forwardEnabled) {
    const customRules = parseForwardRules(value(fields.portForwardCustom), destIp);
    customRules.forEach((rule) => {
      const key = `${rule.protocol}:${rule.ext_port}:${rule.dest_ip}:${rule.dest_port}`;
      if (forwardKeySet.has(key)) {
        return;
      }
      forwardKeySet.add(key);
      forwardRules.push(rule);
    });
  }

  const sortedTcp = Array.from(allowedTcp).sort((a, b) => a - b);
  const sortedUdp = Array.from(allowedUdp).sort((a, b) => a - b);
  const ufwRules = [
    ...sortedTcp.map((port) => `allow ${port}/tcp`),
    ...sortedUdp.map((port) => `allow ${port}/udp`),
  ];

  return {
    allowedTcp: sortedTcp,
    allowedUdp: sortedUdp,
    forwardRules,
    ufwRules,
    destIp,
    forwardEnabled,
  };
}

function parseSignatureList(raw) {
  if (!raw) {
    return [];
  }
  const normalized = normalizeMultiline(raw);
  return normalized
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}


function escapeHclString(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, "\\\"");
}


function escapeYamlString(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, "\\\"");
}

function normalizeMultiline(value) {
  return String(value || "")
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
}

function indentBlock(value, indent) {
  const pad = " ".repeat(indent);
  const text = normalizeMultiline(value);
  if (!text) {
    return pad;
  }
  return text
    .split("\n")
    .map((line) => pad + line)
    .join("\n");
}

function isLocalOnpremHost(onpremIp) {
  const ip = (onpremIp || "").trim();
  if (!ip) {
    return false;
  }
  if (ip === "localhost" || ip === "127.0.0.1" || ip === "::1") {
    return true;
  }
  const host = window.location && window.location.hostname ? window.location.hostname.trim() : "";
  return host !== "" && ip === host;
}

function renderInventory() {
  const plan = getPlanOptions();
  const onpremIp = value(fields.onpremIp);
  const vpsIp = value(fields.vpsIp);
  const ec2Ip = value(fields.ec2Ip);
  const onpremUser = value(fields.onpremUser);
  const vpsUser = value(fields.vpsUser);
  const ec2User = value(fields.ec2User);
  const onpremKeyName = keyNameValue(fields.onpremKeyName, "onprem_ed25519");
  const vpsKeyName = keyNameValue(fields.vpsKeyName, "vps_ed25519");
  const ec2KeyName = keyNameValue(fields.ec2KeyName, "ec2_key.pem");
  const onpremKey = keyPath(onpremKeyName);
  const vpsKey = keyPath(vpsKeyName);
  const ec2Key = keyPath(ec2KeyName);
  const onpremLocal = isLocalOnpremHost(onpremIp);

  const lines = [];
  const pushGroup = (group, hostLine, enabled) => {
    lines.push(`# ${group}`);
    if (enabled) {
      lines.push(`[${group}]`);
      lines.push(hostLine);
    } else {
      lines.push(`# [${group}]`);
      lines.push(`# ${hostLine}`);
    }
    lines.push("");
  };

  pushGroup(
    "onprem",
    onpremLocal
      ? `onprem-1 ansible_host=${onpremIp || "127.0.0.1"} ansible_user=${onpremUser || "root"} ansible_connection=local`
      : `onprem-1 ansible_host=${onpremIp || "<onprem_ip>"} ansible_user=${onpremUser || "root"} ansible_ssh_private_key_file=${onpremKey || "<onprem_key>"}`,
    plan.onprem && Boolean(onpremIp),
  );
  pushGroup(
    "vps",
    `vps-1 ansible_host=${vpsIp || "<vps_ip>"} ansible_user=${vpsUser || "root"} ansible_ssh_private_key_file=${vpsKey || "<vps_key>"}`,
    plan.vps && Boolean(vpsIp),
  );
  pushGroup(
    "ec2",
    `ec2-1 ansible_host=${ec2Ip || "<ec2_ip>"} ansible_user=${ec2User || "root"} ansible_ssh_private_key_file=${ec2Key || "<ec2_key>"}`,
    plan.ec2 && Boolean(ec2Ip),
  );

  lines.push("[all:vars]");
  lines.push("ansible_python_interpreter=/usr/bin/python3");
  return `${lines.join("\n")}\n`;
}


function enabledContainers() {
  const map = [
    ["minecraft", "enable_minecraft"],
    ["valheim", "enable_valheim"],
    ["7dtd", "enable_7dtd"],
    ["web_portal", "enable_web_portal"],
    ["player_monitor", "enable_player_monitor"],
  ];
  return map
    .filter(([_, id]) => {
      const el = document.getElementById(id);
      return el && el.checked;
    })
    .map(([name]) => name);
}

function getFeatureFlags() {
  return {
    wireguard: value(fields.enableWireguard),
    failover: value(fields.enableFailover),
    frr: value(fields.enableFrr),
    suricata: value(fields.enableSuricata),
    cloudflared: value(fields.enableCloudflared),
    portctl: value(fields.enablePortctl),
  };
}

function renderGroupVars() {
  const setupMode = (document.body && document.body.dataset.setupMode) || "custom";
  const simpleMode = setupMode === "beginner";
  const backupFull = value(fields.backupFullEnabled) ? "true" : "false";
  const backupGames = value(fields.backupGamesEnabled) ? "true" : "false";
  const backupsManage = (backupFull === "true" || backupGames === "true") ? "true" : "false";
  const containersStart = value(fields.containersStart) ? "true" : "false";
  const containersRoot = containersRootValue();
  const containersOwner = containersOwnerValue();
  const containersGroup = containersGroupValue();
  const containersManageUser = value(fields.containersManageUser) ? "true" : "false";
  const wireguardManage = value(fields.enableWireguard) ? "true" : "false";
  const failoverManage = value(fields.enableFailover) ? "true" : "false";
  const failoverActive = simpleMode ? "false" : failoverManage;
  const frrManage = value(fields.enableFrr) ? "true" : "false";
  const suricataManage = value(fields.enableSuricata) ? "true" : "false";
  const cloudflaredManage = value(fields.enableCloudflared) ? "true" : "false";
  const portctlManage = value(fields.enablePortctl) ? "true" : "false";
  const sysctlForwardManage = (wireguardManage === "true" || portctlManage === "true") ? "true" : "false";
  const portPlan = buildPortPlan();
  const portctlDefaultDestIp = portPlan.destIp;
  const portctlUfwRulesBlock = portPlan.ufwRules.length
    ? `portctl_ufw_rules:\n${portPlan.ufwRules.map((rule) => `  - \"${escapeYamlString(rule)}\"`).join("\n")}`
    : "portctl_ufw_rules: []";
  const portctlForwardRulesBlock = portPlan.forwardRules.length
    ? `portctl_forward_rules:\n${portPlan.forwardRules.map((rule) => [
      "  - ext_port: \"" + escapeYamlString(rule.ext_port) + "\"",
      "    dest_port: \"" + escapeYamlString(rule.dest_port) + "\"",
      "    protocol: \"" + escapeYamlString(rule.protocol) + "\"",
      "    dest_ip: \"" + escapeYamlString(rule.dest_ip) + "\"",
    ].join("\n")).join("\n")}`
    : "portctl_forward_rules: []";
  const containers = enabledContainers();
  const containersManage = containers.length ? "true" : "false";
  const dockerManage = containers.length ? "true" : "false";
  const containersBlock = containers.length
    ? `containers_enabled:\n${containers.map((item) => "  - " + item).join("\n")}`
    : "containers_enabled: []";
  const adminEnable = "true";
  const adminUser = value(fields.webPortalAdminUser) || "";
  const adminPassword = value(fields.webPortalAdminPassword) || "";
  const discordWebhook = value(fields.discordWebhook);
  const adminAllow = parseList(value(fields.webPortalAdminAllowCidrs));
  const adminDeny = parseList(value(fields.webPortalAdminDenyCidrs));
  const adminAllowBlock = adminAllow.length
    ? `web_portal_admin_allow_cidrs:\n${adminAllow.map((item) => "  - \"" + item + "\"").join("\n")}`
    : "web_portal_admin_allow_cidrs: []";
  const adminDenyBlock = adminDeny.length
    ? `web_portal_admin_deny_cidrs:\n${adminDeny.map((item) => "  - \"" + item + "\"").join("\n")}`
    : "web_portal_admin_deny_cidrs: []";
  return `---
project_name: "${value(fields.projectName)}"
timezone: "${value(fields.timezone)}"

# Docker
docker_manage: ${dockerManage}

# Containers
containers_manage: ${containersManage}
containers_root: "${containersRoot}"
containers_owner: "${containersOwner}"
containers_group: "${containersGroup}"
containers_manage_user: ${containersManageUser}
containers_start: ${containersStart}
${containersBlock}

# Web portal admin
web_portal_admin_enable: ${adminEnable}
web_portal_admin_user: "${escapeYamlString(adminUser)}"
web_portal_admin_password: "${escapeYamlString(adminPassword)}"
${adminAllowBlock}
${adminDenyBlock}
web_portal_discord_webhook: "${escapeYamlString(discordWebhook)}"

# Sysctl
sysctl_forward_manage: ${sysctlForwardManage}

# WireGuard
wireguard_manage: ${wireguardManage}
wireguard_enable_on_boot: ${simpleMode ? "true" : "false"}
wireguard_restart_on_change: ${simpleMode ? "true" : "false"}
wireguard_allow_overwrite: false

# Failover core
failover_core_manage: ${failoverActive}
failover_core_enable: ${failoverActive}
failover_core_state: ${failoverActive === "true" ? "started" : "stopped"}

# FRR
frr_manage: ${frrManage}
frr_manage_service: ${frrManage}
frr_restart_on_change: ${frrManage}

# Suricata
suricata_manage: ${suricataManage}
suricata_manage_service: ${suricataManage}
suricata_restart_on_change: ${suricataManage}

# Cloudflared
cloudflared_manage: ${cloudflaredManage}

# Portctl
portctl_manage: ${portctlManage}
portctl_default_dest_ip: "${escapeYamlString(portctlDefaultDestIp)}"
portctl_apply_rules: true
portctl_enable_web_wg: false
${portctlUfwRulesBlock}
${portctlForwardRulesBlock}

# Backup
backups_manage: ${backupsManage}
backup_full_enabled: ${backupFull}
backup_games_enabled: ${backupGames}
backup_games_cron: "${value(fields.backupGamesCron)}"

nas_mount: "/mnt/nas"
backup_root: "/mnt/nas/backup"
backup_games_root: "/mnt/nas/backup_games"
backup_full_script: "/usr/local/sbin/backup_to_nas.sh"
backup_games_script: "/usr/local/sbin/backup_games_to_nas.sh"
backup_full_log: "/var/log/backup_rsync.log"
backup_games_log: "/var/log/backup_games_rsync.log"
`;
}

function renderTfvars() {
  const allowedSshRaw = parseList(value(fields.allowedSshCidrs));
  const allowedSsh = allowedSshRaw.length ? allowedSshRaw : ["0.0.0.0/0"];
  const portPlan = buildPortPlan();
  const allowedUdp = portPlan.allowedUdp;
  const allowedTcp = portPlan.allowedTcp;
  const vpcMode = value(fields.vpcMode) || "auto";
  const keyPairModeRaw = value(fields.keyPairMode) || "existing";
  const keyPairMode = keyPairModeRaw;
  const lines = [];
  const awsRegion = value(fields.awsRegion);
  if (awsRegion) {
    lines.push(`aws_region = "${awsRegion}"`);
  } else {
    lines.push(`# aws_region = "ap-northeast-1"`);
  }
  const awsProfile = value(fields.awsProfile);
  if (awsProfile) {
    lines.push(`aws_profile = "${awsProfile}"`);
  } else {
    lines.push(`# aws_profile = "default"`);
  }
  lines.push(`vpc_mode = "${vpcMode}"`);
  if (vpcMode === "custom") {
    if (value(fields.vpcCidr)) {
      lines.push(`vpc_cidr = "${value(fields.vpcCidr)}"`);
    } else {
      lines.push(`# vpc_cidr = "10.20.0.0/16"`);
    }
    if (value(fields.publicSubnetCidr)) {
      lines.push(`public_subnet_cidr = "${value(fields.publicSubnetCidr)}"`);
    } else {
      lines.push(`# public_subnet_cidr = "10.20.10.0/24"`);
    }
    if (value(fields.publicSubnetAz)) {
      lines.push(`public_subnet_az = "${value(fields.publicSubnetAz)}"`);
    } else {
      lines.push(`# public_subnet_az = "ap-northeast-1a"`);
    }
  } else {
    lines.push(`# vpc_cidr = "10.20.0.0/16"`);
    lines.push(`# public_subnet_cidr = "10.20.10.0/24"`);
    lines.push(`# public_subnet_az = "ap-northeast-1a"`);
  }
  const amiMode = value(fields.amiMode) || "manual";
  lines.push(`ami_mode = "${amiMode}"`);
  const amiId = value(fields.amiId);
  if (amiMode === "manual") {
    if (amiId) {
      lines.push(`ami_id = "${amiId}"`);
    } else {
      lines.push(`# ami_id = "ami-xxxxxxxx"`);
    }
    lines.push(`# ami_owners = ["YOUR_AMI_OWNER"]`);
    lines.push(`# ami_name_filter = "YOUR_AMI_NAME_PATTERN"`);
    lines.push(`# ami_architecture = "arm64"`);
    lines.push(`# ami_virtualization_type = "hvm"`);
    lines.push(`# ami_root_device_type = "ebs"`);
  } else {
    lines.push(`# ami_id = "ami-xxxxxxxx"`);
    const owners = parseList(value(fields.amiOwners));
    if (owners.length) {
      lines.push(`ami_owners = [${owners.map((item) => `"${item}"`).join(", ")}]`);
    } else {
      lines.push(`# ami_owners = ["YOUR_AMI_OWNER"]`);
    }
    const nameFilter = value(fields.amiNameFilter);
    if (nameFilter) {
      lines.push(`ami_name_filter = "${escapeHclString(nameFilter)}"`);
    } else {
      lines.push(`# ami_name_filter = "YOUR_AMI_NAME_PATTERN"`);
    }
    const architecture = value(fields.amiArchitecture);
    if (architecture) {
      lines.push(`ami_architecture = "${architecture}"`);
    } else {
      lines.push(`# ami_architecture = "arm64"`);
    }
    const virtualization = value(fields.amiVirtualizationType);
    if (virtualization) {
      lines.push(`ami_virtualization_type = "${virtualization}"`);
    } else {
      lines.push(`# ami_virtualization_type = "hvm"`);
    }
    const rootDevice = value(fields.amiRootDeviceType);
    if (rootDevice) {
      lines.push(`ami_root_device_type = "${rootDevice}"`);
    } else {
      lines.push(`# ami_root_device_type = "ebs"`);
    }
  }
  const instanceType = value(fields.instanceType);
  if (instanceType) {
    lines.push(`instance_type = "${instanceType}"`);
  } else {
    lines.push(`# instance_type = "t4g.medium"`);
  }
  const keyName = value(fields.keyName);
  if (keyName) {
    lines.push(`key_name = "${keyName}"`);
  } else {
    lines.push(`# key_name = "your-keypair"`);
  }
  const instanceName = value(fields.instanceName);
  if (instanceName) {
    lines.push(`instance_name = "${instanceName}"`);
  } else {
    lines.push(`# instance_name = "ec2-edge"`);
  }
  lines.push(`associate_eip = ${value(fields.associateEip) ? "true" : "false"}`);
  lines.push(
    `source_dest_check = ${value(fields.sourceDestCheck) ? "true" : "false"}`,
  );
  const tfKeyPairMode = keyPairMode;
  lines.push(`key_pair_mode = "${tfKeyPairMode}"`);
  if (tfKeyPairMode === "create" || tfKeyPairMode === "auto") {
    if (value(fields.keyPairPublicKey)) {
      lines.push(`key_pair_public_key = "${escapeHclString(value(fields.keyPairPublicKey))}"`);
    } else {
      lines.push(`# key_pair_public_key = "ssh-ed25519 AAAA... user@host"`);
    }
  } else {
    lines.push(`# key_pair_public_key = "ssh-ed25519 AAAA... user@host"`);
  }
  lines.push(
    `allowed_ssh_cidrs = [${allowedSsh.map((item) => `"${item}"`).join(", ")}]`,
  );
  lines.push(
    `allowed_udp_ports = [${allowedUdp.map((item) => String(item)).join(", ")}]`,
  );
  lines.push(
    `allowed_tcp_ports = [${allowedTcp.map((item) => String(item)).join(", ")}]`,
  );
  const failoverAccessKeyId = value(fields.failoverAccessKeyId);
  const failoverSecretAccessKey = value(fields.failoverSecretAccessKey);
  if (failoverAccessKeyId && failoverSecretAccessKey) {
    lines.push(`failover_access_key_id = "${escapeHclString(failoverAccessKeyId)}"`);
    lines.push(`failover_secret_access_key = "${escapeHclString(failoverSecretAccessKey)}"`);
  } else {
    lines.push(`# failover_access_key_id = "AKIA..."`);
    lines.push(`# failover_secret_access_key = "YOUR_SECRET"`);
  }
  return `${lines.join("\n")}\n`;
}

function renderCfTfvars() {
  const lines = [];
  lines.push(`cf_account_id = "${value(fields.cfAccountId) || "YOUR_ACCOUNT_ID"}"`);
  lines.push(`cf_zone_name = "${value(fields.cfZoneName) || "YOUR_DOMAIN"}"`);
  lines.push(`cf_zone_mode = "${value(fields.cfZoneMode) || "existing"}"`);
  lines.push(`cf_zone_plan = "${value(fields.cfZonePlan) || "free"}"`);
  lines.push(`cf_zone_type = "${value(fields.cfZoneType) || "full"}"`);

  const manageFailover = value(fields.cfManageFailoverRecord);
  lines.push(`cf_manage_failover_record = ${manageFailover ? "true" : "false"}`);
  if (value(fields.cfFailoverRecordName)) {
    lines.push(`cf_failover_record_name = "${value(fields.cfFailoverRecordName)}"`);
  } else {
    lines.push(`# cf_failover_record_name = "game.YOUR_DOMAIN"`);
  }
  if (value(fields.cfFailoverRecordValue)) {
    lines.push(`cf_failover_record_value = "${value(fields.cfFailoverRecordValue)}"`);
  } else {
    lines.push(`# cf_failover_record_value = "YOUR_FAILOVER_IP"`);
  }
  lines.push(`cf_failover_record_proxied = ${value(fields.cfFailoverRecordProxied) ? "true" : "false"}`);
  if (value(fields.cfFailoverRecordTtl)) {
    lines.push(`cf_failover_record_ttl = ${Number(value(fields.cfFailoverRecordTtl)) || 1}`);
  } else {
    lines.push(`# cf_failover_record_ttl = 1`);
  }

  const manageTunnels = value(fields.cfManageTunnels);
  lines.push(`cf_manage_tunnels = ${manageTunnels ? "true" : "false"}`);
  const vpsTunnelName = value(fields.cfVpsTunnelName);
  if (vpsTunnelName) {
    lines.push(`cf_vps_tunnel_name = "${vpsTunnelName}"`);
  } else {
    lines.push(`# cf_vps_tunnel_name = "YOUR_VPS_TUNNEL"`);
  }
  const ec2TunnelName = value(fields.cfEc2TunnelName);
  if (ec2TunnelName) {
    lines.push(`cf_ec2_tunnel_name = "${ec2TunnelName}"`);
  } else {
    lines.push(`# cf_ec2_tunnel_name = "YOUR_EC2_TUNNEL"`);
  }
  if (value(fields.cfVpsHostname)) {
    lines.push(`cf_vps_hostname = "${value(fields.cfVpsHostname)}"`);
  } else {
    lines.push(`# cf_vps_hostname = "www.YOUR_DOMAIN"`);
  }
  if (value(fields.cfEc2Hostname)) {
    lines.push(`cf_ec2_hostname = "${value(fields.cfEc2Hostname)}"`);
  } else {
    lines.push(`# cf_ec2_hostname = "sub.YOUR_DOMAIN"`);
  }
  lines.push(`cf_tunnel_proxied = ${value(fields.cfTunnelProxied) ? "true" : "false"}`);
  if (value(fields.cfTunnelTtl)) {
    lines.push(`cf_tunnel_ttl = ${Number(value(fields.cfTunnelTtl)) || 1}`);
  } else {
    lines.push(`# cf_tunnel_ttl = 1`);
  }

  return `${lines.join("\n")}\n`;
}

function renderChecklist() {
  const plan = getPlanOptions();
  const features = getFeatureFlags();
  const sections = [];
  const formatSection = (title, items) => {
    if (!items.length) {
      return;
    }
    sections.push([title, ...items].join("\n"));
  };

  const onpremItems = [];
  if (features.wireguard) {
    onpremItems.push("- wireguard_raw_configs or wireguard_configs");
  }
  if (features.failover) {
    onpremItems.push(
      "- failover_instance_id",
      "- failover_region",
      "- failover_ec2_ip",
      "- failover_cf_token",
      "- failover_cf_zone_id",
      "- failover_cf_record_id",
      "- failover_dns_record_name",
      "- failover_vps_ip",
      "- failover_auto_failback (\"yes\" or \"no\")",
      "- failover_failback_request_file",
      "- failover_core_state",
      "- failover_core_enable",
      "- failover_aws_access_key_id",
      "- failover_aws_secret_access_key",
      "- failover_aws_profile (optional, default=failover)",
    );
  }
  onpremItems.push("- web_portal_admin_user", "- web_portal_admin_password");
  if (plan.onprem) {
    formatSection("onprem-1.yml", onpremItems);
  }

  const vpsItems = [];
  if (features.wireguard) {
    vpsItems.push("- wireguard_raw_configs or wireguard_configs");
  }
  if (features.frr) {
    vpsItems.push("- frr_config_content", "- frr_daemons_content");
  }
  if (features.suricata) {
    vpsItems.push("- suricata_custom_rules_content", "- suricata_custom_rules_path");
  }
  if (value(fields.ddosNotifyEnable)) {
    vpsItems.push(
      "- ddos_notify_primary_ip",
      "- ddos_notify_discord_webhook (shared Discord webhook)",
      "- ddos_notify_signatures (optional)",
    );
  }
  if (features.cloudflared) {
    vpsItems.push(
      "- cloudflared_config_content",
      "- cloudflared_credentials_path",
      "- cloudflared_credentials_content",
    );
  }
  if (features.portctl) {
    vpsItems.push(
      "- portctl_default_dest_ip",
      "- portctl_ufw_rules",
      "- portctl_forward_rules",
    );
  }
  if (plan.vps) {
    formatSection("vps-1.yml", vpsItems);
  }

  const ec2Items = [];
  if (features.wireguard) {
    ec2Items.push("- wireguard_raw_configs or wireguard_configs");
  }
  if (features.suricata) {
    ec2Items.push("- suricata_custom_rules_content", "- suricata_custom_rules_path");
  }
  if (features.cloudflared) {
    ec2Items.push(
      "- cloudflared_config_content",
      "- cloudflared_credentials_path",
      "- cloudflared_credentials_content",
    );
  }
  if (plan.ec2) {
    formatSection("ec2-1.yml", ec2Items);
  }

  const headerJa = "秘密情報チェックリスト（Ansible Vaultに保存）";
  const headerEn = "Secrets checklist (store in Ansible Vault files):";
  const header = currentLang === "ja" ? headerJa : headerEn;
  if (!sections.length) {
    return currentLang === "ja"
      ? `${header}\n\n（選択された機能では秘密情報は不要です）\n`
      : `${header}\n\n(No secrets needed for selected features.)\n`;
  }
  return `${header}\n\n${sections.join("\n\n")}\n`;
}

function renderAdminVaultSnippet() {
  const user = value(fields.webPortalAdminUser) || "admin";
  const password = value(fields.webPortalAdminPassword) || "<set_password>";
  const vaultPath = hostVarsPath("onprem-1.yml");
  const header = currentLang === "ja"
    ? `# ${vaultPath} (Ansible Vault) に貼り付け\n`
    : `# Paste into ${vaultPath} (Ansible Vault)\n`;
  return header +
    `web_portal_admin_user: "${escapeYamlString(user)}"\n` +
    `web_portal_admin_password: "${escapeYamlString(password)}"\n`;
}

function renderFailoverAwsVaultSnippet() {
  const plan = getPlanOptions();
  if (!value(fields.enableFailover) || !plan.onprem) {
    return currentLang === "ja"
      ? "# フェイルオーバーは無効、またはオンプレが未選択です\n"
      : "# Failover is disabled or on-prem is not selected\n";
  }
  const vaultPath = hostVarsPath("onprem-1.yml");
  const header = currentLang === "ja"
    ? `# ${vaultPath} (Ansible Vault) に貼り付け\n`
    : `# Paste into ${vaultPath} (Ansible Vault)\n`;
  const note = currentLang === "ja"
    ? "# Terraform output から取得: failover_access_key_id / failover_secret_access_key\n"
    : "# Get values from Terraform outputs: failover_access_key_id / failover_secret_access_key\n";
  return header +
    note +
    "failover_aws_profile: \"failover\"\n" +
    "failover_aws_access_key_id: \"REPLACE_ME\"\n" +
    "failover_aws_secret_access_key: \"REPLACE_ME\"\n" +
    "failover_aws_session_token: \"\"\n";
}

function renderDdosVaultSnippet() {
  const plan = getPlanOptions();
  if (!value(fields.ddosNotifyEnable) || !value(fields.enableSuricata) || !plan.vps) {
    return currentLang === "ja"
      ? "# DDoS通知は無効、またはVPSが未選択です\n"
      : "# DDoS notify is disabled or VPS is not selected\n";
  }
  const primary = value(fields.ddosNotifyPrimaryIp);
  if (!primary) {
    return currentLang === "ja"
      ? "# DDoS通知の送信先IPが未設定です\n"
      : "# DDoS notify primary IP is not set\n";
  }
  const fallback = value(fields.ddosNotifyFallbackIp);
  const webhook = value(fields.discordWebhook);
  const rawSignatures = value(fields.ddosNotifySignatures);
  const signatures = parseSignatureList(rawSignatures);
  const finalSignatures = signatures.length ? signatures : defaultDdosSignatures;
  const vaultPath = hostVarsPath("vps-1.yml");
  const header = currentLang === "ja"
    ? `# ${vaultPath} (Ansible Vault) に貼り付け\n`
    : `# Paste into ${vaultPath} (Ansible Vault)\n`;

  let output = header;
  output += "ddos_notify_manage: true\n";
  output += `ddos_notify_primary_ip: "${escapeYamlString(primary)}"\n`;
  output += `ddos_notify_fallback_ip: "${escapeYamlString(fallback)}"\n`;
  output += `ddos_notify_discord_webhook: "${escapeYamlString(webhook)}"\n`;
  output += "ddos_notify_signatures:\n" + finalSignatures
    .map((sig) => `  - "${escapeYamlString(sig)}"`)
    .join("\n") + "\n";
  return output;
}

function renderCloudflaredVaultSnippet(target) {
  const plan = getPlanOptions();
  const enabled = value(fields.enableCloudflared);
  const isVps = target === "vps";
  const hostSelected = isVps ? plan.vps : plan.ec2;
  if (!enabled || !hostSelected) {
    return currentLang === "ja"
      ? "# Cloudflared は無効、または対象ホストが未選択です\n"
      : "# Cloudflared is disabled or the host is not selected\n";
  }

  const tunnelId = value(isVps ? fields.cfVpsTunnelId : fields.cfEc2TunnelId) || "REPLACE_ME";
  const hostname = value(isVps ? fields.cfVpsHostname : fields.cfEc2Hostname) || "YOUR_DOMAIN";
  const origin = value(isVps ? fields.cfVpsOrigin : fields.cfEc2Origin) || defaultCloudflaredOrigin();
  const credsRaw = value(isVps ? fields.cfVpsCredentials : fields.cfEc2Credentials);
  const creds = credsRaw || '{"AccountTag":"REPLACE_ME","TunnelSecret":"REPLACE_ME","TunnelID":"REPLACE_ME"}';

  const hostLabel = isVps ? "vps-1.yml" : "ec2-1.yml";
  const vaultPath = hostVarsPath(hostLabel);
  const header = currentLang === "ja"
    ? `# ${vaultPath} (Ansible Vault) に貼り付け\n`
    : `# Paste into ${vaultPath} (Ansible Vault)\n`;

  const escapedTunnel = escapeYamlString(tunnelId);
  const escapedHostname = escapeYamlString(hostname);
  const escapedOrigin = escapeYamlString(origin);
  const credentialsPath = `/etc/cloudflared/${escapedTunnel}.json`;

  return header +
    "cloudflared_config_content: |\n" +
    `  tunnel: "${escapedTunnel}"\n` +
    `  credentials-file: "${credentialsPath}"\n` +
    "  ingress:\n" +
    `    - hostname: "${escapedHostname}"\n` +
    `      service: "${escapedOrigin}"\n` +
    "    - service: http_status:404\n" +
    `cloudflared_credentials_path: "${credentialsPath}"\n` +
    "cloudflared_credentials_content: |\n" +
    `${indentBlock(creds, 2)}\n`;
}

function renderNextSteps() {
  const plan = getPlanOptions();
  const containers = enabledContainers();
  const onpremIp = value(fields.onpremIp) || "<onprem_ip>";
  const onpremLocal = isLocalOnpremHost(value(fields.onpremIp));
  const vpsIp = value(fields.vpsIp) || "<vps_ip>";
  const ec2Ip = value(fields.ec2Ip) || "<ec2_ip>";
  const ddosPrimary = value(fields.ddosNotifyPrimaryIp);
  const vpcMode = value(fields.vpcMode) || "auto";
  const keyPairMode = value(fields.keyPairMode) || "existing";
  const containersRoot = containersRootValue();
  const containersOwner = containersOwnerValue();
  const containersGroup = containersGroupValue();
  const containersManageUser = value(fields.containersManageUser) ? "true" : "false";
  const inventoryFile = inventoryPath();
  const tfvarsFile = tfvarsPath();
  const tfvarsCfFile = tfvarsCfPath();
  const adminVaultSnippet = outputPath("tmp/admin_vault_snippet.txt");
  const failoverVaultSnippet = outputPath("tmp/failover_aws_vault_snippet.txt");
  const ddosVaultSnippet = outputPath("tmp/ddos_vps_vault_snippet.txt");
  const cloudflaredVpsSnippet = outputPath("tmp/cloudflared_vps_vault_snippet.txt");
  const cloudflaredEc2Snippet = outputPath("tmp/cloudflared_ec2_vault_snippet.txt");

  const hostKeyLines = [];
  if (plan.onprem && !onpremLocal) hostKeyLines.push(`ssh-keyscan -H ${onpremIp} >> ~/.ssh/known_hosts`);
  if (plan.vps) hostKeyLines.push(`ssh-keyscan -H ${vpsIp} >> ~/.ssh/known_hosts`);
  if (plan.ec2) hostKeyLines.push(`ssh-keyscan -H ${ec2Ip} >> ~/.ssh/known_hosts`);

  const vaultLines = [];
  if (plan.onprem) vaultLines.push(`ansible-vault edit ${hostVarsPath("onprem-1.yml")}`);
  if (plan.vps) vaultLines.push(`ansible-vault edit ${hostVarsPath("vps-1.yml")}`);
  if (plan.ec2) vaultLines.push(`ansible-vault edit ${hostVarsPath("ec2-1.yml")}`);

  const applyLines = [
    `ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ${inventoryFile} ansible/site.yml --tags base`,
  ];
  if (plan.vps) applyLines.push(`ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ${inventoryFile} ansible/site.yml -l vps`);
  if (plan.ec2) applyLines.push(`ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ${inventoryFile} ansible/site.yml -l ec2`);
  if (plan.onprem) applyLines.push(`ANSIBLE_CONFIG=./ansible.cfg ansible-playbook -i ${inventoryFile} ansible/site.yml -l onprem`);

  const tfLines = [];
  if (plan.terraform) {
    tfLines.push("cd terraform");
    tfLines.push("terraform init");
    tfLines.push(`terraform plan -input=false -var-file=${tfvarsFile}`);
    tfLines.push(`terraform apply -input=false -auto-approve -var-file=${tfvarsFile}`);
  }

  const tfCfLines = [];
  if (plan.cloudflare) {
    tfCfLines.push("cd terraform-cloudflare");
    tfCfLines.push("terraform init");
    tfCfLines.push(`terraform plan -var-file=${tfvarsCfFile}`);
    tfCfLines.push(`terraform apply -auto-approve -input=false -var-file=${tfvarsCfFile}`);
  }

  const tfPrepJa = [];
  const tfPrepEn = [];
  if (plan.terraform) {
    tfPrepJa.push(`${tfvarsFile} を確認`);
    tfPrepEn.push(`Review ${tfvarsFile}`);
    if (vpcMode === "custom") {
      tfPrepJa.push("vpc_cidr / public_subnet_cidr / public_subnet_az を設定");
      tfPrepEn.push("Set vpc_cidr / public_subnet_cidr / public_subnet_az");
    }
    if (keyPairMode === "create") {
      tfPrepJa.push("key_pair_public_key を設定");
      tfPrepEn.push("Set key_pair_public_key");
    }
  }

  const tfCfPrepJa = [];
  const tfCfPrepEn = [];
  if (plan.cloudflare) {
    tfCfPrepJa.push(`${tfvarsCfFile} を確認`);
    tfCfPrepJa.push("CLOUDFLARE_API_TOKEN を環境変数で指定");
    tfCfPrepEn.push(`Review ${tfvarsCfFile}`);
    tfCfPrepEn.push("Set CLOUDFLARE_API_TOKEN in the shell");
  }

  const containerDirs = {
    minecraft: `${containersRoot}/minecraft`,
    valheim: `${containersRoot}/valheim_server`,
    "7dtd": `${containersRoot}/7dtd_server`,
    web_portal: `${containersRoot}/web`,
    player_monitor: `${containersRoot}/monitor`,
  };
  const containerStartLines = containers
    .map((name) => containerDirs[name])
    .filter(Boolean)
    .map((dir) => `cd ${dir}\ndocker compose up -d --build`);

  const vaultPassPath = (lastStatusPayload && lastStatusPayload.vault_pass && lastStatusPayload.vault_pass.path)
    || "~/.config/edge-stack/vault_pass";
  const vaultDir = vaultPassPath.replace(/\/[^\/]+$/, "") || ".";
  const vaultCommands = [
    `mkdir -p ${vaultDir}`,
    `chmod 700 ${vaultDir}`,
    `printf "%s\n" "YOUR_VAULT_PASSWORD" > ${vaultPassPath}`,
    `chmod 600 ${vaultPassPath}`,
  ].join("\n");

  const setupMode = document.body && document.body.dataset.setupMode;
  if (setupMode === "beginner" && currentLang === "ja") {
    const steps = [];
    let step = 0;
    const addStep = (label, body = "") => {
      step += 1;
      steps.push(`${step}) ${label}${body ? "\n" + body : ""}`);
    };

    addStep("（ポータル）入力 → ファイル生成 → サーバーに保存");
    addStep("Vaultパスワード作成（初回のみ）", vaultCommands);

    const vaultEdits = [];
    if (plan.onprem) vaultEdits.push(`ansible-vault edit ${hostVarsPath("onprem-1.yml")}`);
    if (plan.vps) vaultEdits.push(`ansible-vault edit ${hostVarsPath("vps-1.yml")}`);
    if (plan.ec2) vaultEdits.push(`ansible-vault edit ${hostVarsPath("ec2-1.yml")}`);

    const vaultSnippets = [];
    if (plan.onprem) {
      vaultSnippets.push(`${adminVaultSnippet} を ${hostVarsPath("onprem-1.yml")} に貼り付け`);
    }
    if (value(fields.enableCloudflared) && plan.vps) {
      vaultSnippets.push(`${cloudflaredVpsSnippet} を ${hostVarsPath("vps-1.yml")} に貼り付け`);
    }
    if (value(fields.enableCloudflared) && plan.ec2) {
      vaultSnippets.push(`${cloudflaredEc2Snippet} を ${hostVarsPath("ec2-1.yml")} に貼り付け`);
    }
    if (value(fields.ddosNotifyEnable) && plan.vps && ddosPrimary) {
      vaultSnippets.push(`${ddosVaultSnippet} を ${hostVarsPath("vps-1.yml")} に貼り付け`);
    }
    if (vaultEdits.length || vaultSnippets.length) {
      addStep("Vaultを編集してスニペット貼り付け", [...vaultEdits, ...vaultSnippets].join("\n"));
    }

    if (plan.cloudflare) {
      addStep(
        "Terraform（Cloudflare）",
        "ポータルで tf-cf init → plan → apply を実行\n" +
          `CLOUDFLARE_API_TOKEN を環境変数で指定（${tfvarsCfFile} も確認）`,
      );
    }
    if (plan.terraform) {
      addStep(
        "Terraform（EC2）",
        "ポータルで tf init → plan → apply を実行\n" +
          `${tfvarsFile} を確認`,
      );
    }
    if (value(fields.enableFailover) && plan.onprem) {
      addStep(
        "Failover AWS を Vault に反映（Terraform 後）",
        `terraform output -raw failover_access_key_id\nterraform output -raw failover_secret_access_key\n${failoverVaultSnippet} を ${hostVarsPath("onprem-1.yml")} に貼り付け`,
      );
    }

    addStep(
      "Ansible 実行（順番固定）",
      "ポータルで base → vps → ec2 → onprem の順に実行",
    );
    addStep("検証", "make validate");
    return ["簡易ポータル: 次の手順", ...steps].join("\n\n") + "\n";
  }

  const steps = [];
  let step = 0;
  const addStep = (label, body = "") => {
    step += 1;
    steps.push(`${step}) ${label}${body ? "\n" + body : ""}`);
  };

  if (currentLang === "ja") {
    addStep("（ポータル）ファイル生成後に「サーバーに保存」を実行。");
    addStep("Vaultパスワードファイルを作成", vaultCommands);
    if (hostKeyLines.length) {
      addStep("SSHホスト鍵を追加", hostKeyLines.join("\n"));
    }
    if (vaultLines.length) {
      addStep("Vaultに秘密情報を入力", vaultLines.join("\n"));
    }
    if (plan.onprem) {
      addStep("管理者画面の認証情報をVaultへ", `${adminVaultSnippet} を ${hostVarsPath("onprem-1.yml")} に貼り付け`);
    }
    if (value(fields.enableFailover) && plan.onprem) {
      addStep(
        "フェイルオーバー用AWS認証情報",
        `terraform output -raw failover_access_key_id\nterraform output -raw failover_secret_access_key\n${failoverVaultSnippet} に貼り付けて ${hostVarsPath("onprem-1.yml")} へ反映`,
      );
    }
    if (value(fields.ddosNotifyEnable) && plan.vps && ddosPrimary) {
      addStep("DDoS通知（VPS）Vault", `${ddosVaultSnippet} を ${hostVarsPath("vps-1.yml")} に貼り付け`);
    }
    if (value(fields.enableCloudflared) && plan.vps) {
      addStep("Cloudflared（VPS）Vault", `${cloudflaredVpsSnippet} を ${hostVarsPath("vps-1.yml")} に貼り付け`);
    }
    if (value(fields.enableCloudflared) && plan.ec2) {
      addStep("Cloudflared（EC2）Vault", `${cloudflaredEc2Snippet} を ${hostVarsPath("ec2-1.yml")} に貼り付け`);
    }
    if (tfCfPrepJa.length) {
      addStep("Terraform入力を確認（Cloudflare）", tfCfPrepJa.join("\n"));
    }
    if (tfPrepJa.length) {
      addStep("Terraform入力を確認", tfPrepJa.join("\n"));
    }
    if (tfCfLines.length) {
      addStep("Terraform（Cloudflare）", tfCfLines.join("\n"));
    }
    if (tfLines.length) {
      addStep("Terraform（EC2）", tfLines.join("\n"));
    }
    addStep("適用（ポータルまたはCLI）", applyLines.join("\n"));
    if (containers.length) {
      addStep("コンテナ公開情報を設定", "/opt/serveradmin/config/portal_services.json を編集");
    }
    if (containers.length && !value(fields.containersStart)) {
      addStep("コンテナ起動", containerStartLines.join("\n\n"));
    }
    addStep("検証", "make validate");
    return ["次の手順", ...steps].join("\n\n") + "\n";
  }

  addStep('(Portal) Click "Save all to server" after generating files.');
  addStep("Create vault password file", vaultCommands);
  if (hostKeyLines.length) {
    addStep("Add SSH host keys", hostKeyLines.join("\n"));
  }
  if (vaultLines.length) {
    addStep("Fill Ansible Vault secrets", vaultLines.join("\n"));
  }
  if (plan.onprem) {
    addStep("Admin panel credentials", `Paste ${adminVaultSnippet} into ${hostVarsPath("onprem-1.yml")}`);
  }
  if (value(fields.enableFailover) && plan.onprem) {
    addStep(
      "Failover AWS credentials",
      `terraform output -raw failover_access_key_id\nterraform output -raw failover_secret_access_key\nPaste into ${failoverVaultSnippet} then ${hostVarsPath("onprem-1.yml")}`,
    );
  }
  if (value(fields.ddosNotifyEnable) && plan.vps && ddosPrimary) {
    addStep("DDoS notify vault (VPS)", `Paste ${ddosVaultSnippet} into ${hostVarsPath("vps-1.yml")}`);
  }
  if (value(fields.enableCloudflared) && plan.vps) {
    addStep("Cloudflared vault (VPS)", `Paste ${cloudflaredVpsSnippet} into ${hostVarsPath("vps-1.yml")}`);
  }
  if (value(fields.enableCloudflared) && plan.ec2) {
    addStep("Cloudflared vault (EC2)", `Paste ${cloudflaredEc2Snippet} into ${hostVarsPath("ec2-1.yml")}`);
  }
  if (tfCfPrepEn.length) {
    addStep("Review Terraform inputs (Cloudflare)", tfCfPrepEn.join("\n"));
  }
  if (tfPrepEn.length) {
    addStep("Review Terraform inputs", tfPrepEn.join("\n"));
  }
  if (tfCfLines.length) {
    addStep("Terraform (Cloudflare)", tfCfLines.join("\n"));
  }
  if (tfLines.length) {
    addStep("Terraform (EC2)", tfLines.join("\n"));
  }
  addStep("Apply (Portal or CLI)", applyLines.join("\n"));
  if (containers.length) {
    addStep("Update container portal config", "Edit /opt/serveradmin/config/portal_services.json");
  }
  if (containers.length && !value(fields.containersStart)) {
    addStep("Start containers", containerStartLines.join("\n\n"));
  }
  addStep("Validate", "make validate");
  return ["Next steps", ...steps].join("\n\n") + "\n";
}

function isPlaceholderIp(value) {
  const v = (value || "").trim();
  return (
    v.startsWith("192.0.2.") ||
    v.startsWith("198.51.100.") ||
    v.startsWith("203.0.113.")
  );
}

function renderInputWarnings() {
  const plan = getPlanOptions();
  const features = getFeatureFlags();
  const warnings = [];
  const addWarn = (en, ja) => warnings.push({ en, ja });

  const onpremIp = value(fields.onpremIp);
  const vpsIp = value(fields.vpsIp);
  const ec2Ip = value(fields.ec2Ip);

  if (plan.onprem && !onpremIp) {
    addWarn("On-prem IP is empty.", "オンプレIPが空です。");
  }
  if (plan.vps && !vpsIp) {
    addWarn("VPS IP is empty.", "VPSのIPが空です。");
  }
  if (plan.ec2 && !plan.terraform && !ec2Ip) {
    addWarn("EC2 IP is empty.", "EC2のIPが空です。");
  }
  if (plan.onprem && onpremIp && isPlaceholderIp(onpremIp)) {
    addWarn("On-prem IP is still a sample (192.0.2.x).", "オンプレIPがサンプルのままです（192.0.2.x）。");
  }
  if (plan.vps && vpsIp && isPlaceholderIp(vpsIp)) {
    addWarn("VPS IP is still a sample (198.51.100.x).", "VPSのIPがサンプルのままです（198.51.100.x）。");
  }
  if (plan.ec2 && !plan.terraform && ec2Ip && isPlaceholderIp(ec2Ip)) {
    addWarn("EC2 IP is still a sample (203.0.113.x).", "EC2のIPがサンプルのままです（203.0.113.x）。");
  }

  if (features.failover && (!plan.vps || !plan.ec2)) {
    addWarn("Failover requires VPS + EC2.", "フェイルオーバーにはVPSとEC2が必要です。");
  }
  if (features.cloudflared && !plan.vps) {
    addWarn("Cloudflared requires VPS.", "CloudflaredにはVPSが必要です。");
  }
  if (features.portctl && !plan.vps) {
    addWarn("Portctl requires VPS.", "PortctlにはVPSが必要です。");
  }
  if (features.frr && !plan.vps) {
    addWarn("FRR/BFD requires VPS.", "FRR/BFDにはVPSが必要です。");
  }
  const keyPairMode = value(fields.keyPairMode) || "existing";
  if (plan.ec2 && (keyPairMode === "create" || keyPairMode === "auto") && !value(fields.keyPairPublicKey)) {
    addWarn("EC2 key pair is missing (public key not set).", "EC2鍵が未設定です（公開鍵が空です）。");
  }
  if (features.suricata && !plan.vps && !plan.ec2) {
    addWarn("Suricata requires VPS or EC2.", "SuricataにはVPSまたはEC2が必要です。");
  }

  const failoverKeyId = value(fields.failoverAccessKeyId);
  const failoverSecret = value(fields.failoverSecretAccessKey);
  if ((failoverKeyId && !failoverSecret) || (!failoverKeyId && failoverSecret)) {
    addWarn(
      "Failover access key is incomplete (set both ID and secret).",
      "フェイルオーバーのアクセスキーが不完全です（IDとSecretを両方入力してください）。",
    );
  }

  if (value(fields.ddosNotifyEnable) && (!value(fields.enableSuricata) || !plan.vps)) {
    addWarn("DDoS notify requires Suricata + VPS.", "DDoS通知にはSuricataとVPSが必要です。");
  }

  if (value(fields.ddosNotifyEnable) && plan.vps && !value(fields.ddosNotifyPrimaryIp)) {
    addWarn("DDoS notify primary IP is empty.", "DDoS通知の送信先IPが空です。");
  }
  if (value(fields.ddosNotifyEnable) && plan.vps && !value(fields.discordWebhook)) {
    addWarn("Discord webhook is empty (DDoS notify won't send alerts).", "Discord webhookが空です（DDoS通知が送信されません）。");
  }

  if (plan.terraform) {
    const vpcMode = value(fields.vpcMode) || "auto";
    const keyPairMode = value(fields.keyPairMode) || "existing";
    if (!value(fields.awsRegion)) {
      addWarn("Terraform: AWS region is empty.", "Terraform: AWSリージョンが空です。");
    }
    if (vpcMode === "custom" && !value(fields.vpcCidr)) {
      addWarn("Terraform: VPC CIDR is empty (custom mode).", "Terraform: VPC CIDRが空です（カスタム）。");
    }
    if (vpcMode === "custom" && !value(fields.publicSubnetCidr)) {
      addWarn("Terraform: public subnet CIDR is empty (custom mode).", "Terraform: Public Subnet CIDRが空です（カスタム）。");
    }
    const amiMode = value(fields.amiMode) || "manual";
    if (amiMode === "manual" && !value(fields.amiId)) {
      addWarn("Terraform: AMI ID is empty (manual mode).", "Terraform: AMI IDが空です（手動）。");
    }
    if (amiMode === "auto") {
      if (parseList(value(fields.amiOwners)).length === 0) {
        addWarn("Terraform: AMI owners are empty (auto mode).", "Terraform: AMIオーナーが空です（自動）。");
      }
      if (!value(fields.amiNameFilter)) {
        addWarn("Terraform: AMI name filter is empty (auto mode).", "Terraform: AMI名フィルタが空です（自動）。");
      }
    }
    if (!value(fields.instanceType)) {
      addWarn("Terraform: instance type is empty.", "Terraform: インスタンスタイプが空です。");
    }
    if (!value(fields.keyName)) {
      addWarn("Terraform: KeyPair name is empty.", "Terraform: KeyPair名が空です。");
    }
    if ((keyPairMode === "create" || keyPairMode === "auto") && !value(fields.keyPairPublicKey)) {
      addWarn("Terraform: public key is empty (key create mode).", "Terraform: 公開鍵が空です（キー作成モード）。");
    }
  }

  if (plan.cloudflare) {
    if (!value(fields.cfAccountId)) {
      addWarn("Cloudflare: account ID is empty.", "Cloudflare: アカウントIDが空です。");
    }
    if (!value(fields.cfZoneName)) {
      addWarn("Cloudflare: zone name is empty.", "Cloudflare: ゾーン名が空です。");
    }
    if (value(fields.cfManageFailoverRecord) && !value(fields.cfFailoverRecordName)) {
      addWarn("Cloudflare: failover record name is empty.", "Cloudflare: フェイルオーバー用レコード名が空です。");
    }
    if (value(fields.cfManageFailoverRecord) && !value(fields.cfFailoverRecordValue)) {
      addWarn("Cloudflare: failover record IP is empty.", "Cloudflare: フェイルオーバー用IPが空です。");
    }
    if (value(fields.cfManageTunnels) && !value(fields.cfVpsHostname) && !value(fields.cfEc2Hostname)) {
      addWarn("Cloudflare: tunnel hostnames are empty.", "Cloudflare: トンネルホスト名が空です。");
    }
    if (value(fields.cfManageTunnels) && value(fields.cfVpsHostname) && !value(fields.cfVpsTunnelName)) {
      addWarn("Cloudflare: VPS tunnel name is empty.", "Cloudflare: VPSトンネル名が空です。");
    }
    if (value(fields.cfManageTunnels) && value(fields.cfEc2Hostname) && !value(fields.cfEc2TunnelName)) {
      addWarn("Cloudflare: EC2 tunnel name is empty.", "Cloudflare: EC2トンネル名が空です。");
    }
  }

  const cloudflaredAuto = plan.cloudflare && value(fields.cfManageTunnels);
  const cloudflaredReady = !cloudflaredAuto || guidedState.tfCfApply;

  if (features.cloudflared && cloudflaredReady) {
    if (plan.vps) {
      if (!value(fields.cfVpsTunnelId)) {
        addWarn("Cloudflared: VPS tunnel ID is empty.", "Cloudflared: VPSトンネルIDが空です。");
      }
      if (!value(fields.cfVpsOrigin)) {
        addWarn("Cloudflared: VPS origin service is empty.", "Cloudflared: VPS転送先サービスが空です。");
      }
      if (!value(fields.cfVpsCredentials)) {
        addWarn("Cloudflared: VPS credentials JSON is empty.", "Cloudflared: VPS credentials JSONが空です。");
      }
      if (!value(fields.cfVpsHostname)) {
        addWarn("Cloudflared: VPS hostname is empty.", "Cloudflared: VPSホスト名が空です。");
      }
    }
    if (plan.ec2) {
      if (!value(fields.cfEc2TunnelId)) {
        addWarn("Cloudflared: EC2 tunnel ID is empty.", "Cloudflared: EC2トンネルIDが空です。");
      }
      if (!value(fields.cfEc2Origin)) {
        addWarn("Cloudflared: EC2 origin service is empty.", "Cloudflared: EC2転送先サービスが空です。");
      }
      if (!value(fields.cfEc2Credentials)) {
        addWarn("Cloudflared: EC2 credentials JSON is empty.", "Cloudflared: EC2 credentials JSONが空です。");
      }
      if (!value(fields.cfEc2Hostname)) {
        addWarn("Cloudflared: EC2 hostname is empty.", "Cloudflared: EC2ホスト名が空です。");
      }
    }
  }

  const adminEnabled = true;
  if (!enabledContainers().includes("web_portal")) {
    addWarn("Admin panel requires the web portal container.", "管理者画面にはWebポータルが必要です。");
  }
  if (!value(fields.webPortalAdminUser)) {
    addWarn("Admin login is empty.", "管理者ログイン名が空です。");
  }
  if (!value(fields.webPortalAdminPassword)) {
    addWarn("Admin password is empty.", "管理者パスワードが空です。");
  }
  if (parseList(value(fields.webPortalAdminAllowCidrs)).length === 0) {
    addWarn("Admin allow CIDRs are empty.", "管理者の許可CIDRが空です。");
  }

  if (value(fields.containersStart) && enabledContainers().length === 0) {
    addWarn("Auto start is enabled but no containers are selected.", "自動起動が有効ですがコンテナが選択されていません。");
  }

  if (features.portctl && value(fields.portForwardEnable)) {
    const portPlan = buildPortPlan();
    if (!value(fields.portForwardDestIp)) {
      addWarn("Port forwarding destination IP is empty.", "転送先IPが空です。");
    }
    if (portPlan.forwardRules.length === 0) {
      addWarn("Port forwarding is enabled but no rules are selected.", "転送が有効ですがルールがありません。");
    }
  }

  const container = document.getElementById("input_warnings");
  if (!container) {
    return;
  }
  container.innerHTML = "";
  if (!warnings.length) {
    const ok = document.createElement("div");
    ok.className = "input-warning ok";
    ok.textContent = currentLang === "ja"
      ? "入力チェック: 問題は見つかりませんでした。"
      : "Inputs check: no issues detected.";
    container.appendChild(ok);
    return;
  }
  warnings.forEach((warn) => {
    const item = document.createElement("div");
    item.className = "input-warning";
    item.textContent = currentLang === "ja" ? warn.ja : warn.en;
    container.appendChild(item);
  });
}

function setOutput(id, text) {
  const el = document.getElementById(id);
  if (el) {
    el.value = text;
  }
}

function generateAll() {
  setOutput("inventory", renderInventory());
  setOutput("groupvars", renderGroupVars());
  setOutput("tfvars", renderTfvars());
  setOutput("tfvars_cf", renderCfTfvars());
  setOutput("checklist", renderChecklist());
  setOutput("admin_vault", renderAdminVaultSnippet());
  setOutput("failover_aws_vault", renderFailoverAwsVaultSnippet());
  setOutput("ddos_vps_vault", renderDdosVaultSnippet());
  setOutput("cloudflared_vps_vault", renderCloudflaredVaultSnippet("vps"));
  setOutput("cloudflared_ec2_vault", renderCloudflaredVaultSnippet("ec2"));
  setOutput("nextsteps", renderNextSteps());
  setOutput("simple_next_steps", renderNextSteps());
  const wgPlaceholder = currentLang === "ja"
    ? "保存後に自動生成されます。"
    : "Generated after Save.";
  setOutput("wg_onprem_wg0", wgPlaceholder);
  setOutput("wg_onprem_wg1", wgPlaceholder);
  setOutput("wg_vps_wg0", wgPlaceholder);
  setOutput("wg_ec2_wg1", wgPlaceholder);
  renderInputWarnings();
}



function outputValue(id) {
  const el = document.getElementById(id);
  return el ? el.value : "";
}

function setSaveStatus(message, state) {
  const status = document.getElementById("save_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setGenerateStatus(message, state) {
  const status = document.getElementById("generate_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setStatusMessage(message, state) {
  const status = document.getElementById("status_message");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function actionTimestamp() {
  return new Date().toTimeString().slice(0, 8);
}

function setActionNotice(message, state) {
  const status = document.getElementById("action_notice");
  if (!status) {
    return;
  }
  status.textContent = `[${actionTimestamp()}] ${message}`;
  status.dataset.state = state;
}

async function fetchTerraformOutputs(stack) {
  const token = tokenValue();
  if (!token) {
    return null;
  }
  const response = await fetch(`/api/terraform-output?stack=${encodeURIComponent(stack || "ec2")}`, {
    headers: { "X-Portal-Token": token },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.ok) {
    return null;
  }
  return payload.outputs || null;
}

async function refreshEc2IpFromTerraform(force = false) {
  const ec2Input = document.getElementById(fields.ec2Ip);
  if (!ec2Input) {
    return false;
  }
  if (!force && ec2Input.dataset.manual === "true") {
    return false;
  }
  const outputs = await fetchTerraformOutputs("ec2");
  if (!outputs) {
    return false;
  }
  const ip = outputs.elastic_ip || outputs.public_ip || "";
  if (!ip) {
    return false;
  }
  ec2Input.value = ip;
  ec2Input.dataset.manual = "auto";
  generateAll();
  setActionNotice(currentLang === "ja" ? "EC2 IPを自動反映しました。" : "Auto-filled EC2 IP.", "ok");
  return true;
}

async function saveAll() {
  const messages = saveMessages[currentLang] || saveMessages.en;
  const token = tokenValue();
  if (!token) {
    setSaveStatus(messages.missingToken, "error");
    return;
  }

  const plan = getPlanOptions();
  const keyPairMode = value(fields.keyPairMode) || "existing";
  if (plan.ec2 || plan.terraform) {
    if (keyPairMode === "create" && !value(fields.keyPairPublicKey)) {
      setSaveStatus(messages.ec2KeyPublicMissing, "error");
      return;
    }
    const ec2Ready = await ensureEc2KeyPair();
    if (!ec2Ready) {
      setSaveStatus(messages.ec2KeyMissing, "error");
      return;
    }
  }

  if (plan.ec2 && !value(fields.ec2Ip)) {
    await refreshEc2IpFromTerraform(true);
  }

  generateAll();

  const inventory = outputValue("inventory");
  if (!inventory.trim()) {
    setSaveStatus(messages.emptyOutput, "error");
    return;
  }

  const payload = {
    mode: (document.body && document.body.dataset.setupMode) || "custom",
    files: {
      "ansible/hosts.ini": inventory,
      "ansible/group_vars/all.yml": outputValue("groupvars"),
      "terraform/terraform.tfvars": outputValue("tfvars"),
      "terraform-cloudflare/terraform.tfvars": outputValue("tfvars_cf"),
      "tmp/secrets_checklist.txt": outputValue("checklist"),
      "tmp/admin_vault_snippet.txt": outputValue("admin_vault"),
      "tmp/failover_aws_vault_snippet.txt": outputValue("failover_aws_vault"),
      "tmp/ddos_vps_vault_snippet.txt": outputValue("ddos_vps_vault"),
      "tmp/cloudflared_vps_vault_snippet.txt": outputValue("cloudflared_vps_vault"),
      "tmp/cloudflared_ec2_vault_snippet.txt": outputValue("cloudflared_ec2_vault"),
      "tmp/next_steps.txt": outputValue("nextsteps"),
    },
  };
  const autoSecrets = {};
  const vpsPassphrase = value(fields.autoVpsKeyPassphrase);
  if (vpsPassphrase) {
    autoSecrets.vps_key_passphrase = vpsPassphrase;
  }
  const vpsSudoPassword = value(fields.autoVpsSudoPassword);
  if (vpsSudoPassword) {
    autoSecrets.vps_sudo_password = vpsSudoPassword;
  }
  if (Object.keys(autoSecrets).length > 0) {
    payload.secrets = autoSecrets;
  }

  setSaveStatus(messages.saving, "info");

  try {
    const response = await fetch("/api/save", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Portal-Token": token,
      },
      body: JSON.stringify(payload),
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok || !result.ok) {
      const detail = result.error || response.statusText || "Unknown error";
      setSaveStatus(messages.error(detail), "error");
      return;
    }
    setSaveStatus(messages.success, "ok");
    let notice = messages.success;
    let noticeState = "ok";
    const savedCount = result.saved ? Object.keys(result.saved).length : 0;
    if (savedCount > 0) {
      notice += ` ${messages.savedCount(savedCount)}`;
    }
    const importedCount = result.imported ? Object.keys(result.imported).length : 0;
    const importErrorCount = result.import_errors ? Object.keys(result.import_errors).length : 0;
    if (importedCount > 0) {
      notice += ` ${messages.imported(importedCount)}`;
    }
    if (importErrorCount > 0) {
      notice += ` ${messages.importError(importErrorCount)}`;
      noticeState = "error";
    }
    const warningMessages = [];
    const warnings = result.warnings || {};
    if (Array.isArray(warnings)) {
      for (const warning of warnings) {
        if (typeof warning === "string" && warning.trim()) {
          warningMessages.push(warning.trim());
        }
      }
    } else if (warnings && typeof warnings === "object") {
      for (const warning of Object.values(warnings)) {
        if (typeof warning === "string" && warning.trim()) {
          warningMessages.push(warning.trim());
        } else if (warning && typeof warning === "object" && typeof warning.message === "string") {
          const message = warning.message.trim();
          if (message) {
            warningMessages.push(message);
          }
        }
      }
    }
    if (warningMessages.length > 0) {
      const header = messages.warningHeader || "Warnings:";
      notice += ` ${header} ${warningMessages.join(" / ")}`;
      if (noticeState !== "error") {
        noticeState = "info";
      }
    }
    const wgConfigs = result.wireguard_configs || {};
    if (wgConfigs.onprem_wg0) {
      setOutput("wg_onprem_wg0", wgConfigs.onprem_wg0);
    }
    if (wgConfigs.onprem_wg1) {
      setOutput("wg_onprem_wg1", wgConfigs.onprem_wg1);
    }
    if (wgConfigs.vps_wg0) {
      setOutput("wg_vps_wg0", wgConfigs.vps_wg0);
    }
    if (wgConfigs.ec2_wg1) {
      setOutput("wg_ec2_wg1", wgConfigs.ec2_wg1);
    }
    setActionNotice(notice, noticeState);
    guidedState.saved = true;
    updateGuidedSteps();
    loadStatus();
  } catch (error) {
    setSaveStatus(messages.unknownError, "error");
  }
}

function addStatusItem(list, label, ok, detail) {
  const item = document.createElement("li");
  item.className = "status-item";

  const pill = document.createElement("span");
  pill.className = ok ? "status-pill ok" : "status-pill missing";
  pill.textContent = ok
    ? (statusLabels[currentLang] || statusLabels.en).ok
    : (statusLabels[currentLang] || statusLabels.en).missing;

  const text = document.createElement("span");
  text.className = "status-text";
  text.textContent = label;

  const meta = document.createElement("span");
  meta.className = "status-meta";
  meta.textContent = detail || "";

  item.appendChild(pill);
  item.appendChild(text);
  item.appendChild(meta);
  list.appendChild(item);
}

function renderStatus(payload) {
  const list = document.getElementById("status_list");
  if (!list) {
    return;
  }
  list.innerHTML = "";

  const labels = statusLabels[currentLang] || statusLabels.en;
  const files = payload.files || {};
  const plan = getPlanOptions();

  const inventory = files["ansible/hosts.ini"];
  const inventoryLabel = (inventory && inventory.path) || inventoryPath(payload);
  addStatusItem(
    list,
    `${labels.inventory} (${inventoryLabel})`,
    inventory && inventory.exists,
    inventory && inventory.exists ? `${inventory.bytes} bytes` : labels.missing,
  );

  const groupvars = files["ansible/group_vars/all.yml"];
  const groupvarsLabel = (groupvars && groupvars.path) || groupVarsPath(payload);
  addStatusItem(
    list,
    `${labels.groupvars} (${groupvarsLabel})`,
    groupvars && groupvars.exists,
    groupvars && groupvars.exists ? `${groupvars.bytes} bytes` : labels.missing,
  );

  if (plan.terraform) {
    const tfvars = files["terraform/terraform.tfvars"];
    const tfvarsLabel = (tfvars && tfvars.path) || tfvarsPath(payload);
    addStatusItem(
      list,
      `${labels.tfvars} (${tfvarsLabel})`,
      tfvars && tfvars.exists,
      tfvars && tfvars.exists ? `${tfvars.bytes} bytes` : labels.missing,
    );
  }
  if (plan.cloudflare) {
    const tfvarsCf = files["terraform-cloudflare/terraform.tfvars"];
    const tfvarsCfLabel = (tfvarsCf && tfvarsCf.path) || tfvarsCfPath(payload);
    addStatusItem(
      list,
      `${labels.tfvarsCloudflare} (${tfvarsCfLabel})`,
      tfvarsCf && tfvarsCf.exists,
      tfvarsCf && tfvarsCf.exists ? `${tfvarsCf.bytes} bytes` : labels.missing,
    );
  }

  const vaultPass = payload.vault_pass || {};
  addStatusItem(
    list,
    `${labels.vaultPass} (${vaultPass.path || "~/.config/edge-stack/vault_pass"})`,
    vaultPass.exists,
    vaultPass.exists ? labels.ok : labels.missing,
  );

  const secrets = payload.secrets || {};
  if (plan.cloudflare) {
    const cfToken = secrets.cloudflare_token || {};
    addStatusItem(
      list,
      `${labels.cloudflareToken} (${cfToken.path || "~/.config/edge-stack/cloudflare_token"})`,
      cfToken.exists,
      cfToken.exists ? labels.ok : labels.missing,
    );
  }
  if (plan.terraform) {
    const awsCredentials = secrets.aws_credentials || {};
    addStatusItem(
      list,
      `${labels.awsCredentials} (${awsCredentials.path || "~/.aws/credentials"})`,
      awsCredentials.exists,
      awsCredentials.exists ? labels.ok : labels.missing,
    );
    const awsConfig = secrets.aws_config || {};
    addStatusItem(
      list,
      `${labels.awsConfig} (${awsConfig.path || "~/.aws/config"})`,
      awsConfig.exists,
      awsConfig.exists ? labels.ok : labels.missing,
    );
  }

  const vaultFiles = payload.vault_files || {};
  if (plan.onprem) {
    const vaultPath = (vaultFiles["ansible/host_vars/onprem-1.yml"] || {}).path || hostVarsPath("onprem-1.yml", payload);
    addStatusItem(
      list,
      `${labels.vaultOnprem} (${vaultPath})`,
      vaultFiles["ansible/host_vars/onprem-1.yml"] && vaultFiles["ansible/host_vars/onprem-1.yml"].exists,
      vaultFiles["ansible/host_vars/onprem-1.yml"] && vaultFiles["ansible/host_vars/onprem-1.yml"].exists ? labels.ok : labels.missing,
    );
  }
  if (plan.vps) {
    const vaultPath = (vaultFiles["ansible/host_vars/vps-1.yml"] || {}).path || hostVarsPath("vps-1.yml", payload);
    addStatusItem(
      list,
      `${labels.vaultVps} (${vaultPath})`,
      vaultFiles["ansible/host_vars/vps-1.yml"] && vaultFiles["ansible/host_vars/vps-1.yml"].exists,
      vaultFiles["ansible/host_vars/vps-1.yml"] && vaultFiles["ansible/host_vars/vps-1.yml"].exists ? labels.ok : labels.missing,
    );
  }
  if (plan.ec2) {
    const vaultPath = (vaultFiles["ansible/host_vars/ec2-1.yml"] || {}).path || hostVarsPath("ec2-1.yml", payload);
    addStatusItem(
      list,
      `${labels.vaultEc2} (${vaultPath})`,
      vaultFiles["ansible/host_vars/ec2-1.yml"] && vaultFiles["ansible/host_vars/ec2-1.yml"].exists,
      vaultFiles["ansible/host_vars/ec2-1.yml"] && vaultFiles["ansible/host_vars/ec2-1.yml"].exists ? labels.ok : labels.missing,
    );
  }

  const sshKeys = payload.ssh_keys || {};
  const onpremKeyName = keyNameValue(fields.onpremKeyName, "onprem_ed25519");
  const vpsKeyName = keyNameValue(fields.vpsKeyName, "vps_ed25519");
  const ec2KeyName = keyNameValue(fields.ec2KeyName, "ec2_key.pem");
  const onpremKeyPath = keyPath(onpremKeyName);
  const vpsKeyPath = keyPath(vpsKeyName);
  const ec2KeyPath = keyPath(ec2KeyName);
  if (plan.onprem) {
    addStatusItem(
      list,
      `${labels.sshAnsible} (${(sshKeys.ansible || {}).path || onpremKeyPath})`,
      sshKeys.ansible && sshKeys.ansible.exists,
      sshKeys.ansible && sshKeys.ansible.exists ? labels.ok : labels.missing,
    );
  }
  if (plan.vps) {
    addStatusItem(
      list,
      `${labels.sshVps} (${(sshKeys.vps || {}).path || vpsKeyPath})`,
      sshKeys.vps && sshKeys.vps.exists,
      sshKeys.vps && sshKeys.vps.exists ? labels.ok : labels.missing,
    );
  }
  if (plan.ec2) {
    addStatusItem(
      list,
      `${labels.sshEc2} (${(sshKeys.ec2 || {}).path || ec2KeyPath})`,
      sshKeys.ec2 && sshKeys.ec2.exists,
      sshKeys.ec2 && sshKeys.ec2.exists ? labels.ok : labels.missing,
    );
  }

  const tools = payload.tools || {};
  addStatusItem(
    list,
    `${labels.toolAnsible} (ansible-playbook)`,
    tools["ansible-playbook"],
    tools["ansible-playbook"] ? labels.ok : labels.missing,
  );
  addStatusItem(
    list,
    `${labels.toolAnsibleCli} (ansible)`,
    tools.ansible,
    tools.ansible ? labels.ok : labels.missing,
  );
  if (plan.terraform || plan.cloudflare) {
    addStatusItem(
      list,
      `${labels.toolTerraform} (terraform)`,
      tools.terraform,
      tools.terraform ? labels.ok : labels.missing,
    );
  }
  addStatusItem(
    list,
    `${labels.toolSsh} (ssh)`,
    tools.ssh,
    tools.ssh ? labels.ok : labels.missing,
  );
  addStatusItem(
    list,
    `${labels.toolKeyscan} (ssh-keyscan)`,
    tools["ssh-keyscan"],
    tools["ssh-keyscan"] ? labels.ok : labels.missing,
  );
  addStatusItem(
    list,
    `${labels.toolKeygen} (ssh-keygen)`,
    tools["ssh-keygen"],
    tools["ssh-keygen"] ? labels.ok : labels.missing,
  );
  addStatusItem(
    list,
    `${labels.toolPython} (python3)`,
    tools.python3,
    tools.python3 ? labels.ok : labels.missing,
  );
}

async function loadStatus() {
  const messages = statusMessages[currentLang] || statusMessages.en;
  const token = tokenValue();
  if (!token) {
    setStatusMessage(messages.missingToken, "error");
    return;
  }

  setStatusMessage(messages.checking, "info");

  try {
    const onpremKeyName = keyNameValue(fields.onpremKeyName, "onprem_ed25519");
    const vpsKeyName = keyNameValue(fields.vpsKeyName, "vps_ed25519");
    const ec2KeyName = keyNameValue(fields.ec2KeyName, "ec2_key.pem");
    const params = new URLSearchParams({
      onprem_key: onpremKeyName,
      vps_key: vpsKeyName,
      ec2_key: ec2KeyName,
    });
    const response = await fetch(`/api/status?${params.toString()}`, {
      headers: { "X-Portal-Token": token },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      setStatusMessage(messages.error, "error");
      return;
    }
    lastStatusPayload = payload;
    applyAutoAdminAllowCidrs(payload);
    applyAutoAllowedSshCidrs(payload);
    applyAutoPortForwardDestIp(payload);
    applyAutoCloudflaredOrigins(payload);
    guidedState.preflight = true;
    const files = payload.files || {};
    const plan = getPlanOptions();
    const inventoryOk = files["ansible/hosts.ini"] && files["ansible/hosts.ini"].exists;
    const groupvarsOk = files["ansible/group_vars/all.yml"] && files["ansible/group_vars/all.yml"].exists;
    const tfOk = !plan.terraform || (files["terraform/terraform.tfvars"] && files["terraform/terraform.tfvars"].exists);
    const tfCfOk = !plan.cloudflare || (files["terraform-cloudflare/terraform.tfvars"] && files["terraform-cloudflare/terraform.tfvars"].exists);
    guidedState.saved = Boolean(inventoryOk && groupvarsOk && tfOk && tfCfOk);
    renderStatus(payload);
    setStatusMessage(messages.ready, "ok");
    updateGuidedSteps();
    if (document.body && document.body.dataset.setupMode === "beginner") {
      const ec2Ip = value(fields.ec2Ip);
      if (!ec2Ip) {
        refreshEc2IpFromTerraform(false);
      }
    }
  } catch (error) {
    setStatusMessage(messages.error, "error");
  }
}


function getPlanOptions() {
  const plan = {
    onprem: true,
    vps: true,
    ec2: true,
    cloudflared: false,
    portctl: false,
    terraform: false,
    cloudflare: false,
  };
  const onprem = document.getElementById("plan_onprem");
  const vps = document.getElementById("plan_vps");
  const ec2 = document.getElementById("plan_ec2");
  const cloudflared = document.getElementById("plan_cloudflared");
  const portctl = document.getElementById("plan_portctl");
  const terraform = document.getElementById("plan_terraform");
  const cloudflare = document.getElementById("plan_cloudflare");
  if (onprem) plan.onprem = onprem.checked;
  if (vps) plan.vps = vps.checked;
  if (ec2) plan.ec2 = ec2.checked;
  if (cloudflared) plan.cloudflared = cloudflared.checked;
  if (portctl) plan.portctl = portctl.checked;
  if (terraform) plan.terraform = terraform.checked;
  if (cloudflare) plan.cloudflare = cloudflare.checked;
  return plan;
}

function setCheckbox(id, value) {
  const el = document.getElementById(id);
  if (el) {
    el.checked = Boolean(value);
  }
}

function setTemplateStatus(message, state) {
  const el = document.getElementById("template_status");
  if (!el) {
    return;
  }
  el.textContent = message;
  el.dataset.state = state || "info";
}

function syncDependencies() {
  const plan = getPlanOptions();
  if (!plan.vps) {
    setCheckbox("enable_cloudflared", false);
    setCheckbox("plan_cloudflared", false);
    setCheckbox("enable_portctl", false);
    setCheckbox("plan_portctl", false);
    setCheckbox("enable_frr", false);
  }
  if (!plan.vps || !plan.ec2) {
    setCheckbox("enable_failover", false);
  }
  if (!plan.vps && !plan.ec2) {
    setCheckbox("enable_suricata", false);
  }
  if (!plan.vps && !plan.ec2) {
    setCheckbox("enable_wireguard", false);
  }
  if (!plan.vps || !value(fields.enableSuricata)) {
    setCheckbox("ddos_notify_enable", false);
  }
  syncDdosNotify();
}

function toggleFieldGroup(containerId, enabled) {
  const container = document.getElementById(containerId);
  if (!container) {
    return;
  }
  container.hidden = !enabled;
  container.querySelectorAll("input, select, textarea").forEach((item) => {
    item.disabled = !enabled;
  });
}

function syncVpcMode() {
  const mode = value(fields.vpcMode) || "auto";
  toggleFieldGroup("vpc_custom_fields", mode === "custom");
}

function syncKeyPairMode() {
  const mode = value(fields.keyPairMode) || "existing";
  toggleFieldGroup("key_pair_public_fields", mode === "create");
  toggleFieldGroup("key_pair_auto_fields", mode === "auto");
}

function syncAmiMode() {
  const mode = value(fields.amiMode) || "manual";
  toggleFieldGroup("ami_manual_fields", mode === "manual");
  toggleFieldGroup("ami_auto_fields", mode === "auto");
}

function syncDdosNotify() {
  const enabled = value(fields.ddosNotifyEnable);
  toggleFieldGroup("ddos_notify_fields", enabled);
}

function syncUploadKeyName() {
  const targetSelect = document.getElementById("upload_target");
  const keyNameInput = document.getElementById("upload_key_name");
  if (!targetSelect || !keyNameInput) {
    return;
  }
  const suggested = keyNameForTarget(targetSelect.value);
  const current = (keyNameInput.value || "").trim();
  if (!current || current === "auto") {
    keyNameInput.value = suggested;
  }
}

function syncUploadTargetLabels() {
  const targetSelect = document.getElementById("upload_target");
  if (!targetSelect) {
    return;
  }
  const options = {
    onprem: keyNameValue(fields.onpremKeyName, "onprem_ed25519"),
    vps: keyNameValue(fields.vpsKeyName, "vps_ed25519"),
    ec2: keyNameValue(fields.ec2KeyName, "ec2_key.pem"),
  };
  const onpremOption = targetSelect.querySelector('option[value="onprem"]');
  if (onpremOption) {
    onpremOption.textContent = `On-prem (${options.onprem})`;
  }
  const vpsOption = targetSelect.querySelector('option[value="vps"]');
  if (vpsOption) {
    vpsOption.textContent = `VPS (${options.vps})`;
  }
  const ec2Option = targetSelect.querySelector('option[value="ec2"]');
  if (ec2Option) {
    ec2Option.textContent = `EC2 (${options.ec2})`;
  }
}

function getAutoPortForwardDestIp(payload) {
  const wgIps = payload && payload.wg_ips ? payload.wg_ips : {};
  const wg0 = wgIps.wg0;
  if (wg0) {
    return wg0;
  }
  if (document.body && document.body.dataset.setupMode === "beginner") {
    return "10.0.0.2";
  }
  return "";
}

function applyAutoPortForwardDestIp(payload) {
  const input = document.getElementById("port_forward_dest_ip");
  if (!input || input.dataset.manual === "true") {
    return;
  }
  const current = (input.value || "").trim();
  if (current) {
    return;
  }
  const autoIp = getAutoPortForwardDestIp(payload);
  if (autoIp) {
    input.value = autoIp;
  }
}

function defaultCloudflaredOrigin() {
  const input = document.getElementById("port_forward_dest_ip");
  const current = input ? (input.value || "").trim() : "";
  const autoIp = current || getAutoPortForwardDestIp(lastStatusPayload);
  const ip = autoIp || "10.0.0.2";
  return `http://${ip}:8082`;
}

function applyAutoCloudflaredOrigins(payload) {
  const autoIp = getAutoPortForwardDestIp(payload);
  if (!autoIp) {
    return;
  }
  const origin = `http://${autoIp}:8082`;
  ["cf_vps_origin", "cf_ec2_origin"].forEach((id) => {
    const input = document.getElementById(id);
    if (!input || input.dataset.manual === "true") {
      return;
    }
    const current = (input.value || "").trim();
    if (!current) {
      input.value = origin;
    }
  });
}

function applyAutoAdminAllowCidrs(payload) {
  const input = document.getElementById("web_portal_admin_allow_cidrs");
  if (!input || input.dataset.manual === "true") {
    return;
  }
  const current = (input.value || "").trim();
  if (current) {
    return;
  }
  const lanCidrs = Array.isArray(payload.lan_cidrs) ? payload.lan_cidrs : [];
  const defaults = [...lanCidrs];
  const unique = [];
  defaults.forEach((cidr) => {
    if (cidr && !unique.includes(cidr)) {
      unique.push(cidr);
    }
  });
  if (unique.length) {
    input.value = unique.join(",");
  }
}


function applyAutoAllowedSshCidrs(payload) {
  const input = document.getElementById("allowed_ssh_cidrs");
  if (!input || input.dataset.manual === "true") {
    return;
  }
  const current = (input.value || "").trim();
  if (current) {
    return;
  }
  input.value = "0.0.0.0/0";
}

function applyTemplate(name) {
  const templates = {
    single: {
      plan: { onprem: true, vps: false, ec2: false, cloudflared: false, portctl: false, terraform: false, cloudflare: false },
      features: { wireguard: false, failover: false, frr: false, suricata: false, cloudflared: false, portctl: false },
    },
    dual: {
      plan: { onprem: true, vps: true, ec2: false, cloudflared: false, portctl: true, terraform: false, cloudflare: false },
      features: { wireguard: true, failover: false, frr: false, suricata: true, cloudflared: false, portctl: true },
    },
    full: {
      plan: { onprem: true, vps: true, ec2: true, cloudflared: true, portctl: true, terraform: true, cloudflare: true },
      features: { wireguard: true, failover: true, frr: true, suricata: true, cloudflared: true, portctl: true },
    },
  };
  const template = templates[name];
  if (!template) {
    return;
  }

  setCheckbox("plan_onprem", template.plan.onprem);
  setCheckbox("plan_vps", template.plan.vps);
  setCheckbox("plan_ec2", template.plan.ec2);
  setCheckbox("plan_cloudflared", template.plan.cloudflared);
  setCheckbox("plan_portctl", template.plan.portctl);
  setCheckbox("plan_terraform", template.plan.terraform);
  setCheckbox("plan_cloudflare", template.plan.cloudflare);

  setCheckbox("enable_wireguard", template.features.wireguard);
  setCheckbox("enable_failover", template.features.failover);
  setCheckbox("enable_frr", template.features.frr);
  setCheckbox("enable_suricata", template.features.suricata);
  setCheckbox("ddos_notify_enable", false);
  setCheckbox("enable_cloudflared", template.features.cloudflared);
  setCheckbox("enable_portctl", template.features.portctl);

  syncDependencies();
  updateGuidedSteps();
  generateAll();
  renderInputWarnings();

  const messages = {
    single: { en: "Template applied: On-prem only", ja: "テンプレ適用: オンプレのみ" },
    dual: { en: "Template applied: On-prem + VPS", ja: "テンプレ適用: オンプレ + VPS" },
    full: { en: "Template applied: On-prem + VPS + EC2", ja: "テンプレ適用: オンプレ + VPS + EC2" },
  };
  const message = messages[name] ? (messages[name][currentLang] || messages[name].en) : "Template applied";
  setTemplateStatus(message, "ok");
}

function resetGuidedState() {
  guidedState.preflight = false;
  guidedState.saved = false;
  guidedState.tfCfApply = false;
  guidedState.tfApply = false;
  guidedState.ansibleBase = false;
  guidedState.ansibleVps = false;
  guidedState.ansibleCloudflared = false;
  guidedState.ansiblePortctl = false;
  guidedState.ansibleEc2 = false;
  guidedState.ansibleOnprem = false;
  guidedState.validate = false;
}

function updateGuidedStepStatus(stepId, message, state) {
  const el = document.getElementById(stepId);
  if (!el) {
    return;
  }
  el.textContent = message;
  el.dataset.state = state;
}

function setGuidedStepState(stepKey, state) {
  const el = document.getElementById(stepKey);
  if (!el) {
    return;
  }
  el.dataset.state = state;
}

function getStatusValue(path, fallback = null) {
  if (!lastStatusPayload) {
    return fallback;
  }
  const parts = path.split(".");
  let current = lastStatusPayload;
  for (const part of parts) {
    if (current && Object.prototype.hasOwnProperty.call(current, part)) {
      current = current[part];
    } else {
      return fallback;
    }
  }
  return current;
}

function guidedRequirementsMet(plan) {
  const onpremLocal = isLocalOnpremHost(value(fields.onpremIp));
  const requiredKeys = {
    ansible: plan.onprem && !onpremLocal,
    vps: plan.vps,
    ec2: plan.ec2,
  };

  const keysOk = [
    !requiredKeys.ansible || getStatusValue("ssh_keys.ansible.exists", false),
    !requiredKeys.vps || getStatusValue("ssh_keys.vps.exists", false),
    !requiredKeys.ec2 || getStatusValue("ssh_keys.ec2.exists", false),
  ].every(Boolean);

  const vaultFiles = lastStatusPayload && lastStatusPayload.vault_files ? lastStatusPayload.vault_files : {};
  const vaultOk = [
    !plan.onprem || (vaultFiles["ansible/host_vars/onprem-1.yml"] && vaultFiles["ansible/host_vars/onprem-1.yml"].exists),
    !plan.vps || (vaultFiles["ansible/host_vars/vps-1.yml"] && vaultFiles["ansible/host_vars/vps-1.yml"].exists),
    !plan.ec2 || (vaultFiles["ansible/host_vars/ec2-1.yml"] && vaultFiles["ansible/host_vars/ec2-1.yml"].exists),
  ].every(Boolean);

  return { keysOk, vaultOk };
}

function updateGuidedSteps() {
  const plan = getPlanOptions();
  syncDependencies();

  if (plan.cloudflared && !plan.vps) {
    const cloudflared = document.getElementById("plan_cloudflared");
    if (cloudflared) {
      cloudflared.checked = false;
    }
    plan.cloudflared = false;
  }

  if (plan.portctl && !plan.vps) {
    const portctl = document.getElementById("plan_portctl");
    if (portctl) {
      portctl.checked = false;
    }
    plan.portctl = false;
  }

  const steps = [
    {
      id: "guided_step_preflight",
      statusId: "guided_status_preflight",
      done: () => guidedState.preflight,
      active: () => true,
      message: (labels) => guidedState.preflight ? labels.ok : labels.waiting,
    },
    {
      id: "guided_step_save",
      statusId: "guided_status_save",
      done: () => guidedState.saved,
      active: () => true,
      message: (labels) => guidedState.saved ? labels.saved : labels.waiting,
    },
    {
      id: "guided_step_tf_cf",
      statusId: "guided_status_tf_cf",
      done: () => guidedState.tfCfApply,
      active: () => plan.cloudflare,
      message: (labels) => guidedState.tfCfApply ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_tf",
      statusId: "guided_status_tf",
      done: () => guidedState.tfApply,
      active: () => plan.terraform,
      message: (labels) => guidedState.tfApply ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_vault_pass",
      statusId: "guided_status_vault",
      done: () => getStatusValue("vault_pass.exists", false),
      active: () => true,
      message: (labels) => getStatusValue("vault_pass.exists", false) ? labels.ok : labels.missing,
    },
    {
      id: "guided_step_keys",
      statusId: "guided_status_keys",
      done: () => guidedRequirementsMet(plan).keysOk,
      active: () => true,
      message: (labels) => guidedRequirementsMet(plan).keysOk ? labels.ok : labels.missing,
    },
    {
      id: "guided_step_vault_files",
      statusId: "guided_status_vault_files",
      done: () => guidedRequirementsMet(plan).vaultOk,
      active: () => true,
      message: (labels) => guidedRequirementsMet(plan).vaultOk ? labels.ok : labels.missing,
    },
    {
      id: "guided_step_ansible_base",
      statusId: "guided_status_ansible_base",
      done: () => guidedState.ansibleBase,
      active: () => true,
      message: (labels) => guidedState.ansibleBase ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_ansible_vps",
      statusId: "guided_status_ansible_vps",
      done: () => guidedState.ansibleVps,
      active: () => plan.vps,
      message: (labels) => guidedState.ansibleVps ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_ansible_portctl",
      statusId: "guided_status_ansible_portctl",
      done: () => guidedState.ansiblePortctl,
      active: () => plan.portctl,
      message: (labels) => guidedState.ansiblePortctl ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_ansible_cloudflared",
      statusId: "guided_status_ansible_cloudflared",
      done: () => guidedState.ansibleCloudflared,
      active: () => plan.cloudflared,
      message: (labels) => guidedState.ansibleCloudflared ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_ansible_ec2",
      statusId: "guided_status_ansible_ec2",
      done: () => guidedState.ansibleEc2,
      active: () => plan.ec2,
      message: (labels) => guidedState.ansibleEc2 ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_ansible_onprem",
      statusId: "guided_status_ansible_onprem",
      done: () => guidedState.ansibleOnprem,
      active: () => plan.onprem,
      message: (labels) => guidedState.ansibleOnprem ? labels.done : labels.waiting,
    },
    {
      id: "guided_step_validate",
      statusId: "guided_status_validate",
      done: () => guidedState.validate,
      active: () => true,
      message: (labels) => guidedState.validate ? labels.done : labels.waiting,
    },
  ];

  let canProceed = true;
  for (const step of steps) {
    const el = document.getElementById(step.id);
    const statusEl = document.getElementById(step.statusId);
    if (!el) {
      continue;
    }

    if (!step.active()) {
      el.hidden = true;
      continue;
    }
    el.hidden = false;

    const done = step.done();
    const locked = !canProceed;
    const state = done ? "done" : locked ? "locked" : "ready";
    setGuidedStepState(step.id, state);

    if (statusEl) {
      const labels = guidedMessages[currentLang] || guidedMessages.en;
      statusEl.textContent = done
        ? labels.done
        : locked
          ? labels.locked
          : step.message(labels);
      statusEl.dataset.state = done ? "ok" : locked ? "error" : "info";
    }

    const buttons = el.querySelectorAll("button");
    buttons.forEach((button) => {
      button.disabled = locked;
    });

    if (!done) {
      canProceed = false;
    }
  }
}

async function startJob(action, token, confirmValue, cleanup) {
  const confirmWord = confirmWordFor(action);
  if (confirmWord && confirmValue !== confirmWord) {
    return { ok: false, error: `Confirm word required: ${confirmWord}` };
  }

  const response = await fetch("/api/run", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Portal-Token": token,
    },
    body: JSON.stringify({ action, confirm: confirmWord, cleanup }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload.ok) {
    return { ok: false, error: payload.error || response.statusText || "Unknown error" };
  }
  return { ok: true, jobId: payload.job_id };
}

async function waitForJob(jobId, token, onUpdate) {
  while (true) {
    const response = await fetch(`/api/jobs/${jobId}`, {
      headers: { "X-Portal-Token": token },
    });
    const payload = await response.json().catch(() => ({}));
    const job = payload.job;
    let logText = "";

    const logResponse = await fetch(`/api/jobs/${jobId}/logs`, {
      headers: { "X-Portal-Token": token },
    });
    const logPayload = await logResponse.json().catch(() => ({}));
    if (logResponse.ok && logPayload.ok) {
      logText = logPayload.log || "";
    }

    if (onUpdate) {
      onUpdate(job, logText);
    }

    if (!job || job.status !== "running") {
      if (job) {
        announceJobStatus(job);
      }
      return { status: job ? job.status : "failed", log: logText };
    }
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }
}

async function runActionSequence(actions, token, confirmValue, onUpdate) {
  const autoCleanup = cleanupAutoEnabled();
  for (let i = 0; i < actions.length; i += 1) {
    const action = actions[i];
    const cleanup = autoCleanup && i === actions.length - 1;
    const start = await startJob(action, token, confirmValue, cleanup);
    if (!start.ok) {
      return { ok: false, error: start.error || "Failed to start job" };
    }
    setActionNotice(
      currentLang === "ja" ? `ジョブ開始: ${action}` : `Started: ${action}`,
      "info",
    );
    const result = await waitForJob(start.jobId, token, onUpdate);
    if (result.status !== "success") {
      return { ok: false, error: `Action failed: ${action}`, log: result.log };
    }
  }
  return { ok: true };
}

function downloadText(text, filename) {
  const blob = new Blob([text], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

function updatePlaceholders(lang) {
  document.querySelectorAll("[data-placeholder-en]").forEach((el) => {
    const placeholder = el.getAttribute(`data-placeholder-${lang}`);
    if (placeholder) {
      el.setAttribute("placeholder", placeholder);
    }
  });
}

function applyBeginnerDefaults() {
  if (!document.body || document.body.dataset.setupMode != "beginner") {
    return;
  }
  let changed = false;
  const suricata = document.getElementById("enable_suricata");
  if (suricata && suricata.dataset.manual != "true" && !suricata.checked) {
    suricata.checked = true;
    changed = true;
  }
  const terraform = document.getElementById("plan_terraform");
  if (terraform && terraform.dataset.manual != "true" && !terraform.checked) {
    terraform.checked = true;
    changed = true;
  }
  const cloudflare = document.getElementById("plan_cloudflare");
  if (cloudflare && cloudflare.dataset.manual != "true" && !cloudflare.checked) {
    cloudflare.checked = true;
    changed = true;
  }
  if (changed) {
    syncDependencies();
    generateAll();
    updateGuidedSteps();
  }
}

function applySetupMode(mode) {
  if (!mode || !document.body) {
    return;
  }
  document.body.dataset.setupMode = mode;
  applyBeginnerDefaults();
}

function setPage(page) {
  if (!page) {
    return;
  }
  const panels = document.querySelectorAll("section.panel[data-page]");
  const tabs = document.querySelectorAll(".page-tab");
  panels.forEach((panel) => {
    const pages = (panel.dataset.page || "")
      .split(/\s+/)
      .filter(Boolean);
    panel.hidden = !pages.includes(page);
  });
  tabs.forEach((tab) => {
    const active = tab.dataset.page === page;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-pressed", active ? "true" : "false");
  });
  if (page === "beginner" || page === "custom") {
    applySetupMode(page);
    if (window.localStorage) {
      localStorage.setItem("portalSetupMode", page);
    }
  }
  if (window.localStorage) {
    localStorage.setItem("portalPage", page);
  }
}

function setFormSection(section) {
  if (!section) {
    return;
  }
  const sections = document.querySelectorAll(".form-section[data-form-section]");
  const tabs = document.querySelectorAll(".form-tab");
  sections.forEach((panel) => {
    panel.classList.toggle("active", panel.dataset.formSection === section);
  });
  tabs.forEach((tab) => {
    const active = tab.dataset.formSection === section;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-pressed", active ? "true" : "false");
  });
  if (window.localStorage) {
    localStorage.setItem("portalFormSection", section);
  }
}


function tokenValue() {
  const runToken = document.getElementById("run_token");
  const uploadToken = document.getElementById("upload_token");
  if (runToken && runToken.value.trim()) {
    return runToken.value.trim();
  }
  if (uploadToken && uploadToken.value.trim()) {
    return uploadToken.value.trim();
  }
  return "";
}

function confirmWordFor(action) {
  if (action === "tf-apply") {
    return "APPLY";
  }
  if (action === "tf-destroy") {
    return "DESTROY";
  }
  return "";
}

function setRunStatus(message, state) {
  const status = document.getElementById("run_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setCleanupStatus(message, state) {
  const status = document.getElementById("cleanup_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setRunLog(text) {
  const logBox = document.getElementById("run_log");
  if (logBox) {
    logBox.value = text;
  }
}

const jobNoticeCache = {};

function announceJobStatus(job) {
  if (!job || !job.id) {
    return;
  }
  if (jobNoticeCache[job.id] === job.status) {
    return;
  }
  jobNoticeCache[job.id] = job.status;
  if (job.status === "running") {
    setActionNotice(
      currentLang === "ja" ? `実行中: ${job.action}` : `Running: ${job.action}`,
      "info",
    );
    return;
  }
  if (job.status === "success") {
    setActionNotice(
      currentLang === "ja" ? `完了: ${job.action}` : `Completed: ${job.action}`,
      "ok",
    );
    return;
  }
  if (job.status === "failed") {
    setActionNotice(
      currentLang === "ja" ? `失敗: ${job.action}` : `Failed: ${job.action}`,
      "error",
    );
  }
}

function cleanupAutoEnabled() {
  const input = document.getElementById(fields.cleanupAuto);
  return !!(input && input.checked);
}

async function runCleanup() {
  const token = tokenValue();
  if (!token) {
    const msg = currentLang === "ja" ? "ポータルトークンを入力してください。" : "Enter the portal token.";
    setCleanupStatus(msg, "error");
    return;
  }
  setCleanupStatus(currentLang === "ja" ? "削除中..." : "Cleaning up...", "info");
  try {
    const response = await fetch("/api/cleanup", {
      method: "POST",
      headers: {
        "X-Portal-Token": token,
      },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setCleanupStatus(detail, "error");
      return;
    }
    setCleanupStatus(
      currentLang === "ja" ? "削除完了" : "Cleanup complete",
      "ok",
    );
  } catch (error) {
    setCleanupStatus(
      currentLang === "ja" ? "削除に失敗しました。" : "Cleanup failed.",
      "error",
    );
  }
}

async function runAction(action) {
  const token = tokenValue();
  if (!token) {
    const msg = currentLang === "ja" ? "ポータルトークンを入力してください。" : "Enter the portal token.";
    setRunStatus(msg, "error");
    return;
  }

  const confirmWord = confirmWordFor(action);
  if (confirmWord) {
    const confirmInput = document.getElementById("run_confirm");
    const confirmValue = confirmInput ? confirmInput.value.trim() : "";
    if (confirmValue !== confirmWord) {
      const msg = currentLang === "ja"
        ? `確認ワードが必要です: ${confirmWord}`
        : `Confirm word required: ${confirmWord}`;
      setRunStatus(msg, "error");
      return;
    }
  }

  setRunStatus(
    currentLang === "ja" ? "ジョブを開始しています..." : "Starting job...",
    "info",
  );
  setRunLog("");

  try {
    const cleanup = cleanupAutoEnabled();
    const response = await fetch("/api/run", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Portal-Token": token,
      },
      body: JSON.stringify({ action, confirm: confirmWord, cleanup }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setRunStatus(detail, "error");
      return;
    }

    const jobId = payload.job_id;
    setRunStatus(`Job started: ${jobId}`, "info");
    setActionNotice(
      currentLang === "ja" ? `ジョブ開始: ${action}` : `Started: ${action}`,
      "info",
    );
    pollJob(jobId, token);
  } catch (error) {
    setRunStatus(
      currentLang === "ja" ? "ジョブ開始に失敗しました。" : "Failed to start job.",
      "error",
    );
  }
}

async function pollJob(jobId, token) {
  try {
    const response = await fetch(`/api/jobs/${jobId}`, {
      headers: { "X-Portal-Token": token },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      setRunStatus(payload.error || "Failed to read job.", "error");
      return;
    }
    const job = payload.job;
    if (job) {
      setRunStatus(
        `${job.status} (${job.action})`,
        job.status === "failed" ? "error" : "info",
      );
      announceJobStatus(job);
    }

    const logResponse = await fetch(`/api/jobs/${jobId}/logs`, {
      headers: { "X-Portal-Token": token },
    });
    const logPayload = await logResponse.json().catch(() => ({}));
    if (logResponse.ok && logPayload.ok) {
      setRunLog(logPayload.log || "");
    }

    if (job && job.status === "running") {
      setTimeout(() => pollJob(jobId, token), 2000);
    }
  } catch (error) {
    setRunStatus(
      currentLang === "ja" ? "ジョブ監視に失敗しました。" : "Failed to poll job.",
      "error",
    );
  }
}



function setCustomStatus(message, state) {
  const status = document.getElementById("custom_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setCustomLog(text) {
  const logBox = document.getElementById("custom_log");
  if (!logBox) {
    return;
  }
  logBox.value = text;
}

function selectedCustomActions() {
  const actions = [];
  document.querySelectorAll(".custom-item input[data-action]").forEach((input) => {
    if (input.checked) {
      actions.push(input.dataset.action);
    }
  });
  return actions;
}

async function runCustomPlan() {
  const token = tokenValue();
  if (!token) {
    setCustomStatus(currentLang === "ja" ? "ポータルトークンを入力してください。" : "Enter the portal token.", "error");
    return;
  }

  const actions = selectedCustomActions();
  if (!actions.length) {
    setCustomStatus(currentLang === "ja" ? "実行する操作を選択してください。" : "Select at least one action.", "error");
    return;
  }

  if (actions.includes("tf-apply") && actions.includes("tf-destroy")) {
    setCustomStatus(currentLang === "ja" ? "apply と destroy は同時に実行できません。" : "Do not run apply and destroy together.", "error");
    return;
  }

  const confirmValue = (document.getElementById("custom_confirm") || {}).value ? document.getElementById("custom_confirm").value.trim() : "";

  setCustomStatus(currentLang === "ja" ? "実行中..." : "Running...", "info");
  setCustomLog("");

  const result = await runActionSequence(actions, token, confirmValue, (job, logText) => {
    if (job) {
      setCustomStatus(`${job.status} (${job.action})`, job.status === "failed" ? "error" : "info");
    }
    if (logText) {
      setCustomLog(logText);
    }
  });

  if (!result.ok) {
    setCustomStatus(result.error || "Failed", "error");
    return;
  }

  setCustomStatus(currentLang === "ja" ? "完了しました。" : "Completed.", "ok");
}



async function runGuidedTerraform() {
  const token = tokenValue();
  if (!token) {
    updateGuidedStepStatus("guided_status_tf", currentLang === "ja" ? "トークンが必要です" : "Token required", "error");
    return;
  }
  const confirmValue = (document.getElementById("run_confirm") || {}).value ? document.getElementById("run_confirm").value.trim() : "";
  const actions = ["tf-init", "tf-apply"];
  const result = await runActionSequence(actions, token, confirmValue, (job, logText) => {
    setRunLog(logText || "");
    if (job) {
      setRunStatus(`${job.status} (${job.action})`, job.status === "failed" ? "error" : "info");
    }
  });
  if (result.ok) {
    guidedState.tfApply = true;
    if (document.body && document.body.dataset.setupMode === "beginner") {
      await refreshEc2IpFromTerraform(false);
    }
    updateGuidedSteps();
  }
}

async function runGuidedTerraformCf() {
  const token = tokenValue();
  if (!token) {
    updateGuidedStepStatus("guided_status_tf_cf", currentLang === "ja" ? "トークンが必要です" : "Token required", "error");
    return;
  }
  const confirmValue = (document.getElementById("run_confirm") || {}).value ? document.getElementById("run_confirm").value.trim() : "";
  const actions = ["tf-cf-init", "tf-cf-apply"];
  const result = await runActionSequence(actions, token, confirmValue, (job, logText) => {
    setRunLog(logText || "");
    if (job) {
      setRunStatus(`${job.status} (${job.action})`, job.status === "failed" ? "error" : "info");
    }
  });
  if (result.ok) {
    guidedState.tfCfApply = true;
    updateGuidedSteps();
  }
}

async function runGuidedAction(action, stateKey, statusId) {
  const token = tokenValue();
  if (!token) {
    if (statusId) {
      updateGuidedStepStatus(statusId, currentLang === "ja" ? "トークンが必要です" : "Token required", "error");
    }
    return;
  }

  const confirmValue = (document.getElementById("run_confirm") || {}).value ? document.getElementById("run_confirm").value.trim() : "";
  const result = await runActionSequence([action], token, confirmValue, (job, logText) => {
    setRunLog(logText || "");
    if (job) {
      setRunStatus(`${job.status} (${job.action})`, job.status === "failed" ? "error" : "info");
    }
  });

  if (result.ok) {
    guidedState[stateKey] = true;
    updateGuidedSteps();
  }
}

function updateTitle(lang) {
  document.title =
    lang === "ja" ? "edge-stack セットアップポータル" : "edge-stack Setup Portal";
}

function setLanguage(lang) {
  currentLang = lang;
  document.body.dataset.lang = lang;
  document.documentElement.lang = lang;
  const select = document.getElementById("lang-select");
  if (select) {
    select.value = lang;
  }
  updatePlaceholders(lang);
  updateTitle(lang);
  generateAll();
  updateGuidedSteps();
  if (window.localStorage) {
    localStorage.setItem("portalLang", lang);
  }
}

function setUploadStatus(message, state) {
  const status = document.getElementById("upload_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setEc2KeyStatus(message, state) {
  const status = document.getElementById("ec2_key_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setCloudflareTokenStatus(message, state) {
  const status = document.getElementById("cf_api_token_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

function setAwsCredentialsStatus(message, state) {
  const status = document.getElementById("aws_credentials_status");
  if (!status) {
    return;
  }
  status.textContent = message;
  status.dataset.state = state;
}

async function handleUpload() {
  const fileInput = document.getElementById("upload_file");
  const tokenInput = document.getElementById("upload_token");
  const targetSelect = document.getElementById("upload_target");
  const keyNameInput = document.getElementById("upload_key_name");
  const passphraseInput = document.getElementById("upload_passphrase");
  const button = document.getElementById("upload_button");
  const messages = uploadMessages[currentLang] || uploadMessages.en;

  if (!fileInput || !tokenInput || !targetSelect || !keyNameInput) {
    return;
  }

  const file = fileInput.files[0];
  if (!file) {
    setUploadStatus(messages.missingFile, "error");
    return;
  }

  const token = tokenInput.value.trim();
  if (!token) {
    setUploadStatus(messages.missingToken, "error");
    return;
  }

  const keyName = (keyNameInput.value || "").trim() || keyNameForTarget(targetSelect.value);
  if (!keyName) {
    setUploadStatus(messages.missingKeyName, "error");
    return;
  }
  const passphrase = passphraseInput ? passphraseInput.value : "";

  setUploadStatus(messages.uploading, "info");
  if (button) {
    button.disabled = true;
  }

  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("target", targetSelect.value);
    formData.append("token", token);
    formData.append("key_name", keyName);
    if (passphrase) {
      formData.append("passphrase", passphrase);
    }

    const response = await fetch("/upload", {
      method: "POST",
      body: formData,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setUploadStatus(messages.error(detail), "error");
      return;
    }

    const baseMessage = messages.success(payload.path || "~/.ssh");
    if (payload.agent_error) {
      setUploadStatus(`${baseMessage} (${payload.agent_error})`, "error");
      return;
    }
    setUploadStatus(baseMessage, "ok");
  } catch (error) {
    setUploadStatus(messages.unknownError, "error");
  } finally {
    if (button) {
      button.disabled = false;
    }
  }
}

async function handleAwsCredentialsUpload() {
  const fileInput = document.getElementById(fields.awsCredentialsFile);
  const token = tokenValue();
  const button = document.getElementById("aws_credentials_button");
  const messages = awsCredentialsMessages[currentLang] || awsCredentialsMessages.en;

  if (!fileInput) {
    return;
  }
  const file = fileInput.files[0];
  if (!file) {
    setAwsCredentialsStatus(messages.missingFile, "error");
    return;
  }
  if (!token) {
    setAwsCredentialsStatus(messages.missingToken, "error");
    return;
  }

  setAwsCredentialsStatus(messages.uploading, "info");
  if (button) {
    button.disabled = true;
  }

  try {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("profile", value(fields.awsProfile) || "default");
    formData.append("region", value(fields.awsRegion) || "");

    const response = await fetch("/api/aws-credentials", {
      method: "POST",
      headers: {
        "X-Portal-Token": token,
      },
      body: formData,
    });

    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setAwsCredentialsStatus(messages.error(detail), "error");
      return;
    }
    const profile = payload.profile || value(fields.awsProfile) || "default";
    setAwsCredentialsStatus(messages.success(profile), "ok");
    setActionNotice(currentLang === "ja" ? "AWS認証情報を保存しました。" : "Saved AWS credentials.", "ok");
  } catch (error) {
    setAwsCredentialsStatus(messages.unknownError, "error");
  } finally {
    if (button) {
      button.disabled = false;
    }
  }
}

async function handleCloudflareTokenSave() {
  const tokenInput = document.getElementById(fields.cfApiToken);
  const fileInput = document.getElementById(fields.cfApiTokenFile);
  const token = tokenValue();
  const button = document.getElementById("cf_api_token_save");
  const messages = cloudflareTokenMessages[currentLang] || cloudflareTokenMessages.en;

  if (!token) {
    setCloudflareTokenStatus(messages.missingPortalToken, "error");
    return;
  }

  const rawToken = tokenInput ? tokenInput.value.trim() : "";
  const file = fileInput && fileInput.files.length ? fileInput.files[0] : null;
  if (!rawToken && !file) {
    setCloudflareTokenStatus(messages.missingToken, "error");
    return;
  }

  setCloudflareTokenStatus(messages.saving, "info");
  if (button) {
    button.disabled = true;
  }

  try {
    const formData = new FormData();
    if (rawToken) {
      formData.append("token", rawToken);
    }
    if (file) {
      formData.append("file", file);
    }
    const response = await fetch("/api/cloudflare-token", {
      method: "POST",
      headers: {
        "X-Portal-Token": token,
      },
      body: formData,
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setCloudflareTokenStatus(messages.error(detail), "error");
      return;
    }
    setCloudflareTokenStatus(messages.success, "ok");
    setActionNotice(currentLang === "ja" ? "Cloudflareトークンを保存しました。" : "Saved Cloudflare token.", "ok");
  } catch (error) {
    setCloudflareTokenStatus(messages.unknownError, "error");
  } finally {
    if (button) {
      button.disabled = false;
    }
  }
}

async function handleEc2Keygen() {
  const token = tokenValue();
  if (!token) {
    const msg = currentLang === "ja" ? "ポータルトークンを入力してください。" : "Enter the portal token.";
    setEc2KeyStatus(msg, "error");
    return false;
  }

  const keyName = keyNameValue(fields.ec2KeyName, "ec2_key.pem");
  const passphrase = value(fields.ec2KeyPassphrase);

  setEc2KeyStatus(
    currentLang === "ja" ? "EC2鍵を生成中..." : "Generating EC2 key...",
    "info",
  );

  try {
    const response = await fetch("/api/keygen", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Portal-Token": token,
      },
      body: JSON.stringify({
        key_name: keyName,
        passphrase: passphrase || "",
      }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || !payload.ok) {
      const detail = payload.error || response.statusText || "Unknown error";
      setEc2KeyStatus(detail, "error");
      return false;
    }

    if (payload.public_key) {
      const publicField = document.getElementById(fields.keyPairPublicKey);
      if (publicField) {
        publicField.value = payload.public_key;
      }
    }
    generateAll();
    const base = currentLang === "ja"
      ? (payload.created ? "生成完了" : "準備済み")
      : (payload.created ? "Generated" : "Ready");
    const message = payload.path ? `${base}: ${payload.path}` : base;
    if (payload.agent_error) {
      setEc2KeyStatus(`${message} (${payload.agent_error})`, "error");
      return false;
    }
    setEc2KeyStatus(message, "ok");
    return true;
  } catch (error) {
    setEc2KeyStatus(
      currentLang === "ja" ? "EC2鍵生成に失敗しました。" : "Failed to generate EC2 key.",
      "error",
    );
    return false;
  }
}

async function ensureEc2KeyPair() {
  const mode = value(fields.keyPairMode) || "existing";
  if (mode !== "auto") {
    return true;
  }
  if (value(fields.keyPairPublicKey)) {
    return true;
  }
  return handleEc2Keygen();
}

let generateTimer = null;
function scheduleGenerateAll() {
  if (generateTimer) {
    clearTimeout(generateTimer);
  }
  generateTimer = setTimeout(() => {
    generateAll();
    updateGuidedSteps();
  }, 200);
}

const setupForm = document.getElementById("setup-form");
if (setupForm) {
  setupForm.addEventListener("input", scheduleGenerateAll);
  setupForm.addEventListener("change", scheduleGenerateAll);
}

document.querySelectorAll(".template-card").forEach((card) => {
  card.addEventListener("click", () => {
    applyTemplate(card.dataset.template);
  });
});

const generateButton = document.getElementById("generate");
if (generateButton) {
  generateButton.addEventListener("click", () => {
    generateAll();
    const message = currentLang === "ja"
      ? "プレビューを更新しました（未保存）。保存は「生成して保存」を実行してください。"
      : "Preview updated (not saved). Use Generate + Save to write to server.";
    setGenerateStatus(message, "ok");
    setActionNotice(message, "ok");
  });
}

document.querySelectorAll(".download").forEach((button) => {
  button.addEventListener("click", () => {
    const target = button.dataset.target;
    const filename = button.dataset.filename;
    const text = document.getElementById(target).value;
    downloadText(text, filename);
  });
});

const uploadButton = document.getElementById("upload_button");
if (uploadButton) {
  uploadButton.addEventListener("click", handleUpload);
}

const awsCredentialsButton = document.getElementById("aws_credentials_button");
if (awsCredentialsButton) {
  awsCredentialsButton.addEventListener("click", handleAwsCredentialsUpload);
}

const cfTokenButton = document.getElementById("cf_api_token_save");
if (cfTokenButton) {
  cfTokenButton.addEventListener("click", handleCloudflareTokenSave);
}

const ec2KeyButton = document.getElementById("ec2_key_generate");
if (ec2KeyButton) {
  ec2KeyButton.addEventListener("click", () => {
    handleEc2Keygen();
  });
}

const saveAllButton = document.getElementById("save_all");
if (saveAllButton) {
  saveAllButton.addEventListener("click", saveAll);
}

const cleanupButton = document.getElementById("cleanup_now");
if (cleanupButton) {
  cleanupButton.addEventListener("click", runCleanup);
}

const statusButton = document.getElementById("check_status");
if (statusButton) {
  statusButton.addEventListener("click", loadStatus);
}



const guidedPreflight = document.getElementById("guided_preflight");
if (guidedPreflight) {
  guidedPreflight.addEventListener("click", () => {
    loadStatus();
  });
}

const guidedSave = document.getElementById("guided_save");
if (guidedSave) {
  guidedSave.addEventListener("click", () => {
    generateAll();
    saveAll();
  });
}

const guidedCheckVault = document.getElementById("guided_check_vault");
if (guidedCheckVault) {
  guidedCheckVault.addEventListener("click", () => {
    loadStatus();
  });
}

const guidedCheckKeys = document.getElementById("guided_check_keys");
if (guidedCheckKeys) {
  guidedCheckKeys.addEventListener("click", () => {
    loadStatus();
  });
}

const guidedCheckVaultFiles = document.getElementById("guided_check_vault_files");
if (guidedCheckVaultFiles) {
  guidedCheckVaultFiles.addEventListener("click", () => {
    loadStatus();
  });
}

const guidedTerraformCf = document.getElementById("guided_tf_cf_apply");
if (guidedTerraformCf) {
  guidedTerraformCf.addEventListener("click", () => {
    runGuidedTerraformCf();
  });
}

const guidedTerraform = document.getElementById("guided_tf_apply");
if (guidedTerraform) {
  guidedTerraform.addEventListener("click", () => {
    runGuidedTerraform();
  });
}

const guidedAnsibleBase = document.getElementById("guided_ansible_base");
if (guidedAnsibleBase) {
  guidedAnsibleBase.addEventListener("click", () => {
    runGuidedAction("ansible-base", "ansibleBase", "guided_status_ansible_base");
  });
}

const guidedAnsibleVps = document.getElementById("guided_ansible_vps");
if (guidedAnsibleVps) {
  guidedAnsibleVps.addEventListener("click", () => {
    runGuidedAction("ansible-vps", "ansibleVps", "guided_status_ansible_vps");
  });
}

const guidedAnsiblePortctl = document.getElementById("guided_ansible_portctl");
if (guidedAnsiblePortctl) {
  guidedAnsiblePortctl.addEventListener("click", () => {
    runGuidedAction("ansible-portctl", "ansiblePortctl", "guided_status_ansible_portctl");
  });
}

const guidedAnsibleCloudflared = document.getElementById("guided_ansible_cloudflared");
if (guidedAnsibleCloudflared) {
  guidedAnsibleCloudflared.addEventListener("click", () => {
    runGuidedAction("ansible-cloudflared", "ansibleCloudflared", "guided_status_ansible_cloudflared");
  });
}

const guidedAnsibleEc2 = document.getElementById("guided_ansible_ec2");
if (guidedAnsibleEc2) {
  guidedAnsibleEc2.addEventListener("click", () => {
    runGuidedAction("ansible-ec2", "ansibleEc2", "guided_status_ansible_ec2");
  });
}

const guidedAnsibleOnprem = document.getElementById("guided_ansible_onprem");
if (guidedAnsibleOnprem) {
  guidedAnsibleOnprem.addEventListener("click", () => {
    runGuidedAction("ansible-onprem", "ansibleOnprem", "guided_status_ansible_onprem");
  });
}

const guidedValidate = document.getElementById("guided_validate");
if (guidedValidate) {
  guidedValidate.addEventListener("click", () => {
    runGuidedAction("validate", "validate", "guided_status_validate");
  });
}

const guidedReset = document.getElementById("guided_reset");
if (guidedReset) {
  guidedReset.addEventListener("click", () => {
    resetGuidedState();
    updateGuidedSteps();
  });
}

const planInputs = ["plan_onprem", "plan_vps", "plan_ec2", "plan_cloudflared", "plan_portctl", "plan_terraform", "plan_cloudflare"];
planInputs.forEach((id) => {
  const input = document.getElementById(id);
  if (!input) {
    return;
  }
  input.addEventListener("change", () => {
    input.dataset.manual = "true";
    if (id === "plan_cloudflared") {
      setCheckbox("enable_cloudflared", input.checked);
    }
    if (id === "plan_portctl") {
      setCheckbox("enable_portctl", input.checked);
    }
    syncDependencies();
    generateAll();
    updateGuidedSteps();
  });
});

const featureInputs = ["enable_wireguard", "enable_failover", "enable_frr", "enable_suricata", "enable_cloudflared", "enable_portctl", "ddos_notify_enable"];
featureInputs.forEach((id) => {
  const input = document.getElementById(id);
  if (!input) {
    return;
  }
  input.addEventListener("change", () => {
    if (id === "enable_suricata") {
      input.dataset.manual = "true";
    }
    if (id === "enable_cloudflared") {
      setCheckbox("plan_cloudflared", input.checked);
    }
    if (id === "enable_portctl") {
      setCheckbox("plan_portctl", input.checked);
    }
    syncDependencies();
    generateAll();
    updateGuidedSteps();
  });
});

const vpcModeInput = document.getElementById("vpc_mode");
if (vpcModeInput) {
  vpcModeInput.addEventListener("change", () => {
    syncVpcMode();
    generateAll();
  });
}

const keyPairModeInput = document.getElementById("key_pair_mode");
if (keyPairModeInput) {
  keyPairModeInput.addEventListener("change", () => {
    syncKeyPairMode();
    generateAll();
  });
}

const amiModeInput = document.getElementById("ami_mode");
if (amiModeInput) {
  amiModeInput.addEventListener("change", () => {
    syncAmiMode();
    generateAll();
  });
}

const customRun = document.getElementById("custom_run");
if (customRun) {
  customRun.addEventListener("click", () => {
    runCustomPlan();
  });
}

const customClear = document.getElementById("custom_clear");
if (customClear) {
  customClear.addEventListener("click", () => {
    document.querySelectorAll(".custom-item input[data-action]").forEach((input) => {
      input.checked = false;
    });
    const confirm = document.getElementById("custom_confirm");
    if (confirm) {
      confirm.value = "";
    }
    setCustomStatus("", "info");
    setCustomLog("");
  });
}

const runButtons = document.querySelectorAll(".run-action");
runButtons.forEach((button) => {
  button.addEventListener("click", () => {
    runAction(button.dataset.action);
  });
});

const langSelect = document.getElementById("lang-select");
if (langSelect) {
  langSelect.addEventListener("change", (event) => {
    setLanguage(event.target.value);
  });
}

const uploadTargetInput = document.getElementById("upload_target");
if (uploadTargetInput) {
  uploadTargetInput.addEventListener("change", () => {
    syncUploadTargetLabels();
    syncUploadKeyName();
  });
}

const portForwardDestInput = document.getElementById("port_forward_dest_ip");
if (portForwardDestInput) {
  portForwardDestInput.addEventListener("input", () => {
    portForwardDestInput.dataset.manual = "true";
  });
}

const adminAllowInput = document.getElementById("web_portal_admin_allow_cidrs");
if (adminAllowInput) {
  adminAllowInput.addEventListener("input", () => {
    adminAllowInput.dataset.manual = "true";
  });
}

const ec2IpInput = document.getElementById("ec2_ip");
if (ec2IpInput) {
  ec2IpInput.addEventListener("input", () => {
    ec2IpInput.dataset.manual = "true";
  });
}

const allowedSshInput = document.getElementById("allowed_ssh_cidrs");
if (allowedSshInput) {
  allowedSshInput.addEventListener("input", () => {
    allowedSshInput.dataset.manual = "true";
  });
}

["cf_vps_origin", "cf_ec2_origin"].forEach((id) => {
  const input = document.getElementById(id);
  if (!input) {
    return;
  }
  input.addEventListener("input", () => {
    input.dataset.manual = "true";
  });
});

document.querySelectorAll(".page-tab").forEach((button) => {
  button.addEventListener("click", () => {
    setPage(button.dataset.page);
  });
});

document.querySelectorAll(".form-tab").forEach((button) => {
  button.addEventListener("click", () => {
    setFormSection(button.dataset.formSection);
  });
});

["onprem_key_name", "vps_key_name", "ec2_key_name"].forEach((id) => {
  const input = document.getElementById(id);
  if (!input) {
    return;
  }
  input.addEventListener("change", () => {
    syncUploadTargetLabels();
    syncUploadKeyName();
    generateAll();
  });
});

const storedLang = window.localStorage ? localStorage.getItem("portalLang") : null;
const browserLang = (navigator.language || "").toLowerCase().startsWith("ja")
  ? "ja"
  : "en";
const storedPage = window.localStorage ? localStorage.getItem("portalPage") : null;
const storedSection = window.localStorage ? localStorage.getItem("portalFormSection") : null;
const storedSetupMode = window.localStorage ? localStorage.getItem("portalSetupMode") : null;
const normalizedStoredPage = storedPage === "configure" ? "custom" : storedPage;
const defaultPage = normalizedStoredPage && document.querySelector(`.page-tab[data-page="${normalizedStoredPage}"]`)
  ? normalizedStoredPage
  : (storedSetupMode && document.querySelector(`.page-tab[data-page="${storedSetupMode}"]`)
    ? storedSetupMode
    : "beginner");
const defaultSection = storedSection && document.querySelector(`.form-tab[data-form-section="${storedSection}"]`)
  ? storedSection
  : "basics";
syncVpcMode();
syncKeyPairMode();
syncAmiMode();
syncDdosNotify();
syncUploadTargetLabels();
syncUploadKeyName();
applySetupMode(storedSetupMode || "beginner");
setPage(defaultPage);
setFormSection(defaultSection);
setLanguage(storedLang || browserLang);
setActionNotice(currentLang === "ja" ? "準備完了" : "Ready.", "info");
