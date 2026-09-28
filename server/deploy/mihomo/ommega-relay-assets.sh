#!/bin/sh
# 从仓库的 relay-assets 分支把两样东西拉回服务器：
#   1. clash-subscription.enc  —— mihomo 的节点表（**加密的**，解密校验过才换 provider 文件）
#   2. attestation-status.json —— 吊销名单，落在 /opt/relay/ 当服务端的磁盘兜底缓存
#
# 节点表为什么是密文：仓库是 public，明文等于把订阅挂公网（2026-09-28 出过这事）。
# 加密参数要跟 .github/workflows/relay-assets.yml 里那条 openssl 命令一字不差，
# 口令放在 root 600 的 $KEY 里（同一份也存进了仓库 secret SUB_PASSPHRASE）。
#
# 为什么有三条路（fetch 函数）：这台机器连 raw.githubusercontent.com 时通时不通
# （2026-09-28 实测直连超时、jsDelivr 200、走本机 mihomo 也 200），所以直连 raw →
# jsDelivr 镜像 → 本机 mihomo 依次试。jsDelivr 会缓存分支内容一段时间，只当兜底。
#
# 规矩：只有「下载成功 + 解密成功 + 内容看着像那么回事」才动现有文件，网络抖一下或者
# 口令写错了都不能把好好的节点表清空 —— 那样代理就没了，服务端也就拉不到名单了。
set -u

REPO_RAW="https://raw.githubusercontent.com/jiyin004-jpg/ommega/relay-assets"
REPO_CDN="https://cdn.jsdelivr.net/gh/jiyin004-jpg/ommega@relay-assets"
PROXY="http://127.0.0.1:7890"
PROV=/etc/mihomo/providers/sub.yaml
KEY=${RELAY_ASSETS_KEY:-/etc/mihomo/relay-assets.key}

fetch() {
    name="$1"
    out="$2"
    for u in "$REPO_RAW/$name" "$REPO_CDN/$name"; do
        if curl -sSfL --max-time 30 -o "$out" "$u" 2>/dev/null; then
            echo "  $name <- $u"
            return 0
        fi
    done
    if curl -sSfL -x "$PROXY" --max-time 40 -o "$out" "$REPO_RAW/$name" 2>/dev/null; then
        echo "  $name <- via local mihomo"
        return 0
    fi
    echo "  $name 三条路都不通"
    return 1
}

# 1) 节点表（密文 -> 解密 -> 写 provider）
tmpenc="$(mktemp)"
tmp="$(mktemp)"
if [ ! -r "$KEY" ]; then
    echo "no passphrase file at $KEY, keep old subscription"
elif fetch clash-subscription.enc "$tmpenc" \
   && [ "$(wc -c < "$tmpenc")" -gt 100 ] \
   && openssl enc -d -aes-256-cbc -pbkdf2 -iter 300000 -md sha256 \
        -pass file:"$KEY" -in "$tmpenc" -out "$tmp" 2>/dev/null \
   && grep -q '^proxies:' "$tmp" \
   && [ "$(wc -c < "$tmp")" -gt 1000 ]; then
    if cmp -s "$tmp" "$PROV"; then
        echo "subscription unchanged"
    else
        install -m 644 "$tmp" "$PROV"
        # 先让 mihomo 重读这个 provider（不重启，不断正在走的连接）；API 不通才重启
        if curl -sS -X PUT --max-time 10 \
             "http://127.0.0.1:9091/providers/proxies/sub" >/dev/null 2>&1; then
            echo "subscription updated, provider reloaded"
        else
            systemctl restart mihomo
            echo "subscription updated, mihomo restarted"
        fi
    fi
else
    echo "subscription fetch/decrypt failed or looks bogus, keep old"
fi
rm -f "$tmpenc" "$tmp"

# 2) 吊销名单兜底缓存（服务端自己也会经代理去拉官方那份，这条路是最后一道保险）
tmp2="$(mktemp)"
if fetch attestation-status.json "$tmp2" \
   && grep -q '"entries"' "$tmp2" \
   && [ "$(wc -c < "$tmp2")" -gt 1000 ]; then
    install -m 644 "$tmp2" /opt/relay/attestation_status.json
    echo "attestation status cached"
else
    echo "attestation status fetch failed, keep old"
fi
rm -f "$tmp2"
