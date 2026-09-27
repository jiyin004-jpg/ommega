#!/bin/sh
# 从仓库的 relay-assets 分支把两样东西拉回服务器：
#   1. clash-subscription.yaml —— mihomo 的节点列表（写进 provider 文件，成功才换）
#   2. attestation-status.json —— 吊销名单，落在 /opt/relay/ 当服务端的磁盘兜底缓存
#
# 规矩：只有「下载成功 + 内容看着像那么回事」才动现有文件，网络抖一下不能把好好的
# 节点表清空 —— 那样代理就没了，服务端也就拉不到名单了。
set -u

RAW="https://raw.githubusercontent.com/jiyin004-jpg/ommega/relay-assets"
PROV=/etc/mihomo/providers/sub.yaml

# 1) 节点列表
tmp="$(mktemp)"
if curl -sSfL --max-time 60 -o "$tmp" "$RAW/clash-subscription.yaml" \
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
    echo "subscription fetch failed or looks bogus, keep old"
fi
rm -f "$tmp"

# 2) 吊销名单兜底缓存（服务端自己也会经代理去拉官方那份，这条路是最后一道保险）
tmp2="$(mktemp)"
if curl -sSfL --max-time 60 -o "$tmp2" "$RAW/attestation-status.json" \
   && grep -q '"entries"' "$tmp2" \
   && [ "$(wc -c < "$tmp2")" -gt 1000 ]; then
    install -m 644 "$tmp2" /opt/relay/attestation_status.json
    echo "attestation status cached"
else
    echo "attestation status fetch failed, keep old"
fi
rm -f "$tmp2"
