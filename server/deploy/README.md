# 服务器上的出墙代理与资源刷新

这台机器（腾讯云）直连不到 `android.googleapis.com`，也连不到机场的订阅站，但
`raw.githubusercontent.com` 是通的。所以做成两段：

```
GitHub Actions（境外）→ relay-assets 分支（raw）
                             ↑ 每 6 小时
        ommega-relay-assets.sh（本机定时拉，只管这两个文件）
                             ├→ /etc/mihomo/providers/sub.yaml  → mihomo 的节点表
                             └→ /opt/relay/attestation_status.json → 吊销名单兜底缓存
mihomo（127.0.0.1:7890）← relay_rs 拉官方吊销名单时显式走它
```

关键一点：**mihomo 只绑 127.0.0.1、`allow-lan: false`、规则是 `MATCH,PROXY`**，
没有任何 TUN / iptables 接管。也就是说它只服务于「自己带上 `-x` 的请求」——
服务端 A/B 端的业务流量一律不经过它，也不改动系统路由。

## 装

```sh
# 1. 内核（从 mihomo release 取 linux-amd64-compatible 版解压而来，~60MB）
install -m 755 mihomo /usr/local/bin/mihomo

# 2. 配置
mkdir -p /etc/mihomo/providers
install -m 644 mihomo/config.yaml /etc/mihomo/config.yaml
# providers/sub.yaml（节点表，带机场密钥，不入库）等 ommega-relay-assets.timer 第一次拉下来，
# 急的话就从本地先拷一份过去：scp sub.yaml root@host:/etc/mihomo/providers/sub.yaml

# 3. 单元
install -m 644 systemd/mihomo.service /etc/systemd/system/mihomo.service
install -m 755 mihomo/ommega-relay-assets.sh /usr/local/bin/ommega-relay-assets.sh
install -m 644 systemd/ommega-relay-assets.service /etc/systemd/system/
install -m 644 systemd/ommega-relay-assets.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mihomo.service ommega-relay-assets.timer
```

## 验证

```sh
# 直连不通、走代理通
curl -sS -o /dev/null -w '%{http_code}\n' --max-time 8 https://android.googleapis.com/attestation/status   # 000
curl -sS -x http://127.0.0.1:7890 -o /dev/null -w '%{http_code}\n' \
  --max-time 20 https://android.googleapis.com/attestation/status                                            # 200
```

## 注意

- 这台机器内存本来就紧（常年 swap 拉满），所以 `mihomo.service` 里给了
  `GOMEMLIMIT=80MiB` / `MemoryMax=192M`，实测稳定在 60MB 上下。
- 节点表来自机场订阅，但要**用 mihomo 的 UA 抓**：拿 clash 系 UA 请求回来的是
  占位节点（server 全写成 127.0.0.1）。转换脚本在 `.github/scripts/sub_to_clash.js`。
  转出来的 `providers/sub.yaml` 里带着节点密钥，所以**不入库**，只存在服务器上。
- 代理地址默认 `http://127.0.0.1:7890`，服务端可用环境变量 `OMMEGA_OUT_PROXY` 改。
- 拉节点表和名单都是「先下载到临时文件、校验过才替换」，网络抖一下不会把好的配置清空。
