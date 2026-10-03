#!/usr/bin/env python3
"""把 SOTER 槽位的「账号指纹登记表」从日志里种上。

背景：一个 B 端 uid 上会挤十几个微信账号（实测最多 26 个），微信在一次初始化里会打
一发 uid 级全清（AIDL 7 / removeAllUidKey），把同 uid 上所有号的开通记录一起废掉。
relay_rs 的 `soter_mint::note_owner()` 靠请求里的别名认账号，认到两个以上就在收到
uid 级全清时只答复成功、不往下转发（`scope_wipe_from`）。

问题是这份登记表是运行时慢慢认出来的，刚换机、刚清过库时是空的 —— 头几个小时的
连坐照样发生。日志里已经有全部「别名 ↔ (设备, uid)」的历史，直接种一次，让它当场生效。

用法（在服务器上，先 dry-run 看数再落盘）：

    python3 seed_soter_owners.py                       # 只看统计
    systemctl stop relay_rs
    python3 seed_soter_owners.py --apply               # 写出 /tmp/soter_slots.merged.json
    install -m 644 /tmp/soter_slots.merged.json /opt/relay/data/soter_slots.json
    systemctl start relay_rs

必须停服再换文件：进程里那份 map 是权威，跑着的时候它下一次写盘会盖掉手工改的内容。
落盘前先备份：`cp -a /opt/relay/data/soter_slots.json /opt/relay/data/soter_slots.json.bak-$(date +%Y%m%d-%H%M%S)`。
合并只动 `owners`，各个槽位的 `layer` / `at_millis`（钉子）原样保留。
"""

import argparse
import datetime
import json
import os
import re
import sys

# 跟 relay_rs::soter_mint::owner_token() 保持一致的三族别名
PREFIXES = (("WechatAuthKeyPay&", "wx"), ("SoterAuthKeyV2_salt", "v2"), ("SoterAuthKey_salt", "v1"))
CAP = 64  # 跟 relay_rs::soter_mint::OWNER_CAP 一致
ANSI = re.compile(r"\x1b\[[0-9;]*m")
LINE = re.compile(r"soter: op=(\S+) uid=(-?\d+) alias=(\S+) requested=(\S+)")


def token(alias):
    """别名 → 账号指纹，认不出来返回 None。"""
    for pre, tag in PREFIXES:
        p = alias.find(pre)
        if p < 0:
            continue
        rest = alias[p + len(pre):]
        # wx 那族前缀后面整串就是账号名；salt 那两族取到下一个下划线为止
        val = rest.strip() if tag == "wx" else rest.split("_")[0]
        if not val or val == "null":
            return None
        return tag + ":" + val
    return None


def fam_count(owners):
    """同一个槽位上最多有几个账号（三族分开数，取最大，跟 owner_count() 同口径）。"""
    fam = {}
    for t in owners:
        tag, _, val = t.partition(":")
        fam.setdefault(tag, set()).add(val)
    return max((len(v) for v in fam.values()), default=0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default="/opt/relay/relay.out.log")
    ap.add_argument("--slots", default="/opt/relay/data/soter_slots.json")
    ap.add_argument("--out", default="/tmp/soter_slots.merged.json")
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--apply", action="store_true", help="写出合并后的文件（默认只统计）")
    a = ap.parse_args()

    cut = (datetime.datetime.now(datetime.timezone.utc)
           - datetime.timedelta(hours=a.hours)).strftime("%Y-%m-%dT%H:%M:%S")
    print("窗口起点(UTC)", cut)

    seen, ops, kept = {}, 0, 0
    with open(a.log, "r", errors="replace") as f:
        for line in f:
            if line[0] == "\x1b":
                line = ANSI.sub("", line)
            if line[:19] < cut:          # ISO 时间戳，字典序就是时间序
                continue
            m = LINE.search(line)
            if not m:
                continue
            _, uid, alias, dev = m.groups()
            if alias == "-":             # 不带别名的 op（uid 级全清自己就是这种）
                continue
            ops += 1
            t = token(alias)
            if t is None:
                continue
            lst = seen.setdefault(dev + "|" + uid, [])
            if t not in lst and len(lst) < CAP:
                lst.append(t)
                kept += 1
    print("窗口内带别名的 op", ops, "| 认出的指纹条目", kept, "| 涉及槽位", len(seen))

    slots = json.load(open(a.slots))
    had = sum(1 for v in slots.values() if v.get("owners"))
    for key, toks in seen.items():
        cur = slots.setdefault(key, {"layer": "", "at_millis": 0, "owners": []})
        own = cur.get("owners", [])
        new = [t for t in toks if t not in own]
        if new:
            cur["owners"] = (own + new)[:CAP]
    own = [v for v in slots.values() if v.get("owners")]
    shared = sum(1 for v in own if fam_count(v["owners"]) >= 2)
    print("槽位总数", len(slots), "| 有账号记录的", had, "->", len(own), "| 多账号的", shared)
    top = sorted(((fam_count(v["owners"]), k) for k, v in slots.items() if v.get("owners")),
                 reverse=True)[:10]
    print("账号最多的槽位:")
    for n, k in top:
        print("  ", n, k)

    if a.apply:
        with open(a.out, "w") as f:
            json.dump(slots, f, ensure_ascii=False)
        print("WROTE", a.out, os.path.getsize(a.out))
        print("下一步：先备份现有 soter_slots.json，install -m 644 %s /opt/relay/data/soter_slots.json" % a.out)
    else:
        print("（dry-run，加 --apply 才写文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
