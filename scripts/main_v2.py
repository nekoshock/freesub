#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v2 — 全协议 · 高精度 · 低误杀
====================================================

架构（三阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
     - 阶段B 真实探测: 跨源活性探测 (Google/Cloudflare/Microsoft, 至少 2 源通过)
       + 延迟上限门槛 (MAX_LATENCY_MS, 此前延迟只排序不淘汰)
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (稳态吞吐 < 200KB/s)
         · 分母只取首数据块后的稳态区间 (剔除握手/TLS/RTT, 否则快节点被系统性低估)
         · 1MB 二次复测取最小值 (防 CDN 缓存/TCP 突发骗过单轮结果)
         · 跨端点交叉测速 (按需触发: 仅当首测疑似 CDN 短路时才跑物理机房
           Hetzner/Linode 端点; 正常结果直接采用, 省掉每节点 5~8 秒)
         · 重复节点回填 (多源收录的同一节点, 测活后继承真活代表节点的结果)
         · 测速健全性护栏 (全体中位数过高 = CDN 短路, 撤销⚡优选标记)
       + 丢包率探测 (复用 204 探针连发 5 次, 抓抖动严重的节点)
       + 首包时间 TTFB (与握手 RTT 互补, 抓"延迟低但首包慢"的体感杀手)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 去重: 出口IP+端口 唯一化 (保留速度最优), 家宽区严格防同IP刷屏
     - 排序: 家宽优先, 组内按综合质量分 (延迟 + 丢包惩罚 + 半个 TTFB)
"""

import os
import re
import io
import sys
import json
import time
import uuid
import base64
import shutil
import socket
import zipfile
import tarfile
import platform
import subprocess
import threading
import ipaddress
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter

try:
    import requests
    import yaml
    import maxminddb
except ImportError as e:
    print(f"[!] 缺少依赖: {e} — 请先 pip install -r requirements.txt")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════
# 配置
# ══════════════════════════════════════════════════════════════════

SOURCE_URLS = [
    "https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/refs/heads/main/Z.txt",
]

OUTPUT_DIR = "output"
COUNTRY_DIR = os.path.join(OUTPUT_DIR, "by-country")
RESIDENTIAL_COUNTRY_DIR = os.path.join(OUTPUT_DIR, "residential-by-country")

SINGBOX_VERSION = "v1.14.0"
WORKDIR = os.path.dirname(os.path.abspath(__file__))          # scripts/
BASEDIR = os.path.dirname(WORKDIR)                              # repo root
RUNTIME_DIR = os.path.join(BASEDIR, "runtime")                  # kernels & db
SINGBOX_BIN = os.path.join(RUNTIME_DIR, "sing-box")

# --- 测活阈值 (毫秒/秒) ---
# ★ 分层超时: 首击宽 (12s 容慢节点), 重试窄 (4s 快速放弃死节点)
#   依据 CI 实测: 25 分钟里 ~60% 时间烧在死节点 3×12s 满额重试上
PROBE_TIMEOUT          = 12      # 活性首击超时 (秒) — 容纳慢启动节点
PROBE_RETRY_TIMEOUT    = 4       # 活性重试超时 (秒) — 死节点快速放弃
PORT_KNOCK_TIMEOUT     = 2.5     # 端口预检超时
IP_ECHO_TIMEOUT        = 6.0     # 出口 IP 检测超时
# ★ 吞吐门槛 (2026-10 收紧: 断流线 70KB/s → 200KB/s, 分级线 1MB/s)
#   收紧同时修正了旧版测速的三个系统性错误 (否则单纯抬门槛=误杀快节点):
#     1) 分母只取"首数据块→结束"的稳态区间, 握手/TLS/首包 RTT 全部剔除
#        (旧版 t_speed 在 GET 之前起算 → 实测 1MB/s 的节点只算出 500KB/s)
#     2) 并发 48→24, 避免 48 个节点在单台机器上互抢带宽 (阈值 >500KB/s 时自污染)
#     3) 两轮测速取最小值入库 (1MB 复测), 防缓存层/TCP 突发骗过首轮
SPEED_TEST_BYTES       = 5_000_000   # 5MB 下载测速 (样本更多, 压掉 TCP 慢启动)
SPEED_TEST_BUDGET      = 8.0         # 测速时间预算 (秒) — 需 ≥ 门槛对应耗时, 否则平均速率被截断拉低
SPEED_MIN_BYTES_PER_S  = 200_000     # 吞吐 < 200KB/s (≈1.6Mbps) 判定断流/不可用 ★收紧
SPEED_TIER_GOOD        = 1_000_000   # ≥ 1MB/s (≈8Mbps) 标为 premium 优选级
SPEED_WARMUP           = 0.6         # 丢弃首包后 0.6s 数据 (握手 + TCP 慢启动期)
SPEED_IDLE_TIMEOUT     = 2.0         # 空闲 > 2s 无数据 = 断流签名 (原 3.0 偏宽)
SPEED_CHUNK_SIZE       = 32768       # 原 65536 太大, 细粒度更能反映瞬时速率
SPEED_MIN_DATA_BYTES   = 200_000     # 有效测速样本下限, 低于此值视为无法测速
# --- 二次复测 (稳定性) ---
SPEED_RETEST_BYTES     = 1_000_000   # 复测样本 1MB (小样本快速验证)
SPEED_RETEST_BUDGET    = 4.0         # 复测预算 (秒)
SPEED_RETEST_WARMUP    = 0.3         # 复测热身更短 (1MB 样本, 握手占比更大)
SPEED_STABLE_RATIO     = 0.6         # 复测/首测 < 0.6 → 判定首测虚高 (缓存突发)
SPEED_UNSTABLE_PENALTY = 1.5         # 不稳定节点的实际门槛上浮倍数 (×200KB/s = 300KB/s)

# --- 跨端点交叉测速 (防单端点欺骗) ---
#   旧逻辑是"首个成功端点即 break", 等于只看 speed.cloudflare.com 一个数据源:
#   节点只要对 CF 快就定级, 哪怕对其他 CDN/大厂极慢。免费池里"专供 Cloudflare"
#   的节点不少 (常见于机场给订阅做了按源分流)。改为所有端点都测, **取最小值**。
#   与二次复测同思路: 最小值代表"用户实际能拿到的最差体验"。
# 回退探测预算: 前 3 个端点(同区优先)每端点给足 8 秒, 跨区端点给 5 秒。
#   ★ 为什么分档: 跨大西洋握手本身就接近 1 秒, 若与同区端点一样只给 3 秒,
#     扣掉热身期后拿不到 SPEED_MIN_DATA_BYTES 的最小样本量 → 端点被误判为不通。
#     实测 #66 交叉测速几乎全败, 根因就是预算过短而非端点不可用。
#   逐个回退, 拿到第一个有效结果即停 —— 所以正常情况下只花第一个端点的预算。
SPEED_CROSS_MIN_ENDPOINTS = 2        # 至少要有几个端点成功才采信交叉结果 (不足则退化用已有)
SPEED_CROSS_MAX_ENDPOINTS = 6        # 最多试几个端点 (与 SPEED_CROSS_URLS 等长, 保证回退能走到最后一个; 切片 [:N] 会静默截断)

# --- 短路判定阈值 (决定是否启动交叉验证) ---
#   ★ 交叉测速改为**按需触发**: Cloudflare 测速若正常就直接采用, 不跑物理机房端点。
#     判定"疑似短路"用下面几个信号, 命中任意一条才启动交叉 (宁可漏判也不误判):
#       ① 首测速度高得不合常理 (超过 SHORTCUT_ABS_MAX) —— 物理上不现实的带宽
#       ② 复测与首测落差极大 (复测/首测 < SHORTCUT_DROP_RATIO) —— CDN 缓存突发特征
#       ③ 复测未通过 (retest_failed) —— 只有 CDN 端点能通, 换端点就抓瞎
#   这些信号全部指向"测速数字可能来自 CDN 边缘短路而非节点真实带宽"。
SHORTCUT_ABS_MAX      = 4_000_000   # 4MB/s: 超过此值视作疑似短路
#   ★ 定 4MB/s 的依据: 实测 #65 在 Azure runner 上 Cloudflare 测速中位 7.1MB/s
#     (物理上不可能是真实跨境带宽, 是 CDN 边缘短路)。若阈值定 8MB/s, #65 那种
#     "普遍虚高但没到8M"的典型场景反而不会触发交叉, 护栏形同虚设 (初版就踩了这个坑)。
#     4MB/s 已高于 Actions→用户侧的常见真实带宽, 超过即可疑。
SHORTCUT_DROP_RATIO   = 0.25        # 复测/首测 < 0.25 → 落差过大, 疑似首测虚高
SHORTCUT_RETX_PROBE   = 1           # 保留位: 未来若要加"多次重测一致性"判定时的采样数
# 交叉验证专用的宽松门槛: 物理机房链路慢, 用比主测速低得多的样本下限, 避免误判端点不通
SPEED_CROSS_MIN_BYTES = 50_000      # 交叉验证只要 50KB 样本即可 (主测速是 200KB)
SPEED_CROSS_BUDGET       = 8.0       # 首选端点预算 (秒) — 同区端点, 需覆盖握手+热身+稳态采样
SPEED_CROSS_BUDGET_FAR   = 5.0       # 跨区端点预算 (秒) — 握手更慢, 但链路更长稳态采样需求略低
SPEED_CROSS_SAME_REGION  = 3        # 前 N 个端点视为"同区"(走 SPEED_CROSS_BUDGET), 其后为跨区
SPEED_CROSS_WARMUP       = 0.3       # 交叉测速热身 (端点间横向比较, 口径一致即可)
CROSS_BYTES              = 2_000_000 # 交叉测速每端点样本 2MB (够算稳态速率, 不至于太大)

# --- 丢包率 (抓抖动/丢包严重的节点) ---
#   ★ 现有判定只看延迟, 完全没测丢包 —— 而跨太平洋链路的核心问题恰恰是丢包。
#   一个 80ms 但丢包 15% 的节点, 体感远差于 300ms 但丢包 0.2% 的节点。
#   复用已有的 204 探针 (零额外带宽), 连发 N 次统计失败比例。
#   ★ 2026-10 收紧: 实测 #65 丢包标记只占 0.5% (= 几乎没筛掉人), 阈值过松。
#     实测 0% ~ 20% 是正常抖动, ≥20% 明显影响体感, ≥25% 直接不可用。
LOSS_PROBE_COUNT      = 5            # 采样次数 (5 次够抓出 >20% 的丢包, 又不至于太慢)
LOSS_PROBE_TIMEOUT    = 3.0          # 单次丢包探测超时 (秒) — 窄超时, 快速识别失败
MAX_LOSS_RATE         = 0.25         # 丢包率 ≥25% 直接淘汰 ★收紧 (原 34%: 5次下 2/5=40% 才杀, 太宽)
LOSS_UNSTABLE_PENALTY = 0.10         # 丢包率 ≥10% 即视为不稳 ★收紧 (原 20%: 实测几乎不触发)

# --- 落地国黑名单 (无条件剔除) ---
#   ★ 按需求: 落地 IP 在日本的节点一律删除, 不论其速度/延迟/是否家宽。
#   判定用**出口 IP 的归属国**(不是入口 server 的国)—— 落地国才是用户实际
#   出口位置, 中转机在国内、落地在日本的节点同样要删。
#   空字符串 = 不屏蔽任何国家 (默认关闭, 保持开源仓库通用性);
#   想启用日本屏蔽时填 "JP" 或 "JP,KR" 等。
#   生效位置: classify_and_export 的 safe_nodes 过滤 (最早期, 省掉后续情报查询)
BLOCK_COUNTRIES = "JP,RU"             # 例: "JP" = 剔除落地日本; "JP,KR" = 日本+韩国
# --- 首包时间 TTFB (Time To First Byte) ---
#   现有 latency 测的是 TCP+TLS 握手往返; TTFB 测"服务器开始回数据"的时刻。
#   两者背离是常态: 很多节点 RTT 很低但首包要 1~2 秒 (服务端缓冲/链路拥塞),
#   用户体感就是"点了没反应"。测速函数本来就经过握手, 顺带记录不额外花时间。
#   ★ 2026-10 收紧: 实测 #65 TTFB 标记只占 2.9%, 阈值过松。
MAX_TTFB_MS          = 1800          # 首包 >1.8s 直接淘汰 ★收紧 (原 2500ms)
TTFB_SLOW_MS          = 1200         # 首包 >1.2s 视为响应迟钝, 门槛上浮 ★收紧 (原硬编码 1500ms)
# 门槛惩罚上限: 四项惩罚累乘 1.5^4=5.06 会把 200KB/s 门槛推到 1012KB/s (比优选线还高),
# 过严反失真。这里封顶 2.25× (→ 450KB/s), 即最多因"多重不稳"损失一半带宽余量。
MAX_SPEED_PENALTY     = 2.25

IP_ECHO_URLS = [                    # 经代理获取出口 IP (多路冗余)
    "https://api.ip.sb/geoip",                         # JSON: country_code/asn/isp
    "https://ipinfo.io/json",                          # JSON: country/org
    "http://ip-api.com/json/?fields=status,query,countryCode,isp,org,as",  # HTTP free
]
# 活性探测 (跨源冗余 — 关键设计)
#   ★ 旧版三个 URL 全部是 Google 系 (gstatic/google/connectivitycheck.gstatic),
#     那不是冗余而是"同一个探针测三遍": 只对 Google 通、对其他目标全拒的选择性
#     转发节点照样判活, 入库后用户打开普通网站直接失败。
#   现改为跨三源 (Google / Cloudflare / 中立站), 且要求至少 MIN_LIVENESS_HITS
#   个**不同源**通过 —— "能连上"不等于"能正常用"。
#   每项 = (名称, URL, 期望状态码); 名称仅用于日志。
LIVENESS_PROBES = [
    ("google",    "https://www.gstatic.com/generate_204",        (204, 200)),
    ("cloudflare", "https://cp.cloudflare.com/generate_204",     (204, 200)),
    ("microsoft", "http://www.msftconnecttest.com/connecttest.txt", (200,)),
]
MIN_LIVENESS_HITS = 2            # 至少 2 个不同源通过才判活 (三源取二)
MAX_LATENCY_MS    = 1500         # 延迟上限门槛: 超时即淘汰 (此前延迟只用于排序, 不淘汰)
# ══════════════════════════════════════════════════════════════════
# 测速端点配置
#   ★ 核心原则: 端点必须与被测节点**同区域**测, 且优先选**物理机房**而非 Anycast CDN。
#     Cloudflare/Fastly 这类 Anycast CDN 的边缘节点常与运行机同机房 (Actions US
#     runner 与 Cloudflare 边缘仅数百毫秒), 测出的是"内网带宽"而非跨境带宽。
#     实测 #65: Cloudflare 端点测出中位 7.0MB/s / 最快 29MB/s, 76% 节点被标"优选",
#     而 200KB/s 的门槛对 7MB/s 的中位数形同虚设 —— 用户以为筛过了, 其实没有。
#     改用物理机房端点后, 数字才代表用户实际能拿到的带宽。
#   下列每个端点都做过 HTTP 206 (Range) + 实际吞吐实测, 按同区优先排序。
# ══════════════════════════════════════════════════════════════════
SPEED_TEST_URLS = [               # 主测速端点 (Anycast CDN, 快但可能虚高 — 仅作上界参考)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_TEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
# 物理机房测速端点 (跨端点交叉测速主力 — 与 CDN 物理隔离, 数字可信)
#   选址标准: ① 纯物理机房无 Anycast ② 稳定在线、长期提供公开测速服务
#            ③ 覆盖不同运营商/不同网络类型, 避免单一厂商网络成为单点
#            ④ 支持 Range 请求 (HTTP 206), 可只取前若干 MB 而非拉满整包
#   各项 = (名称, URL); 名称仅用于日志与失败归因。
#   ★ 顺序即优先级: 实测可达性最高的排最前, 24 并发下先命中最省时间。
#     Actions US runner 实测 (见 #70): linode-fremont 成功 534/543 (98.3%),
#     hetzner-ash 成功 0/543 (0%) — 已从列表移除 (原因见下)。
#   ★ 已删除 hetzner-ash (#70 教训):
#     实测在 Actions runner 上 543 次尝试**零成功**, 失败类型全是
#     ConnectionError/SSLError (连 TCP/TLS 都建不上, 不是"慢")。
#     连带两个问题: ① 每次失败白耗一个 8 秒预算才回退, 543 次÷24并发 ≈ 3 分钟纯浪费
#                   ② 5 端点冗余退化成单端点 —— 536/543 节点最终都落在 linode-fremont,
#                      另外 4 个端点几乎没被用上, 冗余形同虚设。
#     推测原因: Hetzner 的**美国机房是托管在第三方/AWS** 的 (nbg1/fsn1/hel1 才是自建),
#     Azure → AWS 托管机房的 peering 很可能不通; 德国自建机房反而更稳。
#     ★ 因此不要因为"同区优先"就盲目信任地理邻近 —— 端点在 Actions 视角的真实可达性
#       才是唯一标准, 这也是下面熔断器存在的意义。
SPEED_CROSS_URLS = [
    # ── 首选: Linode/Akamai (实测可达性最高) ──
    ("linode-fremont",  "https://speedtest.fremont.linode.com/100MB-fremont.bin"),
    #   Linode (Akamai 旗下) 加州弗里蒙特。**#70 实测 98.3% 成功率, 唯一被证明可用**。
    ("linode-dallas",   "https://speedtest.dallas.linode.com/100MB-dallas.bin"),
    #   Linode 德州达拉斯, 同运营商不同城市, 对抗单机房故障。
    ("linode-newark",   "https://speedtest.newark.linode.com/100MB-newark.bin"),
    #   Linode 新泽西纽瓦克, 第三重冗余。24 机房统一命名 100MB-<city>.bin, 全球可用。
    # ── 欧洲区 (Hetzner 自建机房, 非托管) ──
    ("hetzner-nbg",     "https://nbg1-speed.hetzner.com/100MB.bin"),
    #   Hetzner 德国纽伦堡 —— **自建**数据中心 (与已删的美国托管机不同性质)。
    ("hetzner-fsn",     "https://fsn1-speed.hetzner.com/100MB.bin"),
    #   Hetzner 德国费尔司芬, 自建机房第二点。
    ("hetzner-hel",     "https://hel1-speed.hetzner.com/100MB.bin"),
    #   Hetzner 芬兰赫尔辛基, 自建机房第三点, 欧洲侧多城冗余。
]
# 端点级失败归因: 全部非 CF 端点都失败 → 判定问题在节点本身, 不再重试端点
#   理由: 物理机房端点分属 2 家运营商/6 个城市, 全部不通的可能性远低于
#   "单个端点故障"。此时继续重试端点是浪费 —— 真正的原因是节点到不了这些
#   物理机房(选择性转发/链路封锁), 或者节点本身已断流。
SPEED_CROSS_FAIL_ALL_THRESHOLD = 1   # 至少要有几个端点成功才采信交叉结果
SPEED_CROSS_RANGE_BYTES = 5_000_000  # Range 请求前 5MB (避免拉满 100MB)

# --- 端点熔断器 (让运行时数据驱动端点选择, 不靠人工猜) ---
#   ★ 为什么需要: 端点在 Actions 视角的可达性会随时间漂移 (peering 变化、网络政策、
#     第三方封锁)。#70 里 hetzner-ash 零成功, 但靠人工看日志才发现 —— 而每轮白耗
#     543×8s。熔断器让"某个端点在本轮明显不可用"这件事自动生效, 无需等下轮人工干预。
#   判据: 连续失败 SPEED_CB_FAIL_THRESHOLD 次 → 本轮不再尝试该端点 (直接跳到下一个);
#         任一次成功 → 立即清零计数, 恢复可用。
#   阈值 20 次的由来: 24 并发下约 1~2 秒就能累积到 20 次, 既不会误伤"偶发一次超时",
#     又能在几十秒内摘掉 100% 失败的端点, 省下后续几百次无效尝试。
SPEED_CB_FAIL_THRESHOLD = 20        # 连续失败多少次后本轮熔断
SPEED_CB_COOLDOWN_HITS = 3          # 成功后需再成功几次才认为"完全恢复"(保守, 防抖动)

# 熔断器运行时状态 (进程内, 每轮 run_liveness_test 前 reset)
#   测活阶段是 24 并发 ThreadPoolExecutor, 下面三个字典的读写必须加锁保护,
#   否则"读-改-写"不是原子的, 并发下会漏计失败次数(熔断器形同失效)。
_CB_LOCK = threading.Lock()
_CB_STATE = {}    # 端点名 -> {"fail": 连续失败数, "tripped": 是否已熔断, "stat": [成功, 总尝试]}


def _reset_endpoint_breaker():
    """每轮测活开始前清空熔断状态 (端点可达性按轮次重新评估)"""
    with _CB_LOCK:
        _CB_STATE.clear()


def _ep_available(ep_name: str) -> bool:
    """端点当前是否可尝试 (已熔断则跳过)"""
    with _CB_LOCK:
        return not _CB_STATE.get(ep_name, {}).get("tripped", False)


def _ep_record(ep_name: str, ok: bool):
    """记录一次端点尝试结果, 达到阈值则熔断; 成功则清零"""
    with _CB_LOCK:
        st = _CB_STATE.setdefault(ep_name, {"fail": 0, "tripped": False,
                                            "stat": [0, 0]})
        st["stat"][1] += 1                     # stat = [成功次数, 总尝试次数]
        if ok:
            st["stat"][0] += 1
            st["fail"] = 0
            st["tripped"] = False              # 成功即解除熔断
        else:
            st["fail"] += 1
            if st["fail"] >= SPEED_CB_FAIL_THRESHOLD:
                st["tripped"] = True


def _ep_success_rates() -> str:
    """生成端点成功率报告 (供日志), 直接反映哪个端点在 Actions 视角真正可用"""
    with _CB_LOCK:
        order = [nm for nm, _ in SPEED_CROSS_URLS]
        out = []
        for nm in order:
            st = _CB_STATE.get(nm)
            if not st or st["stat"][1] == 0:
                out.append(f"{nm}:未尝试")
                continue
            okc, total = st["stat"]
            rate = okc / total * 100
            mark = " ★已熔断" if st["tripped"] else ""
            out.append(f"{nm} {okc}/{total} ({rate:.1f}%){mark}")
        return " | ".join(out)
SPEED_RETEST_URLS = [             # 复测端点 (1MB 小样本)
    "https://speed.cloudflare.com/__down?bytes=" + str(SPEED_RETEST_BYTES),
    "https://cachefly.cachefly.net/10mb.test",
]
TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"      # warp=on 检测套壳节点
# WARP 套壳节点策略: "drop"=直接淘汰 | "demote"=保留但不入家宽专区 | "off"=只打标记
#   套壳 WARP 节点的出口 IP 是 Cloudflare 自己的 IP, 归属地/风控画像全失真,
#   且部分流媒体/支付场景直接不可用。默认 drop (宁缺毋滥)。
WARP_POLICY = os.environ.get("WARP_POLICY", "drop").strip().lower()
if WARP_POLICY not in ("drop", "demote", "off"):
    print(f"[!] WARP_POLICY={WARP_POLICY!r} 非法, 回退 'drop' (可选: drop/demote/off)")
    WARP_POLICY = "drop"
MAX_WORKERS_TEST    = 24            # 同时 sing-box 实测节点数 (★48→24: 测速阶段 48 并发会互抢单台机器带宽, 阈值抬高后自污染成假阴性; sing-box 单实例 < 30MB)

# ══════════════════════════════════════════════════════════════════
# 方案1: 测速健全性护栏 (防"测出内网级假速度")
#   ★ 实测 #65: Azure runner 上 speed.cloudflare.com 测出中位 7MB/s、最快 29MB/s,
#     76% 节点被标"⚡优选" —— 这不是节点有多快, 而是 Azure→Cloudflare 走的是
#     同机房/近缘链路, 测的是内网带宽。后果: 吞吐门槛(200KB/s)完全形同虚设,
#     优选标记失去筛选意义, 且**用被污染的速度给节点排名毫无价值**。
#   护栏逻辑: 跑完测速后先看全体中位数 —
#     · 中位数 > SANITY_MEDIAN_MAX (说明测速环境被短路, 数字整体不可信)
#       → 不再信任任何"优选/速度档", is_premium 一律不标 (宁可漏标不误标),
#         并把该信息打进日志, 提示应更换测速端点 (见 SPEED_TEST_URLS 的 Hetzner)。
#     · 中位数正常 → 按真实数值正常分档。
#   这是"承认测不准"而不是"用假数字排序" ——
#   假数字最坏的地方不是标错, 是让你以为筛过了。
# ══════════════════════════════════════════════════════════════════
SANITY_CHECK_MIN_SAMPLES = 30        # 样本少于这个数不做中位数判断 (统计无意义)
SANITY_MEDIAN_MAX       = 3_000_000  # 全体测速中位数 > 3MB/s 判定为"测速环境被短路"
# 阶段B 单节点最坏耗时估算 (秒) — 仅用于日志里预估"预检硬淘汰省了多少时间",
# 不参与任何判定。上界 = 等SOCKS端口 6 + 跨源探测 (12+4+4) + 出口IP 6
#                    + MITM复检 4 + WARP 4 + 测速首轮 8 + 复测 4 + check 0.5
STAGE_B_WORST_SEC   = 52.5
MAX_WORKERS_FETCH   = 8
MAX_WORKERS_CLASSIFY = 32

# ip-api.com 免费批量: 15 req/min, 每 req ≤100 IP (仅 HTTP)
IP_API_BATCH_URL = "http://ip-api.com/batch?fields=status,countryCode,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
IP_API_BATCH_SIZE = 100
IP_API_BATCH_RPS_INTERVAL = 4.2     # 60/15s ≈ 每 4.2s 一批

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"

# ══════════════════════════════════════════════════════════════════
# 出口 IP 情报 (本地离线兜底)
# ══════════════════════════════════════════════════════════════════

# Cloudflare 官方 Anycast 全网段 (命中即 CDN 任播, 绝非家宽)
CLOUDFLARE_IP_NETWORKS = [ipaddress.ip_network(n) for n in (
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22","103.31.4.0/22",
    "141.101.64.0/18","108.162.192.0/18","190.93.240.0/20","188.114.96.0/20",
    "197.234.240.0/22","198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
)]

# Google / Fastly / Akamai 等常见 CDN 与云入口段 (命中即标 CDN/机房)
CDN_IP_NETWORKS_EXTRA = [ipaddress.ip_network(n) for n in (
    # Google
    "8.8.4.0/24","8.8.8.0/24","8.34.208.0/20","8.35.192.0/20","34.64.0.0/10","35.184.0.0/13",
    "35.192.0.0/14","35.196.0.0/15","35.200.0.0/13","35.216.0.0/15","35.220.0.0/14",
    "64.15.112.0/20","64.233.160.0/19","66.102.0.0/20","66.249.64.0/19","72.14.192.0/18",
    "74.125.0.0/16","108.177.0.0/17","142.250.0.0/15","172.217.0.0/16","173.194.0.0/16",
    "209.85.128.0/17","216.58.192.0/19","216.239.32.0/19",
    # Fastly
    "23.235.32.0/20","43.249.72.0/22","103.244.50.0/24","103.245.222.0/23",
    "104.156.80.0/20","140.248.64.0/18","146.75.0.0/16","151.101.0.0/16",
    "157.52.64.0/18","167.82.0.0/17","199.232.0.0/16","204.129.196.0/22",
    # Akamai (核心段)
    "23.32.0.0/13","23.64.0.0/14","23.192.0.0/11","23.197.0.0/16",
    "95.100.0.0/15","104.64.0.0/10","184.24.0.0/13","184.84.0.0/14",
    # Cloudflare Spectrum / 托管入口
    "104.16.0.0/12",
)]

# 已知云/机房 ASN (离线兜底用; 在线 ip-api hosting=true 为主判据)
DATACENTER_ASNS = {
    13335,  # Cloudflare
    16509, 14618,  # AWS
    15169, 396982,  # Google
    8075, 8068,  # Microsoft
    24940,  # Hetzner
    16276,  # OVH
    14061,  # DigitalOcean
    31898, 63949,  # Oracle
    45102,  # Alibaba
    132203,  # Tencent
    20473,  # Choopa/Vultr 早期
    60068,  # Datacamp (CDN77)
    55081,  # Hostinger
    197540,  # Hostinger EU
    51167,  # Contabo
    8560,  # 1&1 / IONOS
    42708,  # IONOS
    201814, 49981,  # Hosthatch/Hostkey 类
    212238, 46652,  # Serverius/OVH 类
    141995, 200019, 136907, 39351, 9009,  # M247/Hosthatch 等
    174, 3356, 1299, 2914, 6939,  # 骨干 (Cogent/Lumen/Arelion/NTT/Hurricane)
    199524, 206096, 49505,  # Selectel/WorldStream
    62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373, 140224,  # 小型 IDC
    54866,  # Parsebian/HydraTransit 类
    45899,  # VNPT 云? 标记为 IDC
    # ★ 实测漏网: 收购家宽段/伪装 DSL rDNS 的云边网络 (ip-api proxy=true 案例补充)
    62610,  # Zenlayer (AS62610, rDNS 带 dsl.speakeasy.net 但 proxy=true)
    60205,  # 62610 关联段
    8342,  # Deltacomputers/Evrasia 类
    9009, 47692, 62041, 56630, 57502,  # Serverius/ProXmedia/Clouvider 类
}

# 民用宽带 ASN 白名单 (离线兜底; 关键国家主流运营商)
RESIDENTIAL_ASNS = {
    # 台湾
    3462,    # Chunghwa Telecom (中华电信)
    9924, 17709, 4780, 18049,  # 亚太电信/远传/台湾大哥大/凯擘
    9269, 3491,  # 台湾硕网/和宇宽频
    # 香港
    4760, 476, 4515, 9229, 9266, 10103,  # PCCW/HKT/CUHK/HGC/HKBN/HKTBB
    9059, 38861,  # Hong Kong Broadband
    # 日本
    4713, 2516, 17676, 4721, 2497, 9605, 17511, 9318, 2518, 20193,
    # Softbank/NTT Communications/KDDI/IIJ/Sony/Plala/@nifty/JCN
    4766, 3786, 17816, 9357,
    # 韩国
    4713, 9318, 17816, 9357, 4766,  # KT/LG/SK  
    # 美国
    701, 7018, 7922, 20115, 22773, 10796, 20057, 11427, 10507, 6128,
    33363, 21928, 10777, 33660, 33661, 33662, 36466, 53417, 55136,
    20057, 19024, 12271, 11404, 6983, 33554, 7155, 30162, 10790,
    # Comcast (7922/33487/22263...) / Charter (20115/10796/20057) / Cox / AT&T / Verizon
    702, 703, 704, 705, 706, 709, 710, 711, 712, 713, 714, 715,  # legacy Verizon
    2828, 20001, 3549,  # CenturyLink/Level3 (部分为家宽)
    6167, 6162, 7018,  # AT&T
    5056,  # Cox East
    10796,  # Charter
    11351,  # TWC
    6128,  # Atlantis
    # 英国
    2856, 5607, 20650, 13285, 12576, 12725, 19541, 33950, 5413,
    # BT/TalkTalk/Orange/Virgin/Plusnet/Sky/Eclipse
    # 德国
    3320, 3209, 6805, 8888, 9145, 13237, 15366, 20879, 16097, 15594,
    # DT/Vodafone/EWE/netcup/Telefónica
    # 法国
    3215, 12322, 15557, 5410, 21590, 22869, 8228, 8220, 12670,
    # Orange/Free/SFR/Bouygues/LDN/9.tel
    # 荷兰 / 比利时
    33915, 20857, 5418, 6777, 15535, 6830, 8683,
    # KPN/Ziggo/Tele2/Solcon/Proximus/Telenet
    # 加拿大
    577, 6539, 812, 7992, 22995, 23498, 30645, 11260, 5645, 13331,
    # Bell/Rogers/Corus/Cogeco/Videotron/Telus
    # 澳大利亚 / 新西兰
    1221, 4764, 4761, 4747, 4802, 4804, 38293, 9443, 23871, 4771,
    # Telstra/Optus/iinet/AAPT/Exetel/SparkNZ
    # 新加坡 / 马来西亚
    9506, 9224, 10091, 4657, 32308, 55553, 177545, 9534, 17971, 24210,
    # Singtel/StarHub/M1/MyRepublic/TM/Maxis/Time
    # 巴西 / 拉美
    28573, 26599, 28598, 22085, 27699, 11014, 16832, 16397, 26615,
    # Claro/Vivo/Algar/Brisanet
    # 土耳其 / 俄罗斯 / 哈萨克
    9121, 34984, 15924, 31103, 47853, 25513, 12714, 8359, 12389,
    # Türk Telekom/Vodafone TR/MTS/Rostelecom/Kazakhtelecom
    # 意大利 / 西班牙
    3269, 30722, 12874, 12392, 12474, 3352, 12479, 12430,
    # Telecom Italia/Fastweb/Vodafone IT/Telefónica ES
    # 印度 / 越南 / 泰国 / 菲律宾 / 印尼
    55836, 9829, 9498, 17813, 45899, 7552, 9675, 7568, 45773, 45543,
    7590, 17457, 7552, 131293, 9336, 23969, 17816, 24099, 38251,
    # 印尼 Telkomsel/Indosat/Smartfren; 越南 Viettel/FPT; 泰国 AIS/True
}

# rDNS / ISP 名称关键词 (大小写不敏感; 离线兜底)
IDC_NAME_PATTERNS = [
    "hosting", "hoster", "datacenter", "data center", "cloud", "server",
    "vps", "dedicated", "colo", "colocation", "compute", "storage",
    "amazon", "aws", "google cloud", "microsoft", "azure", "oracle",
    "digitalocean", "linode", "vultr", "choopa", "hetzner", "ovh",
    "contabo", "m247", "leaseweb", "online s.a.s", "scaleway",
    "alibaba", "tencent", "huawei cloud", "ucloud", "jdcloud", "ksyun",
    "fastly", "cloudflare", "akamai", "cdn", "anycast", "edge network",
    "hostkey", "selectel", "aeza", "justhost", "idnica", "hostinger",
    "ionos", "1&1", "godaddy", "namecheap", "sucuri", "ispxk",
    "zenlayer", "zencom", "g-core", "gcore", "netcup", "hetzner",
]

RESIDENTIAL_NAME_PATTERNS = [
    # 通用家宽特征
    "broadband", "pppoe", "pppoa", "dsl", "cable", "fiber", "ftth",
    "fibre", "dynamic", "dial", "dialup", "residential", "home",
    "consumer", "cust", "customer", "subscriber", "pool", "dynamic-ip",
    # 台湾
    "chunghwa", "hinet", "taiwanmobile", "twn", "aptg", "kbro",
    "tfn", "sparq", "seednet", "data communication business group",
    # 香港
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "netvigator", "citic telecom", "i-cable", "hk cable",
    # 日本
    "softbank", "ocn", "plala", "so-net", "iiJmio home", "eonet",
    "kddi", "jcom", "au broadband", "biglobe", "nifty",
    # 韩国
    "korea telecom", "kt corp", "sk broadband", "lgu+", "lg uplus",
    # 美国
    "comcast", "charter communications", "spectrum", "cox communications",
    "at&t", "at and t", "bellsouth", "sbc internet", "qwest", "centurylink",
    "verizon fios", "verizon online", "frontier communications", "windstream",
    "altice", "optimum online", "rcn", "wave broadband", "consolidated",
    "hughes", "viasat", "starlink", "mediaserv",
    # 欧洲
    "deutsche telekom", "telekom deutschland", "vodafone d2", "kabel deutschland",
    "british telecom", "bt broadband", "virgin media", "sky uk", "talktalk",
    "orange sa", "free SAS".lower(), "sfr", "bouygues", "bbox", "numericable",
    "kpn", "ziggo", "t-mobile netherlands", "proximus", "telenet",
    "telefonica", "movistar", "vodafone espana", "jazztel", "orange es",
    "telecom italia", "fastweb home", "iliad italia", "windtre",
    "swisscom", "a1 telekom", "magyar telekom", "o2 czech",
    "telia sweden", "telenor", "tele2 sweden", "bredband2",
    "rostelecom home", "mgts", "ertelecom", "dom.ru", "mtu-moscow",
    # 亚太其他
    "singtel", "starhub", "m1 limited", "myrepublic", "viewqwest",
    "maxis", "unifi", "time dotcom", "tm net", "celcom",
    "ais", "true internet", "3bb", "dtac tri", "ntc net",
    "viettel", "vnpt", "fpt telecom", "cmc telecom", "vinaphone",
    "pldt", "globe telecom", "converge ict", "sky broadband ph",
    "telkomsel", "indosat", "xl axiata", "biznet networks", "first media",
    # 拉美 / 土耳其 / 其他
    "claro", "vivo", "tim brasil", "oi internet", "net servicos",
    "turk telekom", "superonline", "ttk", "kablonet", "vodafone net",
    " kazakhtelecom", "beeline kz", "izatelecom",
    "bigpond", "iinet", "optus", "tpg internet", "aussie broadband",
    "spark nz", "vodafone nz", "2degrees", "orcon", "slingshot",
]

# 协议 → 全称 (命名用)
PROTOCOL_LABELS = {
    "vless": "VLESS", "vmess": "VMESS", "trojan": "Trojan",
    "ss": "Shadowsocks", "hysteria2": "Hysteria2", "tuic": "TUIC",
    "anytls": "AnyTLS",
}

COUNTRY_NAMES = {
    "HK": "中国香港 (Hong Kong)", "TW": "中国台湾 (Taiwan)", "JP": "日本 (Japan)",
    "SG": "新加坡 (Singapore)", "US": "美国 (United States)", "KR": "韩国 (South Korea)",
    "DE": "德国 (Germany)", "GB": "英国 (United Kingdom)", "CA": "加拿大 (Canada)",
    "FR": "法国 (France)", "NL": "荷兰 (Netherlands)", "RU": "俄罗斯 (Russia)",
    "IN": "印度 (India)", "AU": "澳大利亚 (Australia)", "IT": "意大利 (Italy)",
    "ES": "西班牙 (Spain)", "TR": "土耳其 (Turkey)", "AE": "阿联酋 (UAE)",
    "BR": "巴西 (Brazil)", "MY": "马来西亚 (Malaysia)", "TH": "泰国 (Thailand)",
    "VN": "越南 (Vietnam)", "PH": "菲律宾 (Philippines)", "ID": "印尼 (Indonesia)",
    "MX": "墨西哥 (Mexico)", "AR": "阿根廷 (Argentina)", "CL": "智利 (Chile)",
    "CO": "哥伦比亚 (Colombia)", "PE": "秘鲁 (Peru)", "ZA": "南非 (South Africa)",
    "EG": "埃及 (Egypt)", "KE": "肯尼亚 (Kenya)", "NG": "尼日利亚 (Nigeria)",
    "UA": "乌克兰 (Ukraine)", "PL": "波兰 (Poland)", "SE": "瑞典 (Sweden)",
    "NO": "挪威 (Norway)", "FI": "芬兰 (Finland)", "DK": "丹麦 (Denmark)",
    "CH": "瑞士 (Switzerland)", "AT": "奥地利 (Austria)", "BE": "比利时 (Belgium)",
    "IE": "爱尔兰 (Ireland)", "PT": "葡萄牙 (Portugal)", "GR": "希腊 (Greece)",
    "CZ": "捷克 (Czech)", "RO": "罗马尼亚 (Romania)", "HU": "匈牙利 (Hungary)",
    "IL": "以色列 (Israel)", "SA": "沙特 (Saudi Arabia)", "QA": "卡塔尔 (Qatar)",
    "KZ": "哈萨克斯坦 (Kazakhstan)", "UZ": "乌兹别克斯坦 (Uzbekistan)",
    "PK": "巴基斯坦 (Pakistan)", "BD": "孟加拉 (Bangladesh)", "LK": "斯里兰卡 (Sri Lanka)",
    "NP": "尼泊尔 (Nepal)", "MM": "缅甸 (Myanmar)", "KH": "柬埔寨 (Cambodia)",
    "LA": "老挝 (Laos)", "NZ": "新西兰 (New Zealand)", "EE": "爱沙尼亚 (Estonia)",
    "LV": "拉脱维亚 (Latvia)", "LT": "立陶宛 (Lithuania)", "BG": "保加利亚 (Bulgaria)",
    "RS": "塞尔维亚 (Serbia)", "HR": "克罗地亚 (Croatia)", "SK": "斯洛伐克 (Slovakia)",
    "SI": "斯洛文尼亚 (Slovenia)", "IS": "冰岛 (Iceland)", "LU": "卢森堡 (Luxembourg)",
    "MT": "马耳他 (Malta)", "CY": "塞浦路斯 (Cyprus)", "GE": "格鲁吉亚 (Georgia)",
    "AM": "亚美尼亚 (Armenia)", "AZ": "阿塞拜疆 (Azerbaijan)", "MD": "摩尔多瓦 (Moldova)",
    "BY": "白俄罗斯 (Belarus)", "SC": "塞舌尔 (Seychelles)", "OTHER": "其他地区 (Other)",
}


# ══════════════════════════════════════════════════════════════════
# 工具函数
# ══════════════════════════════════════════════════════════════════

def get_country_flag(country_code: str) -> str:
    if not country_code:
        return "🌐"
    cc = country_code.upper()
    if cc in ("OTHER", "ZZ", "XX", "T1", "A1", "A2"):
        return "🌐"
    if len(cc) == 2 and cc.isalpha() and cc.isascii():
        return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
    return "🌐"


def b64_decode(data: str) -> str:
    """容错 base64 解码 (支持 URL-safe / 缺失 padding)"""
    data = data.strip()
    try:
        pad = -len(data) % 4
        if data and data[-1] not in "=":
            data += "=" * pad
        raw = base64.urlsafe_b64decode(data)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        pass
    try:
        raw = base64.b64decode(data + "=" * (-len(data) % 4))
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


# ══════════════════════════════════════════════════════════════════
# HTTP 会话 (两分离设计):
#
# 【设计定位: 测活视角 = GitHub Actions 美国微软云 (海外直连节点)】
#   节点从海外可达即入库; 大陆用户经前置代理(链式)访问 —— 与 CI 同视角。
#   因此: 本地开发机 (大陆网络) 只用于调试, 抓订阅源需借系统代理过墙;
#   生产环境 (Actions) 无代理直连, 天然正确。
#
#   - DIRECT_SESSION (trust_env=True): 抓订阅源/下载数据库/IP情报/Scamalytics。
#       本地: 经系统代理 (v2rayN) 过墙; Actions: 直连 — 两种环境都正确。
#   - PROBE_SESSION (trust_env=False): 经 sing-box SOCKS 探测节点。
#       强制隔离环境代理, 保证测的是"运行机→节点"真实链路。
#       (本地调试时受 GFW 影响的失败 ≠ 节点死亡, Actions 上会得到真实结果;
#        宁可本地多杀, 不可 CI 误杀 — 生产判定以 Actions 为准)
# ══════════════════════════════════════════════════════════════════

DIRECT_SESSION = requests.Session()
DIRECT_SESSION.trust_env = True    # 跟随系统/环境代理 (本地大陆网络抓 GitHub 需要; Actions 无代理直连不受影响)
DIRECT_SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})

PROBE_SESSION = requests.Session()
PROBE_SESSION.trust_env = False    # 强制隔离: 节点探测链路绝不经本机代理, 防污染测试结果
PROBE_SESSION.headers.update({"User-Agent": USER_AGENT})


def http_get(url: str, timeout: int = 15, headers: dict = None) -> requests.Response:
    h = {"User-Agent": USER_AGENT, "Accept": "*/*"}
    if headers:
        h.update(headers)
    return DIRECT_SESSION.get(url, timeout=timeout, headers=h)


def ensure_directories():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    os.makedirs(RUNTIME_DIR, exist_ok=True)


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip())
        return True
    except ValueError:
        return False


def parse_host_port(hostinfo: str):
    """解析 '[v6]:port' 或 'v4:port' 或 'host:port'"""
    hostinfo = hostinfo.strip()
    if hostinfo.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", hostinfo)
        if m:
            return m.group(1), int(m.group(2)) if m.group(2) else 0
        return hostinfo, 0
    if hostinfo.count(":") == 1:
        host, _, port = hostinfo.rpartition(":")
        if host and port.isdigit():
            return host, int(port)
    if hostinfo.count(":") > 1 and is_ip_literal(hostinfo):
        return hostinfo, 0  # 裸 IPv6 无端口
    parts = hostinfo.rsplit(":", 1)
    if len(parts) == 2 and parts[1].isdigit():
        return parts[0], int(parts[1])
    return hostinfo, 0


# ══════════════════════════════════════════════════════════════════
# 环境准备 (sing-box / GeoLite)
# ══════════════════════════════════════════════════════════════════

def download_file(url: str, dest: str, timeout: int = 300, retries: int = 3):
    """下载文件到本地; 分块流式 + 原子替换 + 重试 + 镜像切换
    (GitHub 直连失败自动尝试 jsdelivr 镜像 — 本地大陆网络/CI 偶发限流都更稳)"""
    if os.path.exists(dest) and os.path.getsize(dest) > 1024:
        return
    # 镜像: github.com/OWNER/REPO/... → cdn.jsdelivr.net/gh/OWNER/REPO@...
    mirrors = [url]
    m = re.match(r"^https://(?:github\.com|raw\.githubusercontent\.com)/([^/]+)/([^/]+)/(?:raw|releases/download)/(.+)$", url)
    if m and "releases/download" not in url:
        owner, repo, path = m.groups()
        mirrors.append(f"https://cdn.jsdelivr.net/gh/{owner}/{repo.replace('.git','')}@{path}")
    print(f"[*] 下载: {url}")
    tmp = dest + ".part"
    last_err = None
    for mirror in mirrors:
        for attempt in range(retries):
            try:
                with DIRECT_SESSION.get(mirror, timeout=timeout, stream=True,
                                        headers={"Accept": "*/*"}) as r:
                    r.raise_for_status()
                    with open(tmp, "wb") as f:
                        for chunk in r.iter_content(chunk_size=1 << 20):
                            if chunk:
                                f.write(chunk)
                if os.path.getsize(tmp) < 1024:
                    raise RuntimeError(f"下载不完整: {os.path.getsize(tmp)} bytes")
                os.replace(tmp, dest)
                return
            except Exception as e:
                last_err = e
                if attempt < retries - 1:
                    wait = 3 * (attempt + 1)
                    print(f"[!] 下载失败 (第{attempt+1}次): {str(e)[:70]} — {wait}s 后重试")
                    time.sleep(wait)
        if len(mirrors) > 1 and mirror != mirrors[-1]:
            print(f"[!] 切换镜像: {mirrors[1]}")
    # 清理失败的半截文件
    try:
        if os.path.exists(tmp):
            os.remove(tmp)
    except OSError:
        pass
    raise RuntimeError(f"下载最终失败 ({mirrors[0]}): {last_err}")


def setup_environment():
    print("[*] 准备 sing-box 内核与 GeoLite2 离线数据库 ...")
    os.makedirs(RUNTIME_DIR, exist_ok=True)

    # --- sing-box ---
    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")
    if not os.path.exists(exe) or os.path.getsize(exe) < 1024:
        system = "windows" if os.name == "nt" else "linux"
        ext = "zip" if system == "windows" else "tar.gz"
        url = (f"https://github.com/SagerNet/sing-box/releases/download/"
               f"{SINGBOX_VERSION}/sing-box-{SINGBOX_VERSION.lstrip('v')}-{system}-amd64.{ext}")
        archive = os.path.join(RUNTIME_DIR, f"sing-box.{ext}")
        download_file(url, archive)
        if system == "windows":
            with zipfile.ZipFile(archive) as z:
                for name in z.namelist():
                    if name.endswith("sing-box.exe"):
                        with z.open(name) as src, open(exe, "wb") as dst:
                            shutil.copyfileobj(src, dst)
        else:
            with tarfile.open(archive) as t:
                for m in t.getmembers():
                    if m.name.endswith("sing-box"):
                        f = t.extractfile(m)
                        with open(exe, "wb") as dst:
                            shutil.copyfileobj(f, dst)
        os.chmod(exe, 0o755)
        try:
            os.remove(archive)
        except OSError:
            pass
    # 校验内核可运行
    try:
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=20)
        first = (ver.stdout or "").splitlines()[0] if ver.stdout else "?"
        print(f"[+] sing-box 内核就绪: {first.strip()}")
    except Exception as e:
        print(f"[!] sing-box 内核无法运行: {e}")
        raise

    # --- GeoLite2 数据库 ---
    country_db = os.path.join(RUNTIME_DIR, "Country.mmdb")
    asn_db = os.path.join(RUNTIME_DIR, "ASN.mmdb")
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb", country_db)
    download_file("https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb", asn_db)
    print(f"[+] GeoLite 数据库就绪: Country={os.path.getsize(country_db)//1024}KB, ASN={os.path.getsize(asn_db)//1024}KB")


# ═══════════════════════════════════════════N═══════════════════════
# 节点 URI 解析 (全协议 → sing-box outbound JSON)
# ═══════════════════════════════════════════N═══════════════════════

def _query_dict(query: str) -> dict:
    return {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}


def _parse_tls_params(params: dict, host: str) -> dict:
    """从 URI query 提取 TLS/Reality 设置 → sing-box 格式"""
    security = params.get("security", "").lower()
    tls = {}
    if security == "reality":
        pbk = params.get("pbk", "")
        if not pbk:
            return None
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "utls": {"enabled": True, "fingerprint": params.get("fp", "chrome")},
            "reality": {"enabled": True, "public_key": pbk, "short_id": params.get("sid", "")},
        }
    elif security in ("tls", "xtls"):
        tls = {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
            "alpn": params.get("alpn", "").split(",") if params.get("alpn") else None,
        }
        if params.get("fp"):
            tls["utls"] = {"enabled": True, "fingerprint": params["fp"]}
        if tls.get("alpn") is None:
            del tls["alpn"]
    return tls or None


def _parse_transport(params: dict) -> dict:
    """从 URI query 提取传输层 → sing-box transport 格式"""
    network = params.get("type", "tcp").lower()
    if network in ("tcp", "none", "raw"):
        return None
    if network == "ws":
        t = {"type": "ws"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["headers"] = {"Host": params["host"]}
        # 0-RTT early data (v2ray ws 0-RTT: path 含 ?ed=2560 时由 max-early-data 指定)
        if params.get("ed"):
            t["max_early_data"] = 2560
            t["early_data_header_name"] = "Sec-WebSocket-Protocol"
        return t
    if network in ("grpc", "gun"):
        t = {"type": "grpc"}
        if params.get("serviceName"):
            t["service_name"] = urllib.parse.unquote(params["serviceName"])
        return t
    if network in ("h2", "http"):   # v2ray 生态两种写法都有: type=h2 / type=http (导出用 http, 兼容两者)
        t = {"type": "http"}
        host = params.get("host", "")
        if host:
            t["host"] = [h for h in host.split(",") if h]
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        return t
    if network == "httpupgrade":
        t = {"type": "httpupgrade"}
        if params.get("path"):
            t["path"] = urllib.parse.unquote(params["path"])
        if params.get("host"):
            t["host"] = params["host"]
        return t
    return None


def parse_vless(uri: str):
    """vless://uuid@host:port?params#name"""
    m = re.match(r"^vless://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    user, host, port, query, _name = m.groups()
    params = _query_dict(query or "")
    tls = _parse_tls_params(params, host)
    if params.get("security", "").lower() == "reality" and tls is None:
        return None  # reality 缺 pbk 无法测
    outbound = {
        "type": "vless",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": user,
    }
    flow = params.get("flow", "")
    if flow and ("vision" in flow or "xtls" in flow):
        outbound["flow"] = flow
    if tls:
        outbound["tls"] = tls
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_vmess(uri: str):
    """vmess://base64({v,ps,add,port,id,aid,net,tls,sni,path,host,type})"""
    data = json.loads(b64_decode(uri[8:]))
    if not data:
        return None
    server = str(data.get("add", "")).strip()
    port = int(data.get("port", 0) or 0)
    if not server or port <= 0:
        return None
    outbound = {
        "type": "vmess",
        "tag": "node",
        "server": server,
        "server_port": port,
        "uuid": str(data.get("id", "")).strip(),
        "security": "auto",
    }
    aid = int(data.get("aid", 0) or 0)
    if aid > 0:
        outbound["alter_id"] = aid
    net = str(data.get("net", "tcp")).lower()
    if data.get("tls") in ("tls", "1", 1, True):
        outbound["tls"] = {
            "enabled": True,
            "server_name": str(data.get("sni") or data.get("host") or server).strip(),
            "insecure": str(data.get("verify_cert", "false")).lower() in ("true", "1"),
        }
    transport = None
    if net in ("ws",):
        transport = {"type": "ws"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["headers"] = {"Host": str(data["host"])}
    elif net in ("grpc", "gun"):
        transport = {"type": "grpc"}
        if data.get("path"):
            transport["service_name"] = str(data["path"])
    elif net == "h2":
        transport = {"type": "http"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = [str(data["host"])]
    elif net == "httpupgrade":
        transport = {"type": "httpupgrade"}
        if data.get("path"):
            transport["path"] = str(data["path"])
        if data.get("host"):
            transport["host"] = str(data["host"])
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_trojan(uri: str):
    """trojan://password@host:port?params#name"""
    m = re.match(r"^trojan://([^@#]+)@(\[[^\]]+\]|[^:@/]+):(\d+)(?:[/?]([^#]*))?(?:#(.*))?$", uri)
    if not m:
        return None
    password, host, port, query, _ = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "trojan",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("fp"):
        outbound["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
    transport = _parse_transport(params)
    if transport:
        outbound["transport"] = transport
    return outbound


def parse_ss(uri: str):
    """ss://base64(method:password)@host:port#name  或  ss://method:password@... (SIP002)"""
    body = uri[5:].split("#", 1)[0]
    name = urllib.parse.unquote(uri.split("#", 1)[1]) if "#" in uri else ""
    # SIP002: method:password@host:port
    if "@" in body:
        userinfo, _, hostinfo = body.rpartition("@")
        host, port = parse_host_port(hostinfo.split("/")[0].split("?")[0])
        method, password = "", ""
        if ":" in userinfo:
            method, _, password = userinfo.partition(":")
        else:
            dec = b64_decode(userinfo)
            if ":" in dec:
                method, _, password = dec.partition(":")
        method = urllib.parse.unquote(method)
        password = urllib.parse.unquote(password)
        if not (host and port > 0 and method and password):
            return None
        return _ss_outbound(host, port, method, password)
    # legacy: base64(method:password@host:port)
    dec = b64_decode(body)
    if "@" in dec:
        userinfo, _, hostinfo = dec.rpartition("@")
        host, port = parse_host_port(hostinfo.strip())
        method, _, password = userinfo.partition(":")
        if host and port > 0 and method:
            return _ss_outbound(host, port, urllib.parse.unquote(method), urllib.parse.unquote(password))
    return None


def _ss_outbound(host, port, method, password):
    return {
        "type": "shadowsocks",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "method": method.strip().lower(),
        "password": password,
    }


def parse_hysteria2(uri: str):
    """hy2:// / hysteria2:// auth@host:port?sni=..&obfs=salamander&obfs-password=..&insecure=1
    注: auth 可能含 : / 等特殊字符 (如 https:// 前缀的密码) — 以最后一个 @ 为锚点分割"""
    prefix = "hysteria2://" if uri.startswith("hysteria2://") else "hy2://"
    body = uri[len(prefix):].split("#", 1)[0]
    # 以最后一个 @ 分割 (密码内可能含 @); host 部分不含 @
    at = body.rfind("@")
    if at <= 0:
        return None
    auth, rest = body[:at], body[at+1:]
    m = re.match(r"^(\[[^\]]+\]|[^:/?#]+):(\d+)(?:[/?]([^#]*))?$", rest)
    if not m:
        return None
    host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "hysteria2",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(auth),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", params.get("peer", host)),
            "insecure": params.get("allowInsecure", "0") in ("1", "true") or params.get("insecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    if params.get("obfs", "") and params["obfs"] not in ("none", ""):
        outbound["obfs"] = {"type": params["obfs"], "password": params.get("obfs-password", "")}
    mport = params.get("mport") or params.get("ports")
    if mport:
        # 实测验证: server_ports 只接受 "start:end" 区间; 裸单端口 "443" 会 FATAL
        # 单端口保留在 server_port, 区间放 server_ports (两者可共存, 实测 check 通过)
        singles, ranges = [], []
        for part in str(mport).split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, _, b = part.partition("-")
                if a.strip().isdigit() and b.strip().isdigit():
                    if a.strip() == b.strip():
                        singles.append(a.strip())
                    else:
                        ranges.append(f"{a.strip()}:{b.strip()}")
            elif part.isdigit():
                singles.append(part)
        if ranges or singles:
            # 全部转为 "start:end" 区间格式 (实测: 裸单端口 FATAL)
            outbound["server_ports"] = ranges + [f"{s}:{s}" for s in singles]
            outbound.pop("server_port", None)  # 端口跳跃节点无固定单端口
    return outbound


def _parse_port_range(spec: str):
    """'2087-2097,443' → sing-box server_ports 格式 ['2087:2097', '443:443'] (实测: 裸单端口 FATAL, 必须区间)"""
    result = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                result.append(f"{a.strip()}:{b.strip()}")
        elif part.isdigit():
            result.append(f"{part}:{part}")
    return result


def parse_tuic(uri: str):
    """tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3&sni=..&udp_relay_mode=native#name"""
    m = re.match(r"^tuic://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port, query = m.groups()
    if ":" not in userinfo:
        return None
    uuid_, _, password = userinfo.partition(":")
    params = _query_dict(query or "")
    outbound = {
        "type": "tuic",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "uuid": urllib.parse.unquote(uuid_),
        "password": urllib.parse.unquote(password),
        "congestion_control": params.get("congestion_control", "bbr"),
        "udp_relay_mode": params.get("udp_relay_mode", "native"),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("allow_insecure", "0") in ("1", "true"),
            "alpn": [a for a in params.get("alpn", "h3").split(",") if a],
        },
    }
    return outbound


def parse_anytls(uri: str):
    """anytls://password@host:port?sni=..&insecure=1#name"""
    m = re.match(r"^anytls://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)(?:[/?]([^#]*))?$", uri.split("#")[0])
    if not m:
        return None
    password, host, port, query = m.groups()
    params = _query_dict(query or "")
    outbound = {
        "type": "anytls",
        "tag": "node",
        "server": host,
        "server_port": int(port),
        "password": urllib.parse.unquote(password),
        "tls": {
            "enabled": True,
            "server_name": params.get("sni", host),
            "insecure": params.get("insecure", "0") in ("1", "true") or params.get("allowInsecure", "0") in ("1", "true"),
        },
    }
    if params.get("alpn"):
        outbound["tls"]["alpn"] = params["alpn"].split(",")
    return outbound


def parse_ssh(uri: str):
    """ssh://user:pass@host:port#name (少见于免费池, 顺手支持)"""
    m = re.match(r"^ssh://([^@#/?]+)@(\[[^\]]+\]|[^:@/?]+):(\d+)?", uri.split("#")[0])
    if not m:
        return None
    userinfo, host, port = m.groups()
    outbound = {
        "type": "ssh",
        "tag": "node",
        "server": host,
        "server_port": int(port or 22),
        "user": urllib.parse.unquote(userinfo.split(":")[0]),
    }
    if ":" in userinfo:
        outbound["user"] = urllib.parse.unquote(userinfo.split(":")[0])
        outbound["password"] = urllib.parse.unquote(userinfo.split(":", 1)[1])
    return outbound


PARSERS = {
    "vless://": parse_vless,
    "vmess://": parse_vmess,
    "trojan://": parse_trojan,
    "ss://": parse_ss,
    "hy2://": parse_hysteria2,
    "hysteria2://": parse_hysteria2,
    "tuic://": parse_tuic,
    "anytls://": parse_anytls,
    "ssh://": parse_ssh,
}

# 排除明显加密残缺/占位节点
BLACKLIST_NAME_HINTS = re.compile(r"(剩余流量|流量重置|expire|expired|官网|套餐|telegram\.me|t\.me/|获取订阅)", re.I)

# ══════════════════════════════════════════════════════════════════
# 阶段 0: 静态预筛 (零网络零进程, 纯 URI/outbound 字段检查)
#   动机: 池子从 10 源扩到 15 源后, 候选涨到 3000+ 量级, 阶段B 单节点最坏
#   52.5s (跨源探测 20s + 测速 12s + IP/MITM/WARP 14s + 进程开销 6s)。
#   24 并发下 3000 节点最坏 ~109 分钟。必须在进阶段B 之前把垃圾砍掉。
#   ★ 关键: 这道闸筛的是 MITM 检测**抓不到**的节点 —— 主动声明跳过证书校验
#     (insecure=1 / allowInsecure=1 / security=none) 的配置, 测活阶段拿它们
#     没办法 (它们就是设计成不校验证书的), 只能在这里静态砍掉。
# ══════════════════════════════════════════════════════════════════

# 证书校验关闭的字段 (任一命中即视为高危: 无法抵御中间人, 且测活阶段检测不到)
INSECURE_FIELDS = ("insecure", "allow_insecure", "allowinsecure", "skip_cert_verify")
# tls.security 的危险取值 (明文/无 TLS)。
# ★ 只认显式的 "none": 字段**缺失**不代表明文 (sing-box 里 tls.enabled=True 而
#   不写 security 是常规写法, vless/trojan/hysteria2 默认走 TLS)。
#   早先把 "" 和 None 也算进来, 导致所有未显式写 security 的正常节点被误杀。
NONE_SECURITY_VALUES = ("none",)
ENABLE_WORKERS_STATIC = 64         # 静态筛无网络, 纯内存判断, 并发高无所谓


def is_insecure_node(outbound: dict) -> bool:
    """判断节点是否关闭了证书校验 (主动降级安全性, 测活阶段无法检出)"""
    if not isinstance(outbound, dict):
        return False
    # 1) 顶层 insecure / allow_insecure 布尔开关
    for f in INSECURE_FIELDS:
        v = outbound.get(f)
        if v is True or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes")):
            return True
    # 2) tls.security = none (明文传输)
    tls = outbound.get("tls")
    if isinstance(tls, dict):
        if str(tls.get("security", "")).strip().lower() in NONE_SECURITY_VALUES:
            return True
    # 3) 走 TLS/Reality 但 sni 指向本地回环 (常见于生成错误的配置, 证书必然不匹配)
    #    注意: sni 缺失/为空本身不算危险 — 很多服务端靠 IP 或默认值协商,
    #    只有显式写成 127.0.0.1/localhost 才是配置错误。
    sni = outbound.get("sni") or outbound.get("servername")
    if isinstance(sni, str) and sni.strip().lower() in ("127.0.0.1", "::1", "localhost"):
        # 仅当该节点确实走 TLS/Reality 时才判定 (plain 协议无 sni 属正常)
        if isinstance(tls, dict) or outbound.get("reality") or outbound.get("flow"):
            return True
    return False


def static_prescreen(candidates: list) -> list:
    """阶段 0 静态预筛: 砍掉关闭证书校验的节点 (零成本, 不发一个包)

    这类节点占免费池相当比例 (实测某源 131 条 hysteria2 多半 insecure=1),
    它们在阶段B 会被判"活"并入库, 但既不抗 MITM 也常伴随其他质量问题。
    """
    print(f"[*] 静态预筛 (证书校验开关检查): {len(candidates)} 候选 ...")
    kept, dropped = [], 0
    insecure_proto = {}
    for item in candidates:
        _, outbound, server, port, proto = item
        if is_insecure_node(outbound):
            dropped += 1
            insecure_proto[proto] = insecure_proto.get(proto, 0) + 1
            continue
        kept.append(item)
    detail = " ".join(f"{k}:{v}" for k, v in sorted(insecure_proto.items(), key=lambda x: -x[1]))
    print(f"[+] 静态预筛通过: {len(kept)} | 剔除关闭证书校验: {dropped}"
          + (f" ({detail})" if detail else ""))
    return kept



def parse_node_uri(uri: str):
    """解析节点 URI → (outbound, server, port, protocol) ; 失败返回 None"""
    for prefix, parser in PARSERS.items():
        if uri.startswith(prefix):
            try:
                out = parser(uri)
            except Exception:
                return None
            if not out:
                return None
            proto = out["type"]
            port = out.get("server_port")
            if port is None:  # 端口跳跃节点: 无固定端口, 取区间首个起点用于预检
                ports = out.get("server_ports") or []
                first = ports[0].split(":")[0] if ports else "0"
                port = int(first)
            if port <= 0:
                return None
            return out, out["server"], int(port), proto
    return None


def extract_nodes_from_text(text: str) -> set:
    results = set()
    if not text:
        return results
    probe = text.strip()
    # 最多三层 base64 解包 (订阅常见整体 base64)
    for _ in range(3):
        if any(p in probe for p in ("vmess://", "vless://", "ss://", "trojan://",
                                     "hy2://", "hysteria2://", "tuic://", "anytls://")):
            break
        decoded = b64_decode(probe)
        if not decoded or decoded == probe:
            break
        probe = decoded
    # 直接文本也可能混杂 base64 行
    lines_blob = probe
    pattern = (r'((?:vmess|vless|trojan|ss|hy2|hysteria2|tuic|anytls|ssh)://'
               r'[^\s"\'<>\\]+)')
    for m in re.findall(pattern, lines_blob):
        clean = m.strip().rstrip(".,;'\"")
        if len(clean) > 12:
            results.add(clean)
    return results


def fetch_raw_nodes() -> list:
    nodes = set()
    print("[*] 抓取全部订阅源 ...")

    def _fetch(url):
        last_err = None
        # 重试 2 次 (网络抖动/GFW 间歇性重置; 退避 3s)
        for attempt in range(3):
            try:
                r = http_get(url, timeout=30)
                if r.status_code == 200:
                    got = extract_nodes_from_text(r.text)
                    return url, got, None
                last_err = f"HTTP {r.status_code}"
            except Exception as e:
                last_err = str(e)[:70]
            if attempt < 2:
                time.sleep(3)
        return url, set(), last_err

    with ThreadPoolExecutor(MAX_WORKERS_FETCH) as ex:
        futs = [ex.submit(_fetch, u) for u in SOURCE_URLS]
        for f in as_completed(futs):
            url, got, err = f.result()
            if err:
                print(f"[!] 拉取失败 {url} → {err}")
            else:
                print(f"[+] {url} → {len(got)} 节点")
            nodes.update(got)
    print(f"[*] 初始抓取总量: {len(nodes)}")
    return list(nodes)


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 A: 端口预检 (削减死节点, 避免后面浪费 sing-box 全流程)
# ═══════════════════════════════════════════N═══════════════════════

# DoH 域名解析 (Cloudflare): 防 DNS 污染 (本地大陆网络); Actions 上顺带跳过其国内 DNS 限制
_DNS_CACHE = {}

def resolve_host(host: str) -> str:
    """DoH 解析 (带本地缓存); 失败退回系统 DNS"""
    if not host or is_ip_literal(host):
        return host or ""
    if host in _DNS_CACHE:
        return _DNS_CACHE[host]
    # 1) DoH (Cloudflare 1.1.1.1, 走 DIRECT_SESSION 可过墙)
    try:
        r = DIRECT_SESSION.get(
            f"https://cloudflare-dns.com/dns-query?name={urllib.parse.quote(host)}&type=A",
            headers={"Accept": "application/dns-json"}, timeout=5)
        if r.status_code == 200:
            answers = r.json().get("Answer") or []
            for a in answers:
                if a.get("type") == 1 and a.get("data"):
                    _DNS_CACHE[host] = a["data"]
                    return a["data"]
    except Exception:
        pass
    # 2) 系统 DNS 兜底
    try:
        return socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
    except Exception:
        return ""


def knock_port(server: str, port: int, protocol_type: str) -> bool:
    """TCP 直连预检 (DoH 解析防本地 DNS 污染); QUIC 类直接放行阶段B

    ★ 淘汰策略按运行视角分流 (原版一律"不淘汰"是性能浪费):
      - Actions 海外视角 (默认): 预检失败 = 节点真死, 硬淘汰。
        依据: Actions 跑在 Azure US, 不经 GFW 直连海外, 连不上就是节点没了。
        不淘汰的代价 = 每个白等最多 52.5s (阶段B 最坏耗时)。
      - 本地大陆视角: 预检失败可能是 GFW 假死, 降级保留交给阶段B 裁决。
        判定: FRONT_PROXY 有值 = 本地链式模式 = 本地视角; 否则视为 Actions 视角。
    """
    if protocol_type in ("hysteria2", "tuic"):
        # QUIC 无法轻量预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 放行交阶段B
        return True
    try:
        ip = resolve_host(server)
        if not ip:
            return False
        with socket.create_connection((ip, port), timeout=PORT_KNOCK_TIMEOUT):
            return True
    except Exception:
        return False


def prefilter_candidates(candidates: list) -> list:
    """端口预检: 按运行视角决定"淘汰"还是"降级保留"

    Actions 视角 (默认)  预检失败即淘汰 — 池子大时这是最大的一刀
    本地视角 (FRONT_PROXY) 预检失败降级保留, 防止 GFW 假死误杀
    """
    # 本地链式模式 = 本地视角 (GFW 在场) → 不能硬淘汰
    local_view = bool(os.environ.get("FRONT_PROXY", "").strip())
    policy = "降级保留 (本地视角, 防 GFW 假死误杀)" if local_view else "硬淘汰 (Actions 海外视角)"
    print(f"[*] 端口预检 (TCP {PORT_KNOCK_TIMEOUT}s, {policy}): {len(candidates)} 候选 ...")
    passed, failed = [], []

    def _knock(item):
        raw, outbound, server, port, proto = item
        return knock_port(server, port, proto)

    with ThreadPoolExecutor(max_workers=64) as ex:
        for item, ok in zip(candidates, ex.map(_knock, candidates)):
            (passed if ok else failed).append(item)

    if local_view:
        print(f"[+] 预检通过: {len(passed)} | 预检未过(保留低优先级待全测): {len(failed)}")
        # 预检未过的仍进入全流程 (只是排在后面) — 交给 sing-box 真实裁决
        return passed + failed

    dropped = len(failed)
    if dropped:
        pct = dropped * 100.0 / max(len(candidates), 1)
        print(f"[+] 预检通过: {len(passed)} | 预检未过直接淘汰: {dropped} ({pct:.1f}%)")
        print(f"    预估省下 {dropped * STAGE_B_WORST_SEC / MAX_WORKERS_TEST / 60:.1f} 分钟"
              f" (每节点省最多 {STAGE_B_WORST_SEC:.0f}s 阶段B 开销)")
    else:
        print(f"[+] 预检通过: {len(passed)} (全部可达)")
    return passed


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B: sing-box 真实测活
# ═══════════════════════════════════════════N═══════════════════════

def _alloc_socks_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_test_config(outbound: dict, socks_port: int, chain_relay: dict = None) -> dict:
    node = dict(outbound)
    node["tag"] = "node"

    outbounds = [node, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}]

    # ══ 链式前置 (家宽链式复测用) ═════════════════════════════════════
    # chain_relay: 已验证存活的 sing-box outbound dict — node 经它转发 (detour 双跳)
    # 模拟用户 v2rayN "链式/前置代理" 场景: 前置 → 家宽节点 → 目标
    if chain_relay:
        relay = dict(chain_relay)
        relay["tag"] = "chain-relay"
        # relay 自身剥 detour (避免与 node 的 detour 循环)
        relay.pop("detour", None)
        outbounds.append(relay)
        node["detour"] = "chain-relay"

    # ══ 前置代理 (链式) ═════════════════════════════════════════════
    # 模拟 GitHub Actions 海外视角:
    #   - 本地大陆开发机: 经前置代理(默认 v2rayN 127.0.0.1:10808)出海 → 等效 CI 视角
    #     (大陆直连目标节点会被 GFW 拦截, 造成本地假死 ≠ 节点死亡)
    #   - GitHub Actions: FRONT_PROXY 为空 → 直连 (Azure US 本就是海外视角)
    # 用法: 环境变量 FRONT_PROXY=socks5://127.0.0.1:10808
    front = os.environ.get("FRONT_PROXY", "").strip()
    if front and not chain_relay:
        # 解析 socks5://host:port → socks outbound
        m = re.match(r"^(socks5h?|http)://([^:]+):(\d+)$", front)
        if m:
            scheme, fhost, fport = m.groups()
            ftype = "socks" if scheme.startswith("socks5") else "http"
            front_out = {
                "type": ftype, "tag": "front-proxy",
                "server": fhost, "server_port": int(fport),
            }
            if ftype == "socks":
                front_out["version"] = "5"
            outbounds.append(front_out)
            # 节点出站流量经前置代理 (detour 链式)
            node["detour"] = "front-proxy"
            print_once("_FRONT_ENABLED", f"[*] 前置代理已启用: {front} (模拟 CI 海外视角)")

    config = {
        "log": {"level": "warn"},   # 实测: silent 不是合法级别 (trace/debug/info/warn/error/fatal/panic)
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port,
            "sniff": False,
        }],
        "outbounds": outbounds,
        "route": {"rules": [], "final": "node"},
    }
    return config


_PRINTED_ONCE = set()


def print_once(key: str, msg: str):
    if key not in _PRINTED_ONCE:
        _PRINTED_ONCE.add(key)
        print(msg)


def measure_download_speed(proxies: dict, urls: list, budget: float,
                           warmup: float, chunk_size: int = SPEED_CHUNK_SIZE,
                           idle_timeout: float = SPEED_IDLE_TIMEOUT,
                           with_ttfb: bool = False, range_bytes: int = 0,
                           min_data_bytes: int = 0):
    """限时下载测速 → 返回稳态吞吐 (B/s, 0 = 失败/断流)

    ★ 关键修正: 分母只取"首数据块 → 结束"的稳态区间。
      旧版 t_speed 在 GET() 之前起算, 把 TCP/TLS 握手 + 首包 RTT 算进分母,
      导致真实越快的节点被低估得越狠 (实测 1MB/s 节点只算出 ~500KB/s),
      那样单纯抬高 SPEED_MIN_BYTES_PER_S 等于按快慢反向淘汰。
      现改为: 首块到达才开始计时, 前 warmup 秒的数据丢弃 (握手 + TCP 慢启动)。

    with_ttfb=True 时返回 (吞吐, 首包毫秒, 失败原因); 否则返回 (吞吐, 失败原因)。
    ★ TTFB = 从发出 GET 到收到**第一个数据块**的耗时, 含握手 + 服务端首字节时间,
      与 latency (纯握手 RTT) 互补: RTT 低但 TTFB 高 = 服务端缓冲/链路拥塞。

    ★ 2026-10-04: 新增 fail_reason 归集 (可观测性)。
      旧版所有失败路径都是静默 continue, 403/超时/样本不足/断流 全都只返回 0,
      日志里只能看到"最快 0KB/s" —— #67 事故时无法定位到底是哪一环坏的。
      现在把每个端点的失败原因收集起来, 由调用方汇总进日志。

    min_data_bytes: 有效样本下限, 0 表示用全局 SPEED_MIN_DATA_BYTES(200KB)。
      交叉验证传 SPEED_CROSS_MIN_BYTES(50KB) —— 物理机房跨大西洋链路慢,
      拿不到 200KB 就会被误判"端点不通", 导致本可采信的交叉结果丢失。
    """
    fail_reason = ""
    min_bytes = min_data_bytes if min_data_bytes > 0 else SPEED_MIN_DATA_BYTES
    for speed_url in urls:
        downloaded = 0        # 全部收到的字节 (含热身期, 用于判断是否真拿到数据)
        steady_bytes = 0      # 稳态区间内的字节 (用于算速率)
        t_start = time.time()
        last_chunk_time = t_start
        t_first = None        # 首数据块时刻 = 握手结束
        t_steady = None       # 热身结束后首个数据块 = 稳态区间起点 (速率分母起点)
        t_warmup_end = None   # 热身期结束时刻 (= t_first + warm)
        # 热身期取固定值与预算的 12% 取小: 预算越大热身占比越小, 避免长预算下
        # 固定 0.6s 把有效样本削掉一截
        warm = min(warmup, budget * 0.12)
        # range_bytes > 0 时用 Range 请求只取前若干字节 (Hetzner 的 100MB.bin
        # 支持 HTTP 206, 不加 Range 会真的去拉 100MB)
        headers = {"Range": f"bytes=0-{range_bytes - 1}"} if range_bytes else None
        try:
            with PROBE_SESSION.get(speed_url, proxies=proxies, headers=headers,
                                   timeout=(5, budget), stream=True) as r:
                # 206 = 部分内容 (Range 生效), 200 = 完整响应, 两者都算有效
                if r.status_code not in (200, 206):
                    fail_reason = f"HTTP{r.status_code}"   # 403/404/5xx 一望可知
                    continue
                for chunk in r.iter_content(chunk_size=chunk_size):
                    now = time.time()
                    if chunk:
                        if t_first is None:
                            t_first = now
                            t_warmup_end = t_first + warm     # 热身期结束时刻
                        # ★ 2026-10-04 修正 (#68 暴露): 原写法用
                        #   "if t_steady is None and now-t_first>warm" 判定稳态起点,
                        #   但它要求**恰好有一个 chunk 跨过 warm 线**才能赋值。
                        #   两种情况会永久保留 t_steady=None:
                        #     ① 预算在 warm 期内耗尽 → break 时一个 chunk 都没跨线
                        #     ② 数据在 warm 期内全部收完 (小样本 + 快节点)
                        #   结果: 下到 10MB 也被判"样本不足(10485760B/8s)" (#68 实测 90 个)。
                        #   现在改为: 一旦已过热身时刻, 当前这个 chunk 无条件建立稳态起点。
                        if t_steady is None and now >= t_warmup_end:
                            t_steady = now
                        if t_steady is not None:
                            steady_bytes += len(chunk)
                        downloaded += len(chunk)
                        last_chunk_time = now
                    # 总预算超限 → 正常截断 (拿已有数据算吞吐)
                    if now - t_start > budget:
                        break
                    # 空闲超限无任何数据 → 断流签名, 立即中止
                    if now - last_chunk_time > idle_timeout:
                        break
            # 样本量判定: 只要拿到过数据就够算速率 (min_bytes 兜底防虚高瞬时值)。
            # ★ 若 t_steady 仍为 None (预算在热身期内耗尽), 降级用"总下载量/总耗时"计算 ——
            #   宁可给一个偏保守的估计, 也不要把已下过 MB 级数据的节点误判成"样本不足"。
            if t_steady is None:
                if downloaded >= min_bytes:
                    elapsed_fallback = max(time.time() - t_first, 0.001) if t_first else 1.0
                    bps_fallback = int(downloaded / elapsed_fallback)
                    if with_ttfb:
                        return bps_fallback, int((t_first - t_start) * 1000), "热身期耗尽(降级估算)"
                    return bps_fallback, "热身期耗尽(降级估算)"
                fail_reason = f"样本不足({downloaded}B/{budget:.0f}s)"
                continue
            if downloaded < min_bytes:
                fail_reason = f"样本不足({downloaded}B/{budget:.0f}s)"
                continue
            elif not fail_reason:
                fail_reason = ""      # 成功: 清掉前一个端点留下的原因
            elapsed = max(time.time() - t_steady, 0.001)
            steady_bytes = max(steady_bytes, 1)
            bps = int(steady_bytes / elapsed)
            if with_ttfb:
                return bps, int((t_first - t_start) * 1000), fail_reason
            return bps, fail_reason
        except Exception as e:
            # 异常也要归因 (超时/连接重置/DNS 失败…) — 静默 continue 是 #67 无法定位的元凶
            fail_reason = type(e).__name__
            continue
    # 全部端点失败 → 返回 0 + 最后一次失败原因
    if with_ttfb:
        return 0, 0, (fail_reason or "未知")
    return 0, (fail_reason or "未知")


def measure_packet_loss(proxies: dict, probe_count: int = LOSS_PROBE_COUNT) -> float:
    """丢包率探测 → 返回 0.0~1.0 的失败比例 (0 = 全通)

    ★ 为什么必须测: 现有判定只看延迟, 完全没测丢包。但跨太平洋链路的核心问题
      恰恰是丢包 —— 一个 80ms 但丢包 15% 的节点, 体感远差于 300ms 但丢包 0.2% 的节点。
      延迟测的是"能不能通", 丢包测的是"通得稳不稳", 两者不可互相替代。

    实现: 复用已有的 204 探针 (零额外带宽成本, 每次只请求 1 个 204 空响应),
    连发 probe_count 次统计失败比例。任一源成功即算通 (换源轮询, 避免单源
    故障被误判成节点丢包)。

    ★ 耗时说明: 窄超时 LOSS_PROBE_TIMEOUT 是最坏值, 失败时才占满;
      正常通的节点每次仅 RTT 级别 (百毫秒), 5 次合计通常 < 1s。
      这是丢包探测必须在测速**之后**做 (speed_bps>0 才跑) 的另一个理由:
      已经断流的节点没必要再花时间验证它稳不稳。
    """
    if probe_count <= 0:
        return 0.0
    ok = 0
    for i in range(probe_count):
        name, url, expect = LIVENESS_PROBES[i % len(LIVENESS_PROBES)]
        try:
            r = PROBE_SESSION.get(url, proxies=proxies, timeout=LOSS_PROBE_TIMEOUT,
                                  allow_redirects=False)
            if r.status_code in expect:
                ok += 1
        except Exception:
            continue
    return (probe_count - ok) / float(probe_count)


def _is_speed_shortcircuit(speed_bps: int, speed_retest: int,
                          ttfb_ms: int, retest_failed: bool) -> bool:
    """判定 Cloudflare 测速结果是否"疑似短路" (即数字可能来自 CDN 边缘而非节点真实带宽)

    返回 True = 疑似短路, 需要启动物理机房端点做交叉验证;
         False = 结果可信, 直接采用, 不进交叉 (省掉每节点 5~8 秒开销)。

    ★ 为什么要有这个判断: Actions runner 与 Cloudflare 边缘节点常常同机房/近缘,
      speed.cloudflare.com 测出的是"内网带宽" (实测 #65 中位 7.1MB/s / 最快 29MB/s,
      物理上不可能是真实跨境带宽)。而无条件跑物理机房交叉测速代价极大:
      每节点额外 5~8 秒, 且跨大西洋链路本身慢, 端点常因样本不足/超时失败 →
      正常节点被误判不稳 (#68 交叉测速采信 0/297 即此因)。

    三个短路信号 (命中任一即触发):
      ① 首测速度 > SHORTCUT_ABS_MAX: 高得不合常理
      ② 复测/首测 < SHORTCUT_DROP_RATIO: 复测掉得太多, 首测可能是 CDN 缓存突发
      ③ 复测未通过: 只在 Cloudflare 端点测到, 换端点就抓瞎
    刻意**不做**的判断: 不因为"速度慢"而触发 —— 慢节点恰恰是真实问题,
    交叉测速对它们没有额外信息, 不该再花时间。
    """
    if speed_bps <= 0:
        return False                       # 根本没测到速度 → 无从判断短路
    if speed_bps > SHORTCUT_ABS_MAX:
        return True                        # 信号①
    if retest_failed:
        return True                        # 信号③
    if speed_retest > 0 and speed_retest < speed_bps * SHORTCUT_DROP_RATIO:
        return True                        # 信号②
    return False


def test_single_node(item, keep_alive_check=True):
    """返回 dict 或 None; 含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM"""
    raw, outbound, server, port, proto = item
    socks_port = _alloc_socks_port()
    task_id = uuid.uuid4().hex[:10]
    cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

    # ★ 链式前置 (chain relay): 注入已验证存活节点作前置 (chain_retest 用, 模拟 v2rayN 链式)
    chain_out = None
    chain_json = os.environ.get("CHAIN_RELAY_OUT", "").strip()
    if chain_json:
        try:
            chain_out = json.loads(chain_json)
        except Exception:
            chain_out = None
    config = build_test_config(outbound, socks_port, chain_relay=chain_out)
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f)

    exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

    # --- 0) sing-box check 预校验: 快速淘汰 schema 错误 (实测可发现 2022 密钥长度/端口区间等错误) ---
    try:
        chk = subprocess.run([exe, "check", "-c", cfg_path],
                             capture_output=True, text=True, timeout=15,
                             creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
        if chk.returncode != 0:
            return None  # 配置级错误 → 该节点无法被 sing-box 使用, 必淘汰
    except Exception:
        pass  # check 本身失败不阻止后续 run 尝试

    proc = None
    result = None
    try:
        proc = subprocess.Popen(
            [exe, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
        )
        # 等 SOCKS 端口就绪 (主动探测而非盲 sleep — 修复旧版误杀)
        deadline = time.time() + 6
        ready = False
        while time.time() < deadline:
            if proc.poll() is not None:
                break  # 进程崩溃 (配置错误/端口冲突)
            try:
                with socket.create_connection(("127.0.0.1", socks_port), timeout=0.4):
                    ready = True
                    break
            except Exception:
                time.sleep(0.15)
        if not ready:
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测: 跨源多探针 (Google/Cloudflare/Microsoft), 至少 MIN_LIVENESS_HITS 源通过 ---
        #     延迟按"每次尝试各自计时"取最快一次, 不用跨尝试的累计时间:
        #     旧版 t0 在循环外, 若首击耗满 12s 才失败、第二个 URL 秒通,
        #     latency 会记成 ~12s 而非真实 RTT → 去重/排序全被污染 (慢节点反被优先)
        #     ★ 不再 break: 三个源都要探完, 才能识别"只对单源通"的选择性转发节点
        #     (提前 break 会漏判 — 第一个源通就直接判活, 等于退回旧版的宽松标准)
        alive_hits, latency_ms = 0, 99999
        for i, (probe_name, url, expect) in enumerate(LIVENESS_PROBES):
            timeout = PROBE_TIMEOUT if i == 0 else PROBE_RETRY_TIMEOUT
            t_try = time.time()
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout, allow_redirects=False)
                if r.status_code in expect:
                    alive_hits += 1
                    latency_ms = min(latency_ms, (time.time() - t_try) * 1000)
                else:
                    # 该源明确拒绝 (403/407/302 等) = 选择性转发, 但不直接判死,
                    # 交给 MIN_LIVENESS_HITS 裁决
                    pass
            except Exception:
                continue
        if alive_hits < MIN_LIVENESS_HITS:
            return None
        # 延迟上限门槛: 活性过了但延迟过高的节点体验极差, 此前延迟只排序不淘汰
        if latency_ms > MAX_LATENCY_MS:
            return None

        # --- 2) 真实出口 IP (多路冗余) ---
        exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = None, None, None, None, None
        for url in IP_ECHO_URLS:
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                if r.status_code != 200:
                    continue
                j = r.json()
                ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                if not ip:
                    continue
                exit_ip = ip
                if url.startswith("https://api.ip.sb"):
                    exit_country = j.get("country_code")
                    exit_asn = j.get("asn")
                    exit_asn_org = (j.get("asn_organization") or j.get("organization") or "")
                    exit_isp = (j.get("isp") or j.get("organization") or "")
                elif url.startswith("https://ipinfo.io"):
                    exit_country = exit_country or (j.get("country") or "").upper()
                    org = j.get("org") or ""
                    if org and not exit_asn:
                        mm = re.match(r"^AS(\d+)\s+(.*)", org)
                        if mm:
                            exit_asn, exit_asn_org = int(mm.group(1)), mm.group(2)
                    exit_isp = exit_isp or org
                elif "ip-api.com" in url:
                    exit_country = exit_country or (j.get("countryCode") or "").upper()
                    exit_asn = exit_asn or j.get("as")
                    exit_asn_org = exit_asn_org or j.get("asname") or j.get("org") or ""
                    exit_isp = exit_isp or j.get("isp") or j.get("org") or ""
                break
            except Exception:
                continue

        # --- 3) MITM 劫持检测 (轻量: 复用活性首击的 gstatic 请求已验证证书链) ---
        # 3a) 独立复检一次带 verify=True 的请求: SSLError = TLS 拦截
        mitm_risk = False
        try:
            r = PROBE_SESSION.get("https://www.gstatic.com/generate_204", proxies=proxies,
                                  timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code in (204, 200):
                mitm_risk = False
            else:
                mitm_risk = r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
        except requests.exceptions.SSLError:
            # 证书链验证失败 = TLS 拦截 (MITM) 或劣质自签劫持
            mitm_risk = True
        except Exception:
            pass  # 网络层失败不算 MITM (活性探测已通过)

        # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 降权标记) — 4s 窄超时
        is_warp = False
        try:
            r = PROBE_SESSION.get(TRACE_URL, proxies=proxies, timeout=PROBE_RETRY_TIMEOUT, verify=True)
            if r.status_code == 200:
                if re.search(r"^warp=on", r.text, re.M):
                    is_warp = True
        except Exception:
            pass

        # --- 4) 断流检测: 限时下载测速 (稳态吞吐, 剔除握手期; 端点多路兜底) ---
        #     with_ttfb=True 同时取首包时间 (与握手 RTT 互补, 见下方 TTFB 判定)
        speed_bps, ttfb_ms, speed_fail = measure_download_speed(
            proxies, SPEED_TEST_URLS, SPEED_TEST_BUDGET, SPEED_WARMUP, with_ttfb=True)

        # --- 4b) 二次复测 (稳定性闸): 1MB 小样本, 与首测取最小值 ---
        #   动机: 单轮测速会被 CDN 缓存层 / TCP 突发流量骗过 (瞬时冲高后断流)。
        #   复测明显掉速 → 首测虚高, 取小值入库。
        #   ★ 2026-10-04 修正 (#67 事故): 旧版"复测完全失败 → speed_bps=0 直接判死"。
        #     复测只有 1MB 样本 / 4 秒预算, 本身失败率高 (端点抖动、超时、样本不足),
        #     把"复测没测出来"等同于"节点已断流"会产生大量误杀。
        #     现在改为: 复测失败只标记 retest_failed, 保留首测结果继续判定。
        #     真正断流的节点在首测(5MB/8秒)就已被 SPEED_MIN_BYTES_PER_S 卡掉。
        speed_retest = 0
        retest_failed = False
        retest_fail_reason = ""
        speed_unstable = False
        if speed_bps > 0:
            speed_retest, retest_fail_reason = measure_download_speed(
                proxies, SPEED_RETEST_URLS, SPEED_RETEST_BUDGET, SPEED_RETEST_WARMUP)
            if speed_retest <= 0:
                # 复测没测出来 ≠ 节点不可用。保留首测值, 仅标记供排查
                retest_failed = True
            else:
                if speed_retest < speed_bps:
                    # 掉速超过 (1 - STABLE_RATIO) → 标记不稳定, 门槛上浮惩罚
                    if speed_retest < speed_bps * SPEED_STABLE_RATIO:
                        speed_unstable = True
                    speed_bps = min(speed_bps, speed_retest)

        # --- 4c) 跨端点交叉测速 (按需触发: 仅当 Cloudflare 测速疑似短路时才启动) ---
        #   ★ 2026-10-04 改造 (原无条件触发 → 按需触发):
        #     旧逻辑对每个 speed_bps>0 的节点都跑一遍物理机房交叉测速, 带来两个问题:
        #       ① 耗时: 每节点额外 5~8 秒, 2500 节点就是 3~5 小时;
        #       ② 误判: 跨大西洋链路本身就慢, 物理机房端点常因"样本不足/超时"失败,
        #          明明 CDN 测速正常的节点被拖成不稳 (#68 交叉测速采信 0/297 的根因)。
        #     现改为: Cloudflare 测速结果若**正常**(未触发短路特征)就直接采用, 不进交叉;
        #     只有出现"疑似短路"特征(见 _is_speed_shortcircuit)才启动物理机房端点复算。
        #   取最小值 = 用户实际能拿到的最差体验 (对 CF 快但对物理机房慢的
        #     "特供节点"会被拉回真实水平)。
        #   逐个回退: 某端点不通就顺次试下一个, 直到拿到有效结果;
        #   失败的端点按名字记入 cross_fail_names, 便于回查是端点故障还是节点问题。
        speed_cross = 0
        cross_results = []                # [(端点名, 速度)] 首个成功端点即停
        cross_fail_names = []
        cross_fail_reasons = []
        cross_all_failed = False
        cross_skipped = False          # 未触发短路 → 正常放行, 未做交叉
        # 先判定 Cloudflare 结果是否疑似短路 (只在有结果时才可能短路)
        shortcircuit = _is_speed_shortcircuit(speed_bps, speed_retest,
                                             ttfb_ms, retest_failed)
        if speed_bps > 0 and SPEED_CROSS_URLS and shortcircuit:
            # 逐个回退 + 熔断: 已熔断的端点直接跳过(不浪费预算), 成功的即采用
            tried = 0
            for idx_ep, (ep_name, ep_url) in enumerate(SPEED_CROSS_URLS[:SPEED_CROSS_MAX_ENDPOINTS]):
                # ★ 熔断检查: 连续失败达阈值的端点本轮不再尝试。
                #   #70 教训: hetzner-ash 543 次尝试零成功, 每次都白耗 8 秒预算才回退,
                #   543÷24并发 ≈ 3 分钟纯浪费。熔断后约 20 次失败即摘除, 秒级生效。
                if not _ep_available(ep_name):
                    continue
                budget = (SPEED_CROSS_BUDGET if idx_ep < SPEED_CROSS_SAME_REGION
                          else SPEED_CROSS_BUDGET_FAR)
                # ★ 用更宽松的样本下限 (SPEED_CROSS_MIN_BYTES=50KB, 主测速是200KB):
                #   物理机房跨大西洋链路慢, 拿不到 200KB 就会被误判"端点不通",
                #   导致本可采信的交叉结果丢失 (#68 采信 0/297 的直接原因之一)
                b, ep_fail = measure_download_speed(proxies, [ep_url], budget,
                                                   SPEED_CROSS_WARMUP,
                                                   range_bytes=SPEED_CROSS_RANGE_BYTES,
                                                   min_data_bytes=SPEED_CROSS_MIN_BYTES)
                tried += 1
                _ep_record(ep_name, b > 0)
                if b > 0:
                    cross_results.append((ep_name, b))
                    # ★ 只取第一个成功端点即可判定 —— 目的是"用物理机房校准 CDN 虚高",
                    #   不是多端点横向比较。多测一个端点多花几秒, 收益极小。
                    break
                cross_fail_names.append(ep_name)
                cross_fail_reasons.append(f"{ep_name}:{ep_fail}")
            if cross_results:
                speed_cross = min(b for _, b in cross_results)
                if speed_cross < speed_bps:
                    # 物理机房测出的速度远低于 CDN 测速 → 证实 CDN 数字虚高
                    if speed_cross < speed_bps * SPEED_STABLE_RATIO:
                        speed_unstable = True
                    speed_bps = speed_cross
            else:
                # 全部物理机房端点都不通 (或全部已熔断) → 归因判定, 不再重试端点
                # ★ 边界处理: 保留 Cloudflare 首测结果, 不做任何惩罚。
                #   理由: 端点全挂更可能是端点侧问题(物理机房从 Actions 不可达,
                #   或全部端点已被熔断), 此时用首测值只是"可能偏高",
                #   而判死则会造成真活 0 (#67/#68 教训)。
                cross_all_failed = True
        else:
            # 未触发短路 (或无结果) → 不做交叉, 直接采用 Cloudflare 测速值
            cross_skipped = True

        # --- 5) 丢包率探测 (抓抖动/丢包严重的节点) ---
        #   复用 204 探针连发 LOSS_PROBE_COUNT 次, 零额外带宽成本。
        #   延迟测"能不能通", 丢包测"通得稳不稳" — 跨太平洋链路的核心问题是丢包,
        #   现有判定对此完全失明。
        #   ★ 2026-10-04 修正 (#67 事故): 旧版写 `else 1.0`, 把"没测到丢包"直接
        #     等同于"100% 丢包", 于是 speed_bps=0 的节点全被判死, 造成
        #     **真活 0** (实测 #67: 480 个节点全被填 100% 丢包后判死,
        #      而 TTFB 中位 634ms 明明证明隧道是通的)。
        #     现在用 None 表示"未测", 判定时跳过丢包维度, 交由吞吐门槛裁决。
        loss_rate = measure_packet_loss(proxies, LOSS_PROBE_COUNT) if speed_bps > 0 else None
        # 丢包 ≥ MAX_LOSS_RATE → 不可用; LOSS_UNSTABLE_PENALTY~MAX 之间 → 不稳
        # ★ None (未测) 不参与任何丢包判定, 绝不能当成丢包
        loss_unstable = (loss_rate is not None
                         and LOSS_UNSTABLE_PENALTY <= loss_rate < MAX_LOSS_RATE)
        if loss_rate is not None and loss_rate >= MAX_LOSS_RATE:
            speed_bps = 0            # 判死: 走下面 is_stalled 统一出口

        # --- 6) 首包时间 (TTFB) 判定 ---
        #   latency 是握手 RTT, TTFB 是"服务器开始回数据" —— 两者背离时
        #   (RTT 低但 TTFB 高) 用户体感是"点了没反应"。超上限直接淘汰;
        #   偏慢但未超限视为响应迟钝, 叠加门槛惩罚。
        ttfb_slow = ttfb_ms > TTFB_SLOW_MS
        if ttfb_ms > MAX_TTFB_MS:
            speed_bps = 0

        # 断流判定: 稳态吞吐达不到门槛 → 断流/极慢, 真实不可用
        # 不稳定节点门槛上浮: 复测掉速 / 复测失败 / 交叉落差 / 丢包 / TTFB 迟钝, 累乘。
        # ★ 必须设上限: 多项全中会累乘到 1.5^5, 门槛 200KB/s 被推得过高,
        #   把"只是有点抖但本来很快"的节点全砍掉, 过严反失真。
        # ★ retest_failed 也计入惩罚: 复测没通过说明链路有一定不确定性,
        #   但**不再直接判死** (P3 的核心修复)。
        penalty = 1.0
        if speed_unstable:
            penalty *= SPEED_UNSTABLE_PENALTY
        if retest_failed:
            penalty *= SPEED_UNSTABLE_PENALTY
        if loss_unstable:
            penalty *= SPEED_UNSTABLE_PENALTY
        if ttfb_slow:
            penalty *= TTFB_UNSTABLE_PENALTY
        penalty = min(penalty, MAX_SPEED_PENALTY)
        speed_threshold = int(SPEED_MIN_BYTES_PER_S * penalty)
        is_stalled = speed_bps < speed_threshold
        is_premium = speed_bps >= SPEED_TIER_GOOD and not is_stalled

        result = {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            "alive": True,
            "alive_hits": alive_hits,
            "latency_ms": int(latency_ms),
            "exit_ip": exit_ip,
            "exit_country_online": exit_country,
            "exit_asn_online": exit_asn,
            "exit_asn_org_online": (exit_asn_org or "")[:120],
            "exit_isp_online": (exit_isp or "")[:120],
            "mitm_risk": mitm_risk,
            "is_warp": is_warp,
            "speed_bps": speed_bps,
            "speed_retest_bps": speed_retest,
            "retest_failed": retest_failed,          # 复测没测出来 (≠ 节点断流)
            "retest_fail_reason": retest_fail_reason,
            "speed_fail_reason": speed_fail,          # 主测速失败原因 (HTTP403/超时/样本不足)
            "speed_cross_bps": speed_cross,
            "cross_fail_names": cross_fail_names,        # 失败端点名, 便于回查
            "cross_fail_reasons": cross_fail_reasons,    # 失败端点+原因
            "cross_all_failed": cross_all_failed,        # 全部非CF端点不通 → 问题在节点
            "cross_skipped": cross_skipped,              # 未触发短路, 未做交叉
            "speed_shortcircuit": shortcircuit,          # 是否判定为疑似短路
            "speed_unstable": speed_unstable,
            "ttfb_ms": ttfb_ms,
            "ttfb_slow": ttfb_slow,
            "loss_rate": loss_rate,
            "loss_unstable": loss_unstable,
            "is_premium": is_premium,
            "is_stalled": is_stalled,
        }
        return result
    except Exception:
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except OSError:
            pass


def _apply_speed_sanity_guard(results: list) -> bool:
    """测速健全性护栏: 中位数过高则判定测速环境被短路, 撤销所有优选标记

    返回 True = 环境可信, False = 环境被短路(已撤销优选标记)。

    ★ 为什么必须做 (实测 #65 的教训):
      Azure runner 与 Cloudflare 边缘节点常常同机房/近缘, speed.cloudflare.com
      测出的是"内网带宽"。实测中位 7MB/s、最快 29MB/s, 76% 节点被标⚡优选。
      这类假速度最坏的地方不是标错等级, 而是让人误以为"已经筛过了"——
      实际上 200KB/s 门槛对 7MB/s 的中位数来说形同虚设。

    ★ 只撤销"优选"分档, 不动淘汰判定:
      即使测速偏高, 200KB/s 的**相对**比较仍有意义(快的确实比慢的快),
      而丢包率/TTFB 完全不受测速失真影响(它们不走 CDN 测速路径)。
      所以只撤销 is_premium 这个最容易被误读的标记。
    """
    speeds = sorted(r["speed_bps"] for r in results if r.get("speed_bps", 0) > 0)
    if len(speeds) < SANITY_CHECK_MIN_SAMPLES:
        print(f"[+] 测速样本仅 {len(speeds)} 个 (<{SANITY_CHECK_MIN_SAMPLES}), "
              f"跳过健全性检查")
        return True
    median = speeds[len(speeds) // 2]
    if median <= SANITY_MEDIAN_MAX:
        print(f"[+] 测速健全性: 中位 {median//1024}KB/s (阈值 "
              f"{SANITY_MEDIAN_MAX//1024}KB/s) — 环境可信, 优选分档有效")
        return True
    # 环境被短路 → 撤销全部优选标记
    revoked = 0
    for r in results:
        if r.get("is_premium"):
            r["is_premium"] = False
            r["speed_sanity_suspect"] = True
            revoked += 1
    print(f"[!] 测速健全性告警: 中位 {median//1024}KB/s 超过阈值 "
          f"{SANITY_MEDIAN_MAX//1024}KB/s")
    print(f"    → 判定测速环境被短路 (CDN 边缘节点/Actions 同区导致虚高), "
          f"撤销 {revoked} 个⚡优选标记")
    print(f"    → 淘汰判定仍有效 (相对比较有意义); 丢包率/TTFB 不受影响")
    return False


def run_liveness_test(candidates: list) -> list:
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    done_count = [0]
    # 端点熔断状态按轮次重置 —— 端点可达性会随时间漂移, 不跨轮沿用
    _reset_endpoint_breaker()

    def _work(item):
        return test_single_node(item)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r = fut.result()
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, 通过 {len(results)}")

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    unstable = sum(1 for r in results if r.get("speed_unstable"))
    premium = sum(1 for r in results if r.get("is_premium"))
    speeds = sorted((r["speed_bps"] for r in results if r["speed_bps"] > 0), reverse=True)
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} | MITM 风险 {mitm}")

    # ★ 2026-10-04 新增: 测速失败原因归集 (#67 事故时只能看到"最快 0KB/s",
    #   无法判断是端点 403 / 超时 / 样本不足 / 断流)。现在一眼能看出瓶颈在哪一环。
    sp_fail = Counter()
    for r in results:
        if r.get("speed_bps", 0) <= 0 and r.get("speed_fail_reason"):
            sp_fail[r["speed_fail_reason"]] += 1
    if sp_fail:
        top = " | ".join(f"{k}:{v}" for k, v in sp_fail.most_common(6))
        print(f"    测速失败原因 (共 {sum(sp_fail.values())} 个): {top}")
    rt_fail = sum(1 for r in results if r.get("retest_failed"))
    if rt_fail:
        rt_why = Counter(r.get("retest_fail_reason", "?")
                         for r in results if r.get("retest_failed"))
        why = " | ".join(f"{k}:{v}" for k, v in rt_why.most_common(4))
        print(f"    复测未通过 {rt_fail} 个 (已保留首测值, 计入门槛惩罚×1.5): {why}")
    print(f"[+] 吞吐分布 (门槛 {SPEED_MIN_BYTES_PER_S//1000}KB/s): "
          f"优选≥{SPEED_TIER_GOOD//1000}KB/s {premium} | 复测不稳 {unstable} | "
          f"最快 {speeds[0]//1000 if speeds else 0}KB/s | "
          f"中位 {speeds[len(speeds)//2]//1000 if speeds else 0}KB/s")
    lats = sorted(r["latency_ms"] for r in results if r["latency_ms"] < 99999)
    if lats:
        print(f"[+] 延迟分布 (上限 {MAX_LATENCY_MS}ms): "
              f"最快 {lats[0]:.0f}ms | 中位 {lats[len(lats)//2]:.0f}ms | "
              f"最慢 {lats[-1]:.0f}ms")
    # 记录探针命中数分布, 便于评估跨源门槛 (2 = 三源取二通过)
    hit_dist = {}
    for r in results:
        hit_dist[r.get("alive_hits", 0)] = hit_dist.get(r.get("alive_hits", 0), 0) + 1
    print(f"[+] 跨源命中分布 (需≥{MIN_LIVENESS_HITS}): "
          + " | ".join(f"{k}源:{v}" for k, v in sorted(hit_dist.items())))
    # 新增三维度统计
    ttfb = sorted(r.get("ttfb_ms", 0) for r in results if r.get("ttfb_ms", 0) > 0)
    if ttfb:
        print(f"[+] 首包 TTFB (上限 {MAX_TTFB_MS}ms): "
              f"最快 {ttfb[0]}ms | 中位 {ttfb[len(ttfb)//2]}ms | 最慢 {ttfb[-1]}ms")
    # ★ 只统计真正测过丢包的节点 (loss_rate is not None);
    #   "未测" 数量单独报出, 避免再次出现 #67 那种"全是100%丢包"的误判假象
    losses = sorted(r["loss_rate"] for r in results
                    if r.get("loss_rate") is not None)
    untested = sum(1 for r in results if r.get("loss_rate") is None)
    if losses:
        zero_loss = sum(1 for v in losses if v == 0)
        tail = f" | 未测 {untested}" if untested else ""
        print(f"[+] 丢包率 (淘汰线 {MAX_LOSS_RATE:.0%}, 已测 {len(losses)} 个): "
              f"零丢包 {zero_loss} | "
              f"中位 {losses[len(losses)//2]:.0%} | 最差 {losses[-1]:.0%}{tail}")
    elif untested:
        print(f"[+] 丢包率: 全部未测 ({untested} 个) — 无节点通过吞吐门槛, 该维度跳过")
    # 交叉测速生效判定 (按需触发: 仅疑似短路的节点才进交叉)
    cross_used = [r for r in results if r.get("speed_cross_bps", 0) > 0]
    cross_lowered = sum(1 for r in cross_used
                        if r.get("speed_cross_bps", 0) < r.get("speed_retest_bps", 0) or
                        r.get("speed_cross_bps", 0) < r.get("speed_bps", 0))
    sc_count = sum(1 for r in results if r.get("speed_shortcircuit"))
    sc_used = sum(1 for r in results if r.get("speed_shortcircuit") and r.get("speed_cross_bps", 0) > 0)
    print(f"[+] 交叉测速 (按需触发, 仅疑似短路才跑物理机房端点): "
          f"疑似短路 {sc_count}/{len(results)} | 交叉成功 {sc_used} | 被最小值拉低 {cross_lowered}")
    if sc_count == 0:
        print(f"    → 无节点触发短路特征, 全部直接采用 Cloudflare 测速值 (省掉每节点 5~8s)")
    # 端点级失败归因: 哪个端点老失败 = 该端点/线路有问题; 全失败 = 节点自身问题
    ep_fail = Counter()
    for r in results:
        for nm in r.get("cross_fail_names") or []:
            ep_fail[nm] += 1
    if ep_fail:
        ep_order = [nm for nm, _ in SPEED_CROSS_URLS]
        detail = " | ".join(f"{nm}:{ep_fail.get(nm, 0)}" for nm in ep_order)
        print(f"    端点失败次数 (按尝试序): {detail}")
        # 失败原因 Top 归集 — 区分"端点挂了(HTTP403/超时)"与"节点到不了(样本不足)"
        ep_why = Counter()
        for r in results:
            for item in r.get("cross_fail_reasons") or []:
                ep_why[item] += 1
        if ep_why:
            print(f"    端点失败原因 Top5: "
                  + " | ".join(f"{k}:{v}" for k, v in ep_why.most_common(5)))
    # ★ 端点成功率: 直接反映哪个端点在 Actions 视角真正可用 (无失败时也要打印)。
    #   #70 就是靠这行才发现 hetzner-ash 是 0/543 (而非"慢")。
    #   下轮若某个端点被熔断, 这行会显示 "★已熔断", 无需人工翻日志找原因。
    print(f"    端点成功率 (本轮): {_ep_success_rates()}")
    all_fail = [r for r in results if r.get("cross_all_failed")]
    if all_fail:
        print(f"    [!] {len(all_fail)} 个节点对**全部** {len(SPEED_CROSS_URLS)} 个非CF端点"
              f"均不通 → 判定问题在节点/线路本身 (选择性转发或链路封锁), 已跳过剩余端点重试")
    # ── 方案1: 测速健全性护栏 (必须在全部节点测完后判断) ──
    #   实测 #65: Azure runner 上 Cloudflare 测出中位 7MB/s —— 那是 CDN 边缘节点
    #   造成的测速环境短路, 不是节点真实速度。若不处理, 76% 节点被标"⚡优选",
    #   优选标记完全失去筛选意义, 而用户会以为"已经筛过了"。
    #   做法: 看全体测速中位数, 过高即判定环境被短路 → 撤销所有优选标记。
    #   宁可漏标 (不标⚡) 也不误标 (标了假优选), 因为假优选会误导用户选择。
    sane = _apply_speed_sanity_guard(results)
    if not sane:
        # 环境被短路时, 预筛阶段把明显慢的节点筛掉仍然有效, 只撤销"优选"分档
        pass

    return results  # 保留全部信息, 分类阶段再决定去留


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 先跑一遍轻量分类拿到家宽候选 → 取最快存活节点做 relay →
    家宽候选逐个双跳复测 → 双跳也活的保留, 双跳死的降级普通区。
    返回: 更新 net_type 后的 test_results (原对象原地修改)。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 的节点
    ip_api_info = {}
    all_exit_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    if all_exit_ips:
        try:
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
        except Exception as e:
            print(f"[!] 链式复测: ip-api 批量失败 ({e}), 跳过链式复测")
            return test_results

    res_candidates = {}
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        rec = ip_api_info.get(r.get("exit_ip"), {})
        t, c = classify_network_type(r["exit_ip"], r.get("exit_country_online"),
                                     r.get("exit_asn_online"),
                                     r.get("exit_asn_org_online"), rec or None)
        if t in ("residential", "mobile") and c >= 60:
            res_candidates[(r["server"].lower(), r["port"], r["proto"])] = r

    if not res_candidates:
        print("[*] 链式复测: 无家宽候选, 跳过")
        return test_results
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选")

    # 2) 选 relay: 全体存活节点里延迟最低、非家宽候选自己 (避免自己套自己)
    alive_sorted = sorted(
        [r for r in test_results if r.get("alive") and not r.get("is_stalled")],
        key=lambda x: x.get("latency_ms", 99999))
    relay_result = None
    for r in alive_sorted:
        if (r["server"].lower(), r["port"], r["proto"]) not in res_candidates:
            relay_result = r
            break
    if not relay_result:
        print("[!] 链式复测: 无可用 relay 节点, 跳过")
        return test_results
    relay_out = relay_result.get("outbound")
    if not relay_out:
        # 重新解析 relay 的 raw 拿 outbound
        p = parse_node_uri(relay_result["raw"])
        if p:
            relay_out = p[0]
    if not relay_out:
        print("[!] 链式复测: relay outbound 构建失败, 跳过")
        return test_results
    # relay 必须剥离 detour (前置链复用时防循环)
    relay_out = dict(relay_out)
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选逐个双跳复测 (注入 CHAIN_RELAY_OUT, test_single_node 自动加 detour)
    os.environ["CHAIN_RELAY_OUT"] = json.dumps(relay_out)
    chain_alive, chain_dead = [], []
    try:
        for key, r in res_candidates.items():
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                chain_dead.append(r)
                continue
            recheck = test_single_node(item)
            if recheck and recheck.get("alive") and not recheck.get("is_stalled"):
                chain_alive.append(r)
            else:
                chain_dead.append(r)
    finally:
        os.environ.pop("CHAIN_RELAY_OUT", None)

    # 4) 双跳失败的 → 降级普通区 (不从订阅删除, 用户直连场景仍可能可用)
    for r in chain_dead:
        r["_chain_failed"] = True

    print(f"[+] 链式复测完成: 双跳可用 {len(chain_alive)} | 双跳失败降级 {len(chain_dead)}")
    return test_results


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 C: 出口 IP 批量情报 (ip-api.com 免费 batch) + 离线兜底
# ═══════════════════════════════════════════N═══════════════════════

def ip_api_batch_lookup(ip_list: list) -> dict:
    """ip-api.com batch (免费 HTTP, ≤100/req, 15 req/min → 1500 IP/min)"""
    info = {}
    session = requests.Session()
    session.trust_env = True  # 直连即可; ip-api.com 免费层全球可达 (CI 无代理/本地走系统代理均可)
    total_batches = (len(ip_list) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
    for bi, i in enumerate(range(0, len(ip_list), IP_API_BATCH_SIZE), 1):
        chunk = ip_list[i:i + IP_API_BATCH_SIZE]
        payload = [{"query": ip} for ip in chunk]
        for attempt in range(3):
            try:
                r = session.post(IP_API_BATCH_URL, json=payload, timeout=20)
                if r.status_code == 200:
                    for rec in r.json():
                        q = rec.get("query")
                        if q:
                            info[q] = rec
                    break
                elif r.status_code == 429:
                    time.sleep(4 + attempt * 3)
                else:
                    time.sleep(2)
            except Exception:
                time.sleep(2)
        if total_batches >= 3 and (bi % 5 == 0 or bi == total_batches):
            print(f"[*] ip-api 进度: 批 {bi}/{total_batches} ({len(info)} IP 已查)")
        time.sleep(IP_API_BATCH_RPS_INTERVAL)
    return info


def offline_ip_lookup(ip: str, country_reader, asn_reader) -> tuple:
    """GeoLite2 离线查询 → (country, asn, org)"""
    country, asn, org = None, None, None
    try:
        c = country_reader.get(ip)
        if c and c.get("country", {}).get("iso_code"):
            country = c["country"]["iso_code"]
    except Exception:
        pass
    try:
        a = asn_reader.get(ip)
        if a:
            asn = a.get("autonomous_system_number")
            org = a.get("autonomous_system_organization", "")
    except Exception:
        pass
    return country, asn, org


def get_rdns(ip: str) -> str:
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return ""
    finally:
        socket.setdefaulttimeout(old)


def classify_network_type(ip: str, country: str, asn, org: str, ip_api_rec: dict = None) -> tuple:
    """
    返回 (net_type, confidence):
      net_type ∈ {datacenter, residential, mobile, cdn, unknown}
    优先级: ip-api.com hosting/mobile 字段 > CDN 网段 > ASN 白/黑名单 > 名称关键词
    """
    ip_str = str(ip)
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return "unknown", 0

    # 1) CDN / Anycast 网段 (硬判据)
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return "cdn", 100
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return "cdn", 95

    asn_int = None
    if isinstance(asn, int):
        asn_int = asn
    elif isinstance(asn, str) and asn:
        m = re.match(r"AS(\d+)", asn)
        if m:
            asn_int = int(m.group(1))

    org_lower = (org or "").lower()
    hosting_flag = False
    mobile_flag = False
    proxy_flag = False

    # 2) ip-api.com 在线字段 (最高可信)
    if ip_api_rec:
        hosting_flag = bool(ip_api_rec.get("hosting"))
        mobile_flag = bool(ip_api_rec.get("mobile"))
        proxy_flag = bool(ip_api_rec.get("proxy"))
        rec_asn = ip_api_rec.get("as") or ""
        m = re.match(r"AS(\d+)", str(rec_asn))
        if m and asn_int is None:
            asn_int = int(m.group(1))
        org_lower = (ip_api_rec.get("asname") or ip_api_rec.get("org") or org_lower).lower()

    if hosting_flag:
        return "datacenter", 90
    # ★ proxy/VPN/Tor 出口标志 (ip-api) — 硬否决家宽/民用
    # 实测 AS62610 Zenlayer (收购 speakeasy DSL legacy 段): hosting=false 但 proxy=true
    # 此类"机房收购家宽段"是假家宽主要形态, rDNS 带 dsl/pppoe 也不能信
    if proxy_flag:
        return "datacenter", 88
    if mobile_flag:
        return "mobile", 85

    # 3) ASN 白/黑名单
    if asn_int:
        if asn_int in DATACENTER_ASNS:
            return "datacenter", 80
        if asn_int in RESIDENTIAL_ASNS:
            return "residential", 82

    # 4) ISP 名称关键词
    if org_lower:
        for kw in IDC_NAME_PATTERNS:
            if kw in org_lower:
                return "datacenter", 70
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in org_lower:
                return "residential", 70

    # 5) rDNS 兜底
    rdns = get_rdns(ip_str)
    if rdns:
        for kw in IDC_NAME_PATTERNS:
            if kw in rdns:
                return "datacenter", 60
        for kw in RESIDENTIAL_NAME_PATTERNS:
            if kw in rdns:
                return "residential", 60

    return "unknown", 30


# ═══════════════════════════════════════════N═══════════════════════
# 节点 → 各客户端配置转换
# ═══════════════════════════════════════════N═══════════════════════

def outbound_to_clash(node: dict, name: str) -> dict:
    """sing-box outbound → Clash (Meta/mihomo) proxy dict

    ★ 端口跳跃节点 (hy2 mport) 的 sing-box outbound 里没有 server_port
      (见 parse_hysteria2: 端口区间会 pop 掉 server_port), 直接 node["server_port"]
      会 KeyError: 'server_port' 崩掉整个导出流程 ——
      实测 #64 就死在这里 (新增订阅源带来大量 mport 节点, 把这个潜伏 bug 引爆了)。
      兜底逻辑与 outbound_to_v2ray_link 保持一致: 取 server_ports 首区间起始端口。
    """
    t = node.get("type")
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        # "2087:2097" → 2087 (取首个跳跃区间的起始端口作为代表)
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return {}          # 无端口信息 → 无法生成 clash 配置, 跳过该节点
    server = node["server"]
    proxy = {"name": name, "server": server, "port": port, "udp": True}

    if t == "vless":
        proxy["type"] = "vless"
        proxy["uuid"] = node["uuid"]
        if node.get("flow"):
            proxy["flow"] = node["flow"]
        tls = node.get("tls") or {}
        if tls.get("reality"):
            proxy["tls"] = True
            proxy["reality-opts"] = {"public-key": tls["reality"]["public_key"]}
            if tls["reality"].get("short_id"):
                proxy["reality-opts"]["short-id"] = tls["reality"]["short_id"]
            proxy["servername"] = tls.get("server_name") or server
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        elif tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
            if tls.get("utls"):
                proxy["client-fingerprint"] = tls["utls"].get("fingerprint", "chrome")
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
            elif transport["type"] == "httpupgrade":
                proxy["network"] = "httpupgrade"
                proxy["httpupgrade-opts"] = {"path": transport.get("path", "/"),
                                              "headers": {"Host": transport.get("host", "")}}
    elif t == "vmess":
        proxy["type"] = "vmess"
        proxy["uuid"] = node["uuid"]
        proxy["alterId"] = node.get("alter_id", 0)
        proxy["cipher"] = "auto"
        tls = node.get("tls") or {}
        if tls.get("enabled"):
            proxy["tls"] = True
            proxy["servername"] = tls.get("server_name") or server
            proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
                if transport.get("headers"):
                    proxy["ws-opts"]["headers"] = transport["headers"]
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
            elif transport["type"] == "http":
                proxy["network"] = "h2"
                proxy["h2-opts"] = {"host": transport.get("host", []),
                                    "path": transport.get("path", "/")}
    elif t == "trojan":
        proxy["type"] = "trojan"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        transport = node.get("transport") or {}
        if transport.get("type"):
            proxy["network"] = transport["type"]
            if transport["type"] == "ws":
                proxy["ws-opts"] = {"path": transport.get("path", "/")}
            elif transport["type"] == "grpc":
                proxy["grpc-opts"] = {"grpc-service-name": transport.get("service_name", "")}
    elif t == "shadowsocks":
        proxy["type"] = "ss"
        proxy["cipher"] = node["method"]
        proxy["password"] = node["password"]
    elif t == "hysteria2":
        proxy["type"] = "hysteria2"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        if node.get("obfs"):
            proxy["obfs"] = node["obfs"].get("type")
            proxy["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            proxy["ports"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
    elif t == "tuic":
        proxy["type"] = "tuic"
        proxy["uuid"] = node["uuid"]
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
        proxy["congestion-controller"] = node.get("congestion_control", "bbr")
        proxy["udp-relay-mode"] = node.get("udp_relay_mode", "native")
        if tls.get("alpn"):
            proxy["alpn"] = tls["alpn"]
    elif t == "anytls":
        proxy["type"] = "anytls"
        proxy["password"] = node["password"]
        tls = node.get("tls") or {}
        proxy["sni"] = tls.get("server_name") or server
        proxy["skip-cert-verify"] = bool(tls.get("insecure"))
    else:
        return None
    return proxy


def outbound_to_v2ray_link(node: dict, name: str) -> str:
    """sing-box outbound → v2rayN 兼容 URI"""
    t = node.get("type")
    # 端口跳跃节点 (hy2 mport): 无 server_port 时取 server_ports 首区间起始端口
    if "server_port" in node:
        port = node["server_port"]
    elif node.get("server_ports"):
        port = int(str(node["server_ports"][0]).split(":")[0])
    else:
        return ""
    server = node["server"]
    tls = node.get("tls") or {}
    transport = node.get("transport") or {}

    if t == "vmess":
        ttype = transport.get("type", "tcp")
        data = {
            "v": "2", "ps": name, "add": server, "port": str(port),
            "id": node["uuid"], "aid": str(node.get("alter_id", 0)),
            "scy": "auto", "net": ttype,
            "type": "none",
            "host": "", "path": "",
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if ttype == "ws":
            if transport.get("path"):
                data["path"] = transport["path"]
            if (transport.get("headers") or {}).get("Host"):
                data["host"] = transport["headers"]["Host"]
            if transport.get("max_early_data"):
                data["path"] = (data["path"] or "") + f"?ed={transport['max_early_data']}"
        elif ttype == "grpc":
            if transport.get("service_name"):
                data["path"] = transport["service_name"]
        elif ttype == "http":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = ",".join(transport["host"])
        elif ttype == "httpupgrade":
            if transport.get("path"):
                data["path"] = transport["path"]
            if transport.get("host"):
                data["host"] = transport["host"]
        # ★ 用 urlsafe_b64encode: 标准 base64 的 "+" "/" 在 URI 传输中会被中间层
        #   当成 query 的空格/分隔符 → 客户端解码直接失败 (实测 #65 有 27 个 vmess
        #   节点整条 URI 退化成 base64 串, 名称/配置全丢)。
        #   节点名含空格和 emoji 时 base64 极容易产生 "+", 必须 URL-safe。
        #   v2rayN / v2rayNG / Clash Verge 均同时支持两种变体, 无兼容风险。
        return "vmess://" + base64.urlsafe_b64encode(
            json.dumps(data, ensure_ascii=False).encode()).decode()
    if t == "vless":
        q = {}
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "http":
                if transport.get("host"):
                    q["host"] = ",".join(transport["host"])
                if transport.get("path"):
                    q["path"] = transport["path"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        if tls.get("reality"):
            q["security"] = "reality"
            q["pbk"] = tls["reality"]["public_key"]
            q["sid"] = tls["reality"].get("short_id", "")
            q["fp"] = (tls.get("utls") or {}).get("fingerprint", "chrome")
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
        elif tls.get("enabled"):
            q["security"] = "tls"
            if tls.get("server_name"):
                q["sni"] = tls["server_name"]
            if tls.get("alpn"):
                q["alpn"] = ",".join(tls["alpn"])
            if tls.get("utls"):
                q["fp"] = tls["utls"].get("fingerprint", "chrome")
            if tls.get("insecure"):
                q["allowInsecure"] = "1"
        if node.get("flow"):
            q["flow"] = node["flow"]
        query = urllib.parse.urlencode(q)
        return f"vless://{node['uuid']}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "trojan":
        q = {"security": "tls"}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("alpn"):
            q["alpn"] = ",".join(tls["alpn"])
        if (tls.get("utls") or {}).get("fingerprint"):
            q["fp"] = tls["utls"]["fingerprint"]
        if tls.get("insecure"):
            q["allowInsecure"] = "1"
        ttype = transport.get("type")
        if ttype:
            q["type"] = ttype
            if ttype == "ws":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if (transport.get("headers") or {}).get("Host"):
                    q["host"] = transport["headers"]["Host"]
                if transport.get("max_early_data"):
                    q["ed"] = str(transport["max_early_data"])
            elif ttype == "grpc":
                if transport.get("service_name"):
                    q["serviceName"] = transport["service_name"]
            elif ttype == "httpupgrade":
                if transport.get("path"):
                    q["path"] = transport["path"]
                if transport.get("host"):
                    q["host"] = transport["host"]
        query = urllib.parse.urlencode(q)
        return f"trojan://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "shadowsocks":
        # SIP002: userinfo = urlsafe-base64(method:password), ★ 必须保留 padding ("=")
        # 实测: rstrip("=") 砍 padding 后 v2rayN 解析失败 (无 padding 的畸形 base64)
        # urlsafe 字母表 (A-Za-z0-9-_) + "=" 均为 URI 合法字符, 不需再 quote (quote 反而破坏 "=")
        userinfo = base64.urlsafe_b64encode(
            f"{node['method']}:{node['password']}".encode()).decode()
        return f"ss://{userinfo}@{server}:{port}#{urllib.parse.quote(name)}"
    if t == "hysteria2":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        if node.get("obfs"):
            q["obfs"] = node["obfs"].get("type", "salamander")
            q["obfs-password"] = node["obfs"].get("password", "")
        if node.get("server_ports"):
            q["mport"] = ",".join(p.replace(":", "-") for p in node["server_ports"])
        query = urllib.parse.urlencode(q)
        return f"hysteria2://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "tuic":
        q = {
            "congestion_control": node.get("congestion_control", "bbr"),
            "udp_relay_mode": node.get("udp_relay_mode", "native"),
            "alpn": ",".join((tls.get("alpn") or ["h3"])),
        }
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["allow_insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"tuic://{urllib.parse.quote(node['uuid'])}:{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if t == "anytls":
        q = {}
        if tls.get("server_name"):
            q["sni"] = tls["server_name"]
        if tls.get("insecure"):
            q["insecure"] = "1"
        query = urllib.parse.urlencode(q)
        return f"anytls://{urllib.parse.quote(node['password'])}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    return ""


def outbound_to_singbox(node: dict, name: str) -> dict:
    n = dict(node)
    n["tag"] = name
    return n


# ═══════════════════════════════════════════N═══════════════════════
# 分类 + 导出
# ═══════════════════════════════════════════N═══════════════════════

def scamalytics_fraud_score(ip: str) -> int:
    """Scamalytics 免费风控评分 (HTML 抓取, subs-check 同款方案)
    返回 0-100: 越高越危险; 失败返回 -1 (不参与判定)"""
    try:
        r = DIRECT_SESSION.get(f"https://scamalytics.com/ip/{ip}", timeout=10)
        if r.status_code != 200:
            return -1
        m = re.search(r"Fraud Score:\s*(\d+)", r.text)
        return int(m.group(1)) if m else -1
    except Exception:
        return -1


def ipapi_is_verify(ip: str) -> dict:
    """ipapi.is 免费交叉源 (1000 req/天, 无 key)
    实测对 AS62610 Zenlayer (收购 speakeasy DSL 段伪装家宽) 能给出
    company=Bunny Communications; 对真家宽 (SK Broadband) 给运营商名。
    仅用其 company/asn 字段做家宽候选的二次否决。失败返回 {}"""
    try:
        r = DIRECT_SESSION.get(f"https://api.ipapi.is/?q={ip}", timeout=10)
        if r.status_code != 200:
            return {}
        j = r.json()
        return {"company": j.get("company") or "", "asn": j.get("asn") or "",
                "country": j.get("country") or ""}
    except Exception:
        return {}


def classify_and_export(test_results: list):
    print("[*] 出口 IP 情报与分类 ...")
    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    no_exit_ip = []
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = {}
    scam_scores = {}
    if all_exit_ips:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")

    country_reader = asn_reader = None
    try:
        country_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "Country.mmdb"))
        asn_reader = maxminddb.open_database(os.path.join(RUNTIME_DIR, "ASN.mmdb"))
    except Exception as e:
        print(f"[!] MaxMind 数据库打开失败: {e}")

    nodes = []
    for r in test_results:
        exit_ip = r["exit_ip"]
        online_country = r.get("exit_country_online")
        country = online_country
        asn, org = r.get("exit_asn_online"), r.get("exit_asn_org_online")
        if isinstance(asn, int):
            pass
        elif isinstance(asn, str):
            m = re.match(r"AS(\d+)", asn)
            asn = int(m.group(1)) if m else None

        # 在线情报缺失 → 离线 mmdb 兜底
        if country_reader and (not country or not asn):
            off_c, off_asn, off_org = offline_ip_lookup(exit_ip, country_reader, asn_reader)
            country = country or off_c
            asn = asn or off_asn
            org = org or off_org

        # ★ 出口 IP 查不到国家 (云内网/中转隧道) → 回退用入口服务器 IP 定位国家
        #    (中转节点出口常是内网地址, mmdb 也查不到; 入口国 ≠ 出口国但至少给用户可用地区)
        if (not country or country in ("OTHER", "ZZ")) and r.get("server"):
            srv_ip = r["server"] if is_ip_literal(r["server"]) else resolve_host(r["server"])
            if srv_ip and country_reader:
                off_c, srv_asn, srv_org = offline_ip_lookup(srv_ip, country_reader, asn_reader)
                if off_c and off_c not in ("OTHER", "ZZ"):
                    country = off_c
                    asn, org = asn or srv_asn, org or srv_org

        rec = ip_api_info.get(exit_ip, {})
        net_type, confidence = classify_network_type(
            exit_ip, country, asn, org, rec or None)

        # 无真实出口 IP 的节点: 国家未知, 不入家宽区
        if not exit_ip:
            country = country or "OTHER"

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            "country": (country or "OTHER").upper(),
            "net_type": net_type,
            "confidence": confidence,
            "exit_ip": exit_ip,
            "asn": asn,
            "org": org,
            "isp": r.get("exit_isp_online") or (rec.get("isp") if rec else ""),
            "latency_ms": r["latency_ms"],
            "speed_bps": r["speed_bps"],
            "speed_retest_bps": r.get("speed_retest_bps", 0),
            "speed_cross_bps": r.get("speed_cross_bps", 0),
            "speed_unstable": r.get("speed_unstable", False),
            "ttfb_ms": r.get("ttfb_ms", 0),
            "ttfb_slow": r.get("ttfb_slow", False),
            "loss_rate": r.get("loss_rate"),          # None = 未测 (非 0)
            "loss_unstable": r.get("loss_unstable", False),
            "retest_failed": r.get("retest_failed", False),
            "speed_fail_reason": r.get("speed_fail_reason", ""),
            "is_premium": r.get("is_premium", False),
            "mitm_risk": r["mitm_risk"],
            "is_warp": r.get("is_warp", False),
            "is_stalled": r["is_stalled"],
        })

    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # ── 风险过滤 ──
    # MITM 劫持节点: 高危, 直接丢弃 (204 能通但证书被劫持 = 中间人)
    safe_nodes = [n for n in nodes if not n["mitm_risk"]]
    mitm_dropped = len(nodes) - len(safe_nodes)
    # 断流节点已无 (在 liveness 阶段淘汰), 但 double-check
    safe_nodes = [n for n in safe_nodes if not n["is_stalled"]]
    print(f"[*] MITM 劫持高风险节点已剔除: {mitm_dropped}")

    # ── WARP 套壳节点过滤 (is_warp 此前算出却未接入任何判定, 这里正式生效) ──
    #   套壳节点出口 IP 属 Cloudflare, 国家/ISP/风控画像全部失真, 且流媒体场景常不可用
    warp_total = sum(1 for n in safe_nodes if n.get("is_warp"))
    if warp_total and WARP_POLICY == "drop":
        before = len(safe_nodes)
        safe_nodes = [n for n in safe_nodes if not n.get("is_warp")]
        print(f"[*] WARP 套壳节点已剔除 (WARP_POLICY=drop): {before - len(safe_nodes)}/{warp_total}")
    elif warp_total:
        print(f"[*] WARP 套壳节点: {warp_total} 个 (WARP_POLICY={WARP_POLICY}, 不淘汰仅标记)")

    # ── 落地国黑名单 (无条件剔除, 不论速度/延迟/是否家宽) ──
    #   判定用**出口 IP 归属国**(country 字段), 即用户实际落地位置, 而非入口
    #   server 的国家 —— 中转机在国内、落地在日本的节点同样要剔除。
    if BLOCK_COUNTRIES:
        blocked = {c.strip().upper() for c in BLOCK_COUNTRIES.split(",") if c.strip()}
        by_cc = Counter()
        kept, dropped = [], 0
        for n in safe_nodes:
            cc = (n.get("country") or "").upper()
            if cc in blocked:
                dropped += 1
                by_cc[cc] += 1
                continue
            kept.append(n)
        if dropped:
            detail = " ".join(f"{k}:{v}" for k, v in by_cc.items())
            print(f"[*] 落地国黑名单 {sorted(blocked)} 已剔除: {dropped} ({detail})")
        else:
            print(f"[*] 落地国黑名单 {sorted(blocked)}: 无命中")
        safe_nodes = kept

    # ── Scamalytics 风控评分 (免费 HTML, 逐个; 只查家宽候选 + 抽样普通节点) ──
    # 家宽候选: 全查 (宁缺毋滥); 普通节点: 每 IP 查一次 (通常 <= 出口 IP 数)
    scam_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            scam_candidates.add(n["exit_ip"])
    if scam_candidates:
        print(f"[*] Scamalytics 风控评分: 查询 {len(scam_candidates)} 个家宽候选出口 IP ...")
        def _scam(ip):
            return ip, scamalytics_fraud_score(ip)
        with ThreadPoolExecutor(max_workers=6) as ex:
            for ip, score in ex.map(_scam, scam_candidates):
                scam_scores[ip] = score
        got = sum(1 for v in scam_scores.values() if v >= 0)
        print(f"[+] Scamalytics 评分获得: {got}/{len(scam_candidates)}")

    # ── ipapi.is 交叉核验 (只查家宽候选, 免费 1000 次/天) ──
    # ip-api 判 hosting/proxy 也有漏 (伪装家宽: 收购 DSL 段的云边网络)。
    # ipapi.is 独立数据源: company 含 IDC 词 → 否决家宽
    ipapi_verify = {}
    verify_candidates = set()
    for n in safe_nodes:
        if n["net_type"] in ("residential", "mobile") and n["exit_ip"]:
            verify_candidates.add(n["exit_ip"])
    if verify_candidates:
        print(f"[*] ipapi.is 交叉核验: {len(verify_candidates)} 个家宽候选 ...")
        def _verify(ip):
            return ip, ipapi_is_verify(ip)
        with ThreadPoolExecutor(max_workers=4) as ex:
            for ip, info in ex.map(_verify, verify_candidates):
                ipapi_verify[ip] = info
        # 否决: company/asn 含机房词
        vetoed = 0
        for n in safe_nodes:
            if n["net_type"] not in ("residential", "mobile"):
                continue
            info = ipapi_verify.get(n["exit_ip"]) or {}
            comp_asn = (info.get("company", "") + " " + info.get("asn", "")).lower()
            if any(kw in comp_asn for kw in (
                "zenlayer", "bunny", "cloudflare", "akamai", "fastly",
                "amazon", "google llc", "microsoft", "digitalocean", "vultr",
                "hetzner", "ovh", "contabo", "leaseweb", "datacamp",
                "serverius", "clouvider", "m247", "gcore", "g-core",
                "choopa", "linode", "alibaba", "tencent", "huawei cloud",
            )):
                n["net_type"] = "datacenter"
                n["confidence"] = 85
                vetoed += 1
        if vetoed:
            print(f"[*] ipapi.is 否决假家宽: {vetoed} 个 (云商收购家宽段伪装)")

    # 风险分 >= 75 的家宽候选降级为普通 (fraud 池/被滥用 IP 绝不入家宽区)
    downgraded = 0
    for n in safe_nodes:
        sc = scam_scores.get(n["exit_ip"], -1)
        n["fraud_score"] = sc
        if n["net_type"] in ("residential", "mobile") and sc >= 75:
            n["net_type"] = "datacenter"  # 高 fraud 分: 大概率代理池滥用 IP
            n["confidence"] = 60
            downgraded += 1
    if downgraded:
        print(f"[*] 高 fraud 分 (≥75) 家宽候选降级: {downgraded} 个")

    # ── 去重 (同出口IP+端口 只留最优) ──
    #   ★ 旧版按 latency 最小者保留, 会把同一出口 IP 下**速度最快**的那个节点丢掉,
    #     只留下延迟最低但吞吐一般的 (排序键与用户实际体感脱节)。
    #   现改为: 速度达标者优先 → 速度相同取延迟更低 → 再相同取吞吐更高。
    #   延迟已在上游由 MAX_LATENCY_MS 兜底, 这里不需要再当主键。
    def _dedup_rank(n):
        spd = n.get("speed_bps", 0) or 0
        return (0 if spd >= SPEED_MIN_BYTES_PER_S else 1,      # 速度达标优先
                n["latency_ms"],                                 # 延迟次之
                -spd)                                            # 同延迟取吞吐更高

    best_by_key = {}
    for n in safe_nodes:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or _dedup_rank(n) < _dedup_rank(cur):
            best_by_key[key] = n
    unique_nodes = list(best_by_key.values())
    dup_dropped = len(safe_nodes) - len(unique_nodes)
    print(f"[*] 去重: {len(safe_nodes)} → {len(unique_nodes)} (剔除重复 {dup_dropped}, 保留速度最优)")

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    res_seen_ip = set()
    for n in unique_nodes:
        if n["net_type"] in ("residential", "mobile") and n["confidence"] >= 60:
            if n.get("raw") in chain_failed_raws:
                n["net_type"] = "datacenter"
                n["confidence"] = 70
                continue
            # WARP 套壳节点 (demote 模式): 出口 IP 属 Cloudflare, 归属地画像失真,
            # 绝不能进家宽专区 (会伪装成当地家宽), 降级为普通节点
            if n.get("is_warp") and WARP_POLICY != "off":
                n["net_type"] = "datacenter"
                n["confidence"] = 70
                continue
            if n["exit_ip"] and n["exit_ip"] not in res_seen_ip:
                res_seen_ip.add(n["exit_ip"])
                residential.append(n)
    # fraud 分极高 (≥90) 的节点整体剔除 (任何区都不要)
    before_total = len(unique_nodes)
    unique_nodes = [n for n in unique_nodes if not (0 <= n.get("fraud_score", -1) >= 90)]
    residential = [n for n in residential if not (0 <= n.get("fraud_score", -1) >= 90)]
    if len(unique_nodes) < before_total:
        print(f"[*] 极高危节点 (fraud≥90) 剔除: {before_total - len(unique_nodes)} 个")

    non_residential = [n for n in unique_nodes if n not in residential]
    print(f"[*] 家宽/移动网络节点: {len(residential)} | 普通(机房/CDN): {len(non_residential)}")

    # 排序: 家宽在前, 组内按"可用性综合分"升序
    #   ★ 旧版只按 latency 升序, 等于默认"延迟低 = 体验好"。但跨太平洋链路上
    #     丢包率和首包时间对体感的权重远大于延迟 —— 一个 80ms/丢包 15% 的节点
    #     排序会排在 300ms/零丢包 前面, 实际体验更差。
    #   综合分 = 延迟 + 丢包惩罚(每次丢失按 1500ms 计) + TTFB 的一半。
    def _quality_key(n):
        # ★ loss_rate 为 None 表示"未测丢包"(非 0 也非 100%), 按 0 参与排序,
        #   不能因为缺数据就把节点排到最末 (#67 事故衍生问题)
        loss = n.get("loss_rate") or 0.0
        ttfb = n.get("ttfb_ms", 0) or 0
        return (n["latency_ms"] + loss * 1500.0 + ttfb * 0.5)

    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, _quality_key(x)))
    residential.sort(key=_quality_key)
    non_residential.sort(key=_quality_key)
    # ★ 链式复测双跳失败的家宽 → 降级普通区 (v2rayN 链式场景不可靠)
    #    保留在总订阅/国家订阅里 (直连场景仍可用), 只是退出家宽专区

    # 重建 outbound (测活阶段的 outbound 已验证可用); 剥离测试专用字段 (detour 等绝不入订阅)
    for n in unique_nodes:
        parsed = parse_node_uri(n["raw"])
        if parsed:
            ob = parsed[0]
            ob.pop("detour", None)
            n["outbound"] = ob
        else:
            n["outbound"] = None

    return unique_nodes, residential, non_residential


def make_node_name(item, idx, force_residential=False):
    cc = item["country"]
    flag = get_country_flag(cc)
    cname = COUNTRY_NAMES.get(cc, cc)
    is_res = item["net_type"] in ("residential", "mobile") and (item["confidence"] >= 60 or force_residential)
    tag = ""
    if is_res:
        tag = " (家宽)" if item["net_type"] == "residential" else " (移动家宽)"
    # Scamalytics 风控分: 高风险节点名内标注 (R分数), 低危不标 (保持简洁)
    fraud = item.get("fraud_score", -1)
    risk_tag = f" R{fraud}" if 0 <= fraud < 75 and fraud >= 40 else (" ⚠R" if fraud >= 75 else "")
    # 吞吐标注: 优选级 (≥1MB/s) 标 ⚡; 不稳定 (复测掉速/交叉落差) 标 ⚠S; 其余标速率
    #   ★ 显示用 KB 整数 (B/s // 1024), 不再二次取整。旧写法对已经是 KB 的值
    #     做过 round(…, -1) 再拼 K, 导致 203776 B/s (合法过 200KB/s 门槛)
    #     显示成 "195K" 或 "199K", 看着像不达标 —— 实测 #65 的 "俄罗斯 199K"
    #     就是这么来的, 白排查一轮。速度值直接照实显示, 不做美化。
    spd = item.get("speed_bps", 0) or 0
    spd_kb = spd // 1024
    if item.get("is_premium"):
        speed_tag = f" ⚡{spd_kb}K"
    elif item.get("speed_unstable"):
        speed_tag = f" ⚠S{spd_kb}K"
    elif spd > 0:
        speed_tag = f" {spd_kb}K"
    else:
        speed_tag = ""
    # 链路质量标注: 丢包 ⚠L<百分比> (≥20% 才标; 未测不标)
    loss = item.get("loss_rate") or 0
    loss_tag = f" ⚠L{loss:.0%}" if loss >= 0.20 else ""
    # 首包迟钝标注: TTFB > 1500ms (RTT 低但首包慢 = 用户体感"点了没反应")
    ttfb = item.get("ttfb_ms", 0) or 0
    ttfb_tag = f" ⏱{ttfb}ms" if (ttfb and ttfb > TTFB_SLOW_MS) else ""
    # WARP 套壳节点标注 (出口 IP 属 Cloudflare, 非真实落地)
    warp_tag = " ⚠WARP" if item.get("is_warp") else ""
    return (f"{flag} {cname} {idx:02d}{tag}{speed_tag}{loss_tag}{ttfb_tag}"
            f"{warp_tag}{risk_tag} - NEKO")


def export_all(unique_nodes, residential, non_residential):
    ensure_directories()

    def build_group(nodes_list, force_res=False):
        links, proxies, sb_nodes = [], [], []
        for idx, item in enumerate(nodes_list, start=1):
            name = make_node_name(item, idx, force_res)
            ob = item["outbound"]
            if not ob:
                continue
            # 三个转换器都可能返回空 (无端口信息的端口跳跃节点):
            # 任何一个为空就整条跳过, 避免订阅里混入空行/半截配置
            link = outbound_to_v2ray_link(ob, name)
            cp = outbound_to_clash(ob, name)
            if not (link and cp):
                continue
            links.append(link)
            proxies.append(cp)
            sb_nodes.append(outbound_to_singbox(ob, name))
        return links, proxies, sb_nodes

    # 1) 全量
    all_links, all_proxies, all_sb = build_group(unique_nodes)
    with open(os.path.join(OUTPUT_DIR, "v2ray.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(all_links).encode()).decode())
    export_clash_yaml(all_proxies, os.path.join(OUTPUT_DIR, "clash.yaml"))
    export_singbox_json(all_sb, os.path.join(OUTPUT_DIR, "singbox.json"))

    # 2) 家宽总订阅
    res_links, res_proxies, res_sb = build_group(residential, force_res=True)
    with open(os.path.join(OUTPUT_DIR, "residential.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(res_links).encode()).decode())
    if res_proxies:
        export_clash_yaml(res_proxies, os.path.join(OUTPUT_DIR, "residential-clash.yaml"))
        export_singbox_json(res_sb, os.path.join(OUTPUT_DIR, "residential-singbox.json"))
    else:
        for fn in ("residential-clash.yaml", "residential-singbox.json"):
            p = os.path.join(OUTPUT_DIR, fn)
            if os.path.exists(p):
                os.remove(p)

    # 3) 按国家 - 普通区
    shutil.rmtree(COUNTRY_DIR, ignore_errors=True)
    os.makedirs(COUNTRY_DIR, exist_ok=True)
    by_cc = {}
    for n in non_residential:
        by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in by_cc.items():
        l, p, s = build_group(lst)
        with open(os.path.join(COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(COUNTRY_DIR, f"singbox-{cc}.json"))

    # 4) 按国家 - 家宽区
    shutil.rmtree(RESIDENTIAL_COUNTRY_DIR, ignore_errors=True)
    os.makedirs(RESIDENTIAL_COUNTRY_DIR, exist_ok=True)
    res_by_cc = {}
    for n in residential:
        res_by_cc.setdefault(n["country"], []).append(n)
    for cc, lst in res_by_cc.items():
        l, p, s = build_group(lst, force_res=True)
        with open(os.path.join(RESIDENTIAL_COUNTRY_DIR, f"{cc}.txt"), "w", encoding="utf-8") as f:
            f.write(base64.b64encode("\n".join(l).encode()).decode())
        export_clash_yaml(p, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"clash-{cc}.yaml"))
        export_singbox_json(s, os.path.join(RESIDENTIAL_COUNTRY_DIR, f"singbox-{cc}.json"))

    # 5) ★ 家宽合并订阅 (跨地区汇总, 独立于地区分类)
    #   目的: 家宽节点本就稀少 (#70 仅 6 个), 分散在各地区订阅里让用户要一个个试。
    #         这里按"同一落地出口只留一条"的规则合并, 给一个单点入口。
    #   合并规则 (界面/README 中同步说明, 便于用户理解为何数量会变少):
    #     ① 跨地区去重: 同一 出口IP:端口 只保留一条 —— 家宽代理池里同一落地 IP
    #        常被多源以不同地区名收录, 不去重会出现"换了地区其实是同一台机器"。
    #     ② 保留信息量最高的一条: 按 (有出口IP > 延迟更低 > 吞吐更高) 择优,
    #        避免同一落地节点保留了性能最差的那个副本。
    #     ③ 全部按地区归入家宽区展示 (force_res=True), 与地区分类互不影响。
    #   产出: residential-all.{txt,clash.yaml,singbox.json} 三份格式, 独立可订阅。
    #   ★ 不影响既有产物: 步骤 1~4 全程只读 residential/non_residential, 此处不修改。
    res_merged, merge_dropped, merge_kept_cc = _merge_residential(residential)
    if res_merged:
        ml, mp, ms = build_group(res_merged, force_res=True)
    else:
        ml, mp, ms = [], [], []
    with open(os.path.join(OUTPUT_DIR, "residential-all.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(ml).encode()).decode())
    if mp:
        export_clash_yaml(mp, os.path.join(OUTPUT_DIR, "residential-all-clash.yaml"))
        export_singbox_json(ms, os.path.join(OUTPUT_DIR, "residential-all-singbox.json"))
    else:
        # 空状态: 清掉上一轮遗留文件, 避免链接指向过期的陈旧订阅
        for fn in ("residential-all-clash.yaml", "residential-all-singbox.json"):
            p = os.path.join(OUTPUT_DIR, fn)
            if os.path.exists(p):
                os.remove(p)
        print("[!] 家宽合并订阅为空 — 已生成空 residential-all.txt, "
              "并清理上一轮的 residential-all-* 文件 (避免链接指向过期数据)")
    if merge_dropped:
        print(f"[*] 家宽合并: 原始 {len(residential)} → 合并后 {len(res_merged)} "
              f"(跨地区去重剔除 {merge_dropped} 个同落地IP副本) | 覆盖地区: {merge_kept_cc}")

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽 {len(res_links)} | 家宽合并 {len(ml)}")
    return len(all_links), len(res_links)


def _merge_residential(residential: list) -> tuple:
    """家宽跨地区合并: 按 出口IP:端口 去重, 择优保留 → (合并后列表, 去重数, 地区串)

    规则说明 (与 README 中的描述严格一致, 改这里就要同步改那里):
      ① 无出口 IP 的节点**不参与去重**, 全部保留 —— 它们无法判定是否为同一落地,
         贸然合并会丢节点。
      ② 同 出口IP:端口 时择优: 有出口IP > 延迟低 > 吞吐高。
      ③ 排序沿用 classify_and_export 已给出的质量分顺序, 这里的择优只做兜底。
    """
    best = {}          # dedup_key -> 最优节点
    pass_through = []  # 无出口 IP, 原样保留
    dropped = 0
    for n in residential:
        ip = n.get("exit_ip") or ""
        if not ip:
            pass_through.append(n)
            continue
        key = f"{ip}:{n['port']}"
        cur = best.get(key)
        if cur is None:
            best[key] = n
            continue
        dropped += 1
        # 择优: 延迟更低者胜; 延迟相同则吞吐更高者胜
        cur_lat = cur.get("latency_ms") or 999999
        new_lat = n.get("latency_ms") or 999999
        if (new_lat, -(n.get("speed_bps") or 0)) < (cur_lat, -(cur.get("speed_bps") or 0)):
            best[key] = n
    merged = list(best.values()) + pass_through
    ccs = sorted({n.get("country", "??") for n in merged})
    return merged, dropped, ",".join(ccs)


def export_clash_yaml(clash_proxies, filepath):
    names = [p["name"] for p in clash_proxies]
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "mode": "rule",
        "log-level": "info",
        "proxies": clash_proxies,
        "proxy-groups": [
            {"name": "PROXIES", "type": "select", "proxies": ["AUTO"] + names},
            {"name": "AUTO", "type": "url-test", "url": "https://www.gstatic.com/generate_204",
             "interval": 300, "proxies": names},
        ],
        "rules": ["MATCH,PROXIES"],
    }
    with open(filepath, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)


def export_singbox_json(sb_nodes, filepath):
    names = [n["tag"] for n in sb_nodes]
    outbounds = sb_nodes + [
        {"type": "selector", "tag": "select", "outbounds": ["auto"] + names},
        {"type": "urltest", "tag": "auto", "outbounds": names,
         "url": "https://www.gstatic.com/generate_204"},
        {"type": "direct", "tag": "direct"},
        {"type": "block", "tag": "block"},
    ]
    config = {"log": {"level": "warn"},
              "outbounds": outbounds}
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


# ═══════════════════════════════════════════N═══════════════════════
# README 生成
# ═══════════════════════════════════════════N═══════════════════════

def update_readme(total_count, res_count):
    repo_name = os.environ.get("GITHUB_REPOSITORY", "hezhanleiok/freesub").strip()
    cache_bust = ""
    # 私有化部署 Worker 脚本里的仓库参数 (默认值兜底)
    try:
        owner, repo = repo_name.split("/", 1)
    except ValueError:
        owner, repo = "hezhanleiok", "freesub"

    def count_file(path):
        if not os.path.exists(path):
            return 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                c = f.read().strip()
                if not c:
                    return 0
                decoded = base64.b64decode(c).decode("utf-8", errors="ignore")
                return len([ln for ln in decoded.splitlines() if ln.strip()])
        except Exception:
            return 0

    res_counts, normal_counts = {}, {}
    for d, store in ((RESIDENTIAL_COUNTRY_DIR, res_counts), (COUNTRY_DIR, normal_counts)):
        if os.path.exists(d):
            for fn in os.listdir(d):
                if fn.endswith(".txt"):
                    cnt = count_file(os.path.join(d, fn))
                    if cnt > 0:
                        store[fn[:-4]] = cnt

    def table_rows(counts, sub):
        rows = []
        for cc in sorted(counts, key=lambda x: counts[x], reverse=True):
            flag = get_country_flag(cc)
            name = COUNTRY_NAMES.get(cc, cc)
            cnt = counts[cc]
            v2 = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/{cc}.txt) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/{cc}.txt)"
            cl = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/clash-{cc}.yaml) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/clash-{cc}.yaml)"
            sb = f"[CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/{sub}/singbox-{cc}.json) · [Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/{sub}/singbox-{cc}.json)"
            rows.append(f"| {flag} {name} | {cnt} | {v2} | {cl} | {sb} |")
        return "\n".join(rows) if rows else "| 暂无可用节点 | 0 | - | - | - |"

    res_table = table_rows(res_counts, "residential-by-country")
    normal_table = table_rows(normal_counts, "by-country")

    # 家宽合并订阅的实际节点数 (直接数文件, 不靠传入值, 避免与导出结果不一致)
    _merged_txt = os.path.join(OUTPUT_DIR, "residential-all.txt")
    res_merged_count = count_file(_merged_txt) if os.path.exists(_merged_txt) else 0
    # 空状态提示: 合并结果为空时明确告知, 避免用户点进链接得到空白却一头雾水
    res_merged_empty = (
        f"\n> **当前合并家宽节点数: {res_merged_count}**\n" if res_merged_count else
        "\n> ⚠️ **本轮未测得任何家宽节点**, 上述链接会返回空内容 (家宽 IP 极稀少, "
        "属正常现象)。下方按地区分类同样为空。空订阅已清理上一轮残留文件, "
        "不会指向过期数据; 家宽节点出现后会自动填充。\n"
    )

    readme = f"""# 🚀 免费节点自动测活订阅池 (含真实家宽/住宅IP甄选)

> 👤 **定制规范命名**: 所有订阅节点均重命名为 `国旗 地区 序号 (家宽) - xiaohe`
> ⚡ **真实可用保障**: 所有节点由 `sing-box v{SINGBOX_VERSION}` 内核建立实际代理隧道, 完成真实 HTTPS 双向传输握手 + 出口 IP 穿透验证 + Cloudflare 限速下载断流检测 + TLS 证书校验 (MITM 劫持识别), 拒绝虚假通畅、断流节点与高危劫持节点。
> 🛡️ **全协议支持**: VLESS (Reality/Vision) · VMESS · Trojan · Shadowsocks · Hysteria2 · TUIC · AnyTLS

---

## 📌 全部节点总订阅链接

| 客户端 / 格式类型 | 节点总数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| 🚀 **Clash (YAML 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/clash.yaml) |
| ⚡ **V2RayN (Base64 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/v2ray.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/v2ray.txt) |
| 📦 **sing-box (JSON 格式)** | `{total_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/singbox.json) |

---

## 🏠 按照家宽分类节点订阅 (住宅 IP 专区)

> 家宽判定六重信号: ① ip-api.com `hosting` 字段 ② `mobile` 移动网络字段 ③ Cloudflare/主流 CDN Anycast 网段比对 ④ MaxMind GeoLite2 ASN 白/黑名单 (覆盖 60+ 国家主流民用运营商) ⑤ rDNS/ISP 名称特征 ⑥ Scamalytics 风控评分复核 (fraud ≥75 降级、≥90 剔除)。排除所有云主机/数据中心/CDN 任播, 保留真实民用宽带与移动网络。

### 🌐 家宽节点合并订阅 (跨地区汇总 · 单点入口)

> 家宽节点数量本就稀少, 分散在下方各地区订阅里需要逐个尝试。这里提供**全部家宽节点的合并订阅**,
> 独立于地区分类单独更新, 适合直接导入客户端一次性使用。

**合并规则与筛选条件** (便于理解合并后数量为何会变少):

| 规则 | 说明 |
| :--- | :--- |
| ① **跨地区去重** | 同一 `出口IP:端口` 只保留一条。家宽代理池里同一台落地机器常被多源以不同地区名重复收录, 不去重会出现"换了地区其实是同一台" |
| ② **择优保留** | 同出口IP 时按 **延迟更低 → 吞吐更高** 保留, 避免留下性能最差的副本 |
| ③ **无出口IP 全保留** | 拿不到出口 IP 的节点不参与去重 (无法判定是否同一落地), 全部保留 |
| ④ **家宽身份不变** | 合并只做去重与择优, 不改变家宽判定结果, 也不影响下方地区分类 |

**订阅入口**:

| 客户端 / 格式 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :---: |
| ⚡ **V2RayN (Base64)** | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential-all.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential-all.txt) |
| 📦 **Clash (YAML)** | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential-all-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential-all-clash.yaml) |
| 📦 **sing-box (JSON)** | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/residential-all-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/residential-all-singbox.json) |

{res_merged_empty}

### 🗺️ 按地区细分家宽订阅

> 下方按地区拆分的家宽订阅保持独立更新, 与上方合并订阅互不影响, 按需选择即可。

| 家宽地区 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{res_table}

---

## 🗺️ 按照国家分类节点订阅 (非家宽/数据中心节点)

| 地区/国家 | 节点数 | V2RayN 专属订阅 | Clash 专属订阅 | sing-box 专属订阅 |
| :--- | :---: | :---: | :---: | :---: |
{normal_table}

---

## 🔒 私有仓库（Private）无感免翻订阅方案 (基于 Cloudflare Workers)

> 如果你希望将本 GitHub 仓库设置为 **Private (私有仓库)** 保护节点资产，外部客户端无法直接拉取原生 Raw 或公共 CDN 链接，可以通过以下 Cloudflare Worker 搭建轻量级私密网关反代：

### 1. 获取 GitHub 永久个人令牌 (PAT)
1. 进入 GitHub -> **Settings** -> **Developer Settings** -> **Personal access tokens (classic)**。
2. 点击 **Generate new token (classic)**，勾选 `repo` 权限，有效期设为 `No expiration`（永不过期）。
3. 复制保存生成的以 `ghp_` 开头的 Token。

### 2. 部署 Cloudflare Worker
登录 Cloudflare Dashboard，创建一个新的 Worker，复制以下脚本粘贴并部署（把 `OWNER`/`REPO`/`GITHUB_TOKEN` 改成你自己的）：

```javascript
export default {{
  async fetch(request) {{
    const GITHUB_TOKEN = "ghp_你的GitHub永久访问令牌";
    const OWNER = "{owner}";
    const REPO = "{repo}";
    const BRANCH = "main";

    const url = new URL(request.url);
    const filePath = "output" + url.pathname;
    const ghUrl = "https://raw.githubusercontent.com/" + OWNER + "/" + REPO + "/" + BRANCH + "/" + filePath;

    const res = await fetch(ghUrl, {{
      headers: {{
        "Authorization": "token " + GITHUB_TOKEN,
        "User-Agent": "Cloudflare-Worker"
      }}
    }});

    if (!res.ok) {{
      return new Response("Not Found", {{ status: 404 }});
    }}

    return new Response(await res.text(), {{
      headers: {{
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-cache"
      }}
    }});
  }}
}}
```

### 3. 私有订阅链接映射方式
部署后 Worker 会分配一个专属域名（例如 `my-sub.yourname.workers.dev`），你的客户端可以直接无感订阅：
* **总 V2RayN 订阅**: `https://你的域名.workers.dev/v2ray.txt`
* **总 Clash 订阅**: `https://你的域名.workers.dev/clash.yaml`
* **总 sing-box 订阅**: `https://你的域名.workers.dev/singbox.json`
* **台湾家宽 V2RayN**: `https://你的域名.workers.dev/residential-by-country/TW.txt`
* **香港家宽 Clash**: `https://你的域名.workers.dev/residential-by-country/clash-HK.yaml`
* **日本家宽 sing-box**: `https://你的域名.workers.dev/residential-by-country/singbox-JP.json`

---

## ⭐ 项目热度

[![Star History Chart](https://api.star-history.com/svg?repos={repo_name}&type=Date)](https://star-history.com/#{repo_name}&Date)

---

## 🛠️ 项目使用说明
1. **自动更新机制**：GitHub Actions 每 6 小时全自动运行并刷新上述全部订阅与数据。
2. **测活标准**：节点必须通过 ① 静态预筛(剔除关闭证书校验) ② 端口预检 ③ sing-box 实际隧道跨源活性探测 (Google/Cloudflare/Microsoft 至少 2 源) ④ 真实出口 IP 穿透获取 (延迟 ≤ 1500ms) ⑤ 限时下载测速 (稳态吞吐 ≥ 200KB/s, 5MB 首测 + 1MB 复测取最小值 + Hetzner 物理机房交叉测速) ⑥ 丢包率 ≤ 25% ⑦ 首包 TTFB ≤ 1800ms ⑧ TLS 证书校验非 MITM, 方可入库。
3. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v2 · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1. 抓取
    raw_nodes = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ 测前去重 (凭据指纹): 同 凭据+目标+协议 只测一次, 重复项不回填
    #     key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并
    #     凭据指纹: uuid/password 各协议的核心身份字段 (vless uuid / vmess id+alterId /
    #               trojan password / ss 2022密钥 / hy2 auth / tuic uuid+passwd / anytls password)
    #     完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次
    def cred_fingerprint(outbound: dict, proto: str) -> str:
        try:
            if proto == "vless":
                return f"{outbound.get('uuid','')}"
            if proto == "vmess":
                return f"{outbound.get('uuid','') or outbound.get('user_id','')}"
            if proto == "trojan":
                return f"{outbound.get('password','')}"
            if proto == "shadowsocks":
                return f"{outbound.get('method','')}|{outbound.get('password','')}"
            if proto == "hysteria2":
                return f"{outbound.get('password','') or ''}|{outbound.get('server_ports','')}"
            if proto == "tuic":
                return f"{outbound.get('uuid','')}|{outbound.get('password','')}"
            if proto == "anytls":
                return f"{outbound.get('password','')}"
            return json.dumps({k: v for k, v in outbound.items()
                              if k in ("uuid", "password", "user_id", "method")}, sort_keys=True)
        except Exception:
            return ""  # 指纹失败 → 不合并 (宁慢不错)

    # ★ 测前去重 (凭据指纹): 同 凭据+目标+协议 只测一次。
    #   key = (server, port, proto, 凭据指纹): 凭据不同 → 服务端校验结果可能不同, 不可合并。
    #   完全相同 = 同一节点被多源重复收录 (免费池常态, 30+ 份不同名字) → 只测一次。
    #   ★ 这是**测前**去重, 是整条流水线省时间的关键一步: 4838 → 2340,
    #     少起 2498 次 sing-box 进程、少跑 2498 轮探测。
    #   被剔除的重复 URI **不再回填** (2026-10 起): 测活后的回填既不省时间
    #     (测试量已由这里定死), 也因出口IP相同必然在分类去重处被折叠, 还会让
    #     重复项在测活后会回填 (见步骤 4.5), 保证多源收录的同一节点不丢失。
    # seen_keys 记录 key → [该 key 下的全部 URI] (首个是代表节点, 其余是重复项)
    seen_keys, deduped, dup_count = {}, [], 0
    for item in candidates:
        uri, outbound, server, port, proto = item
        key = (server.lower() if server else "", port, proto, cred_fingerprint(outbound, proto))
        if key in seen_keys:
            seen_keys[key].append(uri)   # 记录重复 URI, 测活后回填
            dup_count += 1
        else:
            seen_keys[key] = [uri]
            deduped.append(item)
    if dup_count:
        print(f"[*] 测前去重(凭据指纹): {len(candidates)} → {len(deduped)} "
              f"(剔除重复 {dup_count} — 仅测代表节点, 测活后回填有效项)")
    DEDUP_MAP = seen_keys      # 供测活后回填 (main() 局部使用)
    candidates = deduped

    # 2.6 ★ 静态预筛 (零网络零进程): 砍掉主动关闭证书校验的节点
    #     必须在凭据去重之后 — 先去重才不会对同一垃圾节点重复报计数
    candidates = static_prescreen(candidates)

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 解析成功(去重后): {len(candidates)} | 失败 {parse_fail} | 协议分布 {proto_stat}")

    if not candidates:
        print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        return

    # 3. 端口预检
    candidates = prefilter_candidates(candidates)

    # 4. 真实测活 (只测去重后的代表节点)
    test_results = run_liveness_test(candidates)

    # 4.5 ★ 重复节点结果回填: 同 凭据+目标+协议 的重复 URI 继承代表节点的测活结果。
    #   前提: key = (server, port, proto, 凭据指纹) 完全相同 → 服务端认的是同一份凭据,
    #   对同一目标的行为一致, 因此可以安全继承 (不会把"不同服务的节点"混为一谈)。
    #   位置: 必须在 classify_and_export 的 `出口IP:端口` 去重**之前**,
    #         这样多源收录的同一节点能以各自的 URI 进分类流程, 由最终去重决定谁留。
    #   ⚠️ 入场条件比历史版本更严: 只回填**真活**(alive 且未断流)的代表节点结果,
    #      断流/未测到的代表节点不回填, 避免把失败的结论扩散给同源的其它 URI。
    if DEDUP_MAP:
        result_by_key = {}
        for r in test_results:
            key = ((r["server"] or "").lower(), r["port"], r["proto"])
            result_by_key[key] = r
        expanded = list(test_results)
        backfilled = 0
        for key, uris in DEDUP_MAP.items():
            if len(uris) <= 1:
                continue
            lookup = (key[0], key[1], key[2])
            r = result_by_key.get(lookup)
            # 只继承"确认为有效"的代表节点结果 (alive 且未断流)
            if not r or not r.get("alive") or r.get("is_stalled"):
                continue
            for extra_uri in uris[1:]:
                # dict(r) 浅拷贝: 保证 speed_bps/latency_ms/loss_rate/ttfb_ms/
                # alive/is_stalled/is_premium 等所有状态字段与代表节点完全一致,
                # 只替换 raw 为本条 URI (后续 classify 会据此解析出各自的 outbound)
                clone = dict(r)
                clone["raw"] = extra_uri
                clone["backfilled"] = True        # 标记来源, 便于日志与排查
                expanded.append(clone)
                backfilled += 1
        if backfilled:
            print(f"[+] 重复节点回填: +{backfilled} (继承真活代表节点的测活结果)")
        test_results = expanded


    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    test_results = chain_retest(test_results)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential = classify_and_export(test_results)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return
    total, res = export_all(unique_nodes, residential, non_residential)
    update_readme(total, res)


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s ({elapsed/60:.1f} 分钟) | 抓取 {len(raw_nodes)} → 静态预筛+去重后 {len(candidates)} → 真活 {len(test_results)} → 去重后 {len(unique_nodes)} → 家宽 {len(residential)}")
    by_type = {}
    for n in unique_nodes:
        by_type[n["net_type"]] = by_type.get(n["net_type"], 0) + 1
    print(f"节点类型分布: {by_type}")
    by_proto = {}
    for n in unique_nodes:
        by_proto[n["proto"]] = by_proto.get(n["proto"], 0) + 1
    print(f"协议分布(出库): {by_proto}")
    by_country = {}
    for n in unique_nodes:
        by_country[n["country"]] = by_country.get(n["country"], 0) + 1
    top_c = sorted(by_country.items(), key=lambda x: -x[1])[:10]
    print(f"国家 Top10: {top_c}")


if __name__ == "__main__":
    main()
