#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
免费节点自动测活订阅池 v3 — 全协议 · 高精度 · 低误杀 · 国内可用性导向
====================================================

★ v3 核心变化 (相对 v2): 新增"国内可用性"维度。
  v2 的全部判定都跑在 GitHub Actions (Azure US) 的**海外视角**上 ——
  一个节点从美国秒开、满速下载, 不代表国内能用: 入口端口被 GFW 限流/
  域名被 DNS 污染/协议无伪装被 DPI 识别/线路回国质量差, 这些从海外
  视角完全看不见。v3 在不花钱、只用免费公共服务的前提下补上这块:
    · 入口侧静态评分: 端口(443/80/其他) × 协议伪装(Reality/CDN前置/TLS/明文)
      × 入口 IP 是否落在 CDN 网段 × 域名在大陆 DNS 是否被污染
    · 入口线路质量: 入口 rDNS/ASN 识别 CN2 GIA / 联通4837 / 移动CMI 等精品网
    · 回国方向实测: 经节点 TCP 握手国内公共 DNS (223.5.5.5/114.114.114.114)
      量回国 RTT; 经节点请求 baidu/bilibili/jd 验"回国通不通"
      (很多节点只转发海外流量, 国内站点直接拒 —— 回国场景用户抓瞎)
    · (可选) RIPE Atlas 中国探针: 真·中国大陆视角 ping 入口 IP,
      免费账号领 5 万额度即可用, 默认关闭, 配置 ATLAS_API_KEY 后生效
  产出: 独立的"国内友好订阅" (cn-friendly), 节点名打 🇨🇳/⚠D/⚠P/⚠U/⚠C 标记,
  组内排序按国内可用性加权。

架构（四阶段流水线）:
  1. 抓取订阅源 → 解析全部协议 URI 为统一节点对象
     (vless/vmess/trojan/ss/hysteria2/tuic/anytls + reality + 全部传输层)
  2. 真实测活（sing-box v1.14 内核，逐节点 SOCKS 入站 + 节点出站）:
     - 阶段A 端口预检: TCP/QUIC 直连握手, 快速丢弃死端口 (削减 90% 无效工作)
       ★ v3.2 起测前不再去重 (仅原有筛选), 全部候选直接进预检
     - 阶段B 真实探测 (v3 起组内并发, 单节点最坏耗时 ~52s → ~35s, 死节点 ~20s → ~12s):
       · v3.2 测活期查重 (流程核心变更): 每个节点先拿完整真实信息 (活性+
         真实出口 IP) + 完整指纹, 与**已成功测活**的注册表比对 — 重复
         当场截断 (跳过后续全部测活); 未重复才继续, 成功后注册。
         (旧"测前指纹去重 + 测后回填克隆体"整体删除, 回填必要性评估
          见设计文档第 12 节)
       · 活性三源探测 (Google/Cloudflare/Microsoft, 至少 2 源通过) + 出口 IP
         回声**并发** (旧串行最坏 12+4+4+6=26s, 现 max(12,6)≈12s)
       + 延迟上限门槛 (MAX_LATENCY_MS, 此前延迟只排序不淘汰)
       + 经代理取真实出口 IP (api.ip.sb/geoip → 一次拿 country+asn+isp)
       + Cloudflare 限时下载测速 → 断流节点识别 (稳态吞吐 < 200KB/s)
         · 分母只取首数据块后的稳态区间 (剔除握手/TLS/RTT, 否则快节点被系统性低估)
         · 1MB 二次复测取最小值 (防 CDN 缓存/TCP 突发骗过单轮结果)
           ★ v3: 首测已低于门槛的节点跳过复测 (注定断流, 省 4s×大量节点)
         · 跨端点交叉测速 (按需触发: 仅当首测疑似 CDN 短路时才跑物理机房
           Hetzner/Linode 端点; 正常结果直接采用, 省掉每节点 5~8 秒)
         · 重复节点回填 (v3.2 已删除 — 去重后移到测活期, 见阶段B)
         · 测速健全性护栏 (全体中位数过高 = CDN 短路, 撤销⚡优选标记)
       · MITM 复检 + WARP 检测**并发** (旧串行 4+4s)
       · 丢包率探测 (复用 204 探针连发 5 次) + v3 回国方向探测**并发**:
         裸 SOCKS5 TCP 握手 223.5.5.5:443/114.114.114.114:53 → 回国 RTT;
         经节点 HTTP 请求 baidu/bilibili/jd → 回国可达性
       · v3.2 顺序优化: 丢包 + 回国方向 + 真实网页 + MITM + WARP **五路并发**
         (原 MITM/WARP 在测速前串行 4s×全部节点, 后移后死节点不再白跑,
         活节点墙钟从累加变取 max); 域名解析预热前移、DNS 污染预查后移到
         端口预检之后 (只查真候选); 探测连接池 10→64、预检并发 64→128
       · v3.1 真实网页加载 (wikipedia/github/google, 只读响应头):
         204/测速端点是对出口 IP 最宽容的目标, 补测真实网站抓"隧道通但
         网页打不开"的假活节点 — 三个全不可达判死, 有被拦打 ⚠B
       + 首包时间 TTFB (与握手 RTT 互补, 抓"延迟低但首包慢"的体感杀手)
       + cloudflare trace tls=VERIFIED → MITM/劫持节点识别
  3. 家宽链式复测 (v3 起改 **lite 模式**: 只跑活性+轻测速 ~3s,
     旧全量 ~8.3s — 62 候选 515s → ~90s)
  4. 分类与导出:
     - 国家: 出口 IP ip-api.com 批量(45req/min 免费) → MaxMind GeoLite2 兜底
     - 属性: hosting=true/CDN网段/IDC ASN → 机房 | mobile=true → 移动
            | 运营商白名单+rDNS → 家宽
     - 入口线路 (v3 新增): 入口 IP rDNS/ASN → CN2GIA/4837/CMI 精品网标记
     - 国内可用性综合分 cn_score (静态 + 入口线路 + 回国实测 + 可选 Atlas)
     - 去重: 出口IP+端口 唯一化 (保留速度最优), 家宽区严格防同IP刷屏
     - 排序: 家宽优先, 组内按综合质量分 (延迟 + 丢包惩罚 + 半个 TTFB
            + 国内可用性加权) — v3 起国内用户视角优先
     - 导出: 全量 / 家宽 / 按国家 / **国内友好订阅 (v3 新增)**
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
import gzip
import hashlib
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
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/by-country/v2ray-base64-TW.txt",
    "https://raw.githubusercontent.com/10ium/HiN-VPN/main/subscription/base64/mix",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/protocols/hysteria",
    "https://raw.githubusercontent.com/10ium/telegram-configs-collector/main/security/tls",
    "https://github.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",
    "https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt",
    "https://raw.githubusercontent.com/twj0/subseek/refs/heads/master/data/sub_github.txt",
    "https://raw.githubusercontent.com/free-nodes/v2rayfree/main/sub",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/chengaopan/AutoMergePublicNodes/master/list.txt",
    "https://raw.githubusercontent.com/ShatakVPN/ConfigForge-V2Ray/main/configs/all.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://www.ermao.net/sub/v2ray/ermao.net",
    "https://gist.githubusercontent.com/shuaidaoya/9e5cf2749c0ce79932dd9229d9b4162b/raw/base64.txt",
    "https://raw.githubusercontent.com/awesome-vpn/awesome-vpn/master/all",
    "https://gist.githubusercontent.com/guidongone/72bdfb8a20164bac35debfb182ed646d/raw/864533db03b328588c8543bb78bd90fed2664259/V2ray261003.txt",
    "https://raw.githubusercontent.com/cbusifabcap/daily_free_vpn/refs/heads/main/Z.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha.txt",
    "https://raw.githubusercontent.com/zhuhaiuk/free-nodes/main/nodes.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
    "https://raw.githubusercontent.com/iboxz/free-v2ray-collector/main/main/mix.txt",
    "https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/Export/v2rayN_PC/BLACK_VLESS_RUS_mobile_v2rayN.txt",
    "https://www.xrayvip.com/free.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/super-sub.txt",
    "https://raw.githubusercontent.com/snakem982/proxypool/main/source/v2ray-2.txt",
    "https://gist.githubusercontent.com/guidongone/ac60f0dfeff1a514ebbf795af03abc7f/raw/61620b2129097d1aad6b4f6910ccce98219ce38f/V2ray261011.txt",
    "https://shadowmere.xyz/api/b64sub/",
    "https://raw.githubusercontent.com/ProblemTheCode/SylphNet-public/refs/heads/main/sub/sub.txt",
    "https://raw.githubusercontent.com/penhandev/AutoAiVPN/refs/heads/main/allConfigs.txt",
    "https://raw.githubusercontent.com/sakha1370/OpenRay/refs/heads/main/output/all_valid_proxies.txt",
    "https://raw.githack.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
    "https://raw.githubusercontent.com/wenxig/free-nodes-sub/refs/heads/main/data/sub.txt",
    "https://d.zrfme.com/vless-base64",
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
BLOCK_COUNTRIES = ""             # 例: "JP" = 剔除落地日本; "JP,KR" = 日本+韩国
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
# 国内可用性 (China-usability) 配置 — v3 新增
#   设计原则: 全部用**免费公共服务**, 零购买; 能在 GitHub Actions 上跑。
#   覆盖三个盲区: ① 入口能不能进 (GFW 抗力) ② 域名在大陆解析是否正常
#                ③ 回国方向通不通 / 快不快
# ══════════════════════════════════════════════════════════════════

# --- 回国方向探测 (经节点访问国内目标; 全部免费公共可达, 无需 key) ---
#   TCP RTT 目标: 国内公共 DNS 的 TCP 端口 (裸 SOCKS5 CONNECT 握手计时,
#   量的是"节点出口 → 国内"的真实往返, 即用户回国流量的链路质量)
CN_EXIT_TCP_PROBES = [
    ("223.5.5.5", 443),        # 阿里公共 DNS (DoH over TLS 端口, 全球可达)
    ("114.114.114.114", 53),   # 114DNS (TCP DNS, 全球可达)
]
#   HTTP 可达性目标: 国内站点 (经节点请求, 2xx/3xx 算可达)
#   为什么必须测: 大量节点/机场只转发海外流量, 对国内目标直接拒 —
#   这类节点"出国"没问题, 但用户想看 B 站/连国服游戏/访问国内 API 时抓瞎。
CN_EXIT_HTTP_PROBES = [
    "https://www.baidu.com",
    "https://www.bilibili.com",
    "https://www.jd.com",
]
CN_EXIT_TIMEOUT        = 4.0       # 单个回国探测超时 (秒)
CN_EXIT_RTT_GOOD_MS    = 350       # 回国 RTT ≤ 350ms → 加分 (国内站体感可接受)
CN_EXIT_RTT_BAD_MS     = 900       # 回国 RTT > 900ms → 扣分 (国内站明显卡顿)
CN_EXIT_HTTP_MIN_OK    = 1         # 至少几个 HTTP 目标可达才算"回国通"

# --- 真实网页加载探针 (v3.1 新增: 抓"隧道通但网页打不开"的假活节点) ---
#   ★ 为什么加: 204 端点 (gstatic/cp.cloudflare) 和 speed.cloudflare.com 测速
#     是对出口 IP 最宽容的目标 — CF 不拦 CF 自家 IP 段, 所以"延迟好看+
#     测速过"的节点, 用户开普通网站照样 403/转圈 (机房 IP 被 Cloudflare WAF/
#     Google 风控拦是免费池头号假活形态)。这三个目标分别代表三类真实场景:
#       wikipedia — 无 WAF 全球可达, 当"基线"(它都挂 = 链路真有问题)
#       github    — Cloudflare WAF 后面, 机房 IP 常被 challenge → 403
#       google    — Google 风控, 脏 IP 常 429/验证码
#   判定语义 (见 _web_load_verdict):
#       HTTP < 400                → 可达
#       403/429/503 等            → 被 WAF/风控拦 (IP 脏, ⚠B 标记)
#       超时/连接失败             → 链路问题
#       **三个全不可达 → 判死** (204 全过但一个真实网页都开不了 = 对普通
#       用户就是废节点, 选择性转发/出口全被封的典型形态)
WEB_CHECK_PROBES = [
    ("wikipedia", "https://www.wikipedia.org/"),
    ("github",    "https://github.com/"),
    ("google",    "https://www.google.com/"),
]
WEB_CHECK_TIMEOUT       = 6.0       # 读响应头超时 (秒) — stream 模式不拉 body
WEB_CHECK_CONNECT_TIMEOUT = 4.0     # 建连超时 (秒)

# --- DoH DNS 污染对比 (中国公共 DNS vs 全球 DNS; 全部免 key) ---
#   DNSPod/阿里 是大陆用户最常用的公共 DNS (运营商 DNS 大同小异),
#   Cloudflare 代表海外正确解析。三者对比:
#     大陆侧解析失败(NXDOMAIN/SERVFAIL/空) 且 海外正常 → 域名被污染,
#     国内客户端用默认 DNS 连不上该节点 (v2rayN 默认不走 DoH)。
#   只认"硬失败", 不认"结果不同" — GeoDNS/CDN 分地域返回不同 IP 是合法场景。
CN_DOH_JSON = [
    ("dnspod",  "https://doh.pub/resolve?name={d}&type=A"),          # DNSPod 公共 DoH (JSON)
    ("alidns",  "https://dns.alidns.com/resolve?name={d}&type=A"),   # 阿里公共 DNS (JSON)
]
GLOBAL_DOH_JSON = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query?name={d}&type=A"),  # RFC8484 (Accept: dns-json)
]
DNS_CHECK_TIMEOUT = 6.0           # 单个 DoH 查询超时 (秒)
DNS_CHECK_WORKERS = 24            # DNS 污染预查并发数

# --- 静态 China 友好度评分 (入口侧 GFW 抗力; 纯本地计算, 零请求) ---
#   预测分, 在端口预检前算完, 用于: ① 测试优先级排序 ② 国内友好订阅入选
#   评分语义 (0~100+):
#     端口 443  = HTTPS 天然伪装, GFW 极少整面墙 443        → +30
#     端口 80   = 可用但明文特征明显                          → +12
#     其他端口 = 随机高端口是 GFW 周期性限流/重置的常客      → +0
#     Reality   = 无证书+真前端伪装, 抗主动探测最强          → +25
#     CDN 前置  = 入口 IP 落在 CDN 任播段, 墙 IP 墙不掉      → +18
#     web 传输  = ws/grpc/httpupgrade (流量形态像网页)       → +12
#     裸 TLS    = 有证书但直连 IP, 可被主动探测+墙 IP        → +8
#     无 TLS    = SS 明文等, DPI 可识别                      → -15
#     QUIC 系   = hy2/tuic 走 UDP, GFW 对 UDP 有 QoS 传统   → -12 (只扣分不淘汰)
#     域名干净  = 大陆 DNS 解析正常                          → +10
#     域名被污染= 国内默认 DNS 下直接连不上                  → -45
#     直连 IP   = 无 DNS 污染风险, 但也没有 CDN 掩护         → +6
CN_SCORE_PORT_443        = 30
CN_SCORE_PORT_80         = 12
CN_SCORE_REALITY         = 25
CN_SCORE_TLS_CDN         = 18
CN_SCORE_TLS_WEB         = 12
CN_SCORE_TLS_PLAIN       = 8
CN_SCORE_NO_TLS_PENALTY  = -15
CN_SCORE_QUIC_PENALTY    = -12
CN_SCORE_DNS_OK          = 10
CN_SCORE_DNS_POLLUTED    = -45
CN_SCORE_IP_LITERAL      = 6

# --- 动态加分 (测活后才有; 入口线路 + 回国实测) ---
CN_SCORE_RDNS_CN2        = 22      # 入口 rDNS 含 cn2/gia → CN2 GIA 精品网
CN_SCORE_RDNS_4837       = 18      # 入口 rDNS 含 4837 → 联通精品网
CN_SCORE_RDNS_CMCC       = 16      # 入口 rDNS 含 cmcc/cmi/9808 → 移动内网
CN_SCORE_ASN_CNCLOUD     = 10      # 入口 ASN 为中国云厂商 (回国路由通常较好)
CN_SCORE_EXIT_OK         = 15      # 回国方向可达 (baidu/bilibili/jd 至少1个通)
CN_SCORE_EXIT_RTT_GOOD   = 10      # 回国 RTT ≤ CN_EXIT_RTT_GOOD_MS
CN_SCORE_EXIT_RTT_BAD    = -8      # 回国 RTT > CN_EXIT_RTT_BAD_MS
CN_SCORE_LAT_GOOD        = 5       # 海外延迟 ≤ 300ms (链路底子好)

CN_FRIENDLY_MIN_SCORE    = 55      # 国内友好订阅入选总分门槛
CN_QUALITY_WEIGHT        = 5.0     # 组内排序权重: (100-cn_score)×W 毫秒等效惩罚

# 入口 rDNS 精品网关键词 (按点分 token 匹配, 防子串误判)
#   CN2 GIA 是电信精品网, rDNS 习惯带 cn2/gia; 4837 联通; cmcc/cmi 移动
CN_LINE_RDNS_TOKENS = {
    "cn2":    {"cn2", "cn2gia", "gia"},
    "cu4837": {"4837"},
    "cmi":    {"cmcc", "cmi", "9808", "chinamobile"},
}
# 入口 ASN ∈ 中国云厂商 → 回国路由通常优于随机海外 IDC
#   (可自行扩充: 火山引擎/百度云/金山云等自有 ASN)
CN_CLOUD_ASNS = {
    45102,   # 阿里云国际 (Alibaba Cloud International)
    37963,   # 阿里云 (杭州)
    45090,   # 腾讯云 (Tencent Cloud)
    132203,  # 腾讯 (深圳) 网络
    55990,   # 华为云 (Huawei Cloud)
}

# --- (可选) RIPE Atlas 中国探针 ping — 真·中国大陆视角 ---
#   免费: RIPE NCC Access 账号注册即领 5 万 credits (一次性),
#   Atlas 在中国大陆有 600+ 在线探针。开启后每轮对少量候选入口 IP
#   发起中国探针 ping, 直接测量"大陆 → 入口"的可达性与 RTT/丢包。
#   用法: GitHub Secrets 加 ATLAS_API_KEY (atlas.ripe.net → Create a Key),
#         ATLAS_MAX_IPS 控制每轮测多少个 IP (默认 20), 防止烧额度。
#   不配 key 则整个模块静默跳过, 不影响主流程。
ATLAS_API_KEY      = os.environ.get("ATLAS_API_KEY", "").strip()
ATLAS_MAX_IPS      = int(os.environ.get("ATLAS_MAX_IPS") or 20)
ATLAS_MAX_PROBES   = int(os.environ.get("ATLAS_MAX_PROBES") or 20)
ATLAS_WAIT_SECONDS = int(os.environ.get("ATLAS_WAIT_SECONDS") or 210)
ATLAS_API_CREATE   = "https://atlas.ripe.net/api/v2/measurements//?key="
ATLAS_API_PROBES   = "https://atlas.ripe.net/api/v2/probes/?country_code=CN&status=1&is_public=true&page_size=100"

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

# ══════════════════════════════════════════════════════════════════
# 跨次运行死节点缓存 (v3.3)
#   ★ 动机 (CI 实测 2026-10-18): 一轮 20842 抓取 → 16737 静态预筛 →
#     15467 端口预检 → 测活, 13680 个已处理里**只有 2192 过活性门槛**。
#     84% 的候选死在测活期, 而"它已经死了"这件事在原架构里完全不留痕
#     (test_single_node 的 5 个 return None 被 `if r:` 静默丢弃, 连计数
#     都没有) —— 下一轮同样的死节点要重新花 8~12s × 上万个槽位重测。
#   ★ 存储选 GitHub Actions cache 的理由 (三个位置都排除过):
#     ✗ output/  — workflow 有 `git add -A output/`, 会把缓存提交进仓库
#     ✗ runtime/ — 混装 sing-box 内核 + Country/ASN.mmdb, 且 download_file
#                  L902 对其中文件"存在即跳过", 会被当内核缓存误判
#     ✓ .cache/  — 新建目录, 只被 actions/cache restore/save 两个步骤碰
#     ★ Python 无法自己读写 Actions cache (只能读写被 restore 到工作区的
#       文件), 所以 workflow 侧必须加 restore + save 两步, 见设计文档。
#   ★ 四层防误杀 (本功能最大风险 = 把"这轮环境挂了"固化成"节点永久死"):
#     ① 连续两轮 (DEAD_MIN_HIT=2) —— 时序铁律: 剔除发生在测活**之前**,
#        本轮的测试结果只能决定**下一轮**是否剔除;
#     ② 环境故障闸: 新死亡 >80% 候选 且 >3000 条 → 本轮整轮不入缓存;
#     ③ 剔除比例上限 (DEAD_DROP_MAX_RATIO): 防候选被清空到 0;
#     ④ 抽样复测 (DEAD_RECHECK_N): 复活即删 + 让 hit 计数能持续累积。
#   ★ 键复用 node_key (不含 exit_ip): 死节点本来就拿不到 exit_ip, 且
#     绝不能用序号/下标 —— fetch_raw_nodes 返回 list(set), 顺序跨轮随机。
# ══════════════════════════════════════════════════════════════════
DEAD_CACHE_DIR        = os.path.join(BASEDIR, ".cache")
DEAD_CACHE_SCHEMA     = 1                 # 序列化规则版本 → 键算法变了就 bump
DEAD_CACHE_FILE       = os.path.join(DEAD_CACHE_DIR,
                                      f"deadnodes-v{DEAD_CACHE_SCHEMA}.jsonl.gz")
DEAD_CACHE_ENABLED    = os.environ.get("DEAD_CACHE", "1").strip().lower() \
                        not in ("0", "false", "off")
DEAD_CACHE_TTL_DAYS   = int(os.environ.get("DEAD_CACHE_TTL_DAYS") or 3)
# ★ TTL 必须自己判, 不能靠 Actions cache 的"7 天未访问淘汰": 那 3~7 天
#   的窗口里 Actions 照样会把缓存发下来, 免费节点寿命以天计, 拿 5 天前的
#   死亡结论剔除今天的候选是纯误杀。
DEAD_CACHE_TTL_SEC    = DEAD_CACHE_TTL_DAYS * 86400
DEAD_MIN_HIT          = int(os.environ.get("DEAD_MIN_HIT") or 2)      # 连续两轮才固化
DEAD_RECHECK_N        = int(os.environ.get("DEAD_RECHECK_N") or 50)   # 每轮抽样复测量
DEAD_DROP_MAX_RATIO   = float(os.environ.get("DEAD_DROP_MAX_RATIO") or 0.70)
DEAD_ROUND_FAIL_RATIO = float(os.environ.get("DEAD_ROUND_FAIL_RATIO") or 0.99)  # 本轮新死亡占比阈值 (源常态高死~90%, 抬到0.99防锁死缓存; env可调)
DEAD_ROUND_FAIL_MIN   = 3000              # 且绝对数阈值 (与条件, 防小池误触)

# 死因码 (照抄 speed_fail_reason / cross_fail_names 的归因风格)
DEAD_REASON_CHECK   = "schema"           # sing-box check≠0 → 确定性死, 重测不会好
DEAD_REASON_PORT    = "socks_not_ready"  # 端口未就绪 → 瞬时为主 (进程崩溃/负载)
DEAD_REASON_LIVE    = "liveness"         # 三源命中不足 → 瞬时为主 (实测占 84%)
DEAD_REASON_LATENCY = "latency"          # 延迟超限 → 瞬时/体验性
DEAD_REASON_STALLED = "stalled"          # 隧道通但速度不达标 (过了活性门槛)
DEAD_REASON_EXCEPT  = "exception"        # 兜底 except → 环境级

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
# ★ v3.2 顺序优化: 扩大连接池 (默认 pool_maxsize=10)。
#   测活阶段 24 个节点线程 × 组内多路并发请求 (活性3源+IP/丢包/回国/网页/MITM/WARP)
#   最高 ~120 个并发请求打向同一个 Session — urllib3 的连接池按 host 键计数,
#   超过 pool_maxsize 的请求会**排队等连接归还**, 组内并发被隐式串行化。
#   扩到 64: 小请求 (204/HTML头) 真并行, 请求密集阶段整体提速; 大流量测速
#   本来就是单节点串行下载, 不受影响。零判定变化, 纯速度。
_probe_adapter = requests.adapters.HTTPAdapter(
    pool_connections=64, pool_maxsize=64, max_retries=0)
PROBE_SESSION.mount("http://", _probe_adapter)
PROBE_SESSION.mount("https://", _probe_adapter)


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
# 凭据指纹 + 完整节点身份键 (v3 审计加固 → v3.2 测活期查重)
#
# ★ 审计发现的真实漏洞 (2026-10-16):
#   P0-3 (2026-10-11) 把 reality/transport.type 纳入了指纹, 但**没纳全** —
#   同样一份凭据 + 不同的服务端路由参数, 会被判为"同一节点":
#       vless://U@host:443?type=ws&path=/a     ← 代表, 测活通过
#       vless://U@host:443?type=ws&path=/b     ← 指纹相同被判重, 从不测活,
#                                                 回填继承代表的"可用"结论
#   而 path/host/obfs/sni 这些字段**服务端是按它路由的** — /a 通不代表 /b 通。
#   后果: 一个根本连不上的配置, 顶着继承来的测活结论混进最终订阅。
#   hy2 更明显: 旧指纹只有 password, 同密码不同 obfs-password/sni 全被判重。
#
# ★ 修复路径:
#   v3.2 之前: ① 指纹补全 (本函数) + ② 回填兜底 (_outbound_equiv 深度比较);
#   v3.2 (2026-10-18): 去重整体后移到测活阶段, 回填删除 — 每个节点都真测,
#     指纹完整性由 full_node_key (含真实出口 IP) 承载, equiv 兜底不再需要。
# ══════════════════════════════════════════════════════════════════

def _tr_field(tr: dict, *keys, default=""):
    """transport 字段取值 (host 在 headers.Host 里, 单独处理)"""
    for k in keys:
        v = tr.get(k)
        if v:
            return str(v)
    return default


def canonical_outbound_fp(outbound: dict) -> str:
    """节点配置身份指纹 = 整个 outbound dict 的规范化 JSON 序列化 (v3.3)

    ★ v3.3 换掉 v3.2 的手工枚举 cred_fingerprint() —— 根治那一类漏洞:
      旧实现逐协议手写字段表, 每加一个解析器字段就要补一次, 漏读即
      "同凭据不同配置被判为同一节点" → 漏测 + 继承错误结论。
      已实证漏读 5 类 (每一类都会误杀真实存在的不同节点):
        · uTLS fp             — L1011/L1022/L1172 生成了, 旧指纹却不读
        · h2/httpupgrade host — 旧实现只读 transport.headers.Host, 而 h2
          写在 transport["host"] (L1053, list)、httpupgrade 也写在
          transport["host"] (L1062, str) → 全漏。CDN 分流场景高发
        · grpc service_name   — 路由目标 (L1047/L1132), 不在旧指纹里
        · vmess alpn/insecure — 旧 vless 分支有, vmess 分支整段没有
        · 裸 TCP transport.type — L1031-1032 对 tcp/none/raw 返回 None,
          该位恒空
      改成序列化整个 outbound → 漏读在结构上不可能发生。
      ★ 严格超集证明: 旧指纹读的每个字段都存在于 outbound 之中, 即其
        字段集是 outbound 字段集的真子集 → 新指纹只会减少错杀, 绝不新增。

    规范化规则 (每条都对应一个具体的误杀/漏杀风险):
      ① 剔除 tag: 8 个解析器恒写死 "node" (L1079/1106/1159/1213/L1238/
         L1305/L1331/L1354), 带上只是噪声。
      ② dict 键排序: json.dumps(sort_keys=True) — 解析顺序与语义无关。
      ③ list 保序: alpn / server_ports / h2 host 都有序语义, 排序会把
         "顺序不同"压成"相同" → 新增错杀。保序只会把不同判为不同
         (多测几个, 宁慢不错), 方向安全。
      ④ type 敏感: json.dumps 天然区分 1 / "1" / true。旧实现用
         str(int(bool(x))) 把它们全压成同一个 "1", 是主动的类型混淆。
      ⑤ 异常兜底: 返回 "" → 调用方必须「空指纹不合并」(宁慢不错)。

    ★ hy2 server_ports 纳入键 (推翻 v3.2 L1473-1474 的手工排除):
      键的语义从「凭据身份」变成了「客户端配置身份」, 跳跃区间是配置的
      一部分。且 parse_hysteria2 L1252-1273 已把裸端口与区间统一规范
      成 "s:s", 不会因写法差异炸出假重复。hy2 只占 1.4% (220 个),
      最坏多测 220 个 ≈ 37 秒, 正确性优先。

    ★ 本函数已知不覆盖的 (解析器本身有损, 新旧指纹同样受影响, 本次不修):
      vless 的 packetEncoding/domainStrategy/multiplex/headerType/seed/
      mode(gun vs grpc 都归 grpc); vmess 的 scy (L1110 硬编码覆盖成
      "auto") 与 type(http 伪装); _parse_transport L1064 对未知 network
      静默返回 None (tcp/quic/kcp/无type 四者等价)。这些节点之间仍会
      互相误杀 —— 但这是**解析阶段**丢的信息, 任何基于 outbound 的指纹
      都救不回来, 需要在 parser 层修 (见设计文档第 15 节)。
    """
    try:
        obj = {k: v for k, v in outbound.items() if k != "tag"}
        return json.dumps(obj, sort_keys=True, ensure_ascii=False,
                          separators=(",", ":"))
    except Exception:
        # ★ 宽兜底而非只捕 (TypeError, ValueError): 上面的字典推导会先
        #   迭代 outbound.items(), 而 items() 是**调用方提供的对象**上的
        #   方法 —— 任何异常都可能在那里抛出 (不只是序列化阶段的 TypeError)。
        #   本函数的契约是"指纹失败就返回空串、调用方据此不合并", 所以
        #   任何异常都必须被吞掉, 否则一个畸形节点会让整个去重阶段崩掉。
        #   (实测: 自定义 dict 子类覆写 items() 抛 RuntimeError 即可复现)
        return ""  # 指纹失败 → 不合并 (宁慢不错)


# ══════════════════════════════════════════════════════════════════
# 完整节点身份键 + 测活期查重注册表 (v3.2 流程变更)
#
# ★ 流程变更 (2026-10-18, 用户要求): 去重从"测前静态指纹去重 + 测后回填"
#   整体后移到**测活阶段** —
#     旧: 测前按 (server, port, proto, 指纹) 去重 → 只测代表 → 测后回填克隆体
#     新: 测前**不重** (仅原有筛选) → 每个节点进测活 → 拿到完整真实信息
#         (含真实出口 IP) 后, 与**已成功测活**的节点注册表按完整键比对 →
#         重复则当场截断 (跳过测速/丢包/回国/网页全部后续) → 未重复才继续测
#   ★ 为什么更好:
#     ① 键含真实出口 IP + 完整指纹 — 比测前纯静态指纹信息更全, 判定更准;
#     ② 每个进订阅的节点都是**真跑过测活**的, 不再有"继承结论"的克隆体
#        (旧回填的 equiv/insecure 兜底复杂度整体消失);
#     ③ 失败节点的重复副本不被占位 — 同节点多源收录 = 多次机会, 瞬时
#        波动丢节点的概率比旧方案 (代表失败即全丢) 更低。
# ★ 回填已删除: 重复 URI 不再被提前剔除, 各自进测活被注册表挡掉,
#   "继承代表结果"失去意义 (评估结论见设计文档第 12 节)。
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
# 节点配置身份键 (v3.3) + 测前去重
#
# ★ v3.3 变更 (2026-10-18): 去重从 v3.2 的「测活期查重」**前移到测前**。
#   v3.2: 测前不去重 → 每个节点建隧道 (6~26s) 拿到真实信息后才比对 → 
#         重复节点只能省下测速段 (12~25s), 省不掉前置开销。
#   v3.3: 测前按「客户端配置身份」去重 → 重复节点连 sing-box 都不启动。
#         判重键不再含 exit_ip, 因此完全可以在**零网络零进程**时算完。
#   ★ 为什么移除 exit_ip (它是 v3.2 最大的开销来源):
#     exit_ip 是**服务端运行时属性**, 不是客户端配置属性。把它放进键里
#     会造成: 同一份配置因服务端轮换出口 → 判为不同节点 → 订阅里出现
#     两条配置完全相同的条目, 而出口由服务端负载均衡决定、**用户无法
#     控制**, 留两条纯是噪音。
#     出口维度的去重覆盖**没有丢**, 只是换到更准的层: classify 阶段的
#     三套 exit_ip 去重 (L4048 exit_ip:port / L4370 裸 exit_ip /
#     L4650 家宽合并 exit_ip:port) 都跑在**真实测活之后**, 拿到的是
#     exit_ip 真值, 比测前静态判断更准。
# ══════════════════════════════════════════════════════════════════

def node_key(outbound: dict, proto: str, server: str, port: int) -> str:
    """节点配置身份键 = 入口 + 完整 outbound 序列化 (v3.3, 不含 exit_ip)

    入口三元组 + 凭据/配置全字段全同 = 同一份客户端配置。
    ★ 服务器小写归一 (DNS 大小写不敏感); 不做 DNS 解析 ——
      "1.2.3.4" 与 "example.com" 指向同机时不该强行合并 (那是同机不同
      入口, 服务端可能配了不同的路由/限速), 保持字面判定更保守。
    """
    return "|".join([
        (server or "").lower(),
        str(int(port)),
        proto,
        canonical_outbound_fp(outbound),
    ])


def dedup_candidates(candidates: list) -> tuple:
    """测前去重: 同一份客户端配置只保留一个代表。返回 (kept, stats)

    ★ 为什么能在测活前做: 键 = node_key, 纯本地计算 (json.dumps),
      零网络零进程。免费池里同一份配置被 30 个源以不同名字收录是常态,
      而名字 (#fragment) 从不进 outbound —— 8 个解析器全部写死
      "tag": "node" (L1079/1106/1159/1213/1238/1305/1331/1354),
      所以「同一节点 30 个不同名字」能被完整命中, 不需要名字参与判定。

    ★ 单线程调用, seen 是纯局部 → 无锁。对照 _DEDUP_REGISTRY 为什么必须
      加 _DEDUP_LOCK: 那是 24 并发 worker 共享的读-改-写, 不是原子操作。
      本函数在 main() 里单线程调用一次, 不存在这种竞争。

    ★ 空指纹**不进 seen** —— v3.2 的 full_node_key L1538 把空串直接拼进
      键, 两个指纹失败的**不同**配置会撞成同一个键 → 误杀。本次修掉。

    ★ "代表失败即全丢" 的语义 (v3.1 及更早就是这样, 本次不引入新的):
      同 server:port 的多个副本 TCP 可达性是服务端属性, 所以把去重放在
      端口预检**之前**并不会让"代表被预检淘汰但副本本该通过" ——
      反而比 v3.1 更安全 (v3.1 去重在预检之后, 代表可能被预检淘汰)。
    """
    seen, kept = set(), []
    dropped = nofp = 0
    for item in candidates:
        raw, outbound, server, port, proto = item
        fp = canonical_outbound_fp(outbound)
        if not fp:
            nofp += 1
            kept.append(item)      # 指纹失败 → 保留, 不参与去重 (宁慢不错)
            continue
        k = (server.lower(), int(port), proto, fp)
        if k in seen:
            dropped += 1
            continue
        seen.add(k)
        kept.append(item)
    return kept, {"input": len(candidates), "kept": len(kept),
                  "dropped": dropped, "no_fingerprint": nofp}

# ══════════════════════════════════════════════════════════════════
# 死节点缓存读写 (v3.3)
#   本脚本第一个**跨进程持久化**模块 —— 此前所有缓存 (_DNS_CACHE /
#   _RDNS_CACHE / _DNS_POLLUTION_CACHE / _CB_STATE) 都是进程内内存字典,
#   随进程消失。没有先例可抄, 故参照 download_file (L899-941) 的四个
#   约定: 存在性检查 / .tmp 原子替换 / 失败清理 / 半截文件容错。
# ══════════════════════════════════════════════════════════════════

def _now_ts() -> int:
    return int(time.time())


def load_dead_cache() -> dict:
    """载入死节点缓存 → {node_key: {h, r, f, l, s}}

    ★ 容错分级 (半截/损坏都不能让整轮崩溃):
      ① 文件不存在 → 空 dict (首轮正常路径, 不是错误)
      ② gzip 流损坏 → 空 dict + 告警。比"读出一半"安全: 半份数据可能
         造成不该有的剔除, 而空缓存只是这轮多测一轮。
      ③ header 版本不符 → 空 dict + 告警。键算法变了旧键全部失配, 留着
         只会白占体积; 显式丢弃比静默失配干净 (否则日志上看不出为什么
         去重命中率突然掉到 0)。
      ④ 逐行解析失败 → 跳过该行 + 计数 + 告警。上次被 SIGKILL 写到一半
         的最后一行是真实场景, 不是理论风险。
      ⑤ 残留 .tmp → 忽略并删除 (写侧崩溃的遗留)。

    ★ TTL 3 天在这里判 (见常量区的说明: 不能靠 Actions 的 7 天淘汰)。
      判据用 max(l, s) 而非 l:
        l = 最近一次**测活确认死亡**; 固化的节点此后不再被测, l 会停住
        s = 最近一次**被剔除**(未测), 每轮剔除时刷新
      用 max 保证"持续被剔除的活跃死条目不因 TTL 被清" —— 清了它下轮
      就要重测 8~12s, 缓存白白损失。而真正长期不再出现在任何候选里的
      (源下架了), 两者都不刷新, 3 天后自然清掉。
      反之若把两者合并成一个"最后接触时间", 被持续剔除的节点每轮刷新
      → 永不过期 → 缓存变成只增不减的黑洞。
    """
    cache = {}
    if not DEAD_CACHE_ENABLED or not os.path.exists(DEAD_CACHE_FILE):
        return cache
    try:
        stale = DEAD_CACHE_FILE + ".tmp"
        if os.path.exists(stale):
            os.remove(stale)              # ⑤
    except OSError:
        pass
    try:
        with gzip.open(DEAD_CACHE_FILE, "rt", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"[!] 死节点缓存读取失败 ({str(e)[:70]}) — 本轮按空缓存处理")
        return cache
    if not lines:
        return cache
    try:
        hdr = json.loads(lines[0])
        if int(hdr.get("_v", 0)) != DEAD_CACHE_SCHEMA:
            print(f"[!] 死节点缓存版本 {hdr.get('_v')} ≠ 当前 {DEAD_CACHE_SCHEMA}, "
                  f"整份丢弃 (键算法可能已变, 留着只会白占体积)")
            return cache
    except Exception:
        print("[!] 死节点缓存 header 损坏 — 本轮按空缓存处理")
        return cache
    now = _now_ts()
    bad = expired = 0
    for ln in lines[1:]:                                   # ④
        ln = ln.strip()
        if not ln:
            continue
        try:
            rec = json.loads(ln)
            k = rec["k"]
            rec["h"] = int(rec.get("h", 1))
            rec["f"] = int(rec.get("f", now))
            rec["l"] = int(rec.get("l", now))
            rec["s"] = int(rec.get("s", 0))
        except Exception:
            bad += 1
            continue
        if now - max(rec["l"], rec["s"]) > DEAD_CACHE_TTL_SEC:
            expired += 1
            continue
        cache[k] = rec
    if bad or expired:
        print(f"[!] 死节点缓存: 坏行 {bad} (半截/格式错) | "
              f"TTL>{DEAD_CACHE_TTL_DAYS}天丢弃 {expired} | 有效 {len(cache)}")
    else:
        _solid = sum(1 for v in cache.values() if v["h"] >= DEAD_MIN_HIT)
        print(f"[*] 死节点缓存载入: {len(cache)} 条 "
              f"(已固化 h>={DEAD_MIN_HIT} {_solid} 条, 具备下轮剔除资格)")
    return cache


def save_dead_cache(cache: dict) -> bool:
    """原子写出死节点缓存 (照抄 download_file 的 .part → os.replace 模式)

    排序输出: 同内容 → 同字节, 便于人工 diff 与排查。
    """
    if not DEAD_CACHE_ENABLED:
        return False
    os.makedirs(DEAD_CACHE_DIR, exist_ok=True)
    tmp = DEAD_CACHE_FILE + ".tmp"
    try:
        with gzip.open(tmp, "wt", encoding="utf-8", compresslevel=6) as f:
            f.write(json.dumps({"_v": DEAD_CACHE_SCHEMA, "_n": len(cache),
                                "_saved": _now_ts()}, sort_keys=True) + "\n")
            for k in sorted(cache):
                f.write(json.dumps(cache[k], sort_keys=True,
                                   separators=(",", ":")) + "\n")
        os.replace(tmp, DEAD_CACHE_FILE)      # 原子替换: 半截文件永不出现在正式路径
        print(f"[+] 死节点缓存已写盘: {len(cache)} 条 / "
              f"{os.path.getsize(DEAD_CACHE_FILE) / 1024:.0f}KB "
              f"({os.path.relpath(DEAD_CACHE_FILE, BASEDIR)})")
        return True
    except Exception as e:
        print(f"[!] 死节点缓存写盘失败 ({str(e)[:70]}) — 下轮按空缓存处理 (不致命)")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def update_dead_cache(cache: dict, observed_dead: list,
                      observed_alive: set = None) -> tuple:
    """用本轮测活结果更新缓存 → (cache, stat)

    ★★★ 时序铁律 (本功能最容易错的地方) ★★★
      剔除发生在**测活之前** (select_dead_nodes), 所以本轮的测试结果
      **只能决定下一轮**是否剔除, 不能决定本轮。这里的 hit+1 写进磁盘,
      最早生效于下一轮的 load。

      两轮时序表:
        轮 N   读到 h=1 的条目 → 不具备剔除资格 → 照常测 → 若又死, 落盘 h=2
        轮 N+1 读到 h=2 → **这轮就剔除**, 不再测 (除非被抽样抽中)

    observed_dead: [(node_key, reason), ...] 本轮采集到的全部死亡 (含 is_stalled)
    observed_alive: set(node_key) 本轮测活通过且非 stalled 的节点键
                    (抽样复测的节点也在内 → 复活就走这条路径被删除)

    语义:
      · 死亡且不在缓存 → 新建 hit=1 (第一轮, **不剔除**, 本轮已照常测过)
      · 死亡且已在缓存 → hit += 1, l=now, reason 刷新为本轮原因
      · 存活且在缓存   → **删除该条** (复活)
      · 未出现在本轮候选里 (源下架) → 不动, 靠 TTL 自然清
    """
    now = _now_ts()
    stat = {"new": 0, "bump": 0, "revived": 0, "solid": 0}
    observed_alive = observed_alive or set()
    for k in observed_alive:
        if cache.pop(k, None) is not None:
            stat["revived"] += 1
    for k, reason in observed_dead:
        cur = cache.get(k)
        if cur is None:
            cache[k] = {"k": k, "h": 1, "r": reason,
                        "f": now, "l": now, "s": 0}
            stat["new"] += 1
        else:
            cur["h"] += 1
            cur["l"] = now
            cur["r"] = reason
            stat["bump"] += 1
    stat["solid"] = sum(1 for v in cache.values() if v["h"] >= DEAD_MIN_HIT)
    return cache, stat


def dead_cache_round_guard(cache: dict, stat: dict, n_candidates: int) -> bool:
    """环境级故障闸: False = 本轮死亡数据整轮不入缓存

    ★ 为什么必须有这道闸 (本功能唯一的灾难性风险):
      若某轮 runner 网络整体故障 / DNS 解析批量失败 / 源集体返回垃圾配置,
      会有**上万节点在同一轮全部判死**。此时"连续两轮"门槛在"两轮都坏"
      的情形下形同虚设, 而固化后下轮它们全被剔除 → 候选被清空。
      实测源常态高死: 2026-10-18 连续两轮 ~90% (8765 死 / 9698 候选), 且那轮
      仍有 1601 真活 + DNS 0 异常 → 是源质量退化, 非 runner 熔断。原阈值 0.80
      会把这种持续高死误判为故障 → 缓存永远建不起来, 故抬到 0.99: 只拦"≥99% 全灭"
      的真熔断。误杀兜底靠 DEAD_MIN_HIT=2 + DEAD_DROP_MAX_RATIO + 50/轮抽样复测,
      不靠这道单轮闸; 绝对数 3000 与比例是**与**关系, 小池子不会因比例高误触。

    ★ 缓解链的底座 (最坏后果的边界):
      main() 已有 `if not candidates: return` 会保留上次 output。所以即便
      上面所有防护全部失效, 最坏后果是"连续几轮拿不到新节点", 而不是
      "发布空订阅"。这一条是整个功能的安全底座。
    """
    fresh = stat["new"]
    if n_candidates >= DEAD_ROUND_FAIL_MIN and \
            fresh > n_candidates * DEAD_ROUND_FAIL_RATIO:
        print(f"[!] ★死节点缓存闸: 本轮新增死亡 {fresh} 条 (占候选 "
              f"{fresh * 100.0 / max(n_candidates, 1):.0f}%, 阈值 "
              f"{DEAD_ROUND_FAIL_RATIO:.0%}) → 判环境级故障, 本轮数据不入缓存")
        print(f"    → 沿用上一轮缓存 ({len(cache)} 条); "
              f"请检查日志里是否有源批量失败 / DNS 批量失败 / 网络故障")
        return False
    return True


def flush_dead_cache(cache: dict, observed_dead=None, observed_alive=None,
                     n_candidates: int = 0) -> bool:
    """把本轮结果合入缓存并写盘。返回是否真的写了。

    ★ 早写原则: 调用点在测活**之后立刻**执行, 不等 classify/导出 ——
      Actions cache 只在作业成功结束时才保存, 若等到 main() 末尾才写,
      一旦后续阶段崩溃/被并发限制杀掉就白丢一轮数据。文件早落盘, 剩下
      的只是"没被 Actions 存下来"这一个环节。
    """
    if not DEAD_CACHE_ENABLED:
        return False
    if observed_dead is not None:
        cache, stat = update_dead_cache(cache, observed_dead, observed_alive)
        if stat["new"] or stat["bump"] or stat["revived"]:
            print(f"[+] 死节点更新: 新增 {stat['new']} | hit累加 {stat['bump']} | "
                  f"复活删除 {stat['revived']} | 已固化(h>={DEAD_MIN_HIT}) {stat['solid']}")
            _rr = Counter(r for _k, r in observed_dead)
            if _rr:
                print("    本轮死因分布: "
                      + " | ".join(f"{k}:{v}" for k, v in _rr.most_common(6)))
        if not dead_cache_round_guard(cache, stat, n_candidates):
            return False      # 环境级故障 → 沿用上一轮, 不写盘
    return save_dead_cache(cache)


def _dead_hash(k: str) -> int:
    """确定性哈希 (md5 而非内置 hash) —— 跨进程稳定, 不受 PYTHONHASHSEED 影响

    ★ 为什么不用内置 hash(): str hash 默认随机化, 同一份缓存文件在两次
      运行里会得到不同的抽样结果, 日志无法复盘, 且"每轮剔同一批"的
      上限保护会退化成随机抖动。
    """
    return int(hashlib.md5(k.encode("utf-8", "replace")).hexdigest()[:8], 16)


def select_dead_nodes(candidates: list, cache: dict) -> tuple:
    """用死节点缓存剔除候选 (测活之前执行) → (kept, dropped)

    dropped: [(key, item, record), ...] 保留原始 item 是因为缓存里只有键、
      没有 outbound, 抽样复测要把它放回候选必须用原 item。

    ★ 三重闸:
      ① h >= DEAD_MIN_HIT (连续两轮) —— TTL 已在 load_dead_cache 判过
      ② DEAD_DROP_MAX_RATIO: 剔除量硬上限。按 _dead_hash 升序取到该比例
         为止, 其余照常进测活 —— 防"缓存占满 + 某轮候选全是它们"把候选
         清空到 0。按哈希序而非随机, 保证每轮被截断的是同一批。

    ★ 被剔除的条目 last_skip = now, 这是"持续剔除就不该过期"的实现;
      它靠抽样复测保持 hit 的活性 (否则固化的节点永不被测, h 永远停在
      DEAD_MIN_HIT, TTL 到期后又要全部重测一遍)。
    """
    if not cache or not DEAD_CACHE_ENABLED:
        return candidates, []
    solid = {k: v for k, v in cache.items() if v["h"] >= DEAD_MIN_HIT}
    if not solid:
        return candidates, []
    kept, dropped = [], []
    for it in candidates:
        try:
            k = node_key(it[1], it[4], it[2], it[3])
        except Exception:
            kept.append(it)
            continue
        if k in solid:
            dropped.append((k, it, solid[k]))
        else:
            kept.append(it)
    total = len(kept) + len(dropped)
    limit = int(total * DEAD_DROP_MAX_RATIO)
    if len(dropped) > limit:
        # ★ 上限截断在**小样本**下偏保守: 3 个候选 × 0.70 → int() 得 2,
        #   会留 1 个照常测活。生产环境候选量在万级, 这个比例上限只在
        #   "缓存占满候选池"时才真正生效, 小样本行为无实际影响。
        #   节点总数守恒 (截断时多余项回到 kept), 不会有节点凭空消失。
        dropped.sort(key=lambda d: _dead_hash(d[0]))
        kept.extend(d[1] for d in dropped[limit:])
        dropped = dropped[:limit]
    now = _now_ts()
    for k, _it, rec in dropped:
        rec["s"] = now
    if dropped:
        print(f"[+] ★死节点缓存剔除: {len(dropped)}/{total} 候选命中已固化死节点 "
              f"(连续{DEAD_MIN_HIT}轮 + TTL{DEAD_CACHE_TTL_DAYS}天), 提前不进测活")
        print(f"   预估省下 {len(dropped) * STAGE_B_WORST_SEC / MAX_WORKERS_TEST / 60:.1f} 分钟 "
              f"(每节点省最多 {STAGE_B_WORST_SEC:.0f}s 阶段B 开销)")
        _d = Counter(_rec.get("r", "?") for _k, _i, _rec in dropped)
        print("    死因分布: " + " | ".join(f"{k}:{v}" for k, v in _d.most_common(5)))
    return kept, dropped


def pick_dead_recheck(dropped: list, limit: int) -> list:
    """从被剔除条目里确定性抽样 limit 个放回候选 → [item, ...]

    ★ 为什么不用 random.sample: fetch_raw_nodes 返回 list(set), 顺序跨轮
      不确定 —— random 会让"这轮抽到哪些"变成纯随机, 日志无法复盘。
      md5(key) 升序取前 limit 个: ① 跨进程稳定 ② 每轮键集变了, 抽样
      集合自然跟着变 (不是永远只抽同一批) ③ 均匀覆盖全池而非字典序前缀。

    ★ 这同时是 hit 计数能持续累积的**唯一途径**: 固化后的节点若永不被测,
      h 永远停在 DEAD_MIN_HIT, TTL 到期后它们会被全部清掉、下一轮又要
      从头重新积累两轮才具备剔除资格 —— 缓存自己把自己废掉了。

    ★ 成本量级: DEAD_RECHECK_N / 候选数 ≈ 50/15467 = 0.32%, 可忽略。
      这 50 个换来的"复活捕捉 + hit 活性"是缓存不腐化的前提, 极划算。
    """
    if limit <= 0 or not dropped:
        return []
    ordered = sorted(dropped, key=lambda d: _dead_hash(d[0]))
    return [it for _k, it, _r in ordered[:limit]]


def final_gate(nodes: list, require_cn_signal: bool = False,
               label: str = "交付") -> tuple:
    """交付前最终闸门 (v3 审计加固 2026-10-16)

    ★ 为什么需要: 回填/去重/风险过滤跨多个函数协作, "没有未测活的节点混进
      订阅"不能只靠代码走查 — 用一次结构化断言把它变成可验证的事实。
      本闸门检查每个待交付节点:
        ① 判定字段完整: alive=True / is_stalled=False / mitm_risk=False /
           fraud_score 已评 / cn_score+cn_flags 已算 / outbound 可导出
        ② (友好订阅) DNS 信号闭合: 污染判定必须**明确得过** —
           cn_ok=True (至少一个大陆解析器明确返回正常) 或服务器是 IP 字面量。
           只认"没判污染"不够: CN DoH 整体不可达时污染检测会静默失效,
           被污染域名就靠其他分数混进友好订阅 (审计发现的覆盖缺口)。
           DNS 未闭合 → 只踢出友好订阅并清 🇨🇳 旗标, **不影响全量订阅**
           (该节点海外侧判定都过, 只是国内向缺证据, 宁缺毋滥)。
    返回 (通过的节点列表, 问题描述列表); 任何节点被拦都会打日志。
    """
    kept, problems = [], []
    for n in nodes:
        why = []
        if not n.get("alive"):
            why.append("alive=False")
        if n.get("is_stalled"):
            why.append("is_stalled=True")
        if n.get("mitm_risk"):
            why.append("mitm_risk=True")
        if "fraud_score" not in n or n.get("fraud_score") is None:
            why.append("fraud_score未评")
        if "cn_score" not in n or "cn_flags" not in n \
                or n.get("cn_score") is None or n.get("cn_flags") is None:
            why.append("cn_score未算")
        if not n.get("outbound"):
            why.append("outbound为空")
        dns_open_only = False
        if require_cn_signal and n.get("cn_friendly") and not why:
            # DNS 闭合: 要么明确判过 CN 解析正常, 要么是 IP 字面量 (无 DNS 面)
            flags = n.get("cn_prescore_flags") or []
            if not (("DNS正常" in flags) or ("直连IP" in flags)):
                why.append("DNS信号未闭合(污染判定无明确结论)")
                dns_open_only = True
        if why:
            if dns_open_only:
                # 仅 DNS 未闭合: 踢出友好订阅 + 清旗标, 节点本身留在全量
                n["cn_friendly"] = False
            problems.append(f"{n.get('proto')} {n.get('server')}:{n.get('port')} "
                            f"raw={str(n.get('raw'))[:50]} → {';'.join(why)}")
        else:
            kept.append(n)
    if problems:
        print(f"[!] 最终闸门({label}): 拦截 {len(problems)}/{len(nodes)} 个字段/信号不完整的节点")
        for p in problems[:5]:
            print(f"      · {p}")
        if len(problems) > 5:
            print(f"      · …其余 {len(problems) - 5} 条从略")
    else:
        print(f"[+] 最终闸门({label}): {len(kept)}/{len(nodes)} 个节点全部判定字段完整")
    return kept, problems


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
    """判断节点是否关闭了证书校验 (主动降级安全性, 测活阶段无法检出)

    ★ 2026-10-11 修复: 旧版只查**顶层** insecure 字段, 漏掉了 `tls.insecure` ——
      而 `_parse_tls_params()` (L826) 生成 vless/trojan 的 insecure 时, 写的正是
      `outbound["tls"]["insecure"]`。也就是说**所有 allowInsecure=1 的 vless/trojan
      节点, 静态预筛全部检测不到**, 这道闸对它们形同虚设。
      现在两种位置都查。
    """
    if not isinstance(outbound, dict):
        return False

    def _truthy(v) -> bool:
        return v is True or (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes"))

    tls = outbound.get("tls") if isinstance(outbound.get("tls"), dict) else {}

    # 1) insecure / allow_insecure 布尔开关 —— 顶层与 tls 内都要查 (★ 修复点)
    for f in INSECURE_FIELDS:
        if _truthy(outbound.get(f)) or _truthy(tls.get(f)):
            return True
    # tls.insecure 是 _parse_tls_params 的实际产出字段名, 单独兜一次
    if _truthy(tls.get("insecure")):
        return True
    # 2) tls.security = none (明文传输)
    if str(tls.get("security", "")).strip().lower() in NONE_SECURITY_VALUES:
        return True
    # 3) 走 TLS/Reality 但 sni 指向本地回环 (常见于生成错误的配置, 证书必然不匹配)
    #    注意: sni 缺失/为空本身不算危险 — 很多服务端靠 IP 或默认值协商,
    #    只有显式写成 127.0.0.1/localhost 才是配置错误。
    sni = outbound.get("sni") or outbound.get("servername") or tls.get("server_name")
    if isinstance(sni, str) and sni.strip().lower() in ("127.0.0.1", "::1", "localhost"):
        # 仅当该节点确实走 TLS/Reality 时才判定 (plain 协议无 sni 属正常)
        if tls or outbound.get("reality") or outbound.get("flow"):
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


def prefetch_dns(hosts, workers: int = 32):
    """并发预热 _DNS_CACHE (v3 新增)

    ★ 为什么需要: static_cn_prescore 要在端口预检**之前**跑, 而它要查入口 IP
      是否落在 CDN 网段 → 需要域名解析。若逐个串行 DoH, 2000 个唯一域名
      × ~0.3s = 10 分钟, 全烧在等待上。预检本身是 64 并发, 域名在预检时才
      第一次解析 —— 提前并发预热后, 预筛/预检全部命中缓存。
    返回: 成功解析数 (仅日志用)
    """
    todo = [h for h in {x for x in hosts if x} if not is_ip_literal(h) and h not in _DNS_CACHE]
    if not todo:
        return 0
    ok = [0]

    def _one(h):
        if resolve_host(h):
            ok[0] += 1

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_one, todo))
    return ok[0]


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
        # QUIC 无法 TCP 预检 UDP 端口连通性, 且本地 UDP 常被 QoS → 不硬淘汰。
        # ★ P1-2 修复 (2026-10-11): 但旧版无条件 return True, 连"域名已失效、
        #   DNS 都解析不出来"的节点也放行进阶段B, 白等 8.3s 单节点开销。
        #   现在至少验证域名可解析 + 端口合法 —— 解析失败基本等于节点已死。
        #   #70 实测 hysteria2 有 282 个全量进测活, 其中域名失效的占一部分。
        try:
            ip = resolve_host(server)
        except Exception:
            return False
        return bool(ip) and 0 < int(port) < 65536
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

    # ★ v3.2 顺序优化: 并发 64→128。域名解析已在 2.7 步预热, 本阶段纯 TCP
    #   握手 (0.1~2.5s), 128 并发对 Azure runner (FD 限制 1024+) 无压力,
    #   全死场景墙钟 78s → 39s, 一般场景省 ~10~20s。
    with ThreadPoolExecutor(max_workers=128) as ex:
        # ★ v3: 域名已在 2.7 步并发预热 (prefetch_dns), 这里全部命中缓存,
        #   128 并发的 TCP 握手就是本阶段唯一成本 (每候选 0.1~2.5s)。
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


def _sink_fail(sink, reason: str, item) -> None:
    """把一次死亡判定记进 sink (跨次运行死节点缓存的采集点)

    ★ 为什么需要它: test_single_node 的 5 个 `return None` 让"这个节点死了"
      在返回值层面**完全不可见** —— run_liveness_test 的 `if r:` 静默丢弃,
      调用方既不知道死了多少, 也拿不到死因。本函数是让"死"留痕的唯一途径。

    ★ 为什么 sink 是 list 而不是回调/模块级全局 dict:
      test_single_node 跑在 24 并发 worker 里, 每个 worker 在自己的调用栈
      里建一个局部 list → **天然无竞争, 不需要锁**。这与 _DEDUP_REGISTRY
      形成对照: 那个是跨 worker 共享的读-改-写, 必须加 _DEDUP_LOCK, 否则
      会漏计 (v3.2 注释里记着这个教训)。合并在主线程 fut.result() 处
      单线程 extend, 全程单线程写入。

    ★ 为什么用可选入参而不是模块级全局 list:
      ① 零竞争(同上); ② chain_retest 也调本函数 (lite=True), 显式不传
      sink → 链式复测的"双跳死"天然不会污染单跳死节点缓存; ③ None 语义
      完全不变 —— 5 个 return None 照旧返回 None, 下游 _work / _chain_one
      零改动。

    ★ item 必须是原始五元组 (raw, outbound, server, port, proto):
      node_key 需要 outbound 算凭据指纹, 而解包失败时这些变量还没绑定 ——
      所以传 item 而不是解包后的散装参数。解包/算键失败会被这里的 try
      吞掉: 记不出键就不记, 不制造垃圾条目。
    """
    if sink is None:
        return
    try:
        _, outbound, server, port, proto = item
        sink.append((node_key(outbound, proto, server, port), reason))
    except Exception:
        return


def test_single_node(item, keep_alive_check=True, chain_relay: dict = None,
                     lite: bool = False, fail_sink: list = None):
    """返回 dict 或 None; 含: 活性/延迟/出口IP/国家/ASN/ISP/速度/MITM/回国方向

    chain_relay: 可选的 sing-box outbound dict, 作为前置跳板 (detour 双跳)。
    ★ 2026-10-04 改造: 旧版从 os.environ["CHAIN_RELAY_OUT"] 读 relay, 改成显式入参。
      环境变量是**进程全局**的, 带来三个问题:
        ① 无法并发 —— chain_retest 只能串行跑 (#70: 62个候选耗 515s, 占总时长45%);
        ② 易污染 —— 中途异常若 finally 清理也失败, relay 会泄漏到后续所有阶段;
        ③ 隐式依赖 —— 单独调用 test_single_node 时行为受外部环境变量影响, 不可测。
      build_test_config 本就收 chain_relay 参数, 这里只是把来源从全局改为调用方显式传入。

    lite=True (v3 新增, 链式复测专用): 只跑 活性三源 + 出口IP + 3 秒轻测速 (~3s),
        跳过 MITM/WARP/复测/交叉/丢包/回国探测 —— 双跳复测只关心"隧道通不通",
        旧版在这里跑全量套件 (~8.3s/候选) 是纯浪费。

    ★ v3 并行化改造 (组内并发; 死节点最坏 ~52.5s → ~30s, 活节点省 1~8s):
      ① 活性三源探针 + 出口IP回声并发 (旧串行最坏 12+4+4+6=26s → max(12,6))
         —— 探针之间本就无依赖, 串行等待是纯烧时间; 出口IP与探针同样无依赖
      ② MITM 复检 + WARP 检测并发 (旧串行 4+4s → max(4,4))
      ③ 丢包探测 + 回国方向探测并发 —— 回国探测新增的耗时蹭丢包的等待窗口,
         净增 ≈ 0
      ④ 首测已低于吞吐门槛 → 跳过 1MB 复测 (注定断流, 省 4s × 大量节点)

    fail_sink (v3.3 新增): 可选的 list, 收集本次判定为"死"的 (node_key, reason)。
      ★ 为什么要它: 本函数有 5 个 `return None` (check≠0 / 端口未就绪 /
        三源命中不足 / 延迟超限 / 兜底异常), 而"死"在返回值层面**完全不可见**
        —— 调用方的 `if r:` 会静默丢弃, 于是"死多少、死在哪一环"一个字都看不到
        (实测一轮 13680 个里只有 2192 过门槛, 另外 11488 个怎么死的完全没有记录)。
        跨次运行死节点缓存需要这份数据才能判断"连续两轮都死"。
      ★ 每个 worker 传自己的局部 list → 24 并发下零竞争, 不需要锁。
      ★ chain_retest (lite=True) 不传 → 链式的"双跳死"不污染单跳缓存。
      ★ None 语义完全不变, 5 个 return None 照旧返回 None, 下游零改动。
    """
    # ★ v3.3 健壮性修复: 原来下面 5 行 (解包 item / _alloc_socks_port /
    #   build_test_config / 写 runtime/sb_*.json) 都在 try **之外**
    #   (try 从 sing-box check 之后才开始) —— 任何异常 (畸形 item、端口耗尽、
    #   磁盘满) 都会穿透 _work → fut.result() 重抛 → **整个测活阶段崩掉**,
    #   一轮白跑。另外 check≠0 的 return None 不经过 finally → 配置文件
    #   残留 (每轮几百个 sb_*.json 堆在 runtime/)。
    #   现在整段纳入同一个 try/finally: 异常统一归为 DEAD_REASON_EXCEPT,
    #   且 cfg_path 由 finally 无条件清理。
    proc = None
    result = None
    cfg_path = None
    try:
        raw, outbound, server, port, proto = item
        socks_port = _alloc_socks_port()
        task_id = uuid.uuid4().hex[:10]
        cfg_path = os.path.join(RUNTIME_DIR, f"sb_{task_id}.json")

        # 链式前置 (chain relay): 由调用方显式传入 (chain_retest 用, 模拟 v2rayN 链式)
        config = build_test_config(outbound, socks_port, chain_relay=chain_relay)
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f)

        exe = SINGBOX_BIN + (".exe" if os.name == "nt" else "")

        # --- 0) sing-box check 预校验: 快速淘汰 schema 错误 (实测可发现 2022 密钥长度/端口区间等错误) ---
        try:
            chk = subprocess.run([exe, "check", "-c", cfg_path],
                                 capture_output=True, text=True, timeout=15,
                                 creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0))
            if chk.returncode != 0:
                # ★ 确定性死: schema 错误重测也不会好, 是死节点缓存里最值得
                #   固化的那类 (对比 liveness/端口未就绪等瞬时死)
                _sink_fail(fail_sink, DEAD_REASON_CHECK, item)
                return None  # 配置级错误 → 该节点无法被 sing-box 使用, 必淘汰
        except Exception:
            pass  # check 本身失败不阻止后续 run 尝试

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
            # ★ 瞬时为主: 进程崩溃可能是配置错, 也可能是端口冲突/机器负载,
            #   代码捕获不到崩溃原因 (stdout/stderr 全 DEVNULL) → 归为瞬时
            _sink_fail(fail_sink, DEAD_REASON_PORT, item)
            return None

        proxies = {"http": f"socks5h://127.0.0.1:{socks_port}",
                   "https": f"socks5h://127.0.0.1:{socks_port}"}

        # --- 1) 活性探测 (跨源多探针) + 出口 IP 回声 — v3: 并发执行 ---
        #     延迟按"每次尝试各自计时"取最快一次, 不用跨尝试的累计时间:
        #     旧版 t0 在循环外, 若首击耗满 12s 才失败、第二个 URL 秒通,
        #     latency 会记成 ~12s 而非真实 RTT → 去重/排序全被污染 (慢节点反被优先)
        #     ★ 三个源全部探完 (不提前 break): 识别"只对单源通"的选择性转发节点
        #     ★ v3: 三源探针 + 出口IP 四个请求互相无依赖, 并发发;
        #        死节点最坏从 12+4+4+6=26s 降到 max(12,6)=12s
        def _probe_one(idx, name, url, expect):
            timeout = PROBE_TIMEOUT if idx == 0 else PROBE_RETRY_TIMEOUT
            t_try = time.time()
            try:
                r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout,
                                      allow_redirects=False)
                if r.status_code in expect:
                    return True, (time.time() - t_try) * 1000
            except Exception:
                pass
            # 该源明确拒绝 (403/407/302 等) = 选择性转发, 不直接判死,
            # 交给 MIN_LIVENESS_HITS 裁决
            return False, 0.0

        def _fetch_exit_ip():
            """真实出口 IP (多路冗余) — 与探针并发, 不额外占墙钟时间"""
            for url in IP_ECHO_URLS:
                try:
                    r = PROBE_SESSION.get(url, proxies=proxies, timeout=IP_ECHO_TIMEOUT)
                    if r.status_code != 200:
                        continue
                    j = r.json()
                    ip = (j.get("ip") or j.get("query") or j.get("your_ip") or "").strip()
                    if not ip:
                        continue
                    country = asn = asn_org = isp = None
                    if url.startswith("https://api.ip.sb"):
                        country = j.get("country_code")
                        asn = j.get("asn")
                        asn_org = (j.get("asn_organization") or j.get("organization") or "")
                        isp = (j.get("isp") or j.get("organization") or "")
                    elif url.startswith("https://ipinfo.io"):
                        country = country or (j.get("country") or "").upper()
                        org = j.get("org") or ""
                        if org and not asn:
                            mm = re.match(r"^AS(\d+)\s+(.*)", org)
                            if mm:
                                asn, asn_org = int(mm.group(1)), mm.group(2)
                        isp = isp or org
                    elif "ip-api.com" in url:
                        country = country or (j.get("countryCode") or "").upper()
                        asn = asn or j.get("as")
                        asn_org = asn_org or (j.get("asname") or j.get("org") or "")
                        isp = isp or (j.get("isp") or j.get("org") or "")
                    return ip, country, asn, asn_org, isp
                except Exception:
                    continue
            return None, None, None, None, None

        alive_hits, latency_ms = 0, 99999
        exit_ip = exit_country = exit_asn = exit_asn_org = exit_isp = None
        with ThreadPoolExecutor(max_workers=4) as grp:
            probe_futs = [grp.submit(_probe_one, i, n, u, e)
                          for i, (n, u, e) in enumerate(LIVENESS_PROBES)]
            ip_fut = grp.submit(_fetch_exit_ip)
            for f in as_completed(probe_futs):
                ok, ms = f.result()
                if ok:
                    alive_hits += 1
                    if ms < latency_ms:
                        latency_ms = ms
            exit_ip, exit_country, exit_asn, exit_asn_org, exit_isp = ip_fut.result()

        if alive_hits < MIN_LIVENESS_HITS:
            # ★ 瞬时为主: 三源取二的设计本身就是为容忍抖动 (L2258-2259 注释
            #   "该源明确拒绝 = 选择性转发, 不直接判死, 交给 MIN_LIVENESS_HITS
            #   裁决")。实测这一类占全部死亡的 84% —— 所以死节点缓存必须靠
            #   "连续两轮"门槛, 单轮判死绝不能信。
            _sink_fail(fail_sink, DEAD_REASON_LIVE, item)
            return None
        # 延迟上限门槛: 活性过了但延迟过高的节点体验极差, 此前延迟只排序不淘汰
        if latency_ms > MAX_LATENCY_MS:
            _sink_fail(fail_sink, DEAD_REASON_LATENCY, item)
            return None

        # --- 2.5) v3.3: 测活期查重闸已整体删除 ---
        #   旧方案在这里拿"配置 + 真实出口 IP"与已成功节点注册表比对, 重复
        #   就截断后续测活。但它位置太靠后: sing-box check + 进程启动 +
        #   三源探测 + 出口 IP 已经付掉了 6~26s, 查重只能省下测速段的
        #   12~25s —— 而**真正该省的重复节点本该一次都不启动进程**。
        #   v3.3 把去重前移到测活前 (dedup_candidates, 零网络零进程),
        #   键也不再含 exit_ip, 所以这里天然不可能再有重复, 整段删除。
        #   ★ 顺带修掉一个功能性 bug: 旧代码条件是 `if dedup_check:`
        #     但注释写着"lite 模式不查重" —— 少了 `and not lite`, 而
        #     chain_retest 调用时 dedup_check 取默认 True, 会 100% 命中
        #     → 家宽候选全被误标 _chain_failed → 家宽专区永远为空。

        # --- lite 模式 (v3, 链式复测专用): 隧道通 + 出口正常 + 轻测速即判双跳可用 ---
        if lite:
            spd, _fail = measure_download_speed(proxies, SPEED_TEST_URLS,
                                                3.0, 0.3)
            return {
                "raw": raw, "server": server, "port": port, "proto": proto,
                "outbound": outbound, "alive": True, "alive_hits": alive_hits,
                "latency_ms": int(latency_ms), "exit_ip": exit_ip,
                "exit_country_online": exit_country,
                "exit_asn_online": exit_asn,
                "exit_asn_org_online": (exit_asn_org or "")[:120],
                "exit_isp_online": (exit_isp or "")[:120],
                "mitm_risk": False, "is_warp": False,
                "speed_bps": spd, "speed_retest_bps": 0,
                "retest_failed": False, "retest_fail_reason": "",
                "speed_fail_reason": _fail or "",
                "speed_cross_bps": 0, "cross_fail_names": [],
                "cross_fail_reasons": [], "cross_all_failed": False,
                "cross_skipped": True, "speed_shortcircuit": False,
                "speed_unstable": False, "ttfb_ms": 0, "ttfb_slow": False,
                "loss_rate": None, "loss_unstable": False,
                "is_premium": False, "is_stalled": spd < SPEED_MIN_BYTES_PER_S,
                "cn_exit_rtt_ms": None, "cn_exit_reachable": False,
                "cn_exit_http_ok": 0, "retest_skipped": True, "_lite": True,
                # v3.1 网页探测: lite 模式不跑 (链式复测只关心隧道通不通)
                "web_reachable": 0, "web_blocked": 0, "web_timeout": 0,
                "web_flags": [], "web_dead": False, "web_detail": "未测(lite)",
            }

        # --- 3) MITM 劫持检测 + WARP 套壳检测 (定义在此, 执行后移至组 C) ---
        #   ★ v3.2 顺序优化: 这两个检查原来在测速前串行组 (4s), 但它们只服务
        #     "最终出库判定" (mitm→剔除, warp→drop) — 注定断流的节点跑了也白跑。
        #     现后移进组 C 与丢包/回国/网页 5 路并发, 且只对 speed_pass 节点执行;
        #     未执行的节点 mitm_risk/is_warp 取默认 False (它们 is_stalled,
        #     根本进不了订阅, 无判定影响)。
        def _mitm_check():
            # 3a) 独立复检一次带 verify=True 的请求: SSLError = TLS 拦截
            try:
                r = PROBE_SESSION.get("https://www.gstatic.com/generate_204",
                                      proxies=proxies, timeout=PROBE_RETRY_TIMEOUT,
                                      verify=True)
                if r.status_code in (204, 200):
                    return False
                return r.status_code in (301, 302, 403, 407, 502, 503) or len(r.content) > 0
            except requests.exceptions.SSLError:
                # 证书链验证失败 = TLS 拦截 (MITM) 或劣质自签劫持
                return True
            except Exception:
                return False  # 网络层失败不算 MITM (活性探测已通过)

        def _warp_check():
            # 3b) cloudflare trace: warp=on = 套壳 WARP 节点 (非真实出口, 降权标记)
            try:
                r = PROBE_SESSION.get(TRACE_URL, proxies=proxies,
                                      timeout=PROBE_RETRY_TIMEOUT, verify=True)
                if r.status_code == 200:
                    if re.search(r"^warp=on", r.text, re.M):
                        return True
            except Exception:
                pass
            return False

        mitm_risk = False      # 默认值; 仅 speed_pass 节点实测 (见组 C)
        is_warp = False

        # --- 4) 断流检测: 限时下载测速 (稳态吞吐, 剔除握手期; 端点多路兜底) ---
        #     with_ttfb=True 同时取首包时间 (与握手 RTT 互补, 见下方 TTFB 判定)
        speed_bps, ttfb_ms, speed_fail = measure_download_speed(
            proxies, SPEED_TEST_URLS, SPEED_TEST_BUDGET, SPEED_WARMUP, with_ttfb=True)

        # --- 4b) 二次复测 (稳定性闸): 1MB 小样本, 与首测取最小值 ---
        #   动机: 单轮测速会被 CDN 缓存层 / TCP 突发流量骗过 (瞬时冲高后断流)。
        #   复测明显掉速 → 首测虚高, 取小值入库。
        #   ★ v3 新增门槛闸: 首测已低于 SPEED_MIN_BYTES_PER_S 的节点注定断流
        #     (惩罚系数 ≥1, 门槛只升不降), 复测无论什么结果都改变不了结局,
        #     还要白等 4s — 直接跳过 (实测大量节点死在这一步, 累计省数分钟)。
        #   ★ 2026-10-04 修正 (#67 事故): 旧版"复测完全失败 → speed_bps=0 直接判死"。
        #     复测只有 1MB 样本 / 4 秒预算, 本身失败率高 (端点抖动、超时、样本不足),
        #     把"复测没测出来"等同于"节点已断流"会产生大量误杀。
        #     现在改为: 复测失败只标记 retest_failed, 保留首测结果继续判定。
        speed_retest = 0
        retest_failed = False
        retest_fail_reason = ""
        retest_skipped = False
        speed_unstable = False
        if speed_bps >= SPEED_MIN_BYTES_PER_S:
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
        elif speed_bps > 0:
            retest_skipped = True   # 低于门槛, 跳过复测 (v3)

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
        #   ★ v3: 低于门槛的节点已在上面跳过复测, 且慢节点不可能触发短路信号,
        #     因此交叉对这一大类节点天然不再执行 (省 5~8s × 大量)。
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

        # --- 5) 丢包 + 回国 + 真实网页 + MITM + WARP — v3.2: 五路并发 ---
        #   (仅对已过吞吐门槛的节点; 注定断流的节点不配再花 1 秒)
        #   丢包: 复用 204 探针连发, 零额外带宽成本。
        #   回国方向 (v3): 裸 SOCKS5 握手国内公共 DNS 量回国 RTT + 经节点
        #     请求 baidu/bilibili/jd 验回国可达性。
        #   真实网页 (v3.1): 经节点请求 wikipedia/github/google, 只拿响应头 —
        #     204 和 CF 测速端点是对出口 IP 最宽容的目标, "延迟好看+测速过"
        #     的节点用户开普通网页照样 403/转圈; 三个目标全不可达 = 假活, 判死。
        #   MITM/WARP (v3.2 后移至此): 原在测速前串行跑 (4s×全部节点),
        #     但它们只服务出库判定 — 后移后 ① 死节点不再白跑 4s ② 与其余四路
        #     并发, 活节点墙钟 = max(4, 丢包, 回国, 网页) 而非累加。
        #   ★ 2026-10-04 修正 (#67 事故): 旧版写 `else 1.0`, 把"没测到丢包"直接
        #     等同于"100% 丢包", 于是 speed_bps=0 的节点全被判死, 造成
        #     **真活 0** (实测 #67: 480 个节点全被填 100% 丢包后判死,
        #      而 TTFB 中位 634ms 明明证明隧道是通的)。
        #     现在用 None 表示"未测", 判定时跳过丢包维度, 交由吞吐门槛裁决。
        loss_rate = None
        cn_exit = {"rtt_ms": None, "http_ok": 0,
                   "http_total": len(CN_EXIT_HTTP_PROBES),
                   "reachable": False, "detail": "未测(未过吞吐门槛)"}
        web_load = {"reachable": 0, "blocked": 0, "timeout": 0,
                    "total": len(WEB_CHECK_PROBES), "detail": "未测(未过吞吐门槛)"}
        speed_pass = speed_bps >= SPEED_MIN_BYTES_PER_S
        if speed_pass:
            with ThreadPoolExecutor(max_workers=5) as grp:
                loss_fut = grp.submit(measure_packet_loss, proxies, LOSS_PROBE_COUNT)
                cn_fut = grp.submit(probe_cn_exit, proxies, socks_port)
                web_fut = grp.submit(probe_web_load, proxies)
                mitm_fut = grp.submit(_mitm_check)
                warp_fut = grp.submit(_warp_check)
                loss_rate = loss_fut.result()
                cn_exit = cn_fut.result()
                web_load = web_fut.result()
                mitm_risk = mitm_fut.result()
                is_warp = warp_fut.result()
        # 丢包 ≥ MAX_LOSS_RATE → 不可用; LOSS_UNSTABLE_PENALTY~MAX 之间 → 不稳
        # ★ None (未测) 不参与任何丢包判定, 绝不能当成丢包
        loss_unstable = (loss_rate is not None
                         and LOSS_UNSTABLE_PENALTY <= loss_rate < MAX_LOSS_RATE)
        if loss_rate is not None and loss_rate >= MAX_LOSS_RATE:
            speed_bps = 0            # 判死: 走下面 is_stalled 统一出口

        # --- 5b) 真实网页加载判定 (v3.1) ---
        #   三个真实网站目标全部不可达 → 判死 (204/测速全过但网页全打不开 =
        #   选择性转发或出口 IP 被全面封杀的假活节点, 对普通用户即废节点)
        web_dead, web_flags = _web_load_verdict(web_load)
        if web_dead:
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

        # ★ v3.3: is_stalled (隧道通但速度不达标) 也要进死节点缓存。
        #   它过了活性门槛, 却要跑完 测速+复测+交叉+丢包+回国+网页 五大步
        #   才被判死 (实测最贵的一类死法, 单节点 16~25s), 而缓存能让它下轮
        #   直接不进测活。
        #   ★ 注意它是**返回值**不是 return None, 所以会进 results 并走完
        #     classify/export 全流程 (只是被 is_stalled 过滤掉), 必须在这里
        #     显式采集 —— 否则这一大类完全拿不到。
        #   ★ 更新缓存时算 observed_alive 必须过滤掉 is_stalled, 否则同一条
        #     会既"死"又"活", hit 与复活判定互相矛盾。
        if is_stalled:
            _sink_fail(fail_sink, DEAD_REASON_STALLED, item)

        # ★ v3.3: 原此处有 "测活成功 → 登记完整节点键" 的 dedup_register
        #   调用, 已随测活期查重闸整体删除 (见上方 2.5 的说明)。现在每个
        #   进入测活的节点都是唯一配置, 无需再登记。

        result = {
            "raw": raw,
            "server": server,
            "port": port,
            "proto": proto,
            "outbound": outbound,      # classify 阶段重算入口情报 + 重建导出用
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
            "retest_skipped": retest_skipped,        # v3: 低于门槛跳过复测
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
            # ── v3 国内可用性字段 ──
            "cn_exit_rtt_ms": cn_exit.get("rtt_ms"),          # 回国 RTT (出口→国内 DNS)
            "cn_exit_reachable": cn_exit.get("reachable"),    # 回国 HTTP 可达 (baidu/bili/jd)
            "cn_exit_http_ok": cn_exit.get("http_ok", 0),
            "cn_exit_detail": cn_exit.get("detail", ""),
            # ── v3.1 真实网页加载字段 ──
            "web_reachable": web_load.get("reachable", 0),
            "web_blocked": web_load.get("blocked", 0),
            "web_timeout": web_load.get("timeout", 0),
            "web_flags": web_flags,
            "web_dead": web_dead,
            "web_detail": web_load.get("detail", ""),
        }
        return result
    except Exception:
        # ★ v3.3: 环境级故障 (Popen 失败/二进制缺失/内存错误等), 不是节点问题。
        #   仍记进 sink 是为了死因归因日志能看出"exception 计数异常高"这个
        #   危险信号 (那意味着是环境炸了, 而不是一个批节点坏了)。
        _sink_fail(fail_sink, DEAD_REASON_EXCEPT, item)
        return None
    finally:
        if proc and proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=3)
            except Exception:
                pass
        # ★ v3.3: cfg_path 可能为 None —— 现在解包 item / 建配置都在 try 内,
        #   若在最开头就抛异常 (畸形 item), cfg_path 仍是 None。旧代码里
        #   cfg_path 声明在 try 外所以永远有值, 现在必须加守卫。
        if cfg_path:
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


def run_liveness_test(candidates: list, prescore_map: dict = None) -> tuple:
    """返回 (results, dead_records)

    ★ v3.3 返回值变更: 由 list 改为 (results, dead_records)。
      dead_records = [(node_key, reason), ...] —— 本轮所有判死的节点,
      含 is_stalled (它走**返回值**路径, 不在 results 的死视角里)。
      唯一调用点是 main(), 改签名成本为零, 换来死节点完全可观测
      (此前 `if r:` 把 None 静默丢弃, 13680 个里另外 11488 个怎么死的
      一个字都没有, 跨次缓存更无从谈起)。
    """
    print(f"[*] sing-box 全协议真实测活: {len(candidates)} 节点 (并发 {MAX_WORKERS_TEST}) ...")
    results = []
    dead_records = []
    done_count = [0]
    # 端点熔断状态按轮次重置 —— 端点可达性会随时间漂移, 不跨轮沿用
    _reset_endpoint_breaker()
    # v3.3: 测活期查重注册表已删除 (去重前移到测前 dedup_candidates)
    # v3: 静态 CN 预测分随结果透传给 classify 阶段
    prescore_map = prescore_map or {}

    # ★ v3.3 防御断言: 去重应该在测活前就完成, 候选集理应唯一。
    #   不是性能优化, 而是"去重被绕过"的显式告警 —— 否则重复节点会各自
    #   跑完整流程, 而日志上看不出任何异常 (这是 v3.2 查重闸恒不命中时
    #   最容易被忽略的失败模式)。10 万次哈希 < 30ms, 可忽略不计。
    _seen_keys = {node_key(it[1], it[4], it[2], it[3]) for it in candidates}
    if len(_seen_keys) != len(candidates):
        print(f"[!] 候选集含 {len(candidates) - len(_seen_keys)} 个重复配置 "
              f"(dedup_candidates 被绕过?) — 重复项将各自跑完整流程")

    def _work(item):
        # ★ 每个 worker 调用栈一个**独立局部 list** → worker 线程独占,
        #   无锁 (对照: _DEDUP_REGISTRY 必须加 _DEDUP_LOCK, 因为它是跨
        #   worker 共享的读-改-写)。合并在主线程做, 也是单线程。
        fails = []
        r = test_single_node(item, fail_sink=fails)
        if r:
            ps = prescore_map.get(item[0])
            if ps:
                r["cn_prescore"], r["cn_prescore_flags"] = ps
        return r, fails

    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = {ex.submit(_work, it): it for it in candidates}
        for fut in as_completed(futs):
            done_count[0] += 1
            r, fails = fut.result()
            dead_records.extend(fails)     # ★ 主线程单线程合并, 无竞争
            if r:
                results.append(r)
            if done_count[0] % 40 == 0:
                print(f"[*] 测活进度: {done_count[0]}/{len(candidates)}, "
                      f"通过 {len(results)}")

    # ★ v3.3 死亡归因日志 —— 此前这些信息完全不可见:
    #   实测一轮 13680 个里只有 2192 过活性门槛, 另外那批怎么死的、死在哪
    #   一环, 旧版一个字都没有 (被 `if r:` 静默丢弃)。现在直接可读, 也是
    #   死节点缓存"哪类死值得固化"的判断依据 (schema 确定性死 vs liveness 瞬时死)。
    _dead_measured = len(dead_records) + len(results) - 0
    print(f"[+] ★死亡归因: 本轮判死 {len(dead_records)} 个 "
          f"(占已测 {_dead_measured}, {len(dead_records) * 100.0 / max(_dead_measured, 1):.0f}%)")
    if dead_records:
        _dr = Counter(r for _k, r in dead_records)
        print("    " + " | ".join(f"{k}:{v}" for k, v in _dr.most_common(6)))

    alive = [r for r in results if r["alive"] and not r["is_stalled"]]
    mitm = sum(1 for r in results if r["mitm_risk"])
    stalled = sum(1 for r in results if r["is_stalled"])
    unstable = sum(1 for r in results if r.get("speed_unstable"))
    premium = sum(1 for r in results if r.get("is_premium"))
    retest_skipped = sum(1 for r in results if r.get("retest_skipped"))
    speeds = sorted((r["speed_bps"] for r in results if r["speed_bps"] > 0), reverse=True)
    print(f"[+] 测活完成: 真活 {len(alive)} | 断流淘汰 {stalled} (其中 {retest_skipped} 个首测即低于门槛, "
          f"已跳过复测省 ~4s/个) | 测活期死 {len(candidates) - len(results)} (未过门槛, v3.3 已改为测前去重, 此处仅统计) | MITM 风险 {mitm}")

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
    # v3.1 真实网页加载统计 (204/测速过但网页打不开的假活节点, 在此现形)
    web_tested = [r for r in results if r.get("web_detail") and not r.get("web_detail", "").startswith("未测")]
    if web_tested:
        w_dead = sum(1 for r in web_tested if r.get("web_dead"))
        w_blocked = sum(1 for r in web_tested
                        if any("网页被拦" in f for f in (r.get("web_flags") or [])))
        w_allok = sum(1 for r in web_tested if "网页全通" in (r.get("web_flags") or []))
        print(f"[+] 真实网页加载 (wikipedia/github/google, v3.1): 已测 {len(web_tested)} | "
              f"全通 {w_allok} | 有被拦⚠B {w_blocked} | 全不通判死 {w_dead}")
        if w_dead:
            print(f"    → {w_dead} 个节点 204/测速全过但真实网页全打不开 (选择性转发/出口IP被WAF封杀), 已判死")
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

    return results, dead_records  # results 保留全部信息, 分类阶段再决定去留


# ═══════════════════════════════════════════N═══════════════════════
# 阶段 B2: 家宽链式复测 (chain relay retest)
# ════════════════════════════════════════════════════════════════════

def chain_retest(test_results: list, ip_api_info: dict = None) -> list:
    """家宽链式复测: 模拟用户 v2rayN 链式 (前置 → 家宽节点 → 目标)

    实测背景: 用户反馈家宽节点在 v2rayN 链式代理下仅 ~50% 可用。
    根因: 单跳测活通过 ≠ 双跳可用 (部分节点不允许"已被代理的流量"再入,
    或 UDP/QUIC 节点无法过 socks 链)。解决: CI 里用最快存活节点当前置,
    对家宽候选做双跳复测 — 双跳通过的才进家宽专区。

    流程: 复用已查好的 ip-api 结果拿家宽候选 → 取最快存活节点做 relay →
    家宽候选**并发**双跳复测 → 双跳死的标记 _chain_failed (降级普通区)。
    返回: 更新标记后的 test_results (原对象原地修改)。

    ★ 2026-10-04 三项优化 (#70 实测 62 候选耗时 515s, 占总时长 45%):
      ① 复用 ip_api_info: 旧版在这里又调一次 ip_api_batch_lookup, 而
         classify_and_export 里还有一次 —— 同一个 IP 集合查两遍。
         ip-api 免费额度限 15 req/min, 517 IP = 6 批 ≈ 25s, 白多花一半额度。
         现在由调用方传入, 查不到时再回退到自行查询 (保持函数可独立调用)。
      ② 并发化: 旧版是纯串行 for 循环, 62 个候选 × 8.3s = 515s。
         改 ThreadPoolExecutor 复用 MAX_WORKERS_TEST, 预期降到 ~25s。
      ③ relay 改显式传参 (test_single_node 的 chain_relay 入参), 不再用
         os.environ —— 环境变量是进程全局的, 既阻塞并发, 也可能泄漏污染后续阶段。
    """
    # 1) 轻量分类拿家宽候选 (复用 classify_and_export 的候选判定, 但不导出)
    #    家宽候选 = ip-api/mmdb 六信号判 residential/mobile 且置信度 >= 60 的节点
    if ip_api_info is None:
        # 回退路径: 调用方没传就自己查 (独立调用时的兜底)
        all_ips = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
        if not all_ips:
            print("[*] 链式复测: 无出口 IP, 跳过")
            return test_results
        try:
            ip_api_info = ip_api_batch_lookup(all_ips)
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
    print(f"[*] 链式复测: {len(res_candidates)} 个家宽候选 (并发 {MAX_WORKERS_TEST})")

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
    # ★ 深拷贝: 并发时多个候选共享同一 relay dict, 浅拷贝下任一线程改动
    #   都会污染其他线程的测试配置 (build_test_config 内部还会 pop 字段)
    relay_out = json.loads(json.dumps(relay_out))
    relay_out.pop("detour", None)
    print(f"[*] 链式 relay: {relay_result['proto']} {relay_result['server']}:{relay_result['port']} "
          f"(延迟 {relay_result['latency_ms']}ms)")

    # 3) 家宽候选**并发**双跳复测 (relay 显式传参, 无全局状态)
    #    ★ 为什么要并发: 旧版串行 #70 实测 515s (62候选×8.3s), 占总时长 45%。
    #    ★ 单节点异常不中断整体: 每个 future 单独捕获, 记为双跳失败继续跑,
    #       避免一个坏节点把整轮复测结果全丢 (旧版一个异常会中断整个 for 循环)。
    def _chain_one(key_r):
        _, r = key_r
        try:
            item = (r["raw"], r.get("outbound") or (parse_node_uri(r["raw"]) or [None])[0],
                    r["server"], r["port"], r["proto"])
            if not item[1]:
                return r, False
            # ★ v3: lite=True — 双跳复测只关心"隧道通不通", 跑全量套件
            #   (MITM/WARP/复测/交叉/丢包/回国 ~8.3s) 是纯浪费, 轻量模式 ~3s。
            recheck = test_single_node(item, chain_relay=relay_out, lite=True)
            return r, bool(recheck and recheck.get("alive") and not recheck.get("is_stalled"))
        except Exception:
            return r, False      # 异常 = 双跳不可用, 不让单点失败拖垮整轮

    chain_alive, chain_dead = [], []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS_TEST) as ex:
        futs = [ex.submit(_chain_one, kr) for kr in res_candidates.items()]
        for fut in as_completed(futs):
            r, ok = fut.result()
            (chain_alive if ok else chain_dead).append(r)

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


_RDNS_CACHE = {}
_RDNS_LOCK = threading.Lock()


def get_rdns(ip: str) -> str:
    """rDNS 反查 (带缓存) — v3: 旧版无缓存且被 classify 单线程循环调用,
    每个 unknown 节点一次 2s 超时, 400 节点最坏 800s (13 分钟) 全烧在这。
    现在: 结果缓存 + classify 前 prefetch_rdns 并发预热, 循环内全命中。"""
    if not ip:
        return ""
    with _RDNS_LOCK:
        if ip in _RDNS_CACHE:
            return _RDNS_CACHE[ip]
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(2.0)
        host, _, _ = socket.gethostbyaddr(ip)
        result = host.lower()
    except Exception:
        result = ""
    finally:
        socket.setdefaulttimeout(old)
    with _RDNS_LOCK:
        _RDNS_CACHE[ip] = result
    return result


def prefetch_rdns(ips, workers: int = 32) -> int:
    """并发预热 rDNS 缓存 (v3 新增; 入口线路判定 + classify 兜底共用)"""
    todo = []
    seen = set()
    for ip in ips:
        if ip and ip not in seen:
            seen.add(ip)
            with _RDNS_LOCK:
                if ip not in _RDNS_CACHE:
                    todo.append(ip)
    if not todo:
        return 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(get_rdns, todo))
    return len(todo)


def detect_cn_line(ip: str) -> str:
    """入口 IP 的回国精品网线路识别 (v3 新增)

    社区通行做法: 高端口/CN2 宿主习惯在 rDNS 里带线路名 (cn2/gia/4837/
    cmcc...), 这是唯一零成本能看出"这台机回国走什么路"的信号。
    返回 "" (无标记) 或线路名。
    匹配规则: 字母关键词按点分 token 精确/前缀匹配 (防 "gia" 撞 "giant");
    数字关键词 (4837/9808) 用子串匹配 (真实 rDNS 常写成 v-4837.line.xxx)。
    """
    rdns = get_rdns(ip)
    if not rdns:
        return ""
    tokens = set(rdns.split("."))
    for line, kws in CN_LINE_RDNS_TOKENS.items():
        for kw in kws:
            if kw.isdigit():
                if kw in rdns:
                    return line
            else:
                for t in tokens:
                    if t == kw or (len(kw) >= 3 and t.startswith(kw)):
                        return line
    return ""


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


# ══════════════════════════════════════════════════════════════════
# 国内可用性核心 (v3 新增)
#   全部零购买: DoH 用公共 DNS、回国探测用国内公共站点/公共 DNS、
#   Atlas 用免费账号额度 (可选, 默认关)。
# ══════════════════════════════════════════════════════════════════

# DNS 污染判定缓存 (main 预查填充; static_cn_prescore 只读)
_DNS_POLLUTION_CACHE = {}


def _socks5_connect_rtt(socks_port: int, host: str, port: int, timeout: float):
    """裸 SOCKS5 (无认证) CONNECT 握手 → 返回 RTT 毫秒; 失败返回 None

    ★ 为什么不用 requests: requests 的 socks 代理只支持 http(s) 协议,
      没法对任意 TCP 目标 (223.5.5.5:443) 做"只握手不传输"的纯 RTT 测量。
      这里手写最小 SOCKS5 客户端 (greeting + CONNECT), 拿到 TCP 建连即关,
      量的是"节点出口 → 国内目标"的真实往返 = 用户回国流量的链路质量。
    """
    t0 = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", socks_port), timeout=timeout)
        try:
            def _recv_exact(n):
                """精确读满 n 字节 — TCP 分片下 recv(n) 可能只返回一部分,
                少读会把合法应答误判成失败 (跨境链路上分片是常态)"""
                buf = b""
                while len(buf) < n:
                    chunk = s.recv(n - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                return buf

            # ① 问候: VER=5, NMETHODS=1, METHOD=0 (no auth)
            s.sendall(b"\x05\x01\x00")
            resp = _recv_exact(2)
            if len(resp) != 2 or resp[0] != 5 or resp[1] != 0:
                return None
            # ② CONNECT: VER=5 CMD=1 RSV=0 ATYP=1(IPv4) DST.ADDR DST.PORT
            req = (b"\x05\x01\x00\x01"
                   + socket.inet_aton(host) + int(port).to_bytes(2, "big"))
            s.sendall(req)
            rep = _recv_exact(10)     # IPv4 应答固定 10 字节
            if len(rep) < 2 or rep[1] != 0:
                return None
            return int((time.time() - t0) * 1000)
        finally:
            s.close()
    except Exception:
        return None


def probe_cn_exit(proxies: dict, socks_port: int,
                  timeout: float = CN_EXIT_TIMEOUT) -> dict:
    """回国方向探测 (v3 新增): 经节点测量"出口 → 国内"的可达性与 RTT

    两个盲区一次补上:
      ① 回国 RTT — 裸 SOCKS5 握手国内公共 DNS, 用户访问国内站/
         国服游戏/国内 API 的链路质量 (出国快不代表回国快)
      ② 回国可达性 — 经节点 HTTP 请求 baidu/bilibili/jd;
         大量节点只转发海外流量, 对国内目标直接拒 (回国场景不可用)
    返回 {"rtt_ms": int|None, "http_ok": int, "http_total": int,
          "reachable": bool, "detail": str}
    """
    rtts = []

    def _tcp(host, port):
        return _socks5_connect_rtt(socks_port, host, port, timeout)

    def _http(url):
        try:
            r = PROBE_SESSION.get(url, proxies=proxies, timeout=timeout,
                                  allow_redirects=False)
            return r.status_code < 400
        except Exception:
            return False

    with ThreadPoolExecutor(max_workers=5) as ex:
        tcp_futs = [ex.submit(_tcp, h, p) for h, p in CN_EXIT_TCP_PROBES]
        http_futs = [ex.submit(_http, u) for u in CN_EXIT_HTTP_PROBES]
        for f in as_completed(tcp_futs):
            v = f.result()
            if v is not None:
                rtts.append(v)
        http_ok = sum(1 for f in as_completed(http_futs) if f.result())

    rtt_ms = min(rtts) if rtts else None
    http_total = len(CN_EXIT_HTTP_PROBES)
    reachable = http_ok >= CN_EXIT_HTTP_MIN_OK
    detail = f"回国RTT={rtt_ms}ms" if rtt_ms is not None else "回国RTT=?"
    detail += f" HTTP可达{http_ok}/{http_total}"
    return {"rtt_ms": rtt_ms, "http_ok": http_ok, "http_total": http_total,
            "reachable": reachable, "detail": detail}


def probe_web_load(proxies: dict,
                   timeout: float = WEB_CHECK_TIMEOUT) -> dict:
    """真实网页加载探测 (v3.1 新增): 经节点请求有代表性的真实网站

    ★ 补的盲区: 204 端点 + speed.cloudflare.com 是对出口 IP 最宽容的目标,
      "延迟好看+测速过"的节点用户开普通网页照样 403/转圈 — 机房 IP 被
      Cloudflare WAF / Google 风控拦是免费池头号假活形态, 旧筛选完全看不见。
    ★ 实现: stream=True 只拿响应头就关 (不拉 body), 三个目标并发,
      每节点 ~1~2s, 与丢包/回国探测同组并发, 净增墙钟 ≈ 0。
    返回 {"reachable": n, "blocked": n, "timeout": n, "total": n, "detail": str}
    """
    codes = {}

    def _one(name, url):
        try:
            with PROBE_SESSION.get(url, proxies=proxies, stream=True,
                                   allow_redirects=False,
                                   timeout=(WEB_CHECK_CONNECT_TIMEOUT, timeout)) as r:
                code = r.status_code
            return name, code
        except Exception:
            return name, None

    with ThreadPoolExecutor(max_workers=len(WEB_CHECK_PROBES)) as ex:
        futs = [ex.submit(_one, n, u) for n, u in WEB_CHECK_PROBES]
        for fut in as_completed(futs):
            name, code = fut.result()
            codes[name] = code
    reachable = sum(1 for c in codes.values() if c is not None and c < 400)
    blocked = sum(1 for c in codes.values() if c is not None and c >= 400)
    timeout_n = sum(1 for c in codes.values() if c is None)
    detail = " ".join(f"{n}:{c if c is not None else '超时'}" for n, c in codes.items())
    return {"reachable": reachable, "blocked": blocked, "timeout": timeout_n,
            "total": len(WEB_CHECK_PROBES), "detail": detail}


def _web_load_verdict(web: dict) -> tuple:
    """网页加载探测判定 → (判死: bool, flags: list)

    判死条件: **三个目标全部不可达** (reachable == 0)。
      — 204 三源全过、测速过, 却一个真实网页都开不了 = 对普通用户即废节点
        (选择性转发只放行测试端点 / 出口 IP 被各大 WAF 全面封杀的典型形态)。
    保守边界: 只要有一个目标真开得了就不杀 — 单个目标 403 可能是目标侧
      临时故障, 不构成节点级死刑; 被拦的用 ⚠B 标记 + 扣分, 不判死。
    """
    reachable = web.get("reachable", 0) or 0
    blocked = web.get("blocked", 0) or 0
    total = web.get("total", len(WEB_CHECK_PROBES)) or len(WEB_CHECK_PROBES)
    flags = []
    if reachable <= 0:
        return True, ["网页全不通"]
    if blocked:
        flags.append(f"网页被拦{blocked}/{total}")
    if reachable >= total:
        flags.append("网页全通")
    return False, flags


def _doh_resolve(url_template: str, domain: str):
    """DoH JSON 查询 → (status, [A记录]); 网络失败 (None, [])
    DNSPod/阿里 /resolve 与 Cloudflare dns-query (Accept: dns-json)
    返回同构 JSON: {"Status": int, "Answer": [{"type":1,"data":ip}]}"""
    try:
        r = DIRECT_SESSION.get(url_template.format(d=domain),
                               timeout=DNS_CHECK_TIMEOUT,
                               headers={"Accept": "application/dns-json",
                                        "User-Agent": USER_AGENT})
        if r.status_code != 200:
            return None, []
        j = r.json()
        status = j.get("Status")
        ips = [a["data"] for a in (j.get("Answer") or [])
               if a.get("type") == 1 and a.get("data")]
        return status, ips
    except Exception:
        return None, []


def check_dns_pollution(domain: str) -> dict:
    """DNS 污染对比: 大陆公共 DNS (DNSPod/阿里) vs 全球 DNS (Cloudflare)

    判定 (只认硬失败, 不认"结果不同" — GeoDNS/CDN 分地域返回不同 IP 合法):
      polluted = 大陆侧**全部**解析失败 (NXDOMAIN/SERVFAIL/REFUSED) 或
                 返回空, 且全球侧解析成功。
    返回 {"polluted": bool, "cn_ok": bool, "global_ok": bool, "detail": str}
    域名是 IP 字面量 → 不过 DNS, 直接返回不污染。
    """
    if is_ip_literal(domain):
        return {"polluted": False, "cn_ok": None, "global_ok": None,
                "detail": "ip-literal"}
    key = domain.lower().rstrip(".")
    cached = _DNS_POLLUTION_CACHE.get(key)
    if cached is not None:
        return cached

    cn_fail, cn_ok_cnt, cn_detail = 0, 0, []
    for name, tpl in CN_DOH_JSON:
        status, ips = _doh_resolve(tpl, key)
        if status is None:
            cn_detail.append(f"{name}:网络失败")
            continue                      # 网络失败 ≠ 污染 (Actions 视角可能被墙)
        if status == 0 and ips:
            cn_ok_cnt += 1
            cn_detail.append(f"{name}:ok")
        else:
            cn_fail += 1
            cn_detail.append(f"{name}:status={status}/empty")

    g_ok, g_detail = False, []
    for name, tpl in GLOBAL_DOH_JSON:
        status, ips = _doh_resolve(tpl, key)
        if status == 0 and ips:
            g_ok = True
            g_detail.append(f"{name}:ok({len(ips)})")
        else:
            g_detail.append(f"{name}:status={status}/empty")

    # 大陆侧有任一解析成功 → 不判污染; 大陆全部网络失败 → 无信号, 不判
    polluted = bool(cn_fail) and cn_ok_cnt == 0 and g_ok
    result = {"polluted": polluted,
              "cn_ok": (cn_ok_cnt > 0),
              "global_ok": g_ok,
              "detail": "CN[" + ",".join(cn_detail) + "] G[" + ",".join(g_detail) + "]"}
    _DNS_POLLUTION_CACHE[key] = result
    return result


def precheck_dns_pollution(hosts, workers: int = DNS_CHECK_WORKERS):
    """并发预查全部唯一域名的 DNS 污染状态 (v3 新增; main 在预检前调用)"""
    domains = []
    seen = set()
    for h in hosts:
        if h and not is_ip_literal(h):
            k = h.lower().rstrip(".")
            if k not in seen:
                seen.add(k)
                domains.append(k)
    if not domains:
        return 0, 0
    polluted = [0]

    def _one(d):
        try:
            if check_dns_pollution(d).get("polluted"):
                polluted[0] += 1
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(_one, domains))
    return len(domains), polluted[0]


def _entry_ip_in_cdn(ip_str: str) -> bool:
    """入口 IP 是否落在已知 CDN/Anycast 网段 (GFW 墙 IP 墙不掉)"""
    if not ip_str:
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in CLOUDFLARE_IP_NETWORKS:
        if ip_obj in net:
            return True
    for net in CDN_IP_NETWORKS_EXTRA:
        if ip_obj in net:
            return True
    return False


def static_cn_prescore(item) -> tuple:
    """静态 China 友好度**预测分** (v3 新增; 零网络请求, 只用缓存)

    在端口预检前对每个候选算一遍, 用于:
      ① 测试优先级排序 (高分先测 — 时间预算有限时先保国内友好节点)
      ② 国内友好订阅的入围基础分
    不含入口 rDNS 线路 (那要等节点真活才值得查, 见 compute_cn_score)。
    返回 (score:int, flags:list)
    """
    raw, outbound, server, port, proto = item
    score, flags = 0, []
    tls = outbound.get("tls") or {}
    reality = bool(tls.get("reality"))
    tls_on = bool(tls.get("enabled"))
    transport = (outbound.get("transport") or {}).get("type")

    # ── 端口 (GFW 对 443 最宽容, 随机高端口是周期性限流常客) ──
    if port == 443:
        score += CN_SCORE_PORT_443
        flags.append("443")
    elif port == 80:
        score += CN_SCORE_PORT_80
        flags.append("80")
    else:
        flags.append("非443")

    # ── 协议/传输伪装 (DPI 可识别性) ──
    if proto in ("hysteria2", "tuic"):
        score += CN_SCORE_QUIC_PENALTY
        flags.append("QUIC")
    if reality:
        score += CN_SCORE_REALITY
        flags.append("Reality")
    elif tls_on:
        entry_ip = server if is_ip_literal(server) else resolve_host(server)
        if _entry_ip_in_cdn(entry_ip):
            score += CN_SCORE_TLS_CDN
            flags.append("CDN前置")
        elif transport in ("ws", "grpc", "http", "httpupgrade"):
            score += CN_SCORE_TLS_WEB
            flags.append("web传输")
        else:
            score += CN_SCORE_TLS_PLAIN
    else:
        score += CN_SCORE_NO_TLS_PENALTY
        flags.append("无TLS")

    # ── 域名卫生 (IP 字面量无 DNS 风险; 域名查污染缓存) ──
    if is_ip_literal(server):
        score += CN_SCORE_IP_LITERAL
        flags.append("直连IP")
    else:
        dns_info = _DNS_POLLUTION_CACHE.get(server.lower().rstrip("."))
        if dns_info:
            if dns_info.get("polluted"):
                score += CN_SCORE_DNS_POLLUTED
                flags.append("DNS污染")
            elif dns_info.get("global_ok"):
                score += CN_SCORE_DNS_OK
                flags.append("DNS正常")
    return score, flags


def compute_cn_score(n: dict) -> tuple:
    """国内可用性综合分 (v3 新增; classify 阶段对每个出库节点调用)

    组成 = 静态预测分 (测试前) + 入口精品网线路 (真活后查 rDNS/ASN)
          + 回国方向实测 (经节点) + 海外延迟底子
    返回 (score:int, flags:list) — flags 同时用于节点名标注。
    """
    score = n.get("cn_prescore", 0) or 0
    flags = list(n.get("cn_prescore_flags") or [])

    line = n.get("entry_line") or ""
    if line == "cn2":
        score += CN_SCORE_RDNS_CN2
        flags.append("CN2GIA")
    elif line == "cu4837":
        score += CN_SCORE_RDNS_4837
        flags.append("联通4837")
    elif line == "cmi":
        score += CN_SCORE_RDNS_CMCC
        flags.append("移动CMI")

    if n.get("entry_asn") in CN_CLOUD_ASNS:
        score += CN_SCORE_ASN_CNCLOUD
        flags.append("中国云入口")

    if n.get("cn_exit_reachable"):
        score += CN_SCORE_EXIT_OK
        flags.append("回国通")
    else:
        flags.append("回国不通")

    rtt = n.get("cn_exit_rtt_ms")
    if rtt is not None:
        if rtt <= CN_EXIT_RTT_GOOD_MS:
            score += CN_SCORE_EXIT_RTT_GOOD
        elif rtt > CN_EXIT_RTT_BAD_MS:
            score += CN_SCORE_EXIT_RTT_BAD

    # (可选) Atlas 中国探针实测: 唯一真·大陆视角信号, 权重给最高档
    #   可达率 ≥50% → 强加分; <50% → 强扣分 (IP 被墙/路由黑洞的直接证据)
    ar = n.get("atlas_ok_ratio")
    if ar is not None:
        if ar >= 0.5:
            score += 20
            flags.append(f"大陆可达{ar:.0%}")
        else:
            score -= 25
            flags.append(f"大陆不可达{ar:.0%}")

    # v3.1 真实网页加载: 三个真实网站全通 = "隧道通且网页真能开" (+8);
    #   有被拦 (⚠B) 不加不扣 — 单个目标 403 可能是目标侧故障, 不构成节点级惩罚,
    #   全不通的节点已在测活阶段判死, 到不了这里。
    if n.get("web_reachable", 0) >= 3:
        score += 8
        flags.append("网页全通")

    if 0 < (n.get("latency_ms") or 99999) <= 300:
        score += CN_SCORE_LAT_GOOD

    return score, flags


# ══════════════════════════════════════════════════════════════════
# (可选) RIPE Atlas 中国探针 ping — 真·中国大陆视角
#   免费: 注册 RIPE NCC Access 账号可一次性领取 50,000 credits;
#   Atlas 在中国大陆有 600+ 在线探针。本模块每轮只对少量候选入口 IP
#   发起一次性 ping, 直接测"大陆 → 入口"可达性/RTT/丢包, 是唯一能
#   真正回答"国内能不能连上"的免费手段。不配 ATLAS_API_KEY 则静默跳过。
# ══════════════════════════════════════════════════════════════════

def _atlas_get_probe_ids() -> list:
    """取在线的大陆公共探针 ID (最多 ATLAS_MAX_PROBES 个)"""
    r = DIRECT_SESSION.get(ATLAS_API_PROBES, timeout=20,
                           headers={"Accept": "application/json"})
    r.raise_for_status()
    j = r.json()
    ids = [p["id"] for p in (j.get("results") or [])
           if p.get("id") and p.get("status") == 1]
    return ids[:ATLAS_MAX_PROBES]


def _atlas_create_ping(ip: str, probe_ids: list) -> int:
    """对单个入口 IP 创建一次性 ping 测量 → measurement id"""
    body = {
        "definitions": [{
            "type": "ping", "target": ip, "af": 4,
            "packets": 3, "description": "freesub cn-check",
        }],
        "probes": [{"type": "probes",
                    "value": ",".join(str(i) for i in probe_ids),
                    "requested": len(probe_ids)}],
        "is_oneoff": True,
    }
    r = DIRECT_SESSION.post(ATLAS_API_CREATE + ATLAS_API_KEY,
                            json=body, timeout=30,
                            headers={"Accept": "application/json"})
    r.raise_for_status()
    mids = r.json().get("measurements") or []
    return int(mids[0]) if mids else 0


def _atlas_fetch_result(mid: int):
    """拉取单个测量结果 → (可达比例, 中位RTTms, 样本探针数); 无数据 (None,None,0)"""
    r = DIRECT_SESSION.get(
        f"https://atlas.ripe.net/api/v2/measurements/{mid}/results/",
        timeout=20, headers={"Accept": "application/json"})
    if r.status_code != 200:
        return None, None, 0
    j = r.json()
    rows = j.get("results") if isinstance(j, dict) else j
    if not rows:
        return None, None, 0
    sent = rcvd = 0
    rtts = []
    for row in rows:
        s = row.get("sent")
        c = row.get("rcvd")
        if s is None or c is None:
            res = row.get("result") or []
            s = len(res)
            c = sum(1 for x in res if isinstance(x, dict) and "rtt" in x)
        sent += s or 0
        rcvd += c or 0
        rtt = row.get("avg") or row.get("min")
        if rtt is None:
            res = [x.get("rtt") for x in (row.get("result") or [])
                   if isinstance(x, dict) and "rtt" in x]
            rtt = min(res) if res else None
        if rtt is not None:
            rtts.append(float(rtt))
    if sent <= 0:
        return None, None, 0
    ratio = rcvd / float(sent)
    rtts.sort()
    med = rtts[len(rtts) // 2] if rtts else None
    return ratio, med, len(rows)


def atlas_cn_ping(entry_ips: list) -> dict:
    """(可选) 批量中国探针 ping → {ip: {"ok_ratio":f,"rtt_ms":int|None,"probes":n}}

    预算保护: 每轮最多 ATLAS_MAX_IPS 个 IP × ATLAS_MAX_PROBES 个探针,
    一次性 ping 每探针约 1 credit (5 万免费额度够上百轮, 仍建议盯着余额)。
    任何一步失败都只影响对应 IP, 绝不抛异常中断主流程。
    """
    if not ATLAS_API_KEY or ATLAS_MAX_IPS <= 0 or not entry_ips:
        return {}
    ips = [ip for ip in entry_ips if ip][:ATLAS_MAX_IPS]
    if not ips:
        return {}
    out = {}
    try:
        probe_ids = _atlas_get_probe_ids()
        if not probe_ids:
            print("[!] Atlas: 未取到在线大陆探针, 跳过")
            return {}
        print(f"[*] RIPE Atlas 中国探针 ping: {len(ips)} 个入口 IP × "
              f"{len(probe_ids)} 探针 (免费额度, 每轮最多 {ATLAS_MAX_IPS} IP) ...")
        pend = {}      # ip -> measurement id
        for ip in ips:
            try:
                mid = _atlas_create_ping(ip, probe_ids)
                if mid:
                    pend[ip] = mid
            except Exception as e:
                print(f"[!] Atlas 创建测量失败 {ip}: {str(e)[:60]}")
        if not pend:
            return {}
        deadline = time.time() + max(30, ATLAS_WAIT_SECONDS)
        while time.time() < deadline and pend:
            time.sleep(15)
            for ip in list(pend):
                try:
                    ratio, med, cnt = _atlas_fetch_result(pend[ip])
                except Exception:
                    continue
                if ratio is not None:
                    out[ip] = {"ok_ratio": ratio,
                               "rtt_ms": int(med) if med is not None else None,
                               "probes": cnt}
                    del pend[ip]
            if pend:
                print(f"[*] Atlas: 等待 {len(pend)}/{len(ips)} 个测量结果 ...")
        ok = sum(1 for v in out.values() if v["ok_ratio"] >= 0.5)
        print(f"[+] Atlas 中国探针结果: {len(out)}/{len(ips)} 个 IP 有数据, "
              f"其中 {ok} 个大陆可达率 ≥50%")
    except Exception as e:
        print(f"[!] Atlas 模块异常 (不影响主流程): {str(e)[:80]}")
    return out


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


def classify_and_export(test_results: list, ip_api_info: dict = None):
    print("[*] 出口 IP 情报与分类 ...")

    # ── P1-1 修复 (2026-10-11): 去重前置到情报查询之前 ──
    #   旧版顺序: 建 nodes → 风险过滤 → Scamalytics/ipapi.is → 去重。
    #   问题: classify_network_type() / offline_ip_lookup() / resolve_host() 全在
    #         **去重前**对全量节点执行, 而回填会让 test_results 远大于最终节点数。
    #   #70 实测: 1064 个节点进分类 → 去重后 445, 约 619 个节点的分类计算是纯浪费。
    #   现在先用 exit_ip:port 去重, 下游全部只在去重后的集合上跑。
    #   ★ 键与排序完全沿用原 L3004-3016 的逻辑, 保证结果不变。
    def _dedup_rank(n):
        spd = n.get("speed_bps", 0) or 0
        return (0 if spd >= SPEED_MIN_BYTES_PER_S else 1,      # 速度达标优先
                n["latency_ms"],                                 # 延迟次之
                -spd)                                            # 同延迟取吞吐更高

    best_by_key = {}
    for n in test_results:
        key = f"{n['exit_ip']}:{n['port']}" if n["exit_ip"] else f"{n['server']}:{n['port']}|{n['raw'][:64]}"
        cur = best_by_key.get(key)
        if not cur or _dedup_rank(n) < _dedup_rank(cur):
            best_by_key[key] = n
    deduped_results = list(best_by_key.values())
    dedup_dropped = len(test_results) - len(deduped_results)
    if dedup_dropped:
        print(f"[*] 去重前置: {len(test_results)} → {len(deduped_results)} "
              f"(剔除重复 {dedup_dropped}, 保留速度最优 — 后续情报查询只跑去重后集合)")
    test_results = deduped_results

    # ── v3: 入口侧情报 (国内可用性判定用; 并发 + 缓存, 零额外串行等待) ──
    #   ① 入口 IP 解析 (域名 → IP; resolve_host 带缓存, 端口预检阶段已预热过)
    #   ② 入口 rDNS 线路 (CN2GIA/4837/CMI) — 只对真活节点查, 死节点不配花 rDNS
    #   ③ (可选) RIPE Atlas 中国探针 ping — 真·大陆视角, 默认关闭
    #   ★ 旧版 classify 循环内**单线程** get_rdns (每节点最坏 2s), 400 个 unknown
    #     节点最坏 800s 全烧在这 — v3 起并发预热, 循环内全缓存命中。
    entry_ip_map = {}        # raw -> 入口 IP
    ip_best_score = {}       # 入口 IP -> 该 IP 下最高静态 CN 分 (Atlas 选样用)
    entry_ips = []
    for r in test_results:
        if not (r.get("alive") and not r.get("is_stalled")):
            continue
        srv = r.get("server") or ""
        ip = srv if is_ip_literal(srv) else resolve_host(srv)
        entry_ip_map[r["raw"]] = ip or ""
        if ip:
            ip_best_score[ip] = max(ip_best_score.get(ip, -999),
                                    r.get("cn_prescore", 0) or 0)
            if ip not in entry_ips:
                entry_ips.append(ip)
    prefetch_rdns(entry_ips)
    line_stat = {}
    for ip in entry_ips:
        ln = detect_cn_line(ip)
        if ln:
            line_stat[ln] = line_stat.get(ln, 0) + 1
    if line_stat:
        detail = " ".join(f"{k}:{v}" for k, v in sorted(line_stat.items(), key=lambda x: -x[1]))
        print(f"[*] 入口精品网线路 (rDNS 识别): {detail}")

    # (可选) Atlas 中国探针: 只对静态分最高的入口 IP 发起 (免费额度有限)
    atlas_info = {}
    if ATLAS_API_KEY and ATLAS_MAX_IPS > 0 and entry_ips:
        try:
            ranked_ips = sorted(entry_ips, key=lambda ip: -ip_best_score.get(ip, 0))
            atlas_info = atlas_cn_ping(ranked_ips)
        except Exception as e:
            print(f"[!] Atlas 调用跳过: {str(e)[:60]}")
        if atlas_info:
            cn_reach = sum(1 for v in atlas_info.values()
                           if (v.get("ok_ratio") or 0) >= 0.5)
            print(f"[+] Atlas 大陆视角: {cn_reach}/{len(atlas_info)} 个入口 IP "
                  f"大陆可达率 ≥50% (真·中国探针实测)")

    # 收集全部出口 IP
    all_exit_ips = []
    seen_ip = set()
    for r in test_results:
        if r["exit_ip"] and r["exit_ip"] not in seen_ip:
            seen_ip.add(r["exit_ip"])
            all_exit_ips.append(r["exit_ip"])
    print(f"[*] 待查询出口 IP: {len(all_exit_ips)} 个 (ip-api.com 批量 {len(test_results)} 节点)")

    ip_api_info = ip_api_info or {}      # ★ 2026-10-04: 由 main() 预查一次传入复用,
                                        #   避免这里再查第二遍 (#70 实测白多花 25s + 一半免费额度)
    scam_scores = {}
    if all_exit_ips and not ip_api_info:
        try:
            est_batches = (len(all_exit_ips) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量: {est_batches} 批 × ~4.2s ≈ {est_batches * 4.2:.0f}s (免费限 15 req/min, 请耐心) ...")
            ip_api_info = ip_api_batch_lookup(all_exit_ips)
            print(f"[+] ip-api.com 批量情报: {len(ip_api_info)}/{len(all_exit_ips)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败, 将全量走离线: {e}")
    elif ip_api_info:
        print(f"[+] 复用主流程预查的 ip-api 情报: {len(ip_api_info)} 条 (跳过重复查询)")

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

        # ── v3: 入口侧国内可用性情报 (入口 IP 的线路/ASN; Atlas 实测) ──
        entry_ip = entry_ip_map.get(r["raw"], "")
        entry_line = detect_cn_line(entry_ip) if entry_ip else ""
        entry_asn = None
        if entry_ip and asn_reader:
            try:
                a = asn_reader.get(entry_ip)
                entry_asn = a.get("autonomous_system_number") if a else None
            except Exception:
                entry_asn = None
        atlas_rec = atlas_info.get(entry_ip) if entry_ip else None

        nodes.append({
            "raw": r["raw"],
            "server": r["server"],
            "port": r["port"],
            "proto": r["proto"],
            "outbound": r.get("outbound"),
            # ★ v3 审计修复 (2026-10-16): alive 键必须显式带上 ——
            #   final_gate 断言 n.get("alive") 为真, 而 v2 起本 dict 就没这个键
            #   (v2 没有闸门不需要它), 导致闸门把每个节点都判 alive=False 全杀。
            #   能走到这里的 r 全是 alive=True (test_single_node 只有通过活性
            #   门槛才返回 dict), 这里显式落键, 保持数据形状完整。
            "alive": r.get("alive", True),
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
            # ── v3 国内可用性字段 ──
            "cn_prescore": r.get("cn_prescore", 0) or 0,
            "cn_prescore_flags": r.get("cn_prescore_flags") or [],
            "entry_ip": entry_ip,
            "entry_line": entry_line,
            "entry_asn": entry_asn,
            "cn_exit_rtt_ms": r.get("cn_exit_rtt_ms"),
            "cn_exit_reachable": r.get("cn_exit_reachable", False),
            "atlas_ok_ratio": (atlas_rec or {}).get("ok_ratio"),
            "atlas_rtt_ms": (atlas_rec or {}).get("rtt_ms"),
            # ── v3.1 真实网页加载 ──
            "web_reachable": r.get("web_reachable", 0),
            "web_blocked": r.get("web_blocked", 0),
            "web_flags": r.get("web_flags") or [],
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

    # ── 去重已在函数开头完成 (P1-1: 前置到情报查询之前, 见上方 deduped_results) ──
    #   排序规则保持不变: 速度达标者优先 → 速度相同取延迟更低 → 再相同取吞吐更高。
    #   (旧版按 latency 最小者保留会丢掉同出口 IP 下吞吐最好的那个, 已修正)
    # ★ 必须取 safe_nodes (已过 MITM/断流/WARP/黑名单/fraud 过滤), 不能取 nodes ——
    #   否则风险过滤全部被绕过, 高危节点直接进订阅。
    unique_nodes = safe_nodes

    # 去重: 出口IP+端口 唯一化, 家宽区严格防同IP刷屏
    # ★ 链式复测 (chain_retest) 双跳失败的家宽候选 → 不进家宽专区 (降级普通)
    chain_failed_raws = set()
    for r in test_results:
        if r.get("_chain_failed"):
            chain_failed_raws.add(r.get("raw"))
    residential = []
    # ★ 这是**有意的第二次去重** (不要当成冗余删掉):
    #   上方的去重键是 exit_ip:port, 同一住宅 IP 若开多个端口会有多条记录;
    #   家宽区要"防同 IP 刷屏"(一个真实家庭宽带刷出几十条会淹没整个专区),
    #   所以这里按裸 exit_ip 再去一次, 每个住宅 IP 只留一条。
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

    # ── v3: 国内可用性综合分 + 国内友好订阅入选 ──
    #   cn_score = 静态预测分(端口/协议伪装/CDN/域名卫生)
    #            + 入口精品网线路(CN2GIA/4837/CMI/中国云)
    #            + 回国方向实测(可达性/RTT) + (可选)Atlas 大陆探针实测
    #   入选国内友好订阅的硬条件: 总分 ≥ 门槛 且 域名未被 DNS 污染
    #   (国内客户端默认 DNS 连不上污染域名, 这是"国内能不能用"的一票否决项)
    cn_friendly = []
    for n in unique_nodes:
        score, flags = compute_cn_score(n)
        n["cn_score"] = score
        n["cn_flags"] = flags
        n["cn_friendly"] = (score >= CN_FRIENDLY_MIN_SCORE
                            and "DNS污染" not in flags
                            and not n.get("is_warp"))
        if n["cn_friendly"]:
            cn_friendly.append(n)
    n_back = sum(1 for n in unique_nodes if "回国不通" in (n.get("cn_flags") or []))
    n_dns = sum(1 for n in unique_nodes if "DNS污染" in (n.get("cn_flags") or []))
    n_line = sum(1 for n in unique_nodes if n.get("entry_line"))
    print(f"[*] 国内可用性评分: 友好订阅入选 {len(cn_friendly)}/{len(unique_nodes)} "
          f"(门槛 {CN_FRIENDLY_MIN_SCORE}) | 精品网入口 {n_line} | "
          f"回国不通 {n_back} | DNS 污染 {n_dns}")

    # 排序: 家宽在前, 组内按"可用性综合分"升序
    #   ★ 旧版只按 latency 升序, 等于默认"延迟低 = 体验好"。但跨太平洋链路上
    #     丢包率和首包时间对体感的权重远大于延迟 —— 一个 80ms/丢包 15% 的节点
    #     排序会排在 300ms/零丢包 前面, 实际体验更差。
    #   综合分 = 延迟 + 丢包惩罚(每次丢失按 1500ms 计) + TTFB 的一半。
    #   ★ v3: 再加国内可用性加权 (100-cn_score)×W —— 组内排序从此是
    #     "国内用户视角": 同样延迟下, 国内友好的节点排前面。
    def _quality_key(n):
        # ★ loss_rate 为 None 表示"未测丢包"(非 0 也非 100%), 按 0 参与排序,
        #   不能因为缺数据就把节点排到最末 (#67 事故衍生问题)
        loss = n.get("loss_rate") or 0.0
        ttfb = n.get("ttfb_ms", 0) or 0
        cn_penalty = (100 - (n.get("cn_score") or 0)) * CN_QUALITY_WEIGHT
        return (n["latency_ms"] + loss * 1500.0 + ttfb * 0.5 + cn_penalty)

    unique_nodes.sort(key=lambda x: (0 if x in residential else 1, _quality_key(x)))
    residential.sort(key=_quality_key)
    non_residential.sort(key=_quality_key)
    # v3: 国内友好订阅按 cn_score 降序 (同分再看质量分)
    cn_friendly.sort(key=lambda x: (-(x.get("cn_score") or 0), _quality_key(x)))
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

    return unique_nodes, residential, non_residential, cn_friendly


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
    # ── v3 国内可用性标注 (节点名内, 客户端列表一眼可见) ──
    #   🇨🇳  = 国内友好订阅成员 (cn_score ≥ 门槛, 端口/伪装/域名/回国全过线)
    #   ⚠D = 域名在大陆被 DNS 污染 (默认 DNS 下连不上)
    #   ⚠P = 非 443/80 端口 (GFW 周期性限流常客)
    #   ⚠U = QUIC/UDP 系 (hy2/tuic, GFW 对 UDP 有 QoS 传统)
    #   ⚠C = 回国方向不通 (只出国不回国, 国内站点/国服不可用)
    #   ⚠B = 真实网页被 WAF 拦 (v3.1: 204/测速过但 wikipedia/github/google
    #        有被拦 — 出口 IP 风控脏, 开普通网页可能 403/验证码)
    cn_flags = item.get("cn_flags") or []
    web_flags = item.get("web_flags") or []
    if item.get("cn_friendly"):
        cn_tag = " 🇨🇳"
    else:
        marks = []
        if "DNS污染" in cn_flags:
            marks.append("⚠D")
        if "非443" in cn_flags:
            marks.append("⚠P")
        if "QUIC" in cn_flags:
            marks.append("⚠U")
        if "回国不通" in cn_flags:
            marks.append("⚠C")
        if any("网页被拦" in f for f in web_flags):
            marks.append("⚠B")
        cn_tag = (" " + "".join(marks)) if marks else ""
    return (f"{flag} {cname} {idx:02d}{tag}{speed_tag}{loss_tag}{ttfb_tag}"
            f"{warp_tag}{cn_tag}{risk_tag} - NEKO")


def export_all(unique_nodes, residential, non_residential, cn_friendly=None):
    """v3: 新增 cn_friendly (国内友好订阅) 导出"""
    ensure_directories()
    cn_friendly = cn_friendly or []

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

    # 6) ★ v3 国内友好订阅 (国内可用性优选 — 直击"国内能不能用")
    #    入选: cn_score ≥ CN_FRIENDLY_MIN_SCORE 且域名未被 DNS 污染 (一票否决)
    #    排序: cn_score 降序 (同分看质量分) — 订阅里越靠前越该先用
    if cn_friendly:
        cn_links, cn_proxies, cn_sb = build_group(cn_friendly)
    else:
        cn_links, cn_proxies, cn_sb = [], [], []
    with open(os.path.join(OUTPUT_DIR, "cn-friendly.txt"), "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(cn_links).encode()).decode())
    if cn_proxies:
        export_clash_yaml(cn_proxies, os.path.join(OUTPUT_DIR, "cn-friendly-clash.yaml"))
        export_singbox_json(cn_sb, os.path.join(OUTPUT_DIR, "cn-friendly-singbox.json"))
    else:
        # 空状态: 清掉上一轮遗留文件, 避免链接指向过期数据
        for fn in ("cn-friendly-clash.yaml", "cn-friendly-singbox.json"):
            p = os.path.join(OUTPUT_DIR, fn)
            if os.path.exists(p):
                os.remove(p)
        print("[!] 国内友好订阅为空 — 已生成空 cn-friendly.txt, "
              "并清理上一轮的 cn-friendly-* 文件 (避免链接指向过期数据)")

    print(f"[*] 导出完毕: 全量 {len(all_links)} | 家宽 {len(res_links)} | "
          f"家宽合并 {len(ml)} | 国内友好 {len(cn_links)}")
    return len(all_links), len(res_links), len(cn_links)


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

def update_readme(total_count, res_count, cn_count=0):
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
> 🇨🇳 **国内可用性导向 (v3 新增)**: 在海外视角测活之外, 增加入口侧 GFW 抗力静态评分 (端口/协议伪装/CDN 前置/域名 DNS 污染对比) + 入口精品网线路识别 (CN2 GIA/联通 4837/移动 CMI) + 回国方向实测 (经节点访问百度/B 站/京东 + 国内公共 DNS 握手 RTT) + 真实网页加载复测 (wikipedia/GitHub/Google, 抓"延迟好看但网页打不开"的假活节点), 达标节点进入独立的**国内友好订阅**, 节点名打 🇨🇳 标记; 风险项打 ⚠D(域名污染)/⚠P(非443端口)/⚠U(QUIC)/⚠C(回国不通)/⚠B(网页被WAF拦)。
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

## 🇨🇳 国内友好订阅 (国内可用性优选 · v3 新增)

> 上面的订阅回答"节点活不活", 这一节回答**"节点在国内能不能用"**。CI 跑在海外 (Azure US),
> 从美国秒连、满速下载的节点, 国内用户连不上是常态 —— 入口端口被 GFW 限流、域名被 DNS
> 污染、协议无伪装被 DPI 识别、线路回国质量差, 这些从海外视角全都看不见。
> 国内友好订阅用五路信号把这类节点提前标出来 (全部免费公共服务, 零购买):

| 信号族 | 具体手段 | 拦住/标出什么 |
| :--- | :--- | :--- |
| ① 入口端口 | 443 > 80 > 随机高端口 | 随机高端口是 GFW 周期性限流/重置的常客 |
| ② 协议伪装 | Reality > CDN 前置 (ws/grpc over CDN IP) > web 传输 > 裸 TLS > 明文 | DPI 可识别性 = 被墙风险 |
| ③ 域名卫生 | DNSPod/阿里 (大陆公共 DNS) vs Cloudflare 解析结果对比 | 域名在大陆被污染 → 默认 DNS 下直接连不上 (⚠D) |
| ④ 入口线路 | 入口 IP rDNS/ASN 识别 CN2 GIA / 联通 4837 / 移动 CMI / 中国云 | 回国链路质量 (延迟/丢包的根源) |
| ⑤ 回国方向 | 经节点 TCP 握手 223.5.5.5/114.114.114.114 量回国 RTT; 经节点请求百度/B 站/京东 | 只出国不回国的节点 (国内站点/国服不可用, ⚠C) |

**入选规则**: 综合分 `cn_score` ≥ {CN_FRIENDLY_MIN_SCORE} 且域名未被 DNS 污染 (一票否决);
订阅内按 cn_score 降序, 越靠前越该先用。**可选进阶**: 配置免费 RIPE Atlas key
(注册即领 5 万额度) 后, 还会用中国大陆 600+ 真实探针 ping 入口 IP, 直接实测
"大陆 → 节点"可达性 — 这是唯一真·中国视角的信号 (默认关闭, 见脚本内 Atlas 模块说明)。

**订阅入口** (节点名带 🇨🇳 标记):

| 客户端 / 格式 | 节点数 | 免翻 CDN 订阅直链 (国内直连) | 官方原生 Raw 直链 (开启代理) |
| :--- | :---: | :--- | :--- |
| ⚡ **V2RayN (Base64)** | `{cn_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/cn-friendly.txt) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/cn-friendly.txt) |
| 📦 **Clash (YAML)** | `{cn_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/cn-friendly-clash.yaml) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/cn-friendly-clash.yaml) |
| 📦 **sing-box (JSON)** | `{cn_count}` | [免翻 CDN 直链](https://cdn.jsdelivr.net/gh/{repo_name}@main/output/cn-friendly-singbox.json) | [官方 Raw 直链](https://raw.githubusercontent.com/{repo_name}/main/output/cn-friendly-singbox.json) |

> ⚠️ **诚实声明**: 不配 Atlas key 时, "大陆 → 入口"这一跳没有真探针, 靠的是端口/伪装/
> 线路/DNS 这些**静态与代理侧信号**推断 (它们与 GFW 行为的相关性很高, 但不是实测)。
> 要 100% 确定某个节点国内可达, 要么配 Atlas key, 要么以你本机的实测为准。

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
1. **自动更新机制**：工作流每 6 小时全自动运行并刷新上述全部订阅与数据 (以 workflow 实际触发配置为准)。
2. **测活标准**：节点必须通过 ① 静态预筛(剔除关闭证书校验) ② 端口预检 ③ sing-box 实际隧道跨源活性探测 (Google/Cloudflare/Microsoft 至少 2 源) ④ 真实出口 IP 穿透获取 (延迟 ≤ 1500ms) ⑤ 限时下载测速 (稳态吞吐 ≥ 200KB/s, 5MB 首测 + 1MB 复测取最小值 + Hetzner 物理机房交叉测速) ⑥ 丢包率 ≤ 25% ⑦ 首包 TTFB ≤ 1800ms ⑧ TLS 证书校验非 MITM, 方可入库。
3. **去重时机 (v3.3 变更)**: 测前按 `node_key` (server|port|proto|整个 outbound 规范化序列化, **不含 exit_ip**) 去重 —— 零网络零进程, 重复节点连 sing-box 都不启动。指纹从手工枚举改为序列化整个 outbound, 漏读字段在结构上不可能再发生。出口维度的去重仍在 classify 阶段三套 (exit_ip:port / 裸 exit_ip / 家宽合并), 且它们跑在真实测活之后、拿到 exit_ip 真值。v3.2 的"测活期查重闸 + 已成功节点注册表"已整体删除 (它位置太靠后, 重复节点已付掉 6~26s 开销只能省 12~25s)。
4. **国内可用性标准 (v3)**：入库后再过五路国内向信号 — ① 入口端口/协议伪装静态评分 (443/Reality/CDN 前置优先) ② 域名经大陆公共 DNS 与全球 DNS 对比, 被污染者打 ⚠D 并排除出国内友好订阅 ③ 入口 IP rDNS/ASN 精品网线路识别 (CN2 GIA/4837/CMI) ④ 经节点实测回国方向 (百度/B 站/京东可达性 + 国内公共 DNS 握手 RTT) ⑤ (可选) RIPE Atlas 中国大陆探针实测。综合分 ≥ {CN_FRIENDLY_MIN_SCORE} 且域名干净的节点进入**国内友好订阅** (cn-friendly), 节点名打 🇨🇳。
5. **真实网页加载标准 (v3.1)**：通过吞吐门槛的节点追加经节点请求 wikipedia/github/google (只读响应头) — 204 端点与 CF 测速是对出口 IP 最宽容的目标, "延迟好看+测速过"的节点开普通网页照样可能 403/转圈 (机房 IP 被 Cloudflare WAF/Google 风控拦)。**三个目标全部不可达 → 判死**; 有被拦的打 ⚠B 标记 (IP 风控脏); 全通的在排序中加分。
6. **多客户端兼容**：Clash / v2rayN / sing-box 全格式订阅。
"""
    with open(os.path.join(BASEDIR, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme)
    print(f"[+] README.md 更新完毕: 总节点 {total_count}, 家宽 {res_count}")


# ═══════════════════════════════════════════N═══════════════════════
# 主流程
# ═══════════════════════════════════════════N═══════════════════════

def _verify_export_lineage(unique_nodes: list, test_results: list) -> bool:
    """闭环校验: 每个出库节点的 raw 必须能追溯到"已测活"的节点

    返回 True = 全部有据可查; False = 存在无法追溯的节点 (已打警告)。

    ★ 为什么需要: 去重/风险过滤跨多个函数协作, 光靠读代码很难确信
      "没有未经测试的节点混进订阅"。这里用一次集合比对把它变成可验证的事实。
    ★ v3.2 起合法来源只剩一种: test_results 里的 raw — 跑过完整 sing-box
      测活 (或链式复测)。旧版还有第二种"回填克隆体"来源, 随回填删除一并
      消失。
    ★ v3.3 新增测前去重 (dedup_candidates) 后, 这个不变量**依然成立**,
      不会因去重产生新告警: 被去重剔除的节点从不进入 candidates,
      也就从不出现在 test_results / unique_nodes 任何一个集合里 ——
      它是"从未测过", 而本函数校验的是"进订阅的都测过", 两者不冲突。
      即"测前就被剔除" ≠ "未经测试却进了订阅"。
    """
    traced = set()
    for r in test_results:
        raw = r.get("raw")
        if raw:
            traced.add(raw)
    orphans = [n for n in unique_nodes if n.get("raw") not in traced]
    if orphans:
        print(f"[!] 闭环校验失败: {len(orphans)}/{len(unique_nodes)} 个出库节点无法追溯到测活记录")
        for n in orphans[:5]:
            print(f"      · {n.get('proto')} {n.get('server')}:{n.get('port')} raw={str(n.get('raw'))[:70]}")
        print(f"    → 这些节点未经测试筛选就进了订阅, 需检查回填/去重路径是否有新分支")
        return False
    return True


def main():
    t_start = time.time()
    print(f"==== 免费节点测活订阅池 v3 (国内可用性导向) · 启动于 {datetime.now(timezone.utc).isoformat()} ====")
    ensure_directories()
    setup_environment()

    # 1. 抓取
    raw_nodes = fetch_raw_nodes()

    # 2. 解析
    candidates = []
    parse_fail = 0
    parse_fail_samples = []        # ★ P2: 旧版只报计数, 失败样本全丢 → 无法定位是哪个源/哪种格式烂了
    blacklist_hit = 0              # ★ P2: 占位/广告节点剔除原先完全无计数
    for uri in raw_nodes:
        parsed = parse_node_uri(uri)
        if not parsed:
            parse_fail += 1
            if len(parse_fail_samples) < 5:
                parse_fail_samples.append(uri[:80])
            continue
        outbound, server, port, proto = parsed
        # 屏蔽占位/广告节点
        if BLACKLIST_NAME_HINTS.search(urllib.parse.unquote(uri.split("#", 1)[-1] if "#" in uri else "")):
            blacklist_hit += 1
            continue
        candidates.append((uri, outbound, server, port, proto))

    # 2.5 ★ v3.3 流程变更: 去重回迁到**测前** (v3.2 曾后移到测活期)
    #   v3.2 的做法: 测前不去重 → 每个节点建隧道 (6~26s) 拿到真实出口 IP
    #     后与"已成功测活"注册表比对 → 重复才截断。问题:
    #     ① 查重闸位置太靠后, 重复节点已经付掉了 sing-box check + 进程
    #        启动 + 三源探测 + 出口 IP 的开销, 只能省下测速段 12~25s;
    #     ② 闸门条件漏了 `and not lite`, 而 chain_retest 调用时取默认
    #        True → 家宽候选 100% 命中 → 全被误标 _chain_failed;
    #     ③ gate→register 之间有 12~25s 未注册窗口, 并发下同键副本
    #        可同时放行; ④ 空指纹直接拼进键, 指纹失败的不同配置会撞键。
    #   v3.3 的做法: 测前按**客户端配置身份**去重, 键 = node_key
    #     (server|port|proto|整个 outbound 规范化序列化), 不含 exit_ip →
    #     纯本地计算, 零网络零进程, 重复节点连 sing-box 都不启动。
    #     指纹从"手工枚举字段"改成"序列化整个 outbound", 漏读在结构上
    #     不可能再发生 (v3.2 的 cred_fingerprint 实证漏读 5 类字段)。
    #   ★ 出口维度的去重没丢: classify 阶段三套 exit_ip 去重仍在, 且它们
    #     跑在真实测活之后, 拿到的是 exit_ip 真值, 比测前静态判断更准。
    #   详见: node_key / dedup_candidates (模块级) 与设计文档第 12 节。

    # 2.6 ★ 静态预筛 (零网络零进程): 砍掉主动关闭证书校验的节点
    candidates = static_prescreen(candidates)

    # 2.65 ★ v3.3 测前去重: 同一份客户端配置只保留一个代表
    #   ★ 关口位置裁决 (为什么放在端口预检之前):
    #     ① 本关口是纯内存字典查表, 零网络零进程, 是所有关口里成本最低
    #        的一档 —— 按"越便宜越该前置"原则必然在预检之前;
    #     ② 预检 (prefilter_candidates) 只做 TCP connect(server_ip,port),
    #        QUIC 类只验域名可解析 —— **两者都只看 server/port, 与 outbound
    #        其余字段无关**。所以"先去重后预检"与"先预检后去重"砍掉的
    #        节点集合完全相同, 但前者少做几千次无意义的 TCP 握手
    #        (实测 16737→约 7700 候选, 预检墙钟 52s→24s);
    #     ③ 唯一顾虑"代表被预检淘汰但副本本该通过"不存在: 同 server:port
    #        的 TCP 可达性是服务端属性, 与凭据/配置无关。
    #   ★ 先按 raw URI 排序: fetch_raw_nodes 返回 list(set), 顺序随
    #     PYTHONHASHSEED 随机 → 排序让"保留哪个副本作代表"可复现。
    candidates.sort(key=lambda it: it[0])
    candidates, _dedup_stat = dedup_candidates(candidates)
    _dd = _dedup_stat
    if _dd["dropped"]:
        print(f"[+] 测前去重: {_dd['input']} → {_dd['kept']} "
              f"(剔除重复配置 {_dd['dropped']}, {_dd['dropped']*100.0/max(_dd['input'],1):.1f}%)")
        print(f"    预估省下 {_dd['dropped']*STAGE_B_WORST_SEC/MAX_WORKERS_TEST/60:.1f} 分钟 "
              f"(每节点省最多 {STAGE_B_WORST_SEC:.0f}s 阶段B 开销, 且省掉端口预检的 TCP 握手)")
    if _dd["no_fingerprint"]:
        print(f"[!] {_dd['no_fingerprint']} 个候选指纹生成失败, 已全部保留不参与去重 (宁慢不错)")
    print(f"[*] 测前去重后协议分布: " + " | ".join(
        f"{p}:{n}" for p, n in sorted(Counter(c[4] for c in candidates).items())))

    # 2.66 ★ v3.3 跨次运行死节点缓存: 提前剔除"连续两轮都死"的节点
    #   ★ 为什么也放在端口预检之前 (与去重同理):
    #     ① 纯内存字典查表, 零网络零进程, 成本最低的一档;
    #     ② 缓存里的死节点绝大多数是"端口 TCP 通、隧道死" —— 端口预检
    #        (纯 TCP 握手) 对它们**根本砍不掉**。放在预检后剔除只能省测活
    #        成本, 放在预检前则连预检一起省 (输入 16737→约 11787, -29.6%);
    #     ③ 与测前去重的先后: 两种顺序下"进测活的唯一 node_key 集合"完全
    #        相同 (同一配置的多个副本剔不剔都收敛到 1 个), 但"先剔死"让
    #        后续预检/污染预查/预评分的输入更小 —— 净赚, 严格更优。
    #   ★ 时序铁律: 剔除只读缓存里**上一轮落盘**的 h>=DEAD_MIN_HIT 条目。
    #     本轮的测试结果只决定**下一轮**是否剔除。
    dead_cache = load_dead_cache()
    if dead_cache:
        candidates, _dead_dropped = select_dead_nodes(candidates, dead_cache)
        # 抽样复测: 放回少量已固化节点照常测, 复活即从缓存删除。
        #   ★ 这同时是 hit 计数能持续累积的唯一途径 —— 固化后若永不被测,
        #     h 永远停在 DEAD_MIN_HIT, TTL 到期后全部清掉、下一轮又要从头
        #     积累两轮才具备剔除资格, 缓存自己把自己废掉了。
        _recheck = pick_dead_recheck(_dead_dropped, DEAD_RECHECK_N)
        if _recheck:
            candidates = candidates + _recheck
            print(f"[*] ★死节点抽样复测: 从被剔除的 {len(_dead_dropped)} 个里放回 "
                  f"{len(_recheck)} 个照常测 (复活即从缓存删除; 也是 hit 能持续"
                  f"累积的唯一途径)")
    else:
        _dead_dropped, _recheck = [], []

    # 2.7 ★ v3.2 顺序优化: 域名解析预热前移到此 (端口预检要逐域名解析,
    #     提前并发预热 → 预检内全部命中缓存); 而 **DNS 污染预查后移到端口
    #     预检之后** — 旧顺序对全部域名查污染 (含大量预检就会死的死域名),
    #     新顺序只对预检存活者查, 唯一域名数砍半, 省 ~10~20s; 且污染判定
    #     只服务"能进订阅的节点", 对死节点查询本就是纯浪费。
    #     ① 域名解析并发预热 (32 并发)
    #     ② 端口预检 (砍 50~60% 死节点)  ← 见下方步骤 3
    #     ③ DNS 污染预查 (只对预检后存活域名; 大陆公共 DNS vs 全球 DNS,
    #        硬失败且海外正常 = 域名被污染 → 静态评分 -45 并排除出友好订阅)
    #     ④ 静态 China 友好度评分 + 按分降序 (高分节点先测先出结果)
    n_resolved = prefetch_dns([c[2] for c in candidates])
    candidates = prefilter_candidates(candidates)

    n_dom, n_polluted = precheck_dns_pollution([c[2] for c in candidates])
    if n_dom:
        print(f"[*] DNS 污染预查 (预检后): {n_dom} 个唯一域名, {n_polluted} 个在大陆解析异常 "
              f"(静态评分 {CN_SCORE_DNS_POLLUTED}, 排除出国内友好订阅)")
    prescore_map = {}
    for it in candidates:
        s, fl = static_cn_prescore(it)
        prescore_map[it[0]] = (s, fl)
    candidates.sort(key=lambda it: -prescore_map[it[0]][0])
    hi = sum(1 for it in candidates if prescore_map[it[0]][0] >= CN_FRIENDLY_MIN_SCORE)
    print(f"[*] 静态 China 友好度预评分: 预测分 ≥{CN_FRIENDLY_MIN_SCORE} 的候选 {hi} 个 "
          f"(域名解析预热 {n_resolved} 个; 已按预测分降序进入测试)")

    # ★ v3.3 新增诊断: prescore 分布直方图
    #   为什么必须看: 上面那句"已按预测分降序进入测试"暗示排序在起作用,
    #   但**从未验证过 prescore 真的有区分度**。若大量节点同分, 排序就退化
    #   成近似稳定序, "高分先测"这一优化等于没做 (v3.3 没加时间预算,
    #   排序目前只影响顺序不影响规模, 但一旦将来加预算/预算不足时,
    #   排序质量就直接决定被砍掉的是不是低价值节点)。
    #   同时打印 hi/candidates 比例: 该比例越低, 说明静态评分对未来加
    #   "只测高分候选"的预算机制越友好。
    _hist = Counter(prescore_map[it[0]][0] for it in candidates)
    print("[*] prescore 分布 (验证排序区分度): " + " | ".join(
        f"{s}分:{n}" for s, n in sorted(_hist.items(), reverse=True)[:12]))
    print(f"    ≥{CN_FRIENDLY_MIN_SCORE} 分占比 {hi*100.0/max(len(candidates),1):.1f}% | "
          f"分值跨度 {max(_hist) if _hist else 0}~{min(_hist) if _hist else 0} | "
          f"取值档数 {len(_hist)}")

    proto_stat = {}
    for _, _, _, _, p in candidates:
        proto_stat[p] = proto_stat.get(p, 0) + 1
    print(f"[*] 静态预筛+去重后: {len(candidates)} (原始解析成功 {len(candidates)+_dd['dropped']}) | "
          f"失败 {parse_fail} | 协议分布 {proto_stat}")
    if blacklist_hit:
        print(f"    占位/广告节点剔除: {blacklist_hit} (BLACKLIST_NAME_HINTS 命中)")
    if parse_fail_samples:
        print(f"    解析失败样本 (前 {len(parse_fail_samples)} 条, 便于定位烂源/格式):")
        for s in parse_fail_samples:
            print(f"      · {s}")

    if not candidates:
        print("[!] 无可测节点 (订阅源全部失效?) — 保留上次 output, 不覆盖订阅文件")
        # ★ v3.3: 这里也要 flush 一次 —— 目的不是记新死亡, 而是把 load 时
        #   按 TTL 丢弃掉的过期条目**真正落盘清掉**, 否则它们会在缓存里
        #   再占 3 天 (每轮都被读进来又被丢, 只是没写回去而已)。
        save_dead_cache(dead_cache)
        return

    # 4. 真实测活 (已按静态 CN 分降序, 高分先测; 端口预检已在 2.7 步完成)
    # ★ v3.3 返回值改为 (results, dead_records)
    test_results, dead_records = run_liveness_test(candidates, prescore_map=prescore_map)

    # 4.2 ★ v3.3 死节点缓存**早写**: 测活一结束就落盘, 不等 classify/导出。
    #   ★ 为什么必须早写: Actions cache 只在**作业成功结束**时才保存 (被
    #     并发限制杀掉 exit 143 时不保存)。若等到 main() 末尾才写, 后面任一
    #     阶段崩溃/被杀就白丢一整轮的死节点数据, 缓存的 hit 累积被打回原点。
    #     早写让文件先落盘, 剩下的只是"没被 Actions 存下来"这一个环节。
    #   ★ observed_alive 必须过滤 is_stalled: is_stalled 同时被记进
    #     dead_records (它是"残废") 和 results (它走返回值路径)。不过滤
    #     就会同一条既死又活, hit 与复活判定互相矛盾。
    try:
        _alive_keys = set()
        for _r in test_results:
            if _r.get("alive") and not _r.get("is_stalled"):
                _alive_keys.add(node_key(_r["outbound"], _r["proto"],
                                         _r["server"], _r["port"]))
        flush_dead_cache(dead_cache, observed_dead=dead_records,
                         observed_alive=_alive_keys, n_candidates=len(candidates))
    except Exception as e:
        print(f"[!] 死节点缓存更新失败 ({str(e)[:70]}) — 不影响本轮交付")

    # 4.5 ★ 重复节点回填仍是"已删除"状态 (v3.2 删除, v3.3 让删除更彻底)。
    #   历史: v3.1 及更早 = 测前去重 + 测后回填克隆体 (未真测的节点继承
    #   代表结论进订阅, 靠 P0-2 insecure 复查 + equiv 兜底两层补丁);
    #   v3.2 = 去重后移到测活期, 靠注册表挡重复, 回填失去意义;
    #   v3.3 = 去重回迁到测前 (dedup_candidates), 重复节点连 sing-box
    #   都不启动 —— 比 v3.2 更省, 且同样保证"进订阅的都是真跑过测活的"。
    #   ★ 关键不变式 (被 _verify_export_lineage 依赖): unique_nodes 的
    #     唯一来源是 classify_and_export 逐条从 test_results 构造 (无回填
    #     路径), 而 test_results 的每个元素都真跑过 test_single_node。
    #     被测前去重/死缓存剔除的节点从不进入 candidates, 三个集合里都
    #     不存在, 所以 _verify_export_lineage 不会因去重而误报。


    # 5. ★ 家宽链式复测: 用最快存活节点做前置双跳复测家宽候选
    #    (模拟用户 v2rayN 链式场景, 双跳失败的家宽降级普通区 — 提高链式可用率)
    # 5.0 ★ 2026-10-04 优化: ip-api 情报在此处**预查一次**, 供下面 5 与 6 两阶段共用。
    #   旧版 chain_retest 和 classify_and_export 各查一遍同一个 IP 集合 ——
    #   #70 实测白多花 25s + 消耗一半免费额度 (ip-api 限 15 req/min, 517IP=6批)。
    ip_all = list({r["exit_ip"] for r in test_results if r.get("exit_ip")})
    ip_api_shared = {}
    if ip_all:
        try:
            _est = (len(ip_all) + IP_API_BATCH_SIZE - 1) // IP_API_BATCH_SIZE
            print(f"[*] ip-api 批量情报 (预查, 供链式复测+分类共用): "
                  f"{len(ip_all)} IP / {_est} 批 ≈ {_est * 4.2:.0f}s ...")
            ip_api_shared = ip_api_batch_lookup(ip_all)
            print(f"[+] ip-api.com 预查完成: {len(ip_api_shared)}/{len(ip_all)}")
        except Exception as e:
            print(f"[!] ip-api 批量失败 ({e}), 两阶段将回退到离线判定")
    test_results = chain_retest(test_results, ip_api_info=ip_api_shared)

    # 6. 分类 + 导出 (无真活节点时保留上次 output, 不写空订阅覆盖线上数据)
    if not test_results:
        print("[!] 全部节点测活失败 — 保留上次 output, 不覆盖订阅文件")
        return
    unique_nodes, residential, non_residential, cn_friendly = classify_and_export(
        test_results, ip_api_info=ip_api_shared)
    if not unique_nodes:
        print("[!] 分类后无存活节点 — 保留上次 output")
        return

    # ★ P2 闭环校验: 每个出库节点必须能追溯到"已测活"或"已补筛查的回填体"。
    #   硬要求"未经测试筛选的节点不被保留" —— 用断言把它变成可验证的,
    #   而不是靠人肉 review 代码路径。发现漏网之鱼时打警告并指出具体 raw, 便于定位。
    _verify_export_lineage(unique_nodes, test_results)

    # ★ v3 审计加固 (2026-10-16): 交付前最终闸门 — "未经过全套筛选的节点
    #   不许漏进最终交付"从代码走查升级为结构化断言:
    #     ① 全量订阅: 判定字段完整 (alive/非断流/非MITM/fraud已评/cn_score已算/outbound可导出)
    #     ② 国内友好订阅: 追加 DNS 信号闭合 (污染判定必须明确得过, 防 CN DoH
    #        整体不可达时污染检测静默失效 — 只踢出友好订阅并清旗标, 不动全量)
    #   子集列表随全量闸门同步收敛 (id 集合过滤, 不用 dict __eq__ — 防误伤)。
    unique_nodes, gate_problems = final_gate(unique_nodes, label="全量订阅")
    if not unique_nodes:
        print("[!] 最终闸门后无存活节点 — 保留上次 output")
        return
    if gate_problems:
        un_ids = {id(n) for n in unique_nodes}
        residential = [n for n in residential if id(n) in un_ids]
        cn_friendly = [n for n in cn_friendly if id(n) in un_ids]
    res_ids = {id(n) for n in residential}
    non_residential = [n for n in unique_nodes if id(n) not in res_ids]
    cn_friendly, cn_gate_problems = final_gate(cn_friendly, require_cn_signal=True,
                                               label="国内友好订阅")
    if cn_gate_problems:
        print(f"    → {len(cn_gate_problems)} 个节点因国内向证据不足移出友好订阅 "
              f"(仍在全量订阅内, 节点名已清 🇨🇳 旗标)")

    total, res, cn = export_all(unique_nodes, residential, non_residential,
                                cn_friendly=cn_friendly)
    update_readme(total, res, cn)


    # 统计报告
    elapsed = time.time() - t_start
    print("\n===== 运行报告 =====")
    print(f"总耗时: {elapsed:.0f}s ({elapsed/60:.1f} 分钟) | 抓取 {len(raw_nodes)} → 静态预筛+去重 {len(candidates)} (测前去重剔除 {_dd['dropped']}) → 真活 {len(test_results)} → 出口去重后 {len(unique_nodes)} → 家宽 {len(residential)} → 国内友好 {len(cn_friendly)}")
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
    if cn_friendly:
        top_cn = sorted(cn_friendly, key=lambda x: -(x.get("cn_score") or 0))[:5]
        detail = " | ".join(
            f"{n['proto']}/{n['server']}:{n['port']} cn={n.get('cn_score')}"
            + (f" atlas={n['atlas_ok_ratio']:.0%}" if n.get("atlas_ok_ratio") is not None else "")
            for n in top_cn)
        print(f"国内友好 Top5 (cn_score): {detail}")


if __name__ == "__main__":
    main()
