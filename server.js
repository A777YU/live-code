const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const useragent = require('useragent');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== 数据目录初始化 =====
const DATA_DIR = path.join(__dirname, 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const LOG_FILE = path.join(DATA_DIR, 'ip_log.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked.json');
const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({ url: 'https://example.com/main', fallbackUrl: 'https://example.com/fallback' }));
}
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, JSON.stringify([]));
if (!fs.existsSync(BLOCKED_FILE)) {
    fs.writeFileSync(BLOCKED_FILE, JSON.stringify({ ips: [], cities: [], provinces: [] }));
}
if (!fs.existsSync(WHITELIST_FILE)) {
    fs.writeFileSync(WHITELIST_FILE, JSON.stringify({ ips: [], cities: [], provinces: [] }));
}

// ===== 工具函数 =====
function getConfig() {
    return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
}
function saveConfig(config) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}
function getLogs() {
    try {
        return JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));
    } catch (e) {
        console.error('[getLogs] 读取日志失败，重置为空数组', e);
        return [];
    }
}
function saveLogs(logs) {
    try {
        fs.writeFileSync(LOG_FILE, JSON.stringify(logs, null, 2));
        console.log(`[saveLogs] 成功写入 ${logs.length} 条记录`);
    } catch (e) {
        console.error('[saveLogs] 写入失败', e);
    }
}
function getBlocked() {
    return JSON.parse(fs.readFileSync(BLOCKED_FILE, 'utf-8'));
}
function saveBlocked(blocked) {
    fs.writeFileSync(BLOCKED_FILE, JSON.stringify(blocked, null, 2));
}
function getWhitelist() {
    return JSON.parse(fs.readFileSync(WHITELIST_FILE, 'utf-8'));
}
function saveWhitelist(whitelist) {
    fs.writeFileSync(WHITELIST_FILE, JSON.stringify(whitelist, null, 2));
}

function getIPv4(ip) {
    if (ip.startsWith('::ffff:')) return ip.substring(7);
    return ip;
}
function normalizeRegion(str) {
    if (!str) return '';
    let s = str.trim();
    const suffixes = ['省', '市', '自治区', '特别行政区', '自治州', '盟', '地区', '区', '县', '旗', '自治县', '自治旗', '林区', '特区'];
    for (let suf of suffixes) {
        if (s.endsWith(suf)) {
            s = s.slice(0, -suf.length);
            break;
        }
    }
    return s.trim();
}
function isMatched(list, target) {
    const normalizedTarget = normalizeRegion(target);
    return list.some(item => {
        const normalizedItem = normalizeRegion(item);
        return normalizedTarget === normalizedItem ||
               normalizedTarget.includes(normalizedItem) ||
               normalizedItem.includes(normalizedTarget);
    });
}

// ===== IP地理位置（双服务对比） =====
const geoCache = {};
const CACHE_TTL = 24 * 60 * 60 * 1000;
const IPDATACLOUD_KEY = process.env.IPDATACLOUD_KEY || '75420c4e849e11f1a82800163e167ffb';
const ALIYUN_APPCODE = process.env.ALIYUN_APPCODE || 'e5f69ac13b5a492b86693d5e6c4f1a1b';

// ----- 阿里云 -----
async function getAliyunGeo(ip) {
    console.log(`[阿里云] 开始查询 IP: ${ip}`);
    try {
        const response = await axios.get('https://jisuip.market.alicloudapi.com/ip/location', {
            params: { ip: ip },
            headers: { 'Authorization': 'APPCODE ' + ALIYUN_APPCODE },
            timeout: 3000
        });
        console.log('[阿里云] 原始响应:', JSON.stringify(response.data));
        let data = null;
        if (response.data) {
            if (response.data.status === 0 && response.data.result) {
                data = response.data.result;
            } else if ((response.data.code === 0 || response.data.code === 200) && response.data.data) {
                data = response.data.data;
            } else if (response.data.country) {
                data = response.data;
            }
        }
        if (data) {
            const result = {
                country: data.country || '未知',
                region: data.province || data.region || '未知',
                city: data.city || '未知'
            };
            console.log('[阿里云] 查询成功:', result);
            return result;
        } else {
            console.error('[阿里云] 无法解析响应结构:', response.data);
            return null;
        }
    } catch (e) {
        console.error('[阿里云] 请求失败:', e.message);
        return null;
    }
}

// ----- IP666（超时 3000ms） -----
async function getIp666Geo(ip) {
    console.log(`[IP666] 开始查询 IP: ${ip}`);
    try {
        const url = 'https://api.ipdatacloud.com/v2/query';
        const response = await axios.get(url, {
            params: { ip: ip, key: IPDATACLOUD_KEY },
            timeout: 3000
        });
        console.log('[IP666] 原始响应:', JSON.stringify(response.data));
        const data = response.data?.data;
        if (data && (response.data.code == 200 || response.data.code == 0)) {
            let locationData = data.location || data;
            const result = {
                country: locationData.country || '未知',
                region: locationData.province || locationData.region || '未知',
                city: locationData.city || ''
            };
            console.log('[IP666] 查询成功:', result);
            return result;
        } else {
            console.log(`[IP666] 查询失败，响应码: ${response.data?.code}`);
            return null;
        }
    } catch (e) {
        console.error('[IP666] 请求失败:', e.message);
        return null;
    }
}

async function getGeoInfo(ip) {
    const ipv4 = getIPv4(ip);
    if (geoCache[ipv4] && (Date.now() - geoCache[ipv4].timestamp < CACHE_TTL)) {
        console.log(`[GeoCache] 命中缓存 IP: ${ipv4}`);
        return geoCache[ipv4].data;
    }
    console.log(`[Geo] 开始获取 IP: ${ipv4} 的地理信息`);
    const [ip666, aliyun] = await Promise.all([
        getIp666Geo(ipv4),
        getAliyunGeo(ipv4)
    ]);
    let result = {
        country: '未知',
        region: '未知',
        city: '未知',
        match: false,
        ip666: ip666 || { region: '服务不可用', city: '服务不可用' },
        aliyun: aliyun || { region: '服务不可用', city: '服务不可用' }
    };
    if (ip666 && aliyun) {
        const region666 = normalizeRegion(ip666.region);
        const regionAli = normalizeRegion(aliyun.region);
        result.match = (region666 === regionAli);
        result.country = ip666.country || '未知';
        result.region = ip666.region || '未知';
        result.city = ip666.city || ip666.region || '未知';
        result.ip666 = { region: ip666.region, city: ip666.city || ip666.region };
        result.aliyun = { region: aliyun.region, city: aliyun.city || aliyun.region };
    } else if (ip666) {
        result.country = ip666.country || '未知';
        result.region = ip666.region || '未知';
        result.city = ip666.city || ip666.region || '未知';
        result.match = false;
        result.ip666 = { region: ip666.region, city: result.city };
        result.aliyun = { region: '服务不可用', city: '服务不可用' };
    } else if (aliyun) {
        result.country = aliyun.country || '未知';
        result.region = aliyun.region || '未知';
        result.city = aliyun.city || aliyun.region || '未知';
        result.match = false;
        result.ip666 = { region: '服务不可用', city: '服务不可用' };
        result.aliyun = { region: aliyun.region, city: result.city };
    } else {
        result.match = false;
        result.ip666 = { region: '服务不可用', city: '服务不可用' };
        result.aliyun = { region: '服务不可用', city: '服务不可用' };
    }
    console.log('[Geo] 最终结果:', result);
    geoCache[ipv4] = { data: result, timestamp: Date.now() };
    return result;
}

// ===== ★ 统一屏蔽判断函数（严格参照参考代码） =====
function isBlocked(ip, geo, blockedList, whitelist) {
    const ipv4 = getIPv4(ip);
    // 1. 白名单IP优先
    if (whitelist.ips.includes(ipv4)) {
        return false;
    }
    // 2. 白名单城市/省份
    const wlCityMatch = isMatched(whitelist.cities, geo.city);
    const wlProvinceMatch = isMatched(whitelist.provinces, geo.region);
    if (wlCityMatch || wlProvinceMatch) {
        return false;
    }
    // 3. 屏蔽列表 IP/城市/省份
    const cityMatch = isMatched(blockedList.cities, geo.city);
    const provinceMatch = isMatched(blockedList.provinces, geo.region);
    if (blockedList.ips.includes(ipv4) || cityMatch || provinceMatch) {
        return true;
    }
    // 4. 如果城市和省份都是"未知"，则屏蔽
    if (geo.city === '未知' && geo.region === '未知') {
        return true;
    }
    // 5. 双IP对比不一致则屏蔽
    if (!geo.match) {
        return true;
    }
    // 否则不屏蔽
    return false;
}

// ===== 记录IP日志 =====
async function logIP(ip, action, req) {
    try {
        console.log(`[logIP] 开始记录 - IP: ${ip}, action: ${action}`);
        if (req && req.path && req.path.startsWith('/admin')) {
            console.log(`[logIP] 跳过 admin 路径`);
            return;
        }
        const logs = getLogs();
        const now = new Date().toISOString();
        const ipv4 = getIPv4(ip);
        const geo = await getGeoInfo(ipv4);
        const blockedList = getBlocked();
        const whitelist = getWhitelist();

        let device = '未知';
        if (req) {
            const agent = useragent.parse(req.headers['user-agent'] || '');
            device = `${agent.family} ${agent.major}.${agent.minor} / ${agent.os.family} ${agent.os.major}`.trim() || '未知';
        }

        // ★ 使用统一的判断函数
        const finalBlocked = isBlocked(ipv4, geo, blockedList, whitelist);

        const entry = {
            ip: ipv4,
            action: action,
            time: now,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            device: device,
            blocked: finalBlocked,
            compare: {
                match: geo.match,
                ip666: geo.ip666,
                aliyun: geo.aliyun
            }
        };
        logs.push(entry);
        saveLogs(logs);
        console.log(`[logIP] 记录已保存 - IP: ${ipv4}, blocked: ${finalBlocked}`);
    } catch (err) {
        console.error('[logIP] 记录日志时发生异常:', err);
    }
}

function getClientIP(req) {
    const headers = ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'true-client-ip', 'x-client-ip'];
    for (let h of headers) {
        const val = req.headers[h];
        if (val) {
            const ips = val.split(',').map(v => v.trim());
            if (ips.length > 0) return ips[0];
        }
    }
    return req.connection.remoteAddress || req.ip || '0.0.0.0';
}

// ===== 中间件 =====
app.use(cors());
app.use(bodyParser.json({ limit: '10mb' }));

app.use(async (req, res, next) => {
    const exclude = ['/admin', '/api'];
    const isExcluded = exclude.some(p => req.path.startsWith(p));
    if (req.method === 'GET' && !isExcluded) {
        const ip = getClientIP(req);
        console.log(`[中间件] 捕获到访问 IP: ${ip}, 路径: ${req.path}`);
        await logIP(ip, 'visit', req);
    }
    next();
});

app.use(express.static('public'));

app.use(session({
    secret: 'my-secret-key-2024',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// ============================================
// 公开 API
// ============================================

app.get('/api/config', async (req, res) => {
    const ip = getClientIP(req);
    const referer = req.headers.referer || '';
    if (!referer.includes('/admin')) {
        await logIP(ip, 'click', req);
    }

    const config = getConfig();
    const ipv4 = getIPv4(ip);
    const geo = await getGeoInfo(ipv4);
    const blockedList = getBlocked();
    const whitelist = getWhitelist();

    // ★ 使用统一的判断函数
    const isBlockedResult = isBlocked(ipv4, geo, blockedList, whitelist);

    res.json({
        url: config.url,
        fallbackUrl: config.fallbackUrl || 'https://example.com/fallback',
        blocked: isBlockedResult
    });
});

// ============================================
// 管理后台（需登录）
// ============================================

app.post('/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === '123456') {
        req.session.loggedIn = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ success: false, message: '密码错误' });
    }
});

app.post('/admin/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/admin/check', (req, res) => {
    res.json({ loggedIn: !!req.session.loggedIn });
});

function requireLogin(req, res, next) {
    if (req.session.loggedIn) {
        next();
    } else {
        res.status(401).json({ success: false, message: '请先登录' });
    }
}

// 配置管理
app.get('/api/config', requireLogin, (req, res) => {
    res.json(getConfig());
});
app.post('/api/config', requireLogin, (req, res) => {
    const { url, fallbackUrl } = req.body;
    if (!url) return res.status(400).json({ success: false, message: '缺少主链接' });
    const config = getConfig();
    config.url = url;
    if (fallbackUrl !== undefined) config.fallbackUrl = fallbackUrl;
    saveConfig(config);
    res.json({ success: true });
});

// 屏蔽管理
app.get('/api/blocked', requireLogin, (req, res) => {
    res.json(getBlocked());
});
app.post('/api/blocked', requireLogin, (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) return res.status(400).json({ success: false, message: '缺少参数' });
    if (type === 'ip') {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(value)) return res.status(400).json({ success: false, message: 'IP格式无效' });
    }
    const blocked = getBlocked();
    if (type === 'ip') {
        if (!blocked.ips.includes(value)) { blocked.ips.push(value); saveBlocked(blocked); }
    } else if (type === 'city') {
        if (!blocked.cities.includes(value)) { blocked.cities.push(value); saveBlocked(blocked); }
    } else if (type === 'province') {
        if (!blocked.provinces.includes(value)) { blocked.provinces.push(value); saveBlocked(blocked); }
    } else {
        return res.status(400).json({ success: false, message: '无效类型' });
    }
    res.json({ success: true });
});
app.delete('/api/blocked/:type/:value', requireLogin, (req, res) => {
    const { type, value } = req.params;
    const blocked = getBlocked();
    if (type === 'ip') {
        blocked.ips = blocked.ips.filter(ip => ip !== value);
    } else if (type === 'city') {
        blocked.cities = blocked.cities.filter(city => city !== value);
    } else if (type === 'province') {
        blocked.provinces = blocked.provinces.filter(p => p !== value);
    } else {
        return res.status(400).json({ success: false, message: '无效类型' });
    }
    saveBlocked(blocked);
    res.json({ success: true });
});

// 白名单管理
app.get('/api/whitelist', requireLogin, (req, res) => {
    res.json(getWhitelist());
});
app.post('/api/whitelist', requireLogin, (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) return res.status(400).json({ success: false, message: '缺少参数' });
    if (type === 'ip') {
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(value)) return res.status(400).json({ success: false, message: 'IP格式无效' });
    }
    const whitelist = getWhitelist();
    if (type === 'ip') {
        if (!whitelist.ips.includes(value)) { whitelist.ips.push(value); saveWhitelist(whitelist); }
    } else if (type === 'city') {
        if (!whitelist.cities.includes(value)) { whitelist.cities.push(value); saveWhitelist(whitelist); }
    } else if (type === 'province') {
        if (!whitelist.provinces.includes(value)) { whitelist.provinces.push(value); saveWhitelist(whitelist); }
    } else {
        return res.status(400).json({ success: false, message: '无效类型' });
    }
    res.json({ success: true });
});
app.delete('/api/whitelist/:type/:value', requireLogin, (req, res) => {
    const { type, value } = req.params;
    const whitelist = getWhitelist();
    if (type === 'ip') {
        whitelist.ips = whitelist.ips.filter(ip => ip !== value);
    } else if (type === 'city') {
        whitelist.cities = whitelist.cities.filter(city => city !== value);
    } else if (type === 'province') {
        whitelist.provinces = whitelist.provinces.filter(p => p !== value);
    } else {
        return res.status(400).json({ success: false, message: '无效类型' });
    }
    saveWhitelist(whitelist);
    res.json({ success: true });
});

// ===== 清空缓存 API =====
app.post('/api/clear-cache', requireLogin, (req, res) => {
    const keys = Object.keys(geoCache);
    keys.forEach(key => delete geoCache[key]);
    console.log(`[clear-cache] 已清空 ${keys.length} 条缓存`);
    res.json({ success: true, cleared: keys.length });
});

// ===== 访客统计（被屏蔽/未屏蔽） =====
app.get('/api/visitors/:type', requireLogin, (req, res) => {
    const type = req.params.type;
    // 只统计 visit 动作
    const logs = getLogs().filter(l => l.action === 'visit');
    const map = {};

    logs.forEach(entry => {
        const ip = entry.ip;
        if (!map[ip]) {
            map[ip] = {
                ip,
                country: entry.country,
                region: entry.region,
                city: entry.city,
                compare: entry.compare || { match: false, ip666: {}, aliyun: {} },
                device: entry.device || '未知',
                firstTime: entry.time,
                lastTime: entry.time,
                count: 0,
                blocked: entry.blocked !== undefined ? entry.blocked : false
            };
        }
        const item = map[ip];
        item.count++;
        if (entry.time < item.firstTime) item.firstTime = entry.time;
        if (entry.time > item.lastTime) item.lastTime = entry.time;
        if (entry.blocked !== undefined) item.blocked = entry.blocked;
    });

    const result = Object.values(map).filter(item => {
        return type === 'blocked' ? item.blocked : !item.blocked;
    });
    result.sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));
    res.json(result);
});

// ===== 今日统计 =====
app.get('/api/stats', requireLogin, (req, res) => {
    const logs = getLogs().filter(l => l.action === 'visit');
    const today = new Date().toISOString().slice(0, 10);
    const todayLogs = logs.filter(l => l.time.startsWith(today));
    const ipMap = {};
    todayLogs.forEach(entry => {
        const ip = entry.ip;
        if (!ipMap[ip]) {
            ipMap[ip] = { blocked: entry.blocked !== undefined ? entry.blocked : false };
        }
    });
    let blockedCount = 0, unblockedCount = 0;
    Object.values(ipMap).forEach(item => {
        if (item.blocked) blockedCount++;
        else unblockedCount++;
    });
    res.json({
        total: Object.keys(ipMap).length,
        blocked: blockedCount,
        unblocked: unblockedCount
    });
});

// ============================================
// 管理后台页面（包含清空缓存按钮）
// ============================================
app.get('/admin', (req, res) => {
    if (req.session.loggedIn) {
        res.send(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", Arial, sans-serif; background: #f0f2f5; padding: 12px; max-width: 1200px; margin: 0 auto; }
        h2 { font-size: 20px; margin-bottom: 12px; }
        .card { background: #fff; border-radius: 8px; padding: 12px 14px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); margin-bottom: 12px; }
        .card h3 { font-size: 15px; margin-bottom: 8px; color: #1a3a5c; }
        .btn { background: #1a3a6a; color: #fff; border: none; border-radius: 20px; padding: 4px 14px; cursor: pointer; font-size: 13px; }
        .btn:hover { background: #0b1e3a; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .btn-sm { padding: 2px 10px; font-size: 12px; }
        input[type="text"], select { padding: 4px 8px; border: 1px solid #ddd; border-radius: 4px; font-size: 13px; }
        input[type="text"] { width: 160px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(100px, 1fr)); gap: 8px; }
        .stat-item { background: #f5f7fa; padding: 8px 12px; border-radius: 6px; text-align: center; }
        .stat-item .number { font-size: 22px; font-weight: 700; color: #1a3a6a; }
        .stat-item .label { font-size: 12px; color: #6b7a8f; margin-top: 2px; }
        .log-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .log-table th, .log-table td { padding: 4px 8px; border-bottom: 1px solid #eee; text-align: left; vertical-align: top; }
        .log-table th { background: #f5f7fa; font-weight: 600; font-size: 12px; }
        .log-table tr:hover { background: #f9fafb; }
        .scrollable { max-height: 400px; overflow-y: auto; }
        .blocked-item, .whitelist-item { display: inline-block; background: #f5f7fa; padding: 2px 10px; border-radius: 12px; margin: 2px 4px 2px 0; font-size: 12px; }
        .blocked-item .del, .whitelist-item .del { cursor: pointer; color: #e74c3c; margin-left: 4px; font-weight: bold; }
        .config-row { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; margin-bottom: 4px; }
        .config-row label { width: 70px; font-size: 13px; }
        .config-row input { flex: 1; min-width: 120px; }
        .compare-badge { font-size: 11px; padding: 2px 6px; border-radius: 10px; display: inline-block; }
        .compare-match { background: #d4edda; color: #155724; }
        .compare-fail { background: #f8d7da; color: #721c24; }
        .compare-unknown { background: #e2e3e5; color: #383d41; }
        .flex-row { display: flex; gap: 12px; flex-wrap: wrap; }
        .flex-row .card { flex: 1; min-width: 200px; }
        @media (max-width: 600px) {
            .stats-grid { grid-template-columns: 1fr 1fr; }
            .flex-row { flex-direction: column; }
        }
        .status { margin-left: 10px; font-size: 13px; }
        .status.error { color: #e74c3c; }
        .cache-btn { margin-top: 10px; }
    </style>
</head>
<body>
<div id="app">
    <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px;">
        <h2 style="margin:0;">📋 管理后台</h2>
        <div><button class="btn btn-danger" onclick="logout()">退出登录</button></div>
    </div>

    <div class="card">
        <h3>📊 今日统计</h3>
        <div class="stats-grid">
            <div class="stat-item"><div class="number" id="totalVisits">0</div><div class="label">总访客</div></div>
            <div class="stat-item"><div class="number" id="blockedVisits">0</div><div class="label">已屏蔽</div></div>
            <div class="stat-item"><div class="number" id="unblockedVisits">0</div><div class="label">未屏蔽</div></div>
        </div>
        <div class="cache-btn">
            <button class="btn" onclick="clearCache()">🗑️ 清空 IP 缓存</button>
            <span id="clearStatus" style="margin-left:10px;font-size:13px;"></span>
        </div>
    </div>

    <div class="card">
        <h3>🔗 跳转链接配置</h3>
        <div class="config-row"><label>主链接：</label><input type="text" id="urlInput" placeholder="主链接" /></div>
        <div class="config-row"><label>备用链接：</label><input type="text" id="fallbackUrlInput" placeholder="备用链接" /></div>
        <button class="btn" onclick="updateUrl()">更新链接</button>
        <span id="urlStatus" class="status"></span>
        <p id="currentUrl" style="font-size:12px;color:#888;margin-top:4px;"></p>
    </div>

    <div class="flex-row">
        <div class="card">
            <h3>🚫 屏蔽管理</h3>
            <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                <input type="text" id="blockInput" placeholder="IP/城市/省份" style="width:140px;" />
                <select id="blockType"><option value="ip">IP</option><option value="city">城市</option><option value="province">省份</option></select>
                <button class="btn btn-sm" onclick="addBlock()">添加</button>
            </div>
            <div id="blockedList" style="margin-top:6px;"></div>
        </div>
        <div class="card">
            <h3>✅ 白名单管理</h3>
            <div style="display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                <input type="text" id="whitelistInput" placeholder="IP/城市/省份" style="width:140px;" />
                <select id="whitelistType"><option value="ip">IP</option><option value="city">城市</option><option value="province">省份</option></select>
                <button class="btn btn-sm" onclick="addWhitelist()">添加</button>
            </div>
            <div id="whitelistList" style="margin-top:6px;"></div>
        </div>
    </div>

    <div class="card">
        <h3>🚫 被屏蔽用户详情</h3>
        <div class="scrollable">
            <table class="log-table">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>定位对比</th>
                        <th>省份</th>
                        <th>设备</th>
                        <th>进入次数</th>
                        <th>首次时间(北京)</th>
                        <th>最近时间(北京)</th>
                    </tr>
                </thead>
                <tbody id="blockedVisitorBody"><tr><td colspan="7">加载中...</td></tr></tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <h3>✅ 未屏蔽用户详情</h3>
        <div class="scrollable">
            <table class="log-table">
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>定位对比</th>
                        <th>省份</th>
                        <th>设备</th>
                        <th>进入次数</th>
                        <th>首次时间(北京)</th>
                        <th>最近时间(北京)</th>
                    </tr>
                </thead>
                <tbody id="unblockedVisitorBody"><tr><td colspan="7">加载中...</td></tr></tbody>
            </table>
        </div>
    </div>
</div>

<script>
    function formatBeijingTime(isoString) {
        if (!isoString) return '-';
        const date = new Date(isoString);
        return date.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    }

    function loadStats() {
        fetch('/api/stats').then(r=>r.json()).then(d=>{
            document.getElementById('totalVisits').textContent = d.total || 0;
            document.getElementById('blockedVisits').textContent = d.blocked || 0;
            document.getElementById('unblockedVisits').textContent = d.unblocked || 0;
        }).catch(()=>{});
    }

    function loadConfig() {
        fetch('/api/config').then(r=>r.json()).then(d=>{
            document.getElementById('currentUrl').textContent = '主链接：'+d.url+' | 备用链接：'+d.fallbackUrl;
            document.getElementById('urlInput').value = d.url;
            document.getElementById('fallbackUrlInput').value = d.fallbackUrl||'';
        });
    }

    function updateUrl() {
        const url = document.getElementById('urlInput').value.trim();
        const fallbackUrl = document.getElementById('fallbackUrlInput').value.trim();
        if(!url){ alert('请输入主链接'); return; }
        fetch('/api/config', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ url, fallbackUrl }) })
        .then(r=>r.json()).then(d=>{
            const status = document.getElementById('urlStatus');
            if(d.success){ status.textContent='✅ 更新成功'; status.className='status'; loadConfig(); }
            else{ status.textContent='❌ '+d.message; status.className='status error'; }
        });
    }

    function loadBlocked() {
        fetch('/api/blocked').then(r=>r.json()).then(d=>{
            const container = document.getElementById('blockedList');
            let html='';
            d.ips.forEach(ip=>{ html+=\`<span class="blocked-item">IP:\${ip} <span class="del" onclick="deleteBlock('ip','\${ip}')">✕</span></span> \`; });
            d.cities.forEach(city=>{ html+=\`<span class="blocked-item">城市:\${city} <span class="del" onclick="deleteBlock('city','\${city}')">✕</span></span> \`; });
            d.provinces.forEach(prov=>{ html+=\`<span class="blocked-item">省份:\${prov} <span class="del" onclick="deleteBlock('province','\${prov}')">✕</span></span> \`; });
            container.innerHTML = html || '<span style="color:#888;font-size:13px;">暂无屏蔽</span>';
        });
    }
    function addBlock() {
        const value = document.getElementById('blockInput').value.trim();
        const type = document.getElementById('blockType').value;
        if(!value){ alert('请输入内容'); return; }
        fetch('/api/blocked', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type, value }) })
        .then(r=>r.json()).then(d=>{ if(d.success){ document.getElementById('blockInput').value=''; loadBlocked(); } else { alert(d.message||'添加失败'); } });
    }
    function deleteBlock(type, value) {
        if(!confirm('确认删除屏蔽 '+value+' 吗？')) return;
        fetch('/api/blocked/'+type+'/'+encodeURIComponent(value), { method:'DELETE' })
        .then(r=>r.json()).then(d=>{ if(d.success) loadBlocked(); });
    }

    function loadWhitelist() {
        fetch('/api/whitelist').then(r=>r.json()).then(d=>{
            const container = document.getElementById('whitelistList');
            let html='';
            d.ips.forEach(ip=>{ html+=\`<span class="whitelist-item">IP:\${ip} <span class="del" onclick="deleteWhitelist('ip','\${ip}')">✕</span></span> \`; });
            d.cities.forEach(city=>{ html+=\`<span class="whitelist-item">城市:\${city} <span class="del" onclick="deleteWhitelist('city','\${city}')">✕</span></span> \`; });
            d.provinces.forEach(prov=>{ html+=\`<span class="whitelist-item">省份:\${prov} <span class="del" onclick="deleteWhitelist('province','\${prov}')">✕</span></span> \`; });
            container.innerHTML = html || '<span style="color:#888;font-size:13px;">暂无白名单</span>';
        });
    }
    function addWhitelist() {
        const value = document.getElementById('whitelistInput').value.trim();
        const type = document.getElementById('whitelistType').value;
        if(!value){ alert('请输入内容'); return; }
        fetch('/api/whitelist', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type, value }) })
        .then(r=>r.json()).then(d=>{ if(d.success){ document.getElementById('whitelistInput').value=''; loadWhitelist(); } else { alert(d.message||'添加失败'); } });
    }
    function deleteWhitelist(type, value) {
        if(!confirm('确认删除白名单 '+value+' 吗？')) return;
        fetch('/api/whitelist/'+type+'/'+encodeURIComponent(value), { method:'DELETE' })
        .then(r=>r.json()).then(d=>{ if(d.success) loadWhitelist(); });
    }

    function loadVisitors(type) {
        const endpoint = type === 'blocked' ? '/api/visitors/blocked' : '/api/visitors/unblocked';
        const tbodyId = type === 'blocked' ? 'blockedVisitorBody' : 'unblockedVisitorBody';
        fetch(endpoint)
            .then(r => r.json())
            .then(data => {
                const tbody = document.getElementById(tbodyId);
                if (!data || data.length === 0) {
                    tbody.innerHTML = \`<tr><td colspan="7">暂无数据</td></tr>\`;
                    return;
                }
                tbody.innerHTML = data.map(item => {
                    const compare = item.compare || {};
                    const matchText = compare.match ? '✅ 一致' : '❌ 不一致';
                    const badgeClass = compare.match ? 'compare-match' : 'compare-fail';
                    const ip666 = compare.ip666 || { region: '未知', city: '未知' };
                    const aliyun = compare.aliyun || { region: '未知', city: '未知' };
                    const compareDisplay = \`
                        <span class="compare-badge \${badgeClass}">\${matchText}</span><br>
                        <span style="font-size:11px;color:#666;">IP666: \${ip666.city}(\${ip666.region})<br>阿里云: \${aliyun.city}(\${aliyun.region})</span>
                    \`;
                    return \`
                        <tr>
                            <td>\${item.ip}</td>
                            <td>\${compareDisplay}</td>
                            <td>\${item.region}</td>
                            <td>\${item.device || '未知'}</td>
                            <td>\${item.count}</td>
                            <td>\${formatBeijingTime(item.firstTime)}</td>
                            <td>\${formatBeijingTime(item.lastTime)}</td>
                        </tr>
                    \`;
                }).join('');
            })
            .catch(() => {
                document.getElementById(tbodyId).innerHTML = '<tr><td colspan="7">加载失败</td></tr>';
            });
    }

    function clearCache() {
        if(!confirm('确定清空 IP 定位缓存吗？')) return;
        fetch('/api/clear-cache', { method:'POST' })
            .then(r=>r.json())
            .then(d=>{
                const status = document.getElementById('clearStatus');
                if(d.success){
                    status.textContent = '✅ 已清空 ' + d.cleared + ' 条缓存';
                    status.style.color = '#155724';
                } else {
                    status.textContent = '❌ 清空失败';
                    status.style.color = '#721c24';
                }
            })
            .catch(()=>{
                document.getElementById('clearStatus').textContent = '❌ 请求失败';
                document.getElementById('clearStatus').style.color = '#721c24';
            });
    }

    function logout() {
        fetch('/admin/logout', { method:'POST' }).then(()=>{ location.reload(); });
    }

    loadStats();
    loadConfig();
    loadBlocked();
    loadWhitelist();
    loadVisitors('blocked');
    loadVisitors('unblocked');

    setInterval(() => {
        loadStats();
        loadVisitors('blocked');
        loadVisitors('unblocked');
    }, 30000);
</script>
</body>
</html>
        `);
    } else {
        res.send(`
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>管理后台 - 登录</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "PingFang SC", Arial, sans-serif; background: #f0f2f5; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
.login-form { max-width:320px; width:90%; background:#fff; padding:30px 24px; border-radius:16px; box-shadow:0 4px 20px rgba(0,0,0,0.08); text-align:center; }
.login-form input { width:100%; padding:10px; margin:10px 0; border:1px solid #ddd; border-radius:8px; font-size:15px; }
.login-form .btn { width:100%; padding:12px; background:#1a3a6a; color:#fff; border:none; border-radius:30px; font-size:16px; cursor:pointer; }
.login-form .btn:hover { background:#0b1e3a; }
.login-form .error { color:#e74c3c; font-size:13px; margin-top:8px; }
</style>
</head>
<body>
    <div class="login-form">
        <h1 style="font-size:22px; margin-bottom:8px;">🔐 管理员登录</h1>
        <p style="color:#6b7a8f; font-size:14px;">请输入管理密码</p>
        <input type="password" id="password" placeholder="请输入密码" />
        <button class="btn" onclick="login()">登录</button>
        <div id="errorMsg" class="error"></div>
    </div>
    <script>
        function login() {
            const pwd = document.getElementById('password').value;
            fetch('/admin/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: pwd }) })
            .then(r=>r.json()).then(d=>{ if(d.success){ location.reload(); } else { document.getElementById('errorMsg').textContent = '❌ 密码错误，请重试'; } });
        }
        document.getElementById('password').addEventListener('keydown', function(e){ if(e.key==='Enter') login(); });
    </script>
</body>
</html>
        `);
    }
});

// ===== 启动 =====
app.listen(PORT, () => {
    console.log('🚀 服务已启动，端口：' + PORT);
    console.log('🌐 活码页面：http://localhost:' + PORT);
    console.log('🔧 管理后台：http://localhost:' + PORT + '/admin');
});