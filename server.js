const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const useragent = require('useragent');
const multer = require('multer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== 硬编码参数 =====
const HUAWEI_APPKEY = '79eb530102574552bbb80e4ec640c9dd';
const HUAWEI_APPSECRET = '73687ab6144a4ff8a6d2a2a38495589e';
const IPDATACLOUD_KEY = '75420c4e849e11f1a82800163e167ffb';
const ALIYUN_APPCODE = 'e5f69ac13b5a492b86693d5e6c4f1a1b';

console.log('[启动] 硬编码参数已加载');

// ===== 数据目录初始化 =====
const DATA_DIR = path.join(__dirname, 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const LOG_FILE = path.join(DATA_DIR, 'ip_log.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked.json');
const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');
const COMPLAINTS_FILE = path.join(DATA_DIR, 'complaints.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(CONFIG_FILE)) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify({
        url: 'https://example.com/main',
        fallbackUrl: 'https://example.com/fallback',
        url2: 'https://example.com/main2',
        fallbackUrl2: 'https://example.com/fallback2',
        ipQueryEnabled: true
    }));
}
if (!fs.existsSync(LOG_FILE)) fs.writeFileSync(LOG_FILE, JSON.stringify([]));
if (!fs.existsSync(BLOCKED_FILE)) {
    fs.writeFileSync(BLOCKED_FILE, JSON.stringify({ ips: [], cities: [], provinces: [] }));
}
if (!fs.existsSync(WHITELIST_FILE)) {
    fs.writeFileSync(WHITELIST_FILE, JSON.stringify({ ips: [], cities: [], provinces: [] }));
}
if (!fs.existsSync(COMPLAINTS_FILE)) fs.writeFileSync(COMPLAINTS_FILE, JSON.stringify([]));

// ===== 工具函数 =====
function getConfig() {
    const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
    // 自动补全缺失或空值
    if (!config.url) config.url = 'https://example.com/main';
    if (!config.fallbackUrl) config.fallbackUrl = 'https://example.com/fallback';
    if (!config.url2) config.url2 = 'https://example.com/main2';
    if (!config.fallbackUrl2) config.fallbackUrl2 = 'https://example.com/fallback2';
    if (config.ipQueryEnabled === undefined) config.ipQueryEnabled = true;
    return config;
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
function getComplaints() {
    return JSON.parse(fs.readFileSync(COMPLAINTS_FILE, 'utf-8'));
}
function saveComplaints(complaints) {
    fs.writeFileSync(COMPLAINTS_FILE, JSON.stringify(complaints, null, 2));
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

// ===== 华为云签名函数 =====
function signHuaweiRequest(method, url, body, appKey, appSecret) {
    const parsedUrl = new URL(url);
    const host = parsedUrl.host;
    const pathname = parsedUrl.pathname;
    const query = parsedUrl.search ? parsedUrl.search.substring(1) : '';
    const xSdkDate = new Date().toISOString().replace(/[:\-.]/g, '').slice(0, 15) + 'Z';
    const bodyHash = crypto.createHash('sha256').update(body || '').digest('hex');

    const signedHeaders = 'host;user-agent;x-sdk-date;x-stage';
    const userAgent = 'axios/1.6.0';
    const xStage = 'RELEASE';
    const canonicalHeaders = `host:${host}\nuser-agent:${userAgent}\nx-sdk-date:${xSdkDate}\nx-stage:${xStage}\n`;
    const canonicalRequest = `${method}\n${pathname}\n${query}\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;

    const algorithm = 'SDK-HMAC-SHA256';
    const credentialScope = `${xSdkDate.slice(0, 8)}/apigateway/request`;
    const stringToSign = `${algorithm}\n${xSdkDate}\n${credentialScope}\n${crypto.createHash('sha256').update(canonicalRequest).digest('hex')}`;
    const signingKey = crypto.createHmac('sha256', appSecret).update(xSdkDate.slice(0, 8)).digest();
    const signature = crypto.createHmac('sha256', signingKey).update(stringToSign).digest('hex');
    const authorization = `${algorithm} Access=${appKey}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    return {
        'Host': host,
        'User-Agent': userAgent,
        'X-Sdk-Date': xSdkDate,
        'X-Stage': xStage,
        'Authorization': authorization
    };
}

// ===== 华为风险检测 =====
async function getHuaweiRisk(ip) {
    console.log(`[华为风险] 开始查询 IP: ${ip}`);
    try {
        const url = `https://kzipfx.apistore.huaweicloud.com/api-mall/api/ip/portrait?ip=${ip}`;
        const method = 'POST';
        const body = '';
        const headers = signHuaweiRequest(method, url, body, HUAWEI_APPKEY, HUAWEI_APPSECRET);
        console.log(`[华为风险] 请求头:`, { Host: headers.Host, 'X-Sdk-Date': headers['X-Sdk-Date'], 'X-Stage': headers['X-Stage'] });
        const response = await axios({
            method: method,
            url: url,
            headers: headers,
            data: body,
            timeout: 3000
        });
        console.log('[华为风险] 响应状态:', response.status);
        console.log('[华为风险] 完整响应:', JSON.stringify(response.data));
        if (response.data && response.data.success && response.data.data) {
            const data = response.data.data;
            const tag = data.tag || '';
            const level = data.level || '无';
            const score = data.score || 0;
            console.log(`[华为风险] 查询成功 - tag: "${tag}", level: ${level}, score: ${score}`);
            return { success: true, data: { tag, level, score } };
        } else {
            console.log('[华为风险] 查询失败，响应结构异常:', response.data);
            return { success: false, error: '响应异常' };
        }
    } catch (e) {
        console.error('[华为风险] 请求失败:', e.message);
        if (e.response) {
            console.error('[华为风险] HTTP状态:', e.response.status);
            console.error('[华为风险] 响应数据:', JSON.stringify(e.response.data));
        }
        return { success: false, error: e.message };
    }
}

// ===== IP地理位置（三服务并发 + 风险检测） =====
const geoCache = {};
const riskCache = {};
const CACHE_TTL = 24 * 60 * 60 * 1000;

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
            return { success: true, data: result };
        } else {
            console.error('[阿里云] 无法解析响应结构:', response.data);
            return { success: false, error: '解析失败' };
        }
    } catch (e) {
        console.error('[阿里云] 请求失败:', e.message);
        return { success: false, error: e.message };
    }
}

// ----- IP666 -----
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
            return { success: true, data: result };
        } else {
            console.log(`[IP666] 查询失败，响应码: ${response.data?.code}`);
            return { success: false, error: `响应码 ${response.data?.code}` };
        }
    } catch (e) {
        console.error('[IP666] 请求失败:', e.message);
        return { success: false, error: e.message };
    }
}

// ----- 备用服务（ip-api.com） -----
async function getBackupGeo(ip) {
    console.log(`[备用服务] 开始查询 IP: ${ip}`);
    try {
        const url = `http://ip-api.com/json/${ip}?fields=country,regionName,city&lang=zh-CN`;
        const response = await axios.get(url, {
            timeout: 5000
        });
        console.log('[备用服务] 原始响应:', JSON.stringify(response.data));
        if (response.data && response.data.status !== 'fail') {
            const result = {
                country: response.data.country || '未知',
                region: response.data.regionName || '未知',
                city: response.data.city || '未知'
            };
            console.log('[备用服务] 查询成功:', result);
            return { success: true, data: result };
        } else {
            console.log('[备用服务] 查询失败，响应状态:', response.data?.status);
            return { success: false, error: '查询失败' };
        }
    } catch (e) {
        console.error('[备用服务] 请求失败:', e.message);
        return { success: false, error: e.message };
    }
}

async function getGeoInfo(ip) {
    const ipv4 = getIPv4(ip);
    let geoCacheData = geoCache[ipv4] && (Date.now() - geoCache[ipv4].timestamp < CACHE_TTL) ? geoCache[ipv4].data : null;
    let riskCacheData = riskCache[ipv4] && (Date.now() - riskCache[ipv4].timestamp < CACHE_TTL) ? riskCache[ipv4].data : null;

    if (geoCacheData && riskCacheData) {
        console.log(`[Cache] 命中完整缓存 IP: ${ipv4}`);
        geoCacheData.riskTag = riskCacheData.tag || '';
        geoCacheData.riskLevel = riskCacheData.level || '无';
        geoCacheData.riskScore = riskCacheData.score || 0;
        return geoCacheData;
    }

    console.log(`[Geo] 开始获取 IP: ${ipv4} 的地理信息和风险检测`);
    const [ip666Result, aliyunResult, backupResult, riskResult] = await Promise.all([
        getIp666Geo(ipv4),
        getAliyunGeo(ipv4),
        getBackupGeo(ipv4),
        getHuaweiRisk(ipv4)
    ]);

    let riskTag = '';
    let riskLevel = '无';
    let riskScore = 0;
    if (riskResult.success) {
        riskTag = riskResult.data.tag || '';
        riskLevel = riskResult.data.level || '无';
        riskScore = riskResult.data.score || 0;
        riskCache[ipv4] = { data: { tag: riskTag, level: riskLevel, score: riskScore }, timestamp: Date.now() };
    } else {
        riskCache[ipv4] = { data: { tag: '', level: '无', score: 0 }, timestamp: Date.now() };
        console.log(`[风险] 查询失败，IP: ${ipv4}，不进行风险屏蔽`);
    }

    const services = {
        ip666: ip666Result.success ? ip666Result.data : null,
        aliyun: aliyunResult.success ? aliyunResult.data : null,
        backup: backupResult.success ? backupResult.data : null
    };
    const successCount = Object.values(services).filter(v => v !== null).length;

    console.log(`[Geo] 成功服务数: ${successCount}, 服务状态:`, {
        ip666: ip666Result.success ? '成功' : `失败(${ip666Result.error})`,
        aliyun: aliyunResult.success ? '成功' : `失败(${aliyunResult.error})`,
        backup: backupResult.success ? '成功' : `失败(${backupResult.error})`
    });

    let result = {
        country: '未知',
        region: '未知',
        city: '未知',
        match: false,
        services: {
            ip666: { success: ip666Result.success, data: services.ip666, error: ip666Result.error || null },
            aliyun: { success: aliyunResult.success, data: services.aliyun, error: aliyunResult.error || null },
            backup: { success: backupResult.success, data: services.backup, error: backupResult.error || null }
        },
        riskTag: riskTag,
        riskLevel: riskLevel,
        riskScore: riskScore
    };

    if (successCount >= 2) {
        let available = [];
        if (services.ip666) available.push({ source: 'ip666', data: services.ip666 });
        if (services.aliyun) available.push({ source: 'aliyun', data: services.aliyun });
        if (services.backup) available.push({ source: 'backup', data: services.backup });

        let first = available[0];
        let second = available[1];
        if (first && second) {
            const region1 = normalizeRegion(first.data.region);
            const region2 = normalizeRegion(second.data.region);
            result.match = (region1 === region2);
            result.country = first.data.country || '未知';
            result.region = first.data.region || '未知';
            result.city = first.data.city || '未知';
            result.usedPrimary = first.source;
            result.usedSecondary = second.source;
            result.usedBackup = (first.source === 'backup' || second.source === 'backup');
        } else {
            result.match = false;
        }
    } else {
        result.match = false;
        if (services.ip666) {
            result.country = services.ip666.country;
            result.region = services.ip666.region;
            result.city = services.ip666.city;
        } else if (services.aliyun) {
            result.country = services.aliyun.country;
            result.region = services.aliyun.region;
            result.city = services.aliyun.city;
        } else if (services.backup) {
            result.country = services.backup.country;
            result.region = services.backup.region;
            result.city = services.backup.city;
        }
    }

    result.ip666 = services.ip666 || { region: '服务不可用', city: '服务不可用' };
    result.aliyun = services.aliyun || { region: '服务不可用', city: '服务不可用' };
    result.backup = services.backup || null;

    console.log('[Geo] 最终结果:', result);
    geoCache[ipv4] = { data: result, timestamp: Date.now() };
    return result;
}

// ===== 统一屏蔽判断函数 =====
function isBlocked(ip, geo, blockedList, whitelist) {
    const ipv4 = getIPv4(ip);
    if (whitelist.ips.includes(ipv4)) return false;
    const wlCityMatch = isMatched(whitelist.cities, geo.city);
    const wlProvinceMatch = isMatched(whitelist.provinces, geo.region);
    if (wlCityMatch || wlProvinceMatch) return false;
    const cityMatch = isMatched(blockedList.cities, geo.city);
    const provinceMatch = isMatched(blockedList.provinces, geo.region);
    if (blockedList.ips.includes(ipv4) || cityMatch || provinceMatch) return true;
    if (geo.city === '未知' && geo.region === '未知') return true;
    if (!geo.match) return true;
    const riskTag = geo.riskTag || '';
    if (riskTag.includes('Proxy') || riskTag.includes('VPN') || riskTag.includes('Sec_Dial')) {
        console.log(`[屏蔽] IP ${ipv4} 因风险标签 ${riskTag} 被屏蔽`);
        return true;
    }
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

        const config = getConfig();
        const ipQueryEnabled = config.ipQueryEnabled !== undefined ? config.ipQueryEnabled : true;

        if (!ipQueryEnabled) {
            console.log(`[logIP] IP查询已关闭，跳过日志记录`);
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
                aliyun: geo.aliyun,
                backup: geo.backup || null,
                usedBackup: geo.usedBackup || false,
                services: geo.services || {
                    ip666: { success: false, data: null, error: '未知' },
                    aliyun: { success: false, data: null, error: '未知' },
                    backup: { success: false, data: null, error: '未知' }
                },
                riskTag: geo.riskTag || '',
                riskLevel: geo.riskLevel || '无',
                riskScore: geo.riskScore || 0
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

app.get('/complaint', (req, res) => {
    const filePath = path.join(__dirname, 'public', 'complaint.html');
    fs.access(filePath, fs.constants.F_OK, (err) => {
        if (err) {
            res.status(404).send('投诉页面不存在');
        } else {
            res.sendFile(filePath);
        }
    });
});

app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: 'my-secret-key-2024',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));

// ===== Multer 配置 =====
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = path.join(__dirname, 'uploads');
        if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage, limits: { fileSize: 2 * 1024 * 1024 } });

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// ============================================
// 公开 API（两个页面各自独立）
// ============================================

// 页面1（默认 index.html）配置接口
app.get('/api/config', async (req, res) => {
    const config = getConfig();
    const ipQueryEnabled = config.ipQueryEnabled !== undefined ? config.ipQueryEnabled : true;

    if (!ipQueryEnabled) {
        console.log('[api/config] IP查询已关闭，返回未屏蔽');
        return res.json({
            url: config.url,
            fallbackUrl: config.fallbackUrl || 'https://example.com/fallback',
            blocked: false,
            ipQueryEnabled: false
        });
    }

    const ip = getClientIP(req);
    const referer = req.headers.referer || '';
    if (!referer.includes('/admin')) {
        await logIP(ip, 'click', req);
    }

    const ipv4 = getIPv4(ip);
    const geo = await getGeoInfo(ipv4);
    const blockedList = getBlocked();
    const whitelist = getWhitelist();

    const isBlockedResult = isBlocked(ipv4, geo, blockedList, whitelist);

    res.json({
        url: config.url,
        fallbackUrl: config.fallbackUrl || 'https://example.com/fallback',
        blocked: isBlockedResult,
        ipQueryEnabled: true
    });
});

// 页面2（新 index2.html）配置接口
app.get('/api/config2', async (req, res) => {
    const config = getConfig();
    const ipQueryEnabled = config.ipQueryEnabled !== undefined ? config.ipQueryEnabled : true;

    if (!ipQueryEnabled) {
        console.log('[api/config2] IP查询已关闭，返回未屏蔽');
        return res.json({
            url: config.url2,
            fallbackUrl: config.fallbackUrl2 || 'https://example.com/fallback2',
            blocked: false,
            ipQueryEnabled: false
        });
    }

    const ip = getClientIP(req);
    const referer = req.headers.referer || '';
    if (!referer.includes('/admin')) {
        await logIP(ip, 'click', req);
    }

    const ipv4 = getIPv4(ip);
    const geo = await getGeoInfo(ipv4);
    const blockedList = getBlocked();
    const whitelist = getWhitelist();

    const isBlockedResult = isBlocked(ipv4, geo, blockedList, whitelist);

    res.json({
        url: config.url2,
        fallbackUrl: config.fallbackUrl2 || 'https://example.com/fallback2',
        blocked: isBlockedResult,
        ipQueryEnabled: true
    });
});

app.post('/api/complaint', upload.single('image'), (req, res) => {
    const text = req.body.text || '';
    const contact = req.body.contact || '';
    const imageFile = req.file;
    const complaint = {
        id: Date.now(),
        text,
        contact,
        image: imageFile ? `/uploads/${imageFile.filename}` : null,
        createdAt: new Date().toISOString()
    };
    const complaints = getComplaints();
    complaints.push(complaint);
    saveComplaints(complaints);
    res.json({ success: true, message: '投诉提交成功' });
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

// ===== 测试风险检测接口 =====
app.get('/api/test-risk/:ip', requireLogin, async (req, res) => {
    const testIp = req.params.ip;
    if (!testIp || !/^(\d{1,3}\.){3}\d{1,3}$/.test(testIp)) {
        return res.status(400).json({ success: false, error: 'IP格式无效' });
    }
    const result = await getHuaweiRisk(testIp);
    res.json({
        ip: testIp,
        success: result.success,
        data: result.success ? result.data : null,
        error: result.success ? null : result.error
    });
});

// 配置管理（保存两套链接）
app.get('/api/config', requireLogin, (req, res) => {
    res.json(getConfig());
});
app.post('/api/config', requireLogin, (req, res) => {
    const { url, fallbackUrl, url2, fallbackUrl2, ipQueryEnabled } = req.body;
    const config = getConfig();
    // 如果提交了空字符串，则使用默认值（与页面1逻辑一致）
    if (url !== undefined) config.url = url || 'https://example.com/main';
    if (fallbackUrl !== undefined) config.fallbackUrl = fallbackUrl || 'https://example.com/fallback';
    if (url2 !== undefined) config.url2 = url2 || 'https://example.com/main2';
    if (fallbackUrl2 !== undefined) config.fallbackUrl2 = fallbackUrl2 || 'https://example.com/fallback2';
    if (ipQueryEnabled !== undefined) config.ipQueryEnabled = ipQueryEnabled;
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

// 投诉列表
app.get('/api/complaints', requireLogin, (req, res) => {
    res.json(getComplaints());
});

// ===== 清空缓存 =====
app.post('/api/clear-cache', requireLogin, (req, res) => {
    const geoKeys = Object.keys(geoCache);
    geoKeys.forEach(key => delete geoCache[key]);
    const riskKeys = Object.keys(riskCache);
    riskKeys.forEach(key => delete riskCache[key]);
    console.log(`[clear-cache] 已清空 ${geoKeys.length} 条地理缓存，${riskKeys.length} 条风险缓存`);
    res.json({ success: true, cleared: geoKeys.length + riskKeys.length });
});

// ===== 访客统计 =====
app.get('/api/visitors/:type', requireLogin, (req, res) => {
    const type = req.params.type;
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
                compare: entry.compare || { match: false, ip666: {}, aliyun: {}, backup: null, usedBackup: false, services: {}, riskTag: '', riskLevel: '无', riskScore: 0 },
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
// 管理后台页面（双配置 + 完整功能）
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
        .service-tag { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-right: 4px; }
        .service-success { background: #d4edda; color: #155724; }
        .service-fail { background: #f8d7da; color: #721c24; }
        .backup-tag { background: #ffc107; color: #000; padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-left: 4px; }
        .risk-tag { background: #f44336; color: #fff; padding: 2px 8px; border-radius: 12px; font-size: 11px; margin-left: 4px; }
        .complaint-item { border-bottom: 1px solid #eee; padding: 6px 0; font-size: 12px; }
        .complaint-item img { max-width: 80px; max-height: 80px; border-radius: 4px; margin-top: 4px; }
        .test-risk-area { margin-top: 12px; padding: 12px; background: #f8f9fa; border-radius: 8px; }
        .test-risk-area input { width: 150px; }
        .test-risk-area .btn { margin-left: 8px; }
        .test-result { margin-top: 8px; font-size: 13px; }
        .toggle-container { display: flex; align-items: center; gap: 10px; margin-top: 6px; }
        .toggle { position: relative; width: 48px; height: 26px; background: #ccc; border-radius: 13px; cursor: pointer; transition: background 0.3s; }
        .toggle.active { background: #1a3a6a; }
        .toggle .slider { position: absolute; top: 3px; left: 3px; width: 20px; height: 20px; background: #fff; border-radius: 50%; transition: transform 0.3s; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
        .toggle.active .slider { transform: translateX(22px); }
        .toggle-label { font-size: 14px; color: #1a3a5c; font-weight: 500; }
        .toggle-status { font-size: 13px; color: #6b7a8f; margin-left: 4px; }
        .offline-notice { background: #fff3cd; border-left: 4px solid #ffc107; padding: 10px 14px; border-radius: 6px; margin: 8px 0; color: #856404; }
        .config-section { border: 1px solid #e9ecef; border-radius: 8px; padding: 10px 12px; margin-bottom: 12px; }
        .config-section h4 { margin: 0 0 6px 0; font-size: 14px; color: #1a3a5c; }
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
        <div id="statsContainer">
            <div class="stats-grid">
                <div class="stat-item"><div class="number" id="totalVisits">0</div><div class="label">总访客</div></div>
                <div class="stat-item"><div class="number" id="blockedVisits">0</div><div class="label">已屏蔽</div></div>
                <div class="stat-item"><div class="number" id="unblockedVisits">0</div><div class="label">未屏蔽</div></div>
            </div>
        </div>
        <div class="cache-btn">
            <button class="btn" onclick="clearCache()">🗑️ 清空 IP 缓存</button>
            <span id="clearStatus" style="margin-left:10px;font-size:13px;"></span>
        </div>
        <div class="test-risk-area">
            <strong>风险检测测试工具</strong>
            <div style="margin-top:6px; display:flex; gap:6px; flex-wrap:wrap; align-items:center;">
                <input type="text" id="testIpInput" placeholder="输入IP地址" style="width:150px;" />
                <button class="btn btn-sm" onclick="testRisk()">检测风险</button>
                <span id="testResult" class="test-result"></span>
            </div>
        </div>
    </div>

    <div class="card">
        <h3>⚙️ 系统控制</h3>
        <div class="toggle-container">
            <div class="toggle" id="ipToggle" onclick="toggleIpQuery()">
                <div class="slider"></div>
            </div>
            <span class="toggle-label">启用 IP 定位与屏蔽</span>
            <span class="toggle-status" id="toggleStatus">(已开启)</span>
        </div>
        <p style="font-size:12px;color:#888;margin-top:6px;">关闭后，所有页面直接跳转主链接，不进行任何IP查询和屏蔽判断，加载速度更快。</p>
    </div>

    <!-- 链接配置：两套 -->
    <div class="card">
        <h3>🔗 跳转链接配置</h3>
        <!-- 页面1（默认） -->
        <div class="config-section">
            <h4>📄 页面1（默认活码 /）</h4>
            <div class="config-row"><label>主链接：</label><input type="text" id="urlInput" placeholder="主链接" /></div>
            <div class="config-row"><label>备用链接：</label><input type="text" id="fallbackUrlInput" placeholder="备用链接" /></div>
        </div>
        <!-- 页面2（新页面 /index2.html） -->
        <div class="config-section">
            <h4>📄 页面2（新活码 /index2.html）</h4>
            <div class="config-row"><label>主链接：</label><input type="text" id="urlInput2" placeholder="主链接2" /></div>
            <div class="config-row"><label>备用链接：</label><input type="text" id="fallbackUrlInput2" placeholder="备用链接2" /></div>
        </div>
        <button class="btn" onclick="updateAllConfig()">保存全部链接</button>
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

    <div id="visitorSections">
        <div class="card">
            <h3>🚫 被屏蔽用户详情</h3>
            <div id="blockedVisitorContainer">
                <div class="scrollable">
                    <table class="log-table">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>定位对比 & 服务状态</th>
                                <th>省份</th>
                                <th>风险标签</th>
                                <th>设备</th>
                                <th>进入次数</th>
                                <th>首次时间(北京)</th>
                                <th>最近时间(北京)</th>
                            </tr>
                        </thead>
                        <tbody id="blockedVisitorBody"><tr><td colspan="8">加载中...</td></tr></tbody>
                    </table>
                </div>
            </div>
            <div id="blockedOfflineNotice" style="display:none;" class="offline-notice">
                ⚠️ IP查询已关闭，无实时数据。以下显示的是历史记录（如有）。
            </div>
        </div>

        <div class="card">
            <h3>✅ 未屏蔽用户详情</h3>
            <div id="unblockedVisitorContainer">
                <div class="scrollable">
                    <table class="log-table">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>定位对比 & 服务状态</th>
                                <th>省份</th>
                                <th>风险标签</th>
                                <th>设备</th>
                                <th>进入次数</th>
                                <th>首次时间(北京)</th>
                                <th>最近时间(北京)</th>
                            </tr>
                        </thead>
                        <tbody id="unblockedVisitorBody"><tr><td colspan="8">加载中...</td></tr></tbody>
                    </table>
                </div>
            </div>
            <div id="unblockedOfflineNotice" style="display:none;" class="offline-notice">
                ⚠️ IP查询已关闭，无实时数据。以下显示的是历史记录（如有）。
            </div>
        </div>
    </div>

    <div class="card">
        <h3>📩 投诉列表</h3>
        <div id="complaintList"><p>加载中...</p></div>
    </div>
</div>

<script>
    // 存储开关状态
    let ipQueryEnabled = true;

    function formatBeijingTime(isoString) {
        if (!isoString) return '-';
        const date = new Date(isoString);
        return date.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
    }

    function loadStats() {
        if (!ipQueryEnabled) {
            document.getElementById('statsContainer').innerHTML = '<div class="offline-notice">IP查询已关闭，无实时统计数据</div>' +
                '<div class="stats-grid">' +
                '<div class="stat-item"><div class="number">-</div><div class="label">总访客</div></div>' +
                '<div class="stat-item"><div class="number">-</div><div class="label">已屏蔽</div></div>' +
                '<div class="stat-item"><div class="number">-</div><div class="label">未屏蔽</div></div>' +
                '</div>';
            return;
        }
        fetch('/api/stats').then(r=>r.json()).then(d=>{
            document.getElementById('totalVisits').textContent = d.total || 0;
            document.getElementById('blockedVisits').textContent = d.blocked || 0;
            document.getElementById('unblockedVisits').textContent = d.unblocked || 0;
        }).catch(()=>{});
    }

    function loadConfig() {
        fetch('/api/config').then(r=>r.json()).then(d=>{
            // 显示当前配置（防止 undefined）
            const url = d.url || '未设置';
            const fallbackUrl = d.fallbackUrl || '未设置';
            const url2 = d.url2 || '未设置';
            const fallbackUrl2 = d.fallbackUrl2 || '未设置';
            document.getElementById('currentUrl').textContent = '页面1主链接：'+url+' | 备用：'+fallbackUrl+
                '  页面2主链接：'+url2+' | 备用：'+fallbackUrl2;
            document.getElementById('urlInput').value = d.url || '';
            document.getElementById('fallbackUrlInput').value = d.fallbackUrl || '';
            document.getElementById('urlInput2').value = d.url2 || '';
            document.getElementById('fallbackUrlInput2').value = d.fallbackUrl2 || '';
            // 开关状态
            ipQueryEnabled = d.ipQueryEnabled !== undefined ? d.ipQueryEnabled : true;
            const toggle = document.getElementById('ipToggle');
            const status = document.getElementById('toggleStatus');
            if (ipQueryEnabled) {
                toggle.classList.add('active');
                status.textContent = '(已开启)';
            } else {
                toggle.classList.remove('active');
                status.textContent = '(已关闭)';
            }
            updateVisitorVisibility();
            loadStats();
            loadVisitors('blocked');
            loadVisitors('unblocked');
        });
    }

    function updateVisitorVisibility() {
        const blockedNotice = document.getElementById('blockedOfflineNotice');
        const unblockedNotice = document.getElementById('unblockedOfflineNotice');
        if (ipQueryEnabled) {
            blockedNotice.style.display = 'none';
            unblockedNotice.style.display = 'none';
        } else {
            blockedNotice.style.display = 'block';
            unblockedNotice.style.display = 'block';
        }
    }

    function updateAllConfig() {
        const url = document.getElementById('urlInput').value.trim();
        const fallbackUrl = document.getElementById('fallbackUrlInput').value.trim();
        const url2 = document.getElementById('urlInput2').value.trim();
        const fallbackUrl2 = document.getElementById('fallbackUrlInput2').value.trim();
        if (!url || !url2) {
            alert('两个页面都必须填写主链接');
            return;
        }
        const toggle = document.getElementById('ipToggle');
        const ipQueryEnabledState = toggle.classList.contains('active');
        fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, fallbackUrl, url2, fallbackUrl2, ipQueryEnabled: ipQueryEnabledState })
        })
        .then(r => r.json())
        .then(d => {
            const status = document.getElementById('urlStatus');
            if (d.success) {
                status.textContent = '✅ 保存成功';
                status.className = 'status';
                loadConfig();
            } else {
                status.textContent = '❌ ' + d.message;
                status.className = 'status error';
            }
        });
    }

    function toggleIpQuery() {
        const toggle = document.getElementById('ipToggle');
        const status = document.getElementById('toggleStatus');
        const newState = !toggle.classList.contains('active');
        if (newState) {
            toggle.classList.add('active');
            status.textContent = '(已开启)';
        } else {
            toggle.classList.remove('active');
            status.textContent = '(已关闭)';
        }
        // 保存开关状态（同时保留当前链接配置）
        const url = document.getElementById('urlInput').value.trim();
        const fallbackUrl = document.getElementById('fallbackUrlInput').value.trim();
        const url2 = document.getElementById('urlInput2').value.trim();
        const fallbackUrl2 = document.getElementById('fallbackUrlInput2').value.trim();
        fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, fallbackUrl, url2, fallbackUrl2, ipQueryEnabled: newState })
        })
        .then(r => r.json())
        .then(d => {
            if (!d.success) {
                alert('保存开关状态失败，请重试');
                if (newState) {
                    toggle.classList.remove('active');
                    status.textContent = '(已关闭)';
                } else {
                    toggle.classList.add('active');
                    status.textContent = '(已开启)';
                }
            } else {
                ipQueryEnabled = newState;
                updateVisitorVisibility();
                loadStats();
                loadVisitors('blocked');
                loadVisitors('unblocked');
            }
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
        const tbodyId = type === 'blocked' ? 'blockedVisitorBody' : 'unblockedVisitorBody';
        if (!ipQueryEnabled) {
            document.getElementById(tbodyId).innerHTML = '<tr><td colspan="8" style="text-align:center;color:#6b7a8f;">IP查询已关闭，无实时数据</td></tr>';
            return;
        }
        const endpoint = type === 'blocked' ? '/api/visitors/blocked' : '/api/visitors/unblocked';
        fetch(endpoint)
            .then(r => r.json())
            .then(data => {
                const tbody = document.getElementById(tbodyId);
                if (!data || data.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8">暂无数据</td></tr>';
                    return;
                }
                tbody.innerHTML = data.map(item => {
                    const compare = item.compare || {};
                    const matchText = compare.match ? '✅ 一致' : '❌ 不一致';
                    const badgeClass = compare.match ? 'compare-match' : 'compare-fail';
                    const services = compare.services || {};
                    const ip666Status = services.ip666 ? (services.ip666.success ? '✅' : '❌') : '❌';
                    const aliyunStatus = services.aliyun ? (services.aliyun.success ? '✅' : '❌') : '❌';
                    const backupStatus = services.backup ? (services.backup.success ? '✅' : '❌') : '❌';
                    const ip666Data = services.ip666 && services.ip666.data ? \`\${services.ip666.data.city}(\${services.ip666.data.region})\` : '不可用';
                    const aliyunData = services.aliyun && services.aliyun.data ? \`\${services.aliyun.data.city}(\${services.aliyun.data.region})\` : '不可用';
                    const backupData = services.backup && services.backup.data ? \`\${services.backup.data.city}(\${services.backup.data.region})\` : '不可用';
                    const usedBackup = compare.usedBackup || false;
                    const riskTag = compare.riskTag || '';
                    const riskLevel = compare.riskLevel || '无';
                    let riskDisplay = riskTag ? \`<span class="risk-tag">\${riskTag}</span> (等级:\${riskLevel})\` : '无';

                    let compareDisplay = \`
                        <span class="compare-badge \${badgeClass}">\${matchText}</span><br>
                        <span style="font-size:11px;color:#666;">
                            <span class="service-tag \${services.ip666 && services.ip666.success ? 'service-success' : 'service-fail'}">IP666: \${ip666Status} \${ip666Data}</span><br>
                            <span class="service-tag \${services.aliyun && services.aliyun.success ? 'service-success' : 'service-fail'}">阿里云: \${aliyunStatus} \${aliyunData}</span><br>
                            <span class="service-tag \${services.backup && services.backup.success ? 'service-success' : 'service-fail'}">备用: \${backupStatus} \${backupData}</span>
                            \${usedBackup ? '<span class="backup-tag">🔄 使用了备用</span>' : ''}
                        </span>
                    \`;
                    return \`
                        <tr>
                            <td>\${item.ip}</td>
                            <td>\${compareDisplay}</td>
                            <td>\${item.region}</td>
                            <td>\${riskDisplay}</td>
                            <td>\${item.device || '未知'}</td>
                            <td>\${item.count}</td>
                            <td>\${formatBeijingTime(item.firstTime)}</td>
                            <td>\${formatBeijingTime(item.lastTime)}</td>
                        </tr>
                    \`;
                }).join('');
            })
            .catch(() => {
                document.getElementById(tbodyId).innerHTML = '<tr><td colspan="8">加载失败</td></tr>';
            });
    }

    function loadComplaints() {
        fetch('/api/complaints')
            .then(r => r.json())
            .then(data => {
                const list = document.getElementById('complaintList');
                if (!data || data.length === 0) {
                    list.innerHTML = '<p style="color:#888;font-size:13px;">暂无投诉</p>';
                    return;
                }
                list.innerHTML = data.map(c => \`
                    <div class="complaint-item">
                        <div><strong>时间：</strong>\${formatBeijingTime(c.createdAt)}</div>
                        <div><strong>联系方式：</strong>\${c.contact || '未填写'}</div>
                        <div><strong>内容：</strong>\${c.text || '（无文字）'}</div>
                        \${c.image ? '<div><strong>图片：</strong><br><img src="' + c.image + '" /></div>' : ''}
                    </div>
                \`).join('');
            })
            .catch(() => {
                document.getElementById('complaintList').innerHTML = '<p style="color:#888;font-size:13px;">加载失败</p>';
            });
    }

    function clearCache() {
        if(!confirm('确定清空 IP 缓存（包含风险缓存）吗？页面将刷新以应用最新数据。')) return;
        fetch('/api/clear-cache', { method:'POST' })
            .then(r=>r.json())
            .then(d=>{
                const status = document.getElementById('clearStatus');
                if(d.success){
                    status.textContent = '✅ 已清空 ' + d.cleared + ' 条缓存，页面即将刷新...';
                    status.style.color = '#155724';
                    setTimeout(() => { window.location.reload(); }, 1000);
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

    function testRisk() {
        const ip = document.getElementById('testIpInput').value.trim();
        if (!ip) {
            document.getElementById('testResult').textContent = '⚠️ 请输入IP地址';
            document.getElementById('testResult').style.color = '#e17055';
            return;
        }
        if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
            document.getElementById('testResult').textContent = '⚠️ IP格式无效';
            document.getElementById('testResult').style.color = '#e17055';
            return;
        }
        document.getElementById('testResult').textContent = '查询中...';
        document.getElementById('testResult').style.color = '#6b7a8f';
        fetch('/api/test-risk/' + ip)
            .then(r => r.json())
            .then(data => {
                if (data.success) {
                    const tag = data.data.tag || '无';
                    const level = data.data.level || '无';
                    const score = data.data.score || 0;
                    let msg = \`✅ 标签: \${tag}，等级: \${level}，分数: \${score}\`;
                    if (tag.includes('Proxy') || tag.includes('VPN') || tag.includes('Sec_Dial')) {
                        msg += ' 🔴 将被屏蔽';
                    } else if (tag) {
                        msg += ' ⚪ 忽略（非代理/VPN/秒拨）';
                    } else {
                        msg += ' 🟢 无风险';
                    }
                    document.getElementById('testResult').textContent = msg;
                    document.getElementById('testResult').style.color = '#1a3a5c';
                } else {
                    document.getElementById('testResult').textContent = '❌ 查询失败: ' + (data.error || '未知错误');
                    document.getElementById('testResult').style.color = '#e17055';
                }
            })
            .catch(err => {
                document.getElementById('testResult').textContent = '❌ 网络错误';
                document.getElementById('testResult').style.color = '#e17055';
            });
    }

    function logout() {
        fetch('/admin/logout', { method:'POST' }).then(()=>{ location.reload(); });
    }

    loadConfig();
    loadBlocked();
    loadWhitelist();
    loadComplaints();

    setInterval(() => {
        if (ipQueryEnabled) {
            loadStats();
            loadVisitors('blocked');
            loadVisitors('unblocked');
            loadComplaints();
        }
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
    console.log('🌐 活码页面1：http://localhost:' + PORT + '/');
    console.log('🌐 活码页面2：http://localhost:' + PORT + '/index2.html');
    console.log('🔧 管理后台：http://localhost:' + PORT + '/admin');
});