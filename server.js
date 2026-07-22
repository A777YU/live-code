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

// ===== ★ 调试：打印所有环境变量状态 =====
console.log('[启动检查] 环境变量状态:');
console.log('  HUAWEI_APPKEY:', process.env.HUAWEI_APPKEY ? '✅ 已设置' : '❌ 未设置');
console.log('  HUAWEI_APPSECRET:', process.env.HUAWEI_APPSECRET ? '✅ 已设置' : '❌ 未设置');
console.log('  IPDATACLOUD_KEY:', process.env.IPDATACLOUD_KEY ? '✅ 已设置' : '❌ 未设置');
console.log('  ALIYUN_APPCODE:', process.env.ALIYUN_APPCODE ? '✅ 已设置' : '❌ 未设置');

// ===== 从环境变量读取配置（带默认值） =====
const HUAWEI_APPKEY = process.env.HUAWEI_APPKEY || '79eb530102574552bbb80e4ec640c9dd';
const HUAWEI_APPSECRET = process.env.HUAWEI_APPSECRET || '73687ab6144aff8a6d2a238495589e';
const IPDATACLOUD_KEY = process.env.IPDATACLOUD_KEY || '75420c4e849e11f1a82800163e167ffb';
const ALIYUN_APPCODE = process.env.ALIYUN_APPCODE || 'e5f69ac13b5a492b86693d5e6c4f1a1b';

console.log('[启动检查] 实际使用的配置:');
console.log('  HUAWEI_APPKEY:', HUAWEI_APPKEY ? HUAWEI_APPKEY.substring(0, 10) + '...' : '无');
console.log('  HUAWEI_APPSECRET:', HUAWEI_APPSECRET ? HUAWEI_APPSECRET.substring(0, 10) + '...' : '无');
console.log('  IPDATACLOUD_KEY:', IPDATACLOUD_KEY ? IPDATACLOUD_KEY.substring(0, 10) + '...' : '无');
console.log('  ALIYUN_APPCODE:', ALIYUN_APPCODE ? ALIYUN_APPCODE.substring(0, 10) + '...' : '无');

// ===== 数据目录初始化 =====
const DATA_DIR = path.join(__dirname, 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
const LOG_FILE = path.join(DATA_DIR, 'ip_log.json');
const BLOCKED_FILE = path.join(DATA_DIR, 'blocked.json');
const WHITELIST_FILE = path.join(DATA_DIR, 'whitelist.json');
const COMPLAINTS_FILE = path.join(DATA_DIR, 'complaints.json');

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
if (!fs.existsSync(COMPLAINTS_FILE)) fs.writeFileSync(COMPLAINTS_FILE, JSON.stringify([]));

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
    if (!HUAWEI_APPKEY || !HUAWEI_APPSECRET) {
        console.log('[华为风险] 未配置 AppKey/AppSecret，跳过检测');
        return { success: false, error: '未配置' };
    }
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

// ===== IP地理位置 =====
const geoCache = {};
const riskCache = {};
const CACHE_TTL = 24 * 60 * 60 * 1000;

async function getAliyunGeo(ip) {
    console.log(`[阿里云] 开始查询 IP: ${ip}`);
    if (!ALIYUN_APPCODE) {
        console.log('[阿里云] 未配置 AppCode，跳过');
        return { success: false, error: '未配置' };
    }
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

async function getIp666Geo(ip) {
    console.log(`[IP666] 开始查询 IP: ${ip}`);
    if (!IPDATACLOUD_KEY) {
        console.log('[IP666] 未配置 Key，跳过');
        return { success: false, error: '未配置' };
    }
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

        const finalBlocked = isBlocked(ipv4, geo, blockedList, whitelist);

        const compareInfo = {
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
        };

        const entry = {
            ip: ipv4,
            action: action,
            time: now,
            country: geo.country,
            region: geo.region,
            city: geo.city,
            device: device,
            blocked: finalBlocked,
            compare: compareInfo
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

    const isBlockedResult = isBlocked(ipv4, geo, blockedList, whitelist);

    res.json({
        url: config.url,
        fallbackUrl: config.fallbackUrl || 'https://example.com/fallback',
        blocked: isBlockedResult
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

app.get('/api/blocked', requireLogin, (req, res) => {
    res.json(getBlocked());
});
app.post('/api/blocked', requireLogin, (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) return res.status(400).json({ success: false, message: '缺少参数' });
    if (type === 'ip' && !/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
        return res.status(400).json({ success: false, message: 'IP格式无效' });
    }
    const blocked = getBlocked();
    if (type === 'ip' && !blocked.ips.includes(value)) {
        blocked.ips.push(value);
        saveBlocked(blocked);
    } else if (type === 'city' && !blocked.cities.includes(value)) {
        blocked.cities.push(value);
        saveBlocked(blocked);
    } else if (type === 'province' && !blocked.provinces.includes(value)) {
        blocked.provinces.push(value);
        saveBlocked(blocked);
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

app.get('/api/whitelist', requireLogin, (req, res) => {
    res.json(getWhitelist());
});
app.post('/api/whitelist', requireLogin, (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) return res.status(400).json({ success: false, message: '缺少参数' });
    if (type === 'ip' && !/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) {
        return res.status(400).json({ success: false, message: 'IP格式无效' });
    }
    const whitelist = getWhitelist();
    if (type === 'ip' && !whitelist.ips.includes(value)) {
        whitelist.ips.push(value);
        saveWhitelist(whitelist);
    } else if (type === 'city' && !whitelist.cities.includes(value)) {
        whitelist.cities.push(value);
        saveWhitelist(whitelist);
    } else if (type === 'province' && !whitelist.provinces.includes(value)) {
        whitelist.provinces.push(value);
        saveWhitelist(whitelist);
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

app.get('/api/complaints', requireLogin, (req, res) => {
    res.json(getComplaints());
});

app.post('/api/clear-cache', requireLogin, (req, res) => {
    const geoKeys = Object.keys(geoCache);
    geoKeys.forEach(key => delete geoCache[key]);
    const riskKeys = Object.keys(riskCache);
    riskKeys.forEach(key => delete riskCache[key]);
    res.json({ success: true, cleared: geoKeys.length + riskKeys.length });
});

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
                compare: entry.compare || {},
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
    const result = Object.values(map).filter(item => type === 'blocked' ? item.blocked : !item.blocked);
    result.sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));
    res.json(result);
});

app.get('/api/stats', requireLogin, (req, res) => {
    const logs = getLogs().filter(l => l.action === 'visit');
    const today = new Date().toISOString().slice(0, 10);
    const todayLogs = logs.filter(l => l.time.startsWith(today));
    const ipMap = {};
    todayLogs.forEach(entry => {
        if (!ipMap[entry.ip]) ipMap[entry.ip] = { blocked: entry.blocked !== undefined ? entry.blocked : false };
    });
    let blockedCount = 0, unblockedCount = 0;
    Object.values(ipMap).forEach(item => {
        if (item.blocked) blockedCount++;
        else unblockedCount++;
    });
    res.json({ total: Object.keys(ipMap).length, blocked: blockedCount, unblocked: unblockedCount });
});

// ============================================
// 管理后台页面（精简为静态HTML）
// ============================================
app.get('/admin', (req, res) => {
    if (req.session.loggedIn) {
        res.sendFile(path.join(__dirname, 'public', 'admin.html'));
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