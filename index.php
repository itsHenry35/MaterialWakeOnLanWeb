<?php
session_start();

function verifyRecaptcha($secret, $response) {
    $url = 'https://recaptcha.google.com/recaptcha/api/siteverify';
    $data = [
        'secret' => $secret,
        'response' => $response
    ];
    
    $options = [
        'http' => [
            'header' => "Content-type: application/x-www-form-urlencoded\r\n",
            'method' => 'POST',
            'content' => http_build_query($data)
        ]
    ];
    
    $context = stream_context_create($options);
    $result = file_get_contents($url, false, $context);
    return json_decode($result, true);
}

function loadConfig($file) {
    if (!file_exists($file)) die("Config file not found!");
    return parse_ini_file($file, true);
}

function authenticate($username, $password, $config) {
    return $username === $config['auth']['username'] && 
           $password === $config['auth']['password'];
}

function sendMagicPacket($macAddress, $broadcastIP, $port) {
    $macAddress = preg_replace('/[^0-9A-Fa-f]/', '', $macAddress);
    if (strlen($macAddress) != 12) return "Invalid MAC address.";

    $macHex = hex2bin($macAddress);
    $magicPacket = str_repeat(chr(0xFF), 6) . str_repeat($macHex, 16);

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if (!$socket) return "Failed to create socket.";
    if (!socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1)) {
        socket_close($socket);
        return "Failed to set socket options.";
    }

    $sent = socket_sendto($socket, $magicPacket, strlen($magicPacket), 0, $broadcastIP, $port);
    socket_close($socket);

    return $sent === false ? "Failed to send magic packet." : "Magic packet sent.";
}

function sendSleepPacket($macAddress, $broadcastIP, $port) {
    $macAddress = preg_replace('/[^0-9A-Fa-f]/', '', $macAddress);
    if (strlen($macAddress) != 12) return "Invalid MAC address.";

    $reverseMac = '';
    for ($i = strlen($macAddress) - 2; $i >= 0; $i -= 2) {
        $reverseMac .= substr($macAddress, $i, 2);
    }
    
    $macHex = hex2bin($reverseMac);
    $magicPacket = str_repeat(chr(0xFF), 6) . str_repeat($macHex, 16);

    $socket = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    if (!$socket) return "Failed to create socket.";
    if (!socket_set_option($socket, SOL_SOCKET, SO_BROADCAST, 1)) {
        socket_close($socket);
        return "Failed to set socket options.";
    }

    $sent = socket_sendto($socket, $magicPacket, strlen($magicPacket), 0, $broadcastIP, $port);
    socket_close($socket);

    return $sent === false ? "Failed to send sleep packet." : "Sleep packet sent.";
}

function checkStatus($address, $port, $timeout = 2) {
    $socket = @fsockopen($address, $port, $errno, $errstr, $timeout);
    if ($socket) {
        fclose($socket);
        return true;
    }
    return false;
}

$config = loadConfig('config.ini');

if (isset($_POST['login'])) {
    $recaptchaResponse = verifyRecaptcha(
        $config['auth']['recaptcha_secret_key'],
        $_POST['g-recaptcha-response'] ?? ''
    );
    
    if (!$recaptchaResponse['success']) {
        $error = "Please complete the reCAPTCHA";
    } elseif (authenticate($_POST['username'], $_POST['password'], $config)) {
        $_SESSION['authenticated'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $error = "Invalid credentials";
    }
}

if (isset($_GET['logout'])) {
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

if (isset($_GET['action']) && $_GET['action'] === 'rdp') {
    header('Content-Type: application/x-rdp');
    header('Content-Disposition: attachment; filename="remote.rdp"');
    echo "full address:s:" . $config['network']['tcping_address'] . ":" . $config['network']['tcping_port'] . "\r\n";
    echo "prompt for credentials:i:1\r\n";
    echo "administrative session:i:1\r\n";
    echo "screen mode id:i:2\r\n";
    exit;
}

if (!isset($_SESSION['authenticated'])) {
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login - Device Dashboard</title>
        <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap">
        <script src="https://recaptcha.google.cn/recaptcha/api.js" async defer></script>
        <style>
            :root {
                --md-sys-color-primary: #006495;
                --md-sys-color-surface: #fdfcff;
                --md-sys-color-surface-container: #eef0f3;
            }

            body {
                font-family: 'Roboto', sans-serif;
                background-color: var(--md-sys-color-surface);
                margin: 0;
                display: flex;
                align-items: center;
                justify-content: center;
                min-height: 100vh;
            }

            .login-card {
                background: var(--md-sys-color-surface-container);
                padding: 32px;
                border-radius: 28px;
                width: 100%;
                max-width: 400px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.12);
            }

            .login-title {
                font-size: 24px;
                margin: 0 0 24px;
                text-align: center;
            }

            .form-group {
                margin-bottom: 16px;
            }

            .form-label {
                display: block;
                margin-bottom: 8px;
                font-size: 14px;
            }

            .form-input {
                width: 100%;
                padding: 8px 16px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 16px;
                box-sizing: border-box;
            }

            .login-button {
                width: 100%;
                padding: 10px;
                background: var(--md-sys-color-primary);
                color: white;
                border: none;
                border-radius: 20px;
                font-size: 14px;
                font-weight: 500;
                cursor: pointer;
            }

            .error-message {
                color: #ba1a1a;
                margin-bottom: 16px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h1 class="login-title">Device Dashboard</h1>
            <?php if (isset($error)): ?>
                <div class="error-message"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="form-group">
                    <label class="form-label" for="username">Username</label>
                    <input class="form-input" type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label class="form-label" for="password">Password</label>
                    <input class="form-input" type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <div class="g-recaptcha" data-sitekey="<?= htmlspecialchars($config['auth']['recaptcha_site_key']) ?>"></div>
                </div>
                <button class="login-button" type="submit" name="login">Login</button>
            </form>
        </div>
    </body>
    </html>
    <?php
    exit;
}


if (isset($_GET['action']) && $_GET['action'] === 'status') {
    echo json_encode([
        'status' => checkStatus(
            $config['network']['tcping_address'], 
            $config['network']['tcping_port'],
            2
        )
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_SESSION['authenticated'])) {
        echo json_encode(['result' => 'Authentication required']);
        exit;
    }
    
    $action = $_POST['action'] ?? '';
    $result = "Invalid action.";
    switch ($action) {
        case 'wake':
            $result = sendMagicPacket($config['network']['mac_address'], $config['network']['broadcast_ip'], $config['network']['wol_port']);
            break;
        case 'sleep':
            $result = sendSleepPacket($config['network']['mac_address'], $config['network']['broadcast_ip'], $config['network']['wol_port']);
            break;
    }
    echo json_encode(['result' => $result]);
    exit;
}

$initialStatus = checkStatus(
    $config['network']['tcping_address'], 
    $config['network']['tcping_port'],
    0.5
);

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Dashboard</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap">
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200">
    <style>
        :root {
            --md-sys-color-primary: #006495;
            --md-sys-color-on-primary: #ffffff;
            --md-sys-color-primary-container: #cce5ff;
            --md-sys-color-on-primary-container: #001e31;
            --md-sys-color-error: #ba1a1a;
            --md-sys-color-surface: #fdfcff;
            --md-sys-color-surface-container: #eef0f3;
        }

        body {
            font-family: 'Roboto', sans-serif;
            margin: 0;
            background-color: var(--md-sys-color-surface);
            color: #1a1c1e;
        }

        .container {
            max-width: 600px;
            margin: 32px auto;
            padding: 0 16px;
        }

        .title {
            font-size: 24px;
            font-weight: 400;
            margin: 0 0 24px;
            text-align: center;
        }

        .card {
            background: var(--md-sys-color-surface-container);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.12);
        }

        .card-title {
            font-size: 22px;
            font-weight: 500;
            margin: 0 0 16px;
        }

        .status-container {
            display: flex;
            align-items: center;
            margin-bottom: 24px;
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            margin-left: 8px;
        }

        .status-online {
            background-color: #386a20;
        }

        .status-offline {
            background-color: var(--md-sys-color-error);
        }

        .button-container {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }

        .button {
            font-family: 'Roboto', sans-serif;
            font-size: 14px;
            font-weight: 500;
            padding: 10px 24px;
            border-radius: 20px;
            border: none;
            cursor: pointer;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.2s;
        }

        .button-filled {
            background: var(--md-sys-color-primary);
            color: var(--md-sys-color-on-primary);
        }

        .button-filled:hover {
            background: #00517c;
        }

        .button-tonal {
            background: var(--md-sys-color-primary-container);
            color: var(--md-sys-color-on-primary-container);
        }

        .button-tonal:hover {
            background: #b8d3ec;
        }

        .material-symbols-outlined {
            font-size: 20px;
            margin-right: 8px;
        }

        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0,0,0,0.32);
            align-items: center;
            justify-content: center;
        }

        .modal-content {
            background: var(--md-sys-color-surface);
            border-radius: 28px;
            padding: 24px;
            width: 90%;
            max-width: 560px;
        }

        .modal-title {
            font-size: 24px;
            font-weight: 400;
            margin: 0 0 16px;
        }

        .modal-actions {
            display: flex;
            justify-content: flex-end;
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="title">Device Dashboard</h1>
        <div class="card">
            <h2 class="card-title"><?= htmlspecialchars($config['network']['device_name']) ?></h2>
            <div class="status-container">
                <span>Status:</span>
                <span id="status-dot" class="status-dot status-<?= $initialStatus ? 'online' : 'offline' ?>"></span>
                <span id="status-text" style="margin-left: 8px;"><?= $initialStatus ? 'Online' : 'Offline' ?></span>
            </div>
            <div class="button-container">
                <button id="wake-btn" class="button button-filled" style="display: <?= $initialStatus ? 'none' : 'inline-flex' ?>;">
                    <span class="material-symbols-outlined">power_settings_new</span>
                    Wake
                </button>
                <button id="sleep-btn" class="button button-filled" style="display: <?= $initialStatus ? 'inline-flex' : 'none' ?>;">
                    <span class="material-symbols-outlined">bedtime</span>
                    Sleep
                </button>
                <button id="rdp-btn" class="button button-tonal" style="display: <?= $initialStatus ? 'inline-flex' : 'none' ?>;">
                    <span class="material-symbols-outlined">desktop_windows</span>
                    RDP
                </button>
                <a id="novnc-btn" href="<?= htmlspecialchars($config['network']['novnc_url']) ?>" class="button button-tonal" target="_blank" style="display: <?= $initialStatus ? 'inline-flex' : 'none' ?>;">
                    <span class="material-symbols-outlined">desktop_windows</span>
                    NoVNC
                </a>
                <a href="?logout" class="button button-tonal">
                    <span class="material-symbols-outlined">logout</span>
                    Logout
                </a>
            </div>
        </div>
    </div>

    <div id="result-modal" class="modal">
        <div class="modal-content">
            <h3 class="modal-title">Action Result</h3>
            <p id="modal-result-text"></p>
            <div class="modal-actions">
                <button class="button button-tonal modal-close">Close</button>
            </div>
        </div>
    </div>

    <script>
        let statusCheckInProgress = false;
        
        function refreshStatus() {
            if (statusCheckInProgress) {
                return;
            }
        
            statusCheckInProgress = true;
            fetch('?action=status')
                .then(response => response.json())
                .then(data => {
                    const isOnline = data.status;
                    document.getElementById('status-dot').className = 
                        `status-dot status-${isOnline ? 'online' : 'offline'}`;
                    document.getElementById('status-text').textContent = 
                        isOnline ? 'Online' : 'Offline';
                    document.getElementById('wake-btn').style.display = 
                        isOnline ? 'none' : 'inline-flex';
                    document.getElementById('sleep-btn').style.display = 
                        isOnline ? 'inline-flex' : 'none';
                    document.getElementById('rdp-btn').style.display = 
                        isOnline ? 'inline-flex' : 'none';
                    document.getElementById('novnc-btn').style.display = 
                        isOnline ? 'inline-flex' : 'none';
                })
                .catch(error => {
                    console.error('Status check failed:', error);
                })
                .finally(() => {
                    statusCheckInProgress = false;
                    setTimeout(refreshStatus, 1000);
                });
        }
        
        function sendAction(action) {
            const formData = new FormData();
            formData.append('action', action);
        
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('modal-result-text').textContent = data.result;
                document.getElementById('result-modal').style.display = 'flex';
                refreshStatus();
            });
        }
        
        document.addEventListener('DOMContentLoaded', () => {
            // Start status checking after initial page load
            setTimeout(refreshStatus, 1000);
        
            document.getElementById('wake-btn').addEventListener('click', () => {
                sendAction('wake');
            });
        
            document.getElementById('sleep-btn').addEventListener('click', () => {
                sendAction('sleep');
            });
        
            document.getElementById('rdp-btn').addEventListener('click', () => {
                window.location.href = '?action=rdp';
            });
        
            document.querySelector('.modal-close').addEventListener('click', () => {
                document.getElementById('result-modal').style.display = 'none';
            });
        
            document.getElementById('result-modal').addEventListener('click', (e) => {
                if (e.target === document.getElementById('result-modal')) {
                    document.getElementById('result-modal').style.display = 'none';
                }
            });
        });
</script>
</body>
</html>