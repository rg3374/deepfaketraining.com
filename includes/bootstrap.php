<?php
declare(strict_types=1);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start([
        'cookie_secure' => false,
        'cookie_httponly' => true,
        'use_strict_mode' => true,
        'cookie_samesite' => 'Lax',
    ]);
}

$config = require __DIR__ . '/../config.php';

require_once __DIR__ . '/db.php';
require_once __DIR__ . '/helpers.php';
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/layout.php';

