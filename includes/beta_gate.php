<?php
declare(strict_types=1);

const BETA_COOKIE = 'beta_token';

function beta_is_enabled(): bool
{
    global $config;
    $key = $config['app']['beta_key'] ?? '';
    return is_string($key) && trim($key) !== '';
}

function beta_expected_token(): string
{
    global $config;
    $key = trim((string)($config['app']['beta_key'] ?? ''));
    return hash_hmac('sha256', $key, 'deepfake-beta-gate');
}

function beta_is_verified(): bool
{
    if (!beta_is_enabled()) {
        return true;
    }

    if (!empty($_SESSION['beta_verified'])) {
        return true;
    }

    $cookieToken = $_COOKIE[BETA_COOKIE] ?? null;
    if (is_string($cookieToken) && hash_equals(beta_expected_token(), $cookieToken)) {
        $_SESSION['beta_verified'] = true;
        return true;
    }

    return false;
}

function enforce_beta_access(): void
{
    if (!beta_is_enabled()) {
        return;
    }

    $script = basename($_SERVER['SCRIPT_NAME'] ?? '');
    if ($script === 'beta.php') {
        return;
    }

    if (beta_is_verified()) {
        return;
    }

    if (!empty($_SERVER['REQUEST_URI'])) {
        $_SESSION['beta_after_login'] = $_SERVER['REQUEST_URI'];
    }

    redirect('/beta.php');
}

function beta_set_cookie(): void
{
    if (!beta_is_enabled()) {
        return;
    }

    $options = [
        'expires' => time() + 60 * 60 * 24 * 30,
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ];

    $token = beta_expected_token();
    setcookie(BETA_COOKIE, $token, $options);
    $_COOKIE[BETA_COOKIE] = $token;
}

function beta_clear_cookie(): void
{
    setcookie(BETA_COOKIE, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => false,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    unset($_COOKIE[BETA_COOKIE]);
}

function beta_logout(): void
{
    beta_clear_cookie();
    unset($_SESSION['beta_verified'], $_SESSION['beta_after_login']);
}

