<?php
declare(strict_types=1);

function current_user(): ?array
{
    if (!empty($_SESSION['user'])) {
        return $_SESSION['user'];
    }

    if (empty($_SESSION['user_id'])) {
        return null;
    }

    $stmt = db()->prepare('SELECT id, username, is_admin FROM users WHERE id = ?');
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();

    if ($user) {
        $_SESSION['user'] = $user;
        return $user;
    }

    logout_user();
    return null;
}

function login_user(array $user): void
{
    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['user'] = [
        'id' => (int)$user['id'],
        'username' => $user['username'],
        'is_admin' => (int)$user['is_admin'],
    ];
}

function logout_user(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
}

function require_login(): void
{
    if (!current_user()) {
        set_flash('Please sign in to continue.', 'warning');
        redirect('/login.php');
    }
}

function require_admin(): void
{
    $user = current_user();
    if (!$user || !(int)$user['is_admin']) {
        set_flash('Administrator access required.', 'danger');
        redirect('/dashboard.php');
    }
}

function attempt_login(string $username, string $password): bool
{
    $stmt = db()->prepare('SELECT id, username, password_hash, is_admin FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if ($user && password_verify($password, $user['password_hash'])) {
        login_user($user);
        return true;
    }

    return false;
}

function register_user(string $username, string $password): array
{
    $errors = [];
    $username = trim($username);

    if ($username === '') {
        $errors[] = 'Username is required.';
    }

    if (strlen($username) > 50) {
        $errors[] = 'Username must be 50 characters or fewer.';
    }

    if ($password === '' || strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters.';
    }

    if ($errors) {
        return $errors;
    }

    $stmt = db()->prepare('SELECT id FROM users WHERE username = ?');
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        return ['That username is already taken.'];
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = db()->prepare('INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 0)');
    $stmt->execute([$username, $hash]);

    set_flash('Account created! You can sign in now.', 'success');
    return [];
}

