<?php
declare(strict_types=1);

function render_header(string $title = 'Deepfake Defense'): void
{
    global $config;
    $appName = $config['app']['name'] ?? 'Deepfake Defense Training';
    $user = current_user();
    $flash = get_flash();
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title><?= h($title) ?> · <?= h($appName) ?></title>
        <link rel="stylesheet" href="/assets/styles.css" />
    </head>
    <body>
    <header>
        <div class="logo"><?= h($appName) ?></div>
        <nav>
            <?php if ($user): ?>
                <a href="/dashboard.php">Dashboard</a>
                <a href="/game.php">Game</a>
                <a href="/video.php">Video</a>
                <?php if ((int)$user['is_admin'] === 1): ?>
                    <a href="/admin.php">Admin</a>
                <?php endif; ?>
                <a href="/logout.php">Logout (<?= h($user['username']) ?>)</a>
            <?php else: ?>
                <a href="/login.php">Sign In</a>
                <a href="/register.php">Create Account</a>
            <?php endif; ?>
        </nav>
    </header>
    <main>
        <?php if ($flash): ?>
            <div class="flash <?= h($flash['type']) ?>"><?= h($flash['message']) ?></div>
        <?php endif; ?>
    <?php
}

function render_footer(): void
{
    ?>
    </main>
    </body>
    </html>
    <?php
}

