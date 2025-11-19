<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

if (!beta_is_enabled()) {
    redirect('/');
}

$error = '';

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    beta_logout();
    set_flash('Beta session cleared. Enter the key again to continue.', 'info');
    redirect('/beta.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $provided = trim($_POST['beta_key'] ?? '');
    $expected = $config['app']['beta_key'];

    if (hash_equals($expected, $provided)) {
        $_SESSION['beta_verified'] = true;
        beta_set_cookie();
        $target = $_SESSION['beta_after_login'] ?? '/';
        unset($_SESSION['beta_after_login']);
        set_flash('Access granted. Welcome to the beta!', 'success');
        redirect($target);
    } else {
        $error = 'Invalid beta key.';
    }
}

render_header('Beta Access Required');
?>
<section class="panel">
    <h1>Private Beta</h1>
    <p>This preview build is protected. Enter the beta key to continue.</p>
    <?php if ($error): ?>
        <div class="flash danger"><?= h($error) ?></div>
    <?php endif; ?>
    <form method="post" class="form-auth" style="max-width:420px;">
        <label>Beta Key</label>
        <input type="password" name="beta_key" required autofocus>
        <button type="submit">Unlock</button>
    </form>
    <?php if (!empty($_SESSION['beta_verified'])): ?>
        <p style="margin-top:1rem;"><a href="/beta.php?action=logout">Reset beta session</a></p>
    <?php endif; ?>
</section>
<?php
render_footer();

