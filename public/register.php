<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

if (current_user()) {
    redirect('/dashboard.php');
}

$errors = [];
$username = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    $errors = register_user($username, $password);
    if (!$errors) {
        redirect('/login.php');
    }
}

render_header('Create Account');
?>
<section class="panel">
    <h1>Create your training account</h1>
    <?php if ($errors): ?>
        <div class="flash danger">
            <?= h(implode(' ', $errors)) ?>
        </div>
    <?php endif; ?>
    <form method="post">
        <label>
            Username
            <input type="text" name="username" value="<?= h($username) ?>" required autofocus>
        </label>
        <label>
            Password
            <input type="password" name="password" required minlength="8">
        </label>
        <button type="submit">Create account</button>
    </form>
    <p>Already registered? <a href="/login.php">Sign in here</a>.</p>
</section>
<?php
render_footer();

