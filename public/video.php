<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_login();

global $config;
$videoUrl = $config['app']['default_video_url'];
$pdo = db();
$user = current_user();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $stmt = $pdo->prepare(
        'INSERT INTO user_progress (user_id, part2_completed, last_video_view)
         VALUES (:user_id, 1, NOW())
         ON DUPLICATE KEY UPDATE part2_completed = VALUES(part2_completed), last_video_view = VALUES(last_video_view)'
    );
    $stmt->execute([':user_id' => $user['id']]);
    set_flash('Great! Your completion has been logged.', 'success');
    redirect('/video.php');
}

$progressStmt = $pdo->prepare('SELECT part2_completed, last_video_view FROM user_progress WHERE user_id = ?');
$progressStmt->execute([$user['id']]);
$progress = $progressStmt->fetch() ?: ['part2_completed' => 0, 'last_video_view' => null];

render_header('Awareness Briefing');
?>
<section class="panel">
    <h1>Cyber Deception Briefing</h1>
    <p>Watch the threat intel briefing and log your completion to finish Part 2.</p>
    <div style="margin:1.5rem 0;">
        <video controls width="100%">
            <source src="<?= h($videoUrl) ?>" type="video/mp4">
            Your browser does not support the video tag.
        </video>
    </div>
    <form method="post">
        <button type="submit"><?= $progress['part2_completed'] ? 'Reconfirm completion' : 'Mark as completed' ?></button>
    </form>
    <?php if ($progress['last_video_view']): ?>
        <p style="margin-top:1rem;">Last confirmed: <?= h($progress['last_video_view']) ?></p>
    <?php endif; ?>
</section>
<?php
render_footer();

