<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_login();

$user = current_user();
$pdo = db();

$totalScenarios = (int)$pdo->query('SELECT COUNT(*) FROM scenarios')->fetchColumn();

$attemptStats = $pdo->prepare(
    'SELECT COUNT(*) AS attempts, COALESCE(SUM(is_correct), 0) AS correct, COUNT(DISTINCT scenario_id) AS covered
     FROM user_scenario_attempts WHERE user_id = ?'
);
$attemptStats->execute([$user['id']]);
$stats = $attemptStats->fetch() ?: ['attempts' => 0, 'correct' => 0, 'covered' => 0];

$progressStmt = $pdo->prepare('SELECT part2_completed, last_video_view FROM user_progress WHERE user_id = ?');
$progressStmt->execute([$user['id']]);
$progress = $progressStmt->fetch() ?: ['part2_completed' => 0, 'last_video_view' => null];

$recentAttempts = $pdo->prepare(
    'SELECT s.title, sm.label, usa.is_correct, usa.attempted_at
     FROM user_scenario_attempts usa
     INNER JOIN scenarios s ON usa.scenario_id = s.id
     INNER JOIN scenario_media sm ON usa.media_id = sm.id
     WHERE usa.user_id = ?
     ORDER BY usa.attempted_at DESC
     LIMIT 5'
);
$recentAttempts->execute([$user['id']]);
$attemptRows = $recentAttempts->fetchAll();

render_header('Dashboard');
?>
<section class="panel grid grid-2">
    <div class="score-card">
        <h2>Deepfake Arena</h2>
        <p><strong>Total scenarios:</strong> <?= h((string)$totalScenarios) ?></p>
        <p><strong>Scenarios attempted:</strong> <?= h((string)$stats['covered']) ?></p>
        <p><strong>Accuracy:</strong>
            <?php
            if ($stats['attempts'] > 0) {
                $accuracy = round(($stats['correct'] / max(1, $stats['attempts'])) * 100);
                echo h("{$accuracy}% ({$stats['correct']} / {$stats['attempts']})");
            } else {
                echo 'No attempts yet';
            }
            ?>
        </p>
        <a class="btn" href="/game.php">Enter the arena</a>
    </div>
    <div class="score-card">
        <h2>Awareness Briefing</h2>
        <p>Status:
            <?php if ($progress['part2_completed']): ?>
                <span class="tag" style="border-color:var(--primary); color:var(--primary)">Completed</span>
            <?php else: ?>
                <span class="tag" style="border-color:var(--danger); color:var(--danger)">Pending</span>
            <?php endif; ?>
        </p>
        <?php if ($progress['last_video_view']): ?>
            <p>Last viewed: <?= h($progress['last_video_view']) ?></p>
        <?php endif; ?>
        <a class="btn" href="/video.php">Watch the briefing</a>
    </div>
</section>

<section class="panel" style="margin-top:2rem;">
    <h2>Recent attempts</h2>
    <?php if ($attemptRows): ?>
        <table>
            <thead>
            <tr>
                <th>Scenario</th>
                <th>Clip</th>
                <th>Result</th>
                <th>When</th>
            </tr>
            </thead>
            <tbody>
            <?php foreach ($attemptRows as $row): ?>
                <tr>
                    <td><?= h($row['title']) ?></td>
                    <td><?= h($row['label']) ?></td>
                    <td><?= $row['is_correct'] ? '✅ Correct' : '⚠️ Incorrect' ?></td>
                    <td><?= h($row['attempted_at']) ?></td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php else: ?>
        <p>No attempts logged yet. Start the game to see your stats.</p>
    <?php endif; ?>
</section>
<?php
render_footer();

