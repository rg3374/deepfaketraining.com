<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_login();

$pdo = db();
$user = current_user();

$scenarios = $pdo->query('SELECT id, title, description FROM scenarios ORDER BY created_at ASC')->fetchAll();

if (!$scenarios) {
    render_header('Deepfake Arena');
    ?>
    <section class="panel">
        <h1>No scenarios yet</h1>
        <p>The library is empty. An administrator can upload the first challenge from the admin console.</p>
    </section>
    <?php
    render_footer();
    exit;
}

$scenarioId = isset($_GET['scenario_id']) ? (int)$_GET['scenario_id'] : (int)$scenarios[0]['id'];
$result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $scenarioId = (int)($_POST['scenario_id'] ?? 0);
    $mediaId = (int)($_POST['media_id'] ?? 0);

    $mediaStmt = $pdo->prepare('SELECT sm.id, sm.scenario_id, sm.is_deepfake, s.title FROM scenario_media sm INNER JOIN scenarios s ON sm.scenario_id = s.id WHERE sm.id = ?');
    $mediaStmt->execute([$mediaId]);
    $mediaRow = $mediaStmt->fetch();

    if ($mediaRow && (int)$mediaRow['scenario_id'] === $scenarioId) {
        $isCorrect = (int)$mediaRow['is_deepfake'] === 1 ? 1 : 0;

        $insert = $pdo->prepare('INSERT INTO user_scenario_attempts (user_id, scenario_id, media_id, is_correct) VALUES (?, ?, ?, ?)');
        $insert->execute([$user['id'], $scenarioId, $mediaId, $isCorrect]);

        $result = [
            'is_correct' => $isCorrect === 1,
            'scenario' => $mediaRow['title'],
        ];
    } else {
        $result = [
            'is_correct' => false,
            'error' => 'Please choose one of the available clips for this scenario.',
        ];
    }
}

$scenarioStmt = $pdo->prepare('SELECT id, title, description FROM scenarios WHERE id = ?');
$scenarioStmt->execute([$scenarioId]);
$activeScenario = $scenarioStmt->fetch();

if (!$activeScenario) {
    $activeScenario = $scenarios[0];
    $scenarioId = (int)$activeScenario['id'];
}

$mediaClipsStmt = $pdo->prepare('SELECT id, label, media_type FROM scenario_media WHERE scenario_id = ? ORDER BY id');
$mediaClipsStmt->execute([$scenarioId]);
$mediaClips = $mediaClipsStmt->fetchAll();

render_header('Deepfake Arena');
?>
<section class="panel">
    <h1>Deepfake Challenge Arena</h1>
    <form method="get" style="margin-bottom:1.5rem;">
        <label>
            Scenario
            <select name="scenario_id" onchange="this.form.submit()">
                <?php foreach ($scenarios as $scenario): ?>
                    <option value="<?= h((string)$scenario['id']) ?>" <?= (int)$scenario['id'] === $scenarioId ? 'selected' : '' ?>>
                        <?= h($scenario['title']) ?>
                    </option>
                <?php endforeach; ?>
            </select>
        </label>
    </form>

    <div class="score-card">
        <h2><?= h($activeScenario['title']) ?></h2>
        <p><?= h($activeScenario['description'] ?? '') ?></p>
    </div>

    <?php if ($result): ?>
        <div class="flash <?= $result['is_correct'] ? 'success' : 'danger' ?>">
            <?php if (!empty($result['error'])): ?>
                <?= h($result['error']) ?>
            <?php elseif ($result['is_correct']): ?>
                Nailed it! You spotted the synthetic voice.
            <?php else: ?>
                Not quite. Review the cues and try another scenario.
            <?php endif; ?>
        </div>
    <?php endif; ?>

    <?php if ($mediaClips): ?>
        <form method="post" class="media-grid">
            <input type="hidden" name="scenario_id" value="<?= h((string)$scenarioId) ?>">
            <?php foreach ($mediaClips as $clip): ?>
                <label class="score-card">
                    <strong><?= h($clip['label']) ?></strong>
                    <?php if ($clip['media_type'] === 'audio'): ?>
                        <audio controls preload="none">
                            <source src="/media.php?id=<?= h((string)$clip['id']) ?>">
                        </audio>
                    <?php else: ?>
                        <video controls preload="none">
                            <source src="/media.php?id=<?= h((string)$clip['id']) ?>">
                        </video>
                    <?php endif; ?>
                    <div style="margin-top:0.75rem;">
                        <input type="radio" name="media_id" value="<?= h((string)$clip['id']) ?>" required>
                        <span>Mark as deepfake</span>
                    </div>
                </label>
            <?php endforeach; ?>
            <button type="submit">Submit answer</button>
        </form>
    <?php else: ?>
        <p>No media uploaded for this scenario yet.</p>
    <?php endif; ?>
</section>
<?php
render_footer();

