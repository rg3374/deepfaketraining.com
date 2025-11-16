<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_login();
require_admin();

$pdo = db();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'create_scenario') {
        $title = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');

        if ($title === '') {
            set_flash('Scenario title is required.', 'danger');
        } else {
            $stmt = $pdo->prepare('INSERT INTO scenarios (title, description, created_by) VALUES (?, ?, ?)');
            $stmt->execute([$title, $description, current_user()['id']]);
            set_flash('Scenario created.', 'success');
        }
    } elseif ($action === 'upload_media') {
        $scenarioId = (int)($_POST['scenario_id'] ?? 0);
        $label = trim($_POST['label'] ?? '');
        $mediaType = $_POST['media_type'] ?? 'audio';
        $isDeepfake = isset($_POST['is_deepfake']) ? 1 : 0;

        if ($scenarioId <= 0 || $label === '') {
            set_flash('Scenario and label are required.', 'danger');
        } elseif (empty($_FILES['media']['tmp_name'])) {
            set_flash('Please attach a media file.', 'danger');
        } else {
            $filePath = $_FILES['media']['tmp_name'];
            $data = file_get_contents($filePath);
            if ($data === false) {
                set_flash('Unable to read the media file.', 'danger');
            } else {
                $mime = mime_content_type($filePath) ?: ($_FILES['media']['type'] ?? 'application/octet-stream');

                $stmt = $pdo->prepare(
                    'INSERT INTO scenario_media (scenario_id, label, media_type, mime_type, media_data, is_deepfake)
                     VALUES (:scenario_id, :label, :media_type, :mime_type, :media_data, :is_deepfake)'
                );
                $stmt->bindValue(':scenario_id', $scenarioId, PDO::PARAM_INT);
                $stmt->bindValue(':label', $label);
                $stmt->bindValue(':media_type', $mediaType === 'video' ? 'video' : 'audio');
                $stmt->bindValue(':mime_type', $mime);
                $stmt->bindValue(':media_data', $data, PDO::PARAM_LOB);
                $stmt->bindValue(':is_deepfake', $isDeepfake, PDO::PARAM_INT);
                $stmt->execute();

                set_flash('Media uploaded.', 'success');
            }
        }
    }

    redirect('/admin.php');
}

$scenarios = $pdo->query('SELECT id, title FROM scenarios ORDER BY created_at DESC')->fetchAll();

render_header('Admin Console');
?>
<section class="panel grid grid-2">
    <div>
        <h2>Create scenario</h2>
        <form method="post">
            <input type="hidden" name="action" value="create_scenario">
            <label>
                Title
                <input type="text" name="title" required>
            </label>
            <label>
                Description
                <textarea name="description" rows="4"></textarea>
            </label>
            <button type="submit">Create scenario</button>
        </form>
    </div>
    <div>
        <h2>Upload media</h2>
        <?php if (!$scenarios): ?>
            <p>Create a scenario first.</p>
        <?php else: ?>
            <form method="post" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload_media">
                <label>
                    Scenario
                    <select name="scenario_id" required>
                        <?php foreach ($scenarios as $scenario): ?>
                            <option value="<?= h((string)$scenario['id']) ?>"><?= h($scenario['title']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </label>
                <label>
                    Clip label
                    <input type="text" name="label" required>
                </label>
                <label>
                    Media type
                    <select name="media_type">
                        <option value="audio">Audio</option>
                        <option value="video">Video</option>
                    </select>
                </label>
                <label>
                    File
                    <input type="file" name="media" accept="audio/*,video/*" required>
                </label>
                <label style="display:flex; align-items:center; gap:0.5rem;">
                    <input type="checkbox" name="is_deepfake">
                    Mark as deepfake
                </label>
                <button type="submit">Upload clip</button>
            </form>
        <?php endif; ?>
    </div>
</section>
<?php
render_footer();

