<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/db.php';

$scenarioTitle = 'Executive Wire Transfer Verification';
$scenarioDescription = 'Listen to the three urgent voicemail clips and decide which one is the deepfake requesting a wire transfer.';
$deepfakeNeedle = '02';
$sourceDir = realpath(__DIR__ . '/../source_audio');

if (!$sourceDir || !is_dir($sourceDir)) {
    exit("source_audio directory not found.\n");
}

$audioFiles = glob($sourceDir . '/*.m4a');
if (!$audioFiles) {
    exit("No .m4a files found in {$sourceDir}\n");
}

$pdo = db();
$pdo->beginTransaction();

$scenarioStmt = $pdo->prepare('SELECT id FROM scenarios WHERE title = ? LIMIT 1');
$scenarioStmt->execute([$scenarioTitle]);
$scenarioId = $scenarioStmt->fetchColumn();

if (!$scenarioId) {
    $insertScenario = $pdo->prepare('INSERT INTO scenarios (title, description) VALUES (?, ?)');
    $insertScenario->execute([$scenarioTitle, $scenarioDescription]);
    $scenarioId = (int)$pdo->lastInsertId();
}

$insertMedia = $pdo->prepare(
    'INSERT INTO scenario_media (scenario_id, label, media_type, mime_type, media_data, is_deepfake)
     VALUES (:scenario_id, :label, :media_type, :mime_type, :media_data, :is_deepfake)'
);

foreach ($audioFiles as $index => $filePath) {
    $data = file_get_contents($filePath);
    if ($data === false) {
        echo "Skipping {$filePath} (unable to read)\n";
        continue;
    }

    $fileName = basename($filePath);
    $isDeepfake = str_contains($fileName, $deepfakeNeedle) ? 1 : 0;

    $insertMedia->execute([
        ':scenario_id' => $scenarioId,
        ':label' => "Clip " . ($index + 1),
        ':media_type' => 'audio',
        ':mime_type' => mime_content_type($filePath) ?: 'audio/mpeg',
        ':media_data' => $data,
        ':is_deepfake' => $isDeepfake,
    ]);

    echo "Imported {$fileName}" . ($isDeepfake ? " (deepfake)\n" : "\n");
}

$pdo->commit();

echo "Scenario {$scenarioTitle} is ready.\n";

