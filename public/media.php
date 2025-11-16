<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_login();

$id = isset($_GET['id']) ? (int)$_GET['id'] : 0;

if ($id <= 0) {
    http_response_code(400);
    exit('Missing media id');
}

$stmt = db()->prepare('SELECT media_data, mime_type FROM scenario_media WHERE id = ?');
$stmt->execute([$id]);
$media = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$media) {
    http_response_code(404);
    exit('Media not found');
}

header('Content-Type: ' . $media['mime_type']);
header('Content-Length: ' . strlen($media['media_data']));
header('Cache-Control: private, max-age=3600');

echo $media['media_data'];
exit;

