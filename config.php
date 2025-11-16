<?php
declare(strict_types=1);

return [
    'app' => [
        'name' => 'Deepfake Defense Training',
        'default_video_url' => 'https://videos.pexels.com/video-files/3130449/3130449-uhd_2560_1440_25fps.mp4',
    ],
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'port' => getenv('DB_PORT') ?: '3306',
        'name' => getenv('DB_NAME') ?: 'deepfake_training',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') ?: '',
        'charset' => 'utf8mb4',
    ],
];

