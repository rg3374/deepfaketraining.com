<?php
declare(strict_types=1);

const SIMULATION_TASK_COLUMNS = [
    'payload_prepared' => 'payload_prepared_at',
    'voicemail_generated' => 'voicemail_generated_at',
    'listener_started' => 'listener_started_at',
    'phish_delivered' => 'phish_delivered_at',
    'shell_caught' => 'shell_caught_at',
];

const SIMULATION_TASK_LABELS = [
    'payload_prepared' => 'Task 1 · Prepare Payload',
    'voicemail_generated' => 'Task 2 · Generate Voicemail',
    'listener_started' => 'Task 3 · Start Listener',
    'phish_delivered' => 'Task 4 · Deliver the Phish',
    'shell_caught' => 'Task 5 · Catch the Shell',
];

function simulation_progress_defaults(): array
{
    $defaults = [];
    foreach (SIMULATION_TASK_COLUMNS as $column) {
        $defaults[$column] = null;
    }
    return $defaults;
}

function simulation_progress_ensure_table(): void
{
    static $initialized = false;
    if ($initialized) {
        return;
    }

    $sql = <<<SQL
CREATE TABLE IF NOT EXISTS simulation_progress (
    user_id INT PRIMARY KEY,
    payload_prepared_at TIMESTAMP NULL,
    voicemail_generated_at TIMESTAMP NULL,
    listener_started_at TIMESTAMP NULL,
    phish_delivered_at TIMESTAMP NULL,
    shell_caught_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    CONSTRAINT fk_simulation_progress_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SQL;

    db()->exec($sql);
    $initialized = true;
}

function simulation_progress_get(int $userId): array
{
    simulation_progress_ensure_table();
    $stmt = db()->prepare(
        sprintf(
            'SELECT user_id, %s FROM simulation_progress WHERE user_id = ?',
            implode(', ', SIMULATION_TASK_COLUMNS)
        )
    );
    $stmt->execute([$userId]);
    $row = $stmt->fetch();

    if (!$row) {
        return simulation_progress_defaults();
    }

    return array_replace(simulation_progress_defaults(), $row);
}

function simulation_progress_mark_complete(int $userId, string $taskKey): void
{
    if (!isset(SIMULATION_TASK_COLUMNS[$taskKey])) {
        return;
    }

    simulation_progress_ensure_table();
    $column = SIMULATION_TASK_COLUMNS[$taskKey];
    $sql = "INSERT INTO simulation_progress (user_id, {$column}) VALUES (:user_id, :ts)
            ON DUPLICATE KEY UPDATE {$column} = COALESCE({$column}, VALUES({$column})), updated_at = CURRENT_TIMESTAMP";

    $stmt = db()->prepare($sql);
    $stmt->execute([
        'user_id' => $userId,
        'ts' => date('Y-m-d H:i:s'),
    ]);
}

function simulation_progress_mark_for_current_user(string $taskKey): void
{
    $user = current_user();
    if (!$user) {
        return;
    }
    simulation_progress_mark_complete((int)$user['id'], $taskKey);
}

function simulation_progress_is_task_complete(array $progress, string $taskKey): bool
{
    $column = SIMULATION_TASK_COLUMNS[$taskKey] ?? null;
    if (!$column) {
        return false;
    }
    return !empty($progress[$column]);
}

function simulation_progress_completed_count(array $progress): int
{
    $count = 0;
    foreach (SIMULATION_TASK_COLUMNS as $column) {
        if (!empty($progress[$column])) {
            $count++;
        }
    }
    return $count;
}

function simulation_progress_total_tasks(): int
{
    return count(SIMULATION_TASK_COLUMNS);
}

function simulation_progress_task_labels(): array
{
    return SIMULATION_TASK_LABELS;
}

function simulation_progress_task_timestamp(array $progress, string $taskKey): ?string
{
    $column = SIMULATION_TASK_COLUMNS[$taskKey] ?? null;
    if (!$column) {
        return null;
    }

    return $progress[$column] ?? null;
}

