<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

logout_user();
set_flash('Signed out.', 'success');
redirect('/login.php');

