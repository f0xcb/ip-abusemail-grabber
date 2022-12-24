<?php declare(strict_types=1);

require_once __DIR__ . '/../AbuseMailService.php';

$abuseMailService = new AbuseMailService();
echo $abuseMailService->getAbuseMail('1.1.1.1');
