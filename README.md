# IPv4 & IPv6 Abusemail grabber

This small snippet offers the possibility to get Abuse mail addresses from IPv4 and IPv6 addresses.


Eg.:
```php
require_once __DIR__ . '/../AbuseMailService.php';

$abuseMailService = new AbuseMailService();
echo $abuseMailService->getAbuseMail('1.1.1.1');

// resolver-abuse@cloudflare.com
```
