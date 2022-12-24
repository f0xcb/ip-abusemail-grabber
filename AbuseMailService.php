<?php

class AbuseMailService
{
    const REGEX_IPv4 = '/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/';
    const REGEX_IPv6 = '/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/';
    const REGEX_EXTRACT_MAIL = '/abuse-mailbox:[\s]*([^\s]*)/im';

    public function getAbuseMail(string $ipAddress): string
    {
        $whoIsServer = $this->getWhoIsServer($ipAddress);

        $response = $this->requestWhoIs($whoIsServer, $ipAddress);

        return $this->extractAbuseMail($response);
    }

    private function getWhoIsServer(string $ipAddress): string
    {
        if (preg_match(self::REGEX_IPv4, $ipAddress)) {
            return 'whois.arin.net';
        } elseif (preg_match(self::REGEX_IPv6, $ipAddress)) {
            return 'whois.iana.org';
        }

        return new RuntimeException('IP is no valid IPv4 or IPv6.');
    }

    private function requestWhoIs(string $whoIsServer, string $ipAddress): string
    {
        $connectionWhoIsServer = fsockopen($whoIsServer, 43);

        if (!$connectionWhoIsServer) {
            throw new RuntimeException('connection to who is server ' . $whoIsServer . ' failed.');
        }

        fputs($connectionWhoIsServer, $ipAddress . '\r\n');
        $response = '';

        while (!feof($connectionWhoIsServer)) {
            $response .= fgets($connectionWhoIsServer, 128);
        }

        fclose($connectionWhoIsServer);

        return $response;
    }

    private function extractAbuseMail(string $response): string
    {
        var_dump($response);

        preg_match(self::REGEX_EXTRACT_MAIL, $response, $matches);

        var_dump($matches);

        if (!isset($matches[1])) {
            throw new RuntimeException('can not find/extract abuse mail address');
        }

        return trim($matches[1]);
    }
}