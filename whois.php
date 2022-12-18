<?php

function getAbuseEmail($ip) {
  /*
  INFORMATION
  IPv4 addresses have four octets (e.g. 192.0.2.1).
  IPv6 addresses have eight groups of four hexadecimal characters (z.B. 2001:0db8:85a3:0000:0000:8a2e:0370:7334)
  */
  if (preg_match('/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/', $ip)) {
    // IPv4 address
    $whoisServer = "whois.arin.net";
  } elseif (preg_match('/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/', $ip)) {
    // IPv6 address
    $whoisServer = "whois.iana.org";
  } else {
    return false; // Failed: The IP is not a valid IPv4 or IPv6 address
  }

  $conn = fsockopen($whoisServer, 43);
  if (!$conn) {
    // Connection failed
    return false;
  }

  // Send whois
  fputs($conn, $ip . "\r\n");
  $response = "";
  while(!feof($conn)) {
    $response .= fgets($conn, 128);
  }

  fclose($conn);

  // Extract Abuse email address from Whois response
  // eg: abuse@example.tld
  preg_match('/abuse-mailbox:[\s]*([^\s]*)/im', $response, $matches);
  if (!isset($matches[1])) {
    return false;
  }
  
  // Return found Abuse email address
  return trim($matches[1]);
  
?>
