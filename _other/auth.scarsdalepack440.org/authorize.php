<?php
require_once __DIR__ . '/config.php';
session_start();

// Capture the origin from the request
$origin = null;
if (!empty($_SERVER['HTTP_ORIGIN'])) {
  $origin = $_SERVER['HTTP_ORIGIN'];
} elseif (!empty($_SERVER['HTTP_REFERER'])) {
  $u = parse_url($_SERVER['HTTP_REFERER']);
  if (!empty($u['scheme']) && !empty($u['host'])) {
    $origin = $u['scheme'] . '://' . $u['host'];
    if (!empty($u['port']) && $u['port'] != 80 && $u['port'] != 443) {
      $origin .= ':' . $u['port'];
    }
  }
}

// Store the origin in session so callback can use it
if ($origin && in_array($origin, ALLOWED_ORIGINS, true)) {
  $_SESSION['opener_origin'] = $origin;
}

// Start OAuth on GitHub
$state = bin2hex(random_bytes(16));
$_SESSION['oauth_state'] = $state;

$params = http_build_query([
  'client_id'     => GITHUB_CLIENT_ID,
  'redirect_uri'  => REDIRECT_URI,
  'scope'         => 'repo',
  'state'         => $state,
  'allow_signup'  => 'false',
]);

header('Cache-Control: no-store');
header("Location: https://github.com/login/oauth/authorize?$params", true, 302);
exit;
