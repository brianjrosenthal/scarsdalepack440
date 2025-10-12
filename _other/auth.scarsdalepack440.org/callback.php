<?php
// Handles GitHub OAuth return for Decap CMS
require_once __DIR__ . '/config.php';
session_start();

function request_origin(): ?string {
  if (!empty($_SERVER['HTTP_ORIGIN'])) return $_SERVER['HTTP_ORIGIN'];
  if (!empty($_SERVER['HTTP_REFERER'])) {
    $u = parse_url($_SERVER['HTTP_REFERER']);
    if (!empty($u['scheme']) && !empty($u['host'])) {
      $o = $u['scheme'] . '://' . $u['host'];
      if (!empty($u['port'])) $o .= ':' . $u['port'];
      return $o;
    }
  }
  return null;
}

$origin  = request_origin();
$allowed = in_array($origin, ALLOWED_ORIGINS, true);

// ---- CORS headers (echo back the requester if allowed) ----
header('Cache-Control: no-store');
header('Content-Type: text/html; charset=utf-8');
if ($allowed) {
  header('Access-Control-Allow-Origin: ' . $origin);
  header('Vary: Origin');
}
header('Access-Control-Allow-Credentials: true');
header('Access-Control-Allow-Headers: Content-Type');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
  http_response_code(204);
  exit;
}

// ---- Validate state ----
if (!isset($_GET['code'], $_GET['state'], $_SESSION['oauth_state']) ||
    !hash_equals($_SESSION['oauth_state'], $_GET['state'])) {
  http_response_code(400);
  $err = 'State mismatch or missing parameters.';
  echo "<!doctype html><meta charset='utf-8'><pre>$err</pre>";
  exit;
}

// Retrieve the stored origin
$stored_origin = $_SESSION['opener_origin'] ?? null;

unset($_SESSION['oauth_state']);
unset($_SESSION['opener_origin']);

// ---- Exchange code for token (expects JSON back) ----
$ch = curl_init('https://github.com/login/oauth/access_token');
curl_setopt_array($ch, [
  CURLOPT_POST           => true,
  CURLOPT_POSTFIELDS     => http_build_query([
    'client_id'     => GITHUB_CLIENT_ID,
    'client_secret' => GITHUB_CLIENT_SECRET,
    'code'          => $_GET['code'],
    'redirect_uri'  => REDIRECT_URI,
  ]),
  CURLOPT_HTTPHEADER     => ['Accept: application/json'],
  CURLOPT_RETURNTRANSFER => true,
  CURLOPT_TIMEOUT        => 20,
]);
$raw    = curl_exec($ch);
$status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$cerr   = curl_error($ch);
curl_close($ch);

$token_json = null;
$token_err  = null;

if ($raw === false || $status !== 200) {
  $token_err = "Token exchange failed (HTTP $status): $cerr";
} else {
  $data = json_decode($raw, true);
  if (!is_array($data) || empty($data['access_token'])) {
    $token_err = "No access_token in response: $raw";
  } else {
    $token_json = ['token' => $data['access_token'], 'provider' => 'github'];
  }
}

// ---- Render small HTML page: post token back or show error ----
?>
<!doctype html>
<meta charset="utf-8">
<title>Authentication</title>
<body style="font:14px system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding:16px;">
  <div id="msg">Completing sign-in…</div>
  <pre id="err" style="color:#a00; white-space:pre-wrap;"></pre>
</body>

<script>
(function () {
  const msgEl = document.getElementById('msg') || { textContent: '' };
  const errEl = document.getElementById('err') || { textContent: '' };

  // Use the stored origin from PHP session (set during authorize.php)
  const storedOrigin = <?php echo json_encode($stored_origin); ?>;
  
  // ALLOWED_ORIGINS is rendered by PHP
  const allowed = <?php echo json_encode(ALLOWED_ORIGINS); ?>;
  const openerOrigin = storedOrigin;

  <?php if (!empty($token_err)) { ?>
    msgEl.textContent = 'Token exchange error.';
    errEl.textContent = <?php echo json_encode($token_err); ?>;
    console.error('OAuth error:', errEl.textContent);
    return;
  <?php } ?>

  if (!window.opener) {
    msgEl.textContent = 'Authentication complete, but no opener window found.';
    errEl.textContent = 'Did you open login from /admin as a popup?';
    console.error(errEl.textContent);
    return;
  }

  if (!openerOrigin) {
    msgEl.textContent = 'Could not determine opener origin.';
    errEl.textContent = 'document.referrer was empty or invalid.';
    console.error(errEl.textContent);
    return;
  }

  if (allowed.indexOf(openerOrigin) === -1) {
    msgEl.textContent = 'Origin not allowed: ' + openerOrigin;
    errEl.textContent = 'Allowed: ' + allowed.join(', ');
    console.error(msgEl.textContent, { allowed });
    return;
  }

  try {
    // Decap expects this exact message format
    const payload = <?php echo json_encode($token_json, JSON_UNESCAPED_SLASHES); ?>;
    window.opener.postMessage(
      'authorization:github:success:' + JSON.stringify(payload),
      openerOrigin
    );
    msgEl.textContent = 'Signed in. You can close this window.';
    window.close();
  } catch (e) {
    msgEl.textContent = 'postMessage failed.';
    errEl.textContent = (e && e.message) ? e.message : String(e);
    console.error('postMessage error:', e);
  }
})();
</script>
