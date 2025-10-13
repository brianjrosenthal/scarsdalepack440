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
<html>
<head>
  <meta charset="utf-8">
  <title>Authentication</title>
  <style>
    body {
      font-family: system-ui, -apple-system, sans-serif;
      padding: 20px;
      max-width: 600px;
      margin: 0 auto;
    }
    h1 { color: #333; font-size: 20px; }
    .success { color: #22543d; background: #c6f6d5; padding: 15px; border-radius: 4px; margin: 10px 0; }
    .error { color: #a00; background: #fee; padding: 15px; border-radius: 4px; margin: 10px 0; }
    .debug { background: #f5f5f5; padding: 15px; border-radius: 4px; margin: 10px 0; }
    pre { white-space: pre-wrap; word-wrap: break-word; }
    button { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; margin: 10px 5px 0 0; }
    button:hover { background: #5568d3; }
  </style>
</head>
<body>
  <h1>🔐 OAuth Authentication Debug</h1>
  <div id="msg">Completing sign-in…</div>
  <div id="debug" class="debug"></div>
  <pre id="err"></pre>
  <button id="close-btn" style="display:none" onclick="window.close()">Close Window</button>
  <button id="retry-btn" style="display:none" onclick="retryPostMessage()">Retry Send Token</button>
</body>

<script>
(function () {
  const msgEl = document.getElementById('msg');
  const errEl = document.getElementById('err');
  const debugEl = document.getElementById('debug');
  const closeBtn = document.getElementById('close-btn');
  const retryBtn = document.getElementById('retry-btn');
  
  let debugInfo = [];
  
  function addDebug(msg) {
    debugInfo.push(msg);
    debugEl.innerHTML = '<strong>Debug Info:</strong><br>' + debugInfo.join('<br>');
    console.log('DEBUG:', msg);
  }
  
  // Use the stored origin from PHP session (set during authorize.php)
  const storedOrigin = <?php echo json_encode($stored_origin); ?>;
  const allowed = <?php echo json_encode(ALLOWED_ORIGINS); ?>;
  const tokenPayload = <?php echo json_encode($token_json, JSON_UNESCAPED_SLASHES); ?>;
  const tokenError = <?php echo json_encode($token_err); ?>;
  
  addDebug('Stored origin from session: ' + (storedOrigin || 'NULL'));
  addDebug('Allowed origins: ' + allowed.join(', '));
  addDebug('Has window.opener: ' + !!window.opener);
  addDebug('Has token payload: ' + !!tokenPayload);
  addDebug('Token error: ' + (tokenError || 'none'));

  <?php if (!empty($token_err)) { ?>
    msgEl.className = 'error';
    msgEl.textContent = '❌ Token exchange error';
    errEl.textContent = tokenError;
    addDebug('ERROR: Token exchange failed');
    return;
  <?php } ?>

  if (!window.opener) {
    msgEl.className = 'error';
    msgEl.textContent = '❌ No opener window found';
    errEl.textContent = 'The popup was not opened from the CMS admin page, or the opener was closed.';
    addDebug('ERROR: No window.opener');
    return;
  }

  if (!storedOrigin) {
    msgEl.className = 'error';
    msgEl.textContent = '❌ Could not determine opener origin';
    errEl.textContent = 'The origin was not stored in the session. This might be a session issue.';
    addDebug('ERROR: No stored origin in session');
    return;
  }

  if (allowed.indexOf(storedOrigin) === -1) {
    msgEl.className = 'error';
    msgEl.textContent = '❌ Origin not allowed: ' + storedOrigin;
    errEl.textContent = 'Allowed origins: ' + allowed.join(', ');
    addDebug('ERROR: Origin not in allowed list');
    return;
  }

  // Implement Decap CMS handshake protocol
  addDebug('Setting up handshake with Decap CMS...');
  
  const receiveMessage = function(event) {
    addDebug('Received message from opener: ' + event.data);
    
    // Decap CMS is ready when it responds to our "authorizing" message
    if (event.data === 'authorizing:github:ready' || event.origin === storedOrigin) {
      addDebug('Decap CMS is ready! Sending token...');
      
      try {
        const message = 'authorization:github:success:' + JSON.stringify(tokenPayload);
        window.opener.postMessage(message, storedOrigin);
        
        msgEl.className = 'success';
        msgEl.textContent = '✅ Authentication successful!';
        addDebug('SUCCESS: Token sent to Decap CMS');
        addDebug('You can close this window or it will auto-close');
        
        window.removeEventListener('message', receiveMessage, false);
        
        // Auto-close after 3 seconds
        setTimeout(() => {
          addDebug('Closing window...');
          window.close();
        }, 3000);
        
      } catch (e) {
        msgEl.className = 'error';
        msgEl.textContent = '❌ Failed to send token';
        errEl.textContent = (e && e.message) ? e.message : String(e);
        addDebug('ERROR: ' + e.message);
        closeBtn.style.display = 'inline-block';
      }
    }
  };
  
  // Listen for ready signal from Decap CMS
  window.addEventListener('message', receiveMessage, false);
  
  // Tell Decap CMS we're ready to authenticate
  addDebug('Sending "authorizing:github" signal...');
  window.opener.postMessage('authorizing:github', '*');
})();
</script>
</html>
