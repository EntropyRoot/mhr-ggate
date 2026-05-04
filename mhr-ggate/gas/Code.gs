/**
 * mhr-ggate | Google Apps Script Relay
 *
 * Sits between the client-side relay (client_relay.py) and your VPS
 * server.py. Every request body that reaches GAS is already ASCII
 * base64 text, and every response it forwards back is ASCII base64
 * text — that's the only encoding GAS does not corrupt across
 * doPost/doGet round trips.
 *
 * Deploy:
 *   1. paste this file at script.google.com -> New project
 *   2. fill in VPS_URL and SECRET below
 *   3. Deploy -> New deployment -> Web app
 *        Execute as:        Me
 *        Who has access:    Anyone
 *   4. copy the /exec URL into your client_relay config
 */

// ─── CONFIG ───────────────────────────────────────────────
var VPS_URL = "https://YOUR_VPS_DOMAIN_OR_IP";  // example: https://vpn.example.com
var SECRET  = "CHANGE_THIS_SECRET_KEY";          // must match server.py
var VERSION = "2.0";
// ──────────────────────────────────────────────────────────

// internal: trim trailing slash so VPS_URL + path never doubles up
function _vpsBase() {
  return String(VPS_URL).replace(/\/+$/, "");
}

function _resolvePath(e) {
  // path comes from the client_relay as ?path=/mhr/<session>/<seq>
  var p = (e && e.parameter && e.parameter.path) ? String(e.parameter.path) : "/";
  if (p.charAt(0) !== "/") p = "/" + p;
  return p;
}

function _hopHeaders(extra) {
  var h = {
    "X-MHR-Secret": SECRET,
    "X-MHR-Relay" : "gas/" + VERSION,
  };
  if (extra) {
    for (var k in extra) h[k] = extra[k];
  }
  return h;
}

function _errorResponse(err, code) {
  // 200 with JSON envelope so the client_relay can surface the message.
  return ContentService
    .createTextOutput(JSON.stringify({
      error  : String(err && err.message ? err.message : err),
      code   : code || 500,
      version: VERSION
    }))
    .setMimeType(ContentService.MimeType.JSON);
}

function _fetch(target, options) {
  // UrlFetchApp throws on TLS / DNS errors; muteHttpExceptions catches HTTP 4xx/5xx
  options.muteHttpExceptions = true;
  options.followRedirects    = true;
  options.validateHttpsCertificates = true;
  return UrlFetchApp.fetch(target, options);
}

function doPost(e) {
  try {
    if (!e || !e.postData) {
      return _errorResponse("missing postData", 400);
    }

    // body arrived already base64-encoded by client_relay.
    // we forward it as a plain string so GAS doesn't try to interpret it.
    var body   = e.postData.contents || "";
    var path   = _resolvePath(e);
    var target = _vpsBase() + path;

    var response = _fetch(target, {
      method      : "post",
      contentType : "text/plain; charset=ascii",
      payload     : body,
      headers     : _hopHeaders(),
    });

    // server.py also returns base64 ASCII; pass it through as text.
    var text = response.getContentText("UTF-8");
    var out  = ContentService.createTextOutput(text)
                             .setMimeType(ContentService.MimeType.TEXT);
    return out;

  } catch (err) {
    return _errorResponse(err, 502);
  }
}

function doGet(e) {
  try {
    // health probe shortcut: no path => return version banner
    var p = (e && e.parameter && e.parameter.path) ? e.parameter.path : "";
    if (!p || p === "/" || p === "/health" || e.parameter.health === "1") {
      return ContentService
        .createTextOutput(JSON.stringify({ ok: true, relay: "gas", version: VERSION }))
        .setMimeType(ContentService.MimeType.JSON);
    }

    var path   = _resolvePath(e);
    var target = _vpsBase() + path;
    var response = _fetch(target, {
      method  : "get",
      headers : _hopHeaders(),
    });
    var text = response.getContentText("UTF-8");
    return ContentService.createTextOutput(text)
                         .setMimeType(ContentService.MimeType.TEXT);
  } catch (err) {
    return _errorResponse(err, 502);
  }
}

// optional sanity check you can run inside the GAS editor
function _selfTest() {
  var probe = doGet({ parameter: { health: "1" } });
  Logger.log(probe.getContent());
}
