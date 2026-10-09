// SmartDelegate for a Flowise Custom Tool: fetch a record, then let the
// SmartDelegate daemon decide and mask it before the model sees it.
//
// This file is the *function body* of a Flowise Custom Tool (Tools -> Create
// -> paste into "JavaScript Function"). It is not a module: it ends with a
// top-level `return`, which is how Flowise expects a tool body to hand back
// its string result.
//
// Tool input schema:  customer_id (string, required)
// Flowise variables read through $vars:
//   SMARTDELEGATE_URL      e.g. http://127.0.0.1:8181   (smartdelegate serve)
//   SMARTDELEGATE_PEP_KEY  the daemon's pep key
//   SMARTDELEGATE_TOKEN    the capability token of the task in hand
//   CRM_URL, CRM_API_KEY   the upstream this example reads from
//
// The daemon route used is POST /v1/filter with `Authorization: Bearer <pep key>`
// and the body {token, action, resource: {path, id}, data}. The answer is
// {"ok": true, "effect": "allow" | "deny", "reason", "rule", "detail", "data", ...}
// or {"ok": false, "error": {"code", "message", "rule"}}.
//
// Limits: the record is fetched before the decision, so use this shape for
// reads only. The tool body holds the upstream key, so it binds an agent that
// cooperates; the boundary an agent cannot skip is `smartdelegate http-proxy`.

const ACTION = 'read';
const RESOURCE = 'crm.customer';
const id = String($customer_id || '');
if (!id) return 'Denied by SmartDelegate (invalid_arguments, DELEGATE-INVALID-ARGUMENTS): customer_id is required.';

let record;
try {
  const upstream = await fetch($vars.CRM_URL.replace(/\/+$/, '') + '/customers/' + encodeURIComponent(id), {
    headers: { 'X-Api-Key': $vars.CRM_API_KEY },
  });
  // an upstream error body can echo record data: never pass it on
  if (!upstream.ok) return 'The upstream answered ' + upstream.status + ' (details withheld by SmartDelegate).';
  record = await upstream.json();
} catch (e) {
  return 'The upstream could not be reached (details withheld by SmartDelegate).';
}

let decision;
try {
  const res = await fetch($vars.SMARTDELEGATE_URL.replace(/\/+$/, '') + '/v1/filter', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + $vars.SMARTDELEGATE_PEP_KEY },
    body: JSON.stringify({
      token: $vars.SMARTDELEGATE_TOKEN || '',
      action: ACTION,
      resource: { path: RESOURCE, id: id },
      data: record,
    }),
  });
  decision = await res.json();
} catch (e) {
  // an unreachable decision point is never an allow
  return 'Denied by SmartDelegate (daemon_unreachable, DELEGATE-DAEMON-UNREACHABLE): the decision daemon could not be reached.';
}

if (!decision || decision.ok !== true) {
  const err = (decision && decision.error) || {};
  const code = err.code || 'error';
  return 'Denied by SmartDelegate (' + code + ', ' + (err.rule || 'DELEGATE-' + code.toUpperCase().replace(/_/g, '-')) + '): ' +
    (err.message || 'the request could not be processed') + '.';
}
if (decision.effect !== 'allow') {
  let text = 'Denied by SmartDelegate (' + decision.reason + ', ' + decision.rule + '): ' + (decision.detail || 'not permitted') + '.';
  if (decision.approval && decision.approval.id) {
    text += ' A human can approve it with id ' + decision.approval.id + '; then retry the same call.';
  }
  return text;
}
return JSON.stringify(decision.data);
