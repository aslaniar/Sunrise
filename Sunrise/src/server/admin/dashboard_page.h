#pragma once

#include <string_view>

namespace sunrise::server::admin {

/**
 * The self-contained dashboard page served at GET /.
 *
 * Three live panels over the existing admin verbs: the session ladder polls
 * /state, the flag summary polls /flags for every scope, and the event feed
 * pages /events with server-side channel/level/text filters. The page never
 * interpolates fetched text into markup (textContent only), so event text is
 * purely data.
 *
 * LANE E INSERTION POINT: the protocol call-log section owns one more route
 * (beside /events) and one more panel here; the marked spot is inside the
 * event section, so the call log can share the filter chips' row format.
 */
inline constexpr std::string_view kDashboardPage = R"SUNRISE_DASH(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Sunrise Server Dashboard</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; background: #0d1117; color: #d0d7e5; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; }
  header { padding: 12px 18px; background: #161b22; border-bottom: 1px solid #30363d; }
  h1 { margin: 0 0 4px; font-size: 18px; }
  .muted { color: #8b949e; }
  main { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; padding: 14px 18px; max-width: 1500px; margin: 0 auto; }
  section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; }
  section h2 { margin: 0 0 8px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: #8b949e; }
  .statusline { display: flex; justify-content: space-between; gap: 8px; font-size: 12px; color: #8b949e; margin-top: 8px; }
  .ok { color: #3fb950; }
  .err { color: #f85149; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 3px 6px; border-bottom: 1px solid #21262d; white-space: nowrap; }
  th { color: #8b949e; font-weight: 600; }
  td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
  .feed { width: 100%; height: 420px; overflow: auto; background: #0d1117; border: 1px solid #21262d; border-radius: 6px; }
  .feed table { font: 12px/1.4 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
  .feed td { white-space: normal; }
  .lv-error { color: #f85149; }
  .lv-warn { color: #d29922; }
  .lv-info { color: #58a6ff; }
  .lv-debug { color: #8b949e; }
  .lv-off { color: #8b949e; }
  .chips { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; align-items: center; }
  .chip { border: 1px solid #30363d; background: #21262d; color: #d0d7e5; border-radius: 12px; padding: 2px 10px; font-size: 12px; cursor: pointer; }
  .chip.active { background: #1f6feb; border-color: #1f6feb; color: #fff; }
  #eventText { background: #0d1117; border: 1px solid #30363d; color: #d0d7e5; border-radius: 6px; padding: 4px 8px; width: 240px; font-size: 12px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 8px; }
  .card { background: #0d1117; border: 1px solid #21262d; border-radius: 6px; padding: 8px 10px; }
  .card b { display: block; font-size: 20px; font-variant-numeric: tabular-nums; }
  .card span { font-size: 11px; color: #8b949e; }
</style>
</head>
<body>
<header>
  <h1>Sunrise Server <span class="muted">/ live dashboard</span></h1>
  <div class="muted">Served by the admin listener (8099) inside the sunrise-server process. This page lives in the server, so it keeps serving when the game client is force-quit. Sources: /state, /flags, /events.</div>
</header>
<main>
  <section>
    <h2>Sessions</h2>
    <table>
      <thead><tr><th>id</th><th class="num">auth</th><th class="num">f4 active</th><th class="num">f4 ver</th><th class="num">f0 ver</th><th>root</th><th class="num">repush</th></tr></thead>
      <tbody id="sessionsBody"></tbody>
    </table>
    <div class="statusline"><span id="sessionsStatus" class="ok">idle</span><span id="sessionsMeta" class="muted"></span></div>
  </section>
  <section>
    <h2>Flags</h2>
    <div class="cards" id="flagsCards"></div>
    <div class="statusline"><span id="flagsStatus" class="ok">idle</span><span class="muted">per scope: total / zeros / twos / zero-runs</span></div>
  </section>
  <section style="grid-column: 1 / -1;">
    <h2>Event feed</h2>
    <p class="muted" style="margin: 0 0 8px 0;">
      Three views. <b>merged timeline</b> interleaves both sides on ONE clock, using the
      wire anchor: a server activity push and the client tape row that applies it are the
      same event seen from both ends, so they mark a true shared instant. Same-named
      events on the two sides are NOT the same moment - the client's core lines come from
      the DLL in the game process, the server's from a process that booted earlier.
      <b>server ring</b> is this process's in-memory log.
      <b>client log</b> is the mod DLL's own file, tailed from disk - the DLL runs inside
      the game process and keeps a ring this server cannot reach, so its lines can only
      come from the file. Channel, level and text filters apply to both.
    </p>
    <div class="chips">
      <span class="muted">source</span>
      <button class="chip active" id="src-server" onclick="setSource('server', this)">server ring</button>
      <button class="chip" id="src-client" onclick="setSource('client', this)">client log</button>
      <button class="chip" id="src-merged" onclick="setSource('merged', this)">merged timeline</button>
    </div>
    <div class="chips">
      <span class="muted">channel</span>
      <button class="chip active" id="ch-all" onclick="setChip('channel', 'all', this)">all</button>
      <button class="chip" id="ch-core" onclick="setChip('channel', 'core', this)">core</button>
      <button class="chip" id="ch-client" onclick="setChip('channel', 'client', this)">client</button>
      <button class="chip" id="ch-state" onclick="setChip('channel', 'state', this)">state</button>
      <button class="chip" id="ch-server" onclick="setChip('channel', 'server', this)">server</button>
      <button class="chip" id="ch-middleware" onclick="setChip('channel', 'middleware', this)">middleware</button>
      <span class="muted">level</span>
      <button class="chip active" id="lv-all" onclick="setChip('level', 'all', this)">all</button>
      <button class="chip" id="lv-error" onclick="setChip('level', 'error', this)">error</button>
      <button class="chip" id="lv-warn" onclick="setChip('level', 'warn', this)">warn</button>
      <button class="chip" id="lv-info" onclick="setChip('level', 'info', this)">info</button>
      <button class="chip" id="lv-debug" onclick="setChip('level', 'debug', this)">debug</button>
      <input id="eventText" placeholder="text filter" oninput="textChanged()">
      <button class="chip" onclick="initialSync()">resync</button>
    </div>
    <div class="feed" id="feed">
      <table>
        <thead><tr><th class="num" id="ordCol">seq</th><th>channel</th><th>level</th><th>text</th></tr></thead>
        <tbody id="eventsBody"></tbody>
      </table>
    </div>
    <div class="statusline"><span id="eventsStatus" class="ok">idle</span><span id="eventsMeta" class="muted"></span></div>
    <!-- LANE E INSERTION POINT: the protocol call-log panel lands here, same
         row format, fed by its own route (see the dispatch in admin_http.cpp). -->
  </section>
</main>
<script>
'use strict';
var state = { cursor: 0, channel: 'all', level: 'all', source: 'server' };
var FLAG_SCOPES = ['account', 'profile', 'character', 'character_object'];

function $(id) { return document.getElementById(id); }

function fetchJson(url) {
  return fetch(url).then(function (r) {
    if (!r.ok) { throw new Error('HTTP ' + r.status); }
    return r.json();
  });
}

function stamp() { return new Date().toLocaleTimeString(); }

function refreshSessions() {
  fetchJson('/state').then(function (data) {
    var body = $('sessionsBody');
    body.textContent = '';
    var rows = data.sessions || [];
    for (var i = 0; i < rows.length; i++) {
      var s = rows[i];
      var tr = document.createElement('tr');
      var cells = [
        ['' + s.id, 'num'], [s.authenticated ? 'yes' : 'no', ''],
        [s.family4_active ? 'yes' : 'no', ''], ['' + s.family4_version, 'num'],
        ['' + s.family0_version, 'num'], [s.root, 'num'],
        [s.repush_armed ? 'yes' : 'no', '']
      ];
      for (var c = 0; c < cells.length; c++) {
        var td = document.createElement('td');
        td.textContent = cells[c][0];
        if (cells[c][1]) { td.className = cells[c][1]; }
        tr.appendChild(td);
      }
      body.appendChild(tr);
    }
    $('sessionsStatus').className = 'ok';
    $('sessionsStatus').textContent = 'ok';
    $('sessionsMeta').textContent = 'count=' + data.count + ' | ' + stamp();
  }).catch(function (err) {
    $('sessionsStatus').className = 'err';
    $('sessionsStatus').textContent = 'ERR ' + err.message;
  });
}

function refreshFlags() {
  var pending = FLAG_SCOPES.length;
  var failed = false;
  for (var i = 0; i < FLAG_SCOPES.length; i++) {
    (function (scope) {
      fetchJson('/flags?scope=' + scope).then(function (data) {
        var el = $('flag-' + scope);
        if (el) {
          el.querySelector('.val').textContent = '' + data.total;
          el.querySelector('.sub').textContent =
            'zeros ' + data.zeros + ' | twos ' + data.twos + ' | runs ' + data.run_count;
        }
      }).catch(function () {
        failed = true;
      }).then(function () {
        pending -= 1;
        if (pending === 0) {
          $('flagsStatus').className = failed ? 'err' : 'ok';
          $('flagsStatus').textContent = (failed ? 'ERR' : 'ok') + ' | ' + stamp();
        }
      });
    })(FLAG_SCOPES[i]);
  }
}

function filterSuffix() {
  var url = '';
  if (state.channel !== 'all') { url += '&channel=' + encodeURIComponent(state.channel); }
  if (state.level !== 'all') { url += '&level=' + encodeURIComponent(state.level); }
  var text = $('eventText').value.trim();
  if (text) { url += '&text=' + encodeURIComponent(text); }
  return url;
}

function eventsUrl(cursor) {
  return '/events?since=' + cursor + '&limit=300' + filterSuffix();
}

// The client log is a FILE tail, not a ring with a cursor: every poll re-reads the
// newest window and replaces the table wholesale.
function clientLogUrl() {
  return '/clientlog?limit=2000' + filterSuffix();
}

function fetchClientLog() {
  return fetchJson(clientLogUrl()).then(function (data) {
    appendRows(data, true);
    $('eventsStatus').className = data.ok === false ? 'err' : 'ok';
    $('eventsStatus').textContent = data.ok === false ? 'ERR' : 'ok';
    $('eventsMeta').textContent = data.ok === false
      ? (data.reason || 'client log unavailable')
      : ('client log - ' + data.emitted + ' of ' + data.matched + ' matched, scanned ' +
         data.scanned + ' lines of ' + data.bytes + ' B' +
         (data.truncated ? ' (page truncated)' : '')) + ' | ' + stamp();
    return data;
  }).catch(function (err) {
    $('eventsStatus').className = 'err';
    $('eventsStatus').textContent = 'ERR ' + err.message;
  });
}

// --- the wire anchor -------------------------------------------------------
// A server "ev=activity stage=push ... type=N" and the client "tape=1 svc=9 ...
// type=N" that applies it are one wire event seen from both ends. Pair them
// newest-first (the two windows rarely start together), require every pair to
// agree on type, and take the median delta. Reported spread is p10..p90: a few
// early pairs sit far off the cluster and the full range overstates the error.
function parseT(text) {
  var m = /(^|[^A-Za-z0-9_])t=(\d+)/.exec(text);
  return m ? parseInt(m[2], 10) : null;
}
function parseType(text) {
  var m = /(^|[^A-Za-z0-9_])type=(\d+)/.exec(text);
  return m ? parseInt(m[2], 10) : null;
}

function solveOffset(serverRows, clientRows) {
  var srv = [], cli = [];
  serverRows.forEach(function (r) {
    if (r.text.indexOf('ev=activity') >= 0 && r.text.indexOf('stage=push') >= 0) {
      var t = parseT(r.text), ty = parseType(r.text);
      if (t !== null && ty !== null) { srv.push({ t: t, ty: ty }); }
    }
  });
  clientRows.forEach(function (r) {
    if (r.text.indexOf('tape=1') >= 0 && r.text.indexOf('svc=9') >= 0) {
      var ty = parseType(r.text);
      if (r.t >= 0 && ty !== null) { cli.push({ t: r.t, ty: ty }); }
    }
  });
  if (!srv.length || !cli.length) { return null; }
  var span = Math.min(srv.length, cli.length), best = null;
  for (var k = 0; k < Math.min(16, span); k++) {
    var deltas = [], ok = true;
    for (var i = 0; i < span - k; i++) {
      var a = srv[srv.length - 1 - i], b = cli[cli.length - 1 - i - k];
      if (!b || a.ty !== b.ty) { ok = false; break; }
      deltas.push(a.t - b.t);
    }
    if (!ok || deltas.length < 3) { continue; }
    deltas.sort(function (x, y) { return x - y; });
    var robust = deltas[Math.floor(deltas.length * 0.9)] - deltas[Math.floor(deltas.length * 0.1)];
    var cand = { robust: robust, k: k, pairs: deltas.length,
                 median: deltas[Math.floor(deltas.length / 2)],
                 spread: deltas[deltas.length - 1] - deltas[0] };
    if (!best || cand.robust < best.robust) { best = cand; }
  }
  return best;
}

function fetchMerged() {
  return Promise.all([
    fetchJson('/events?since=0&limit=2000' + filterSuffix()),
    fetchJson(clientLogUrl())
  ]).then(function (both) {
    var srvRows = both[0].rows || [], cliRows = both[1].rows || [];
    var fit = solveOffset(both[0].rows || [], both[1].rows || []);
    var srv = [], cli = [];
    srvRows.forEach(function (r) {
      var t = parseT(r.text);
      srv.push({ t: t === null ? 0 : t, side: 'S', channel: r.channel,
                 level: r.level, text: r.text });
    });
    cliRows.forEach(function (r) {
      cli.push({ t: r.t >= 0 ? r.t : 0, side: 'C', channel: r.channel,
                 level: r.level, text: r.text });
    });
    srv.sort(function (a, b) { return a.t - b.t; });
    cli.sort(function (a, b) { return a.t - b.t; });

    var merged;
    if (fit) {
      // Anchored: one clock, genuinely interleavable.
      cli.forEach(function (r) { r.t = r.t + fit.median; });
      merged = srv.concat(cli);
      merged.sort(function (a, b) { return a.t - b.t; });
    } else {
      // No shared instant in view. Both sides are still shown - hiding the client
      // rows was worse than showing them - but they are NOT interleaved, because
      // the two clocks are independent and sorting across them would invent an
      // order that does not exist. Server block, separator, client block.
      merged = srv.concat([{ separator: true }]).concat(cli);
    }
    appendRows({ rows: merged }, true);
    $('eventsStatus').className = fit ? 'ok' : 'lv-warn';
    $('eventsStatus').textContent = fit ? 'ok' : 'unanchored';
    $('eventsMeta').textContent = fit
      ? ('merged on wire anchor: offset ' + fit.median + 'ms, ' + fit.pairs +
         ' pairs, spread ' + fit.robust + 'ms (p10-p90) | ' + stamp())
      : ('NOT ALIGNED - no wire anchor in view. Both sides are shown on their OWN ' +
         'clocks and cross-side order is meaningless. The anchor needs a server ' +
         'activity push paired with a client tape=1 svc=9 row, which only appears ' +
         'once a session reaches the activity phase. | ' + stamp());
    return merged;
  }).catch(function (err) {
    $('eventsStatus').className = 'err';
    $('eventsStatus').textContent = 'ERR ' + err.message;
  });
}

function setSource(value, el) {
  state.source = value;
  // The two sources do not share an ordinate: server rows carry the ring's monotonic
  // sequence, client rows carry the client process's own t=. Name the column honestly.
  $('ordCol').textContent = value === 'client' ? 't (client)'
                          : value === 'merged' ? 't (unified)' : 'seq';
  var chips = el.parentNode.children;
  for (var i = 0; i < chips.length; i++) {
    if (chips[i].className.indexOf('chip') === 0) { chips[i].classList.remove('active'); }
  }
  el.classList.add('active');
  initialSync();
}

function nearBottom() {
  var f = $('feed');
  return f.scrollHeight - f.scrollTop - f.clientHeight < 60;
}

function appendRows(data, clear) {
  var body = $('eventsBody');
  // Measure BEFORE clearing. Clearing collapses scrollHeight to clientHeight, which
  // makes nearBottom() trivially true, which pinned the view to the bottom on every
  // poll - unusable on the client-log source, where every poll replaces the table.
  var feed = $('feed');
  var pin = nearBottom();
  var keepTop = feed.scrollTop;
  if (clear) { body.textContent = ''; }
  var rows = data.rows || [];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (row.separator) {
      var sep = document.createElement('tr');
      var cell = document.createElement('td');
      cell.colSpan = 4;
      cell.textContent =
        '\u2500\u2500 above: server ring (server clock) \u2502 below: client log '
        + '(client clock) \u2500\u2500 not aligned \u2500\u2500';
      cell.className = 'lv-warn';
      cell.style.textAlign = 'center';
      sep.appendChild(cell);
      body.appendChild(sep);
      continue;
    }
    var tr = document.createElement('tr');
    var seq = document.createElement('td');
    // /events rows carry a ring sequence; /clientlog rows carry the client's own
    // t= instead. They are different spaces and must not be read as comparable.
    seq.textContent = row.seq !== undefined ? ('' + row.seq)
                    : (row.t >= 0 ? row.t + 'ms' : '-');
    if (row.side === 'C') { seq.style.opacity = '0.75'; }
    seq.className = 'num';
    var ch = document.createElement('td');
    ch.textContent = row.side ? (row.side + '\u00B7' + row.channel) : row.channel;
    var lv = document.createElement('td');
    lv.textContent = row.level;
    lv.className = 'lv-' + row.level;
    var tx = document.createElement('td');
    tx.textContent = row.text;
    tr.appendChild(seq);
    tr.appendChild(ch);
    tr.appendChild(lv);
    tr.appendChild(tx);
    body.appendChild(tr);
  }
  var kids = body.children;
  // The server ring holds 4096 entries; a 500-row cap silently threw away most
  // of a boot even after the cursor was fixed.
  while (kids.length > 5000) { body.removeChild(kids[0]); }
  if (pin) {
    feed.scrollTop = feed.scrollHeight;
  } else if (clear) {
    // A full replace would otherwise dump the reader back to the top.
    feed.scrollTop = Math.min(keepTop, feed.scrollHeight);
  }
}

function fetchEvents(first) {
  return fetchJson(eventsUrl(state.cursor)).then(function (data) {
    appendRows(data, first);
    var noFilter = state.channel === 'all' && state.level === 'all' &&
      !$('eventText').value.trim();
    if (noFilter && data.first > data.since + 1) {
      // The ring overwrote events between our cursor and its oldest retained
      // row; rebuild the table from the newest window instead.
      var back = Math.min(data.count, 200);
      state.cursor = Math.max(data.first, data.last - back + 1);
      appendRows(data, true);
      $('eventsMeta').textContent = 'ring gap - resynced to seq ' + state.cursor + ' | ' + stamp();
    } else {
      if (data.truncated) {
        state.cursor = data.next;
      } else {
        state.cursor = data.last > data.since ? data.last : data.since;
      }
      $('eventsMeta').textContent =
        'cursor ' + state.cursor + ' (retained ' + data.count + ', first ' + data.first +
        (data.truncated ? ', paging)' : ')') + ' | ' + stamp();
    }
    $('eventsStatus').className = 'ok';
    $('eventsStatus').textContent = 'ok';
    return data;
  }).catch(function (err) {
    $('eventsStatus').className = 'err';
    $('eventsStatus').textContent = 'ERR ' + err.message;
    $('eventsMeta').textContent = 'will retry';
  });
}

// Pages forward until the feed has caught up with the ring's newest row. One
// response is capped by the server's byte budget, so the whole ring takes
// several round trips; the depth cap keeps a pathological ring from looping.
function pageUntilCaughtUp(first, depth) {
  return fetchEvents(first).then(function (data) {
    if (data && data.truncated && depth < 64) {
      return pageUntilCaughtUp(false, depth + 1);
    }
    return data;
  });
}

function initialSync() {
  $('eventsStatus').className = 'ok';
  $('eventsStatus').textContent = 'syncing';
  if (state.source === 'client') {
    $('eventsBody').textContent = '';
    return fetchClientLog();
  }
  if (state.source === 'merged') {
    $('eventsBody').textContent = '';
    return fetchMerged();
  }
  fetchJson('/events?since=0&limit=0').then(function (e) {
    // Start from the OLDEST retained row, not a fixed window back from the
    // newest. The boot's own core/state lines sit in the first ~30 events, so a
    // short window hid them completely and the feed looked server-only. The
    // cursor is EXCLUSIVE, so step one below the oldest retained sequence.
    state.cursor = (e.count > 0 && e.last >= e.first) ? Math.max(0, e.first - 1) : 0;
    return pageUntilCaughtUp(true, 0);
  }).catch(function (err) {
    $('eventsStatus').className = 'err';
    $('eventsStatus').textContent = 'ERR ' + err.message;
  });
}

function setChip(group, value, el) {
  if (group === 'channel') { state.channel = value; } else { state.level = value; }
  var chips = el.parentNode.children;
  for (var i = 0; i < chips.length; i++) {
    if (chips[i].className.indexOf('chip') === 0) { chips[i].classList.remove('active'); }
  }
  el.classList.add('active');
  initialSync();
}

function textChanged() {
  clearTimeout(state.textTimer);
  state.textTimer = setTimeout(initialSync, 400);
}

function buildFlagCards() {
  var holder = $('flagsCards');
  for (var i = 0; i < FLAG_SCOPES.length; i++) {
    var scope = FLAG_SCOPES[i];
    var card = document.createElement('div');
    card.className = 'card';
    card.id = 'flag-' + scope;
    var val = document.createElement('b');
    val.className = 'val';
    val.textContent = '-';
    var sub = document.createElement('span');
    sub.className = 'sub';
    sub.textContent = scope;
    card.appendChild(val);
    card.appendChild(sub);
    holder.appendChild(card);
  }
}

buildFlagCards();
initialSync();
setInterval(function () {
  if (state.source === 'client') { fetchClientLog(); }
  else if (state.source === 'merged') { fetchMerged(); }
  else { fetchEvents(false); }
}, 1000);
setInterval(refreshSessions, 2000);
setInterval(refreshFlags, 5000);
refreshSessions();
refreshFlags();
</script>
</body>
</html>
)SUNRISE_DASH";

/** @return The complete self-contained dashboard page. */
[[nodiscard]] inline std::string_view dashboard_page() noexcept {
    return kDashboardPage;
}

} // namespace sunrise::server::admin