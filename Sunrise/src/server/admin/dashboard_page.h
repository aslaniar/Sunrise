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
        <thead><tr><th class="num">seq</th><th>channel</th><th>level</th><th>text</th></tr></thead>
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
var state = { cursor: 0, channel: 'all', level: 'all' };
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

function eventsUrl(cursor) {
  var url = '/events?since=' + cursor + '&limit=300';
  if (state.channel !== 'all') { url += '&channel=' + encodeURIComponent(state.channel); }
  if (state.level !== 'all') { url += '&level=' + encodeURIComponent(state.level); }
  var text = $('eventText').value.trim();
  if (text) { url += '&text=' + encodeURIComponent(text); }
  return url;
}

function nearBottom() {
  var f = $('feed');
  return f.scrollHeight - f.scrollTop - f.clientHeight < 60;
}

function appendRows(data, clear) {
  var body = $('eventsBody');
  if (clear) { body.textContent = ''; }
  var pin = nearBottom();
  var rows = data.rows || [];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    var tr = document.createElement('tr');
    var seq = document.createElement('td');
    seq.textContent = '' + row.seq;
    seq.className = 'num';
    var ch = document.createElement('td');
    ch.textContent = row.channel;
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
  while (kids.length > 500) { body.removeChild(kids[0]); }
  if (pin) { $('feed').scrollTop = $('feed').scrollHeight; }
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

function initialSync() {
  $('eventsStatus').className = 'ok';
  $('eventsStatus').textContent = 'syncing';
  fetchJson('/events?since=0&limit=0').then(function (e) {
    if (e.count > 0 && e.last >= e.first) {
      var back = Math.min(e.count, 200);
      state.cursor = Math.max(e.first, e.last - back + 1);
    } else {
      state.cursor = 0;
    }
    return fetchEvents(true);
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
setInterval(function () { fetchEvents(false); }, 1000);
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