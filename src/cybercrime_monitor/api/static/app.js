'use strict';

// ── State ──────────────────────────────────────────────────────────────────
const state = {
  items: [],           // all loaded items (newest first)
  offset: 0,
  pageSize: 100,
  hasMore: false,
  pendingLive: [],     // items arrived via SSE while not at top
  sources: [],
  filters: {
    search: '',
    priority: '',
    matchedOnly: false,
    showFiltered: false,
    sources: new Set(),
    since: '',
    until: '',
    crimeType: '',
    actor: '',
    victim: '',
    classified: '',
    minConfidence: 0,
    cveId: '',
    ioc: '',
    tag: '',
    extraKey: '',
    clusterSize: '',
  },
  classifierEnabled: false, // set after the first /api/classifier/health check
  classifierPollSince: null,
};

// ── DOM refs ───────────────────────────────────────────────────────────────
const feedList       = document.getElementById('feed-list');
const feedEmpty      = document.getElementById('feed-empty');
const loadMoreBtn    = document.getElementById('load-more');
const newBanner      = document.getElementById('new-items-banner');
const totalCount     = document.getElementById('total-count');
const sseStatus      = document.getElementById('sse-status');
const sourceFilters  = document.getElementById('source-filters');
const sourceLegend   = document.getElementById('source-legend');
const searchInput    = document.getElementById('search-input');
const matchedOnlyCb  = document.getElementById('matched-only');
const showFilteredCb = document.getElementById('show-filtered');
const sinceInput     = document.getElementById('since-input');
const untilInput     = document.getElementById('until-input');
const crimeTypeInput = document.getElementById('crime-type-input');
const actorInput     = document.getElementById('actor-input');
const victimInput    = document.getElementById('victim-input');
const classifiedInput = document.getElementById('classified-input');
const confidenceInput = document.getElementById('confidence-input');
const confidenceValue = document.getElementById('confidence-value');
const cveInput       = document.getElementById('cve-input');
const iocInput       = document.getElementById('ioc-input');
const tagInput       = document.getElementById('tag-input');
const extraKeyInput  = document.getElementById('extra-key-input');
const clusterSizeInput = document.getElementById('cluster-size-input');
const adminTokenInput = document.getElementById('admin-token');
const adminTokenStatus = document.getElementById('admin-token-status');

// ── Init ───────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  initTabs();
  loadFiltersFromUrl();
  await loadSources();
  await initClassifierUi(); // must run before the first applyFilters so badges render correctly
  await loadCaseStats(); // populates crime-type dropdown
  syncFilterControls();
  await applyFilters();
  connectSSE();
  initKeywordsAuth();
  setInterval(loadSources, 30000); // refresh source health dots

  initDashboard();
  setInterval(loadDashboard, 30000);

  initCases();
  initStatusBar();

  searchInput.addEventListener('input', debounce(() => {
    state.filters.search = searchInput.value.trim();
    applyFilters();
  }, 400));
  matchedOnlyCb.addEventListener('change', () => {
    state.filters.matchedOnly = matchedOnlyCb.checked;
    applyFilters();
  });
  showFilteredCb.addEventListener('change', () => {
    state.filters.showFiltered = showFilteredCb.checked;
    applyFilters();
  });
  document.querySelectorAll('input[name="priority"]').forEach(r =>
    r.addEventListener('change', () => {
      state.filters.priority = document.querySelector('input[name="priority"]:checked')?.value || '';
      applyFilters();
    }));
  loadMoreBtn.addEventListener('click', loadMore);

  sinceInput.addEventListener('change', () => { state.filters.since = sinceInput.value; applyFilters(); });
  untilInput.addEventListener('change', () => { state.filters.until = untilInput.value; applyFilters(); });
  crimeTypeInput.addEventListener('change', () => { state.filters.crimeType = crimeTypeInput.value; applyFilters(); });
  actorInput.addEventListener('input', debounce(() => { state.filters.actor = actorInput.value.trim(); applyFilters(); }, 400));
  victimInput.addEventListener('input', debounce(() => { state.filters.victim = victimInput.value.trim(); applyFilters(); }, 400));
  classifiedInput.addEventListener('change', () => { state.filters.classified = classifiedInput.value; applyFilters(); });
  confidenceInput.addEventListener('input', () => {
    state.filters.minConfidence = parseFloat(confidenceInput.value) || 0;
    confidenceValue.textContent = confidenceInput.value > 0 ? `≥ ${confidenceInput.value}` : '';
    applyFilters();
  });
  cveInput.addEventListener('input', debounce(() => { state.filters.cveId = cveInput.value.trim(); applyFilters(); }, 400));
  iocInput.addEventListener('input', debounce(() => { state.filters.ioc = iocInput.value.trim(); applyFilters(); }, 400));
  tagInput.addEventListener('input', debounce(() => { state.filters.tag = tagInput.value.trim(); applyFilters(); }, 400));
  extraKeyInput.addEventListener('input', debounce(() => { state.filters.extraKey = extraKeyInput.value.trim(); applyFilters(); }, 400));
  clusterSizeInput.addEventListener('input', debounce(() => { state.filters.clusterSize = clusterSizeInput.value; applyFilters(); }, 400));
});

// ── Tabs ───────────────────────────────────────────────────────────────────
function initTabs() {
  document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => {
        c.classList.remove('active');
        c.classList.add('hidden');
      });
      btn.classList.add('active');
      const target = document.getElementById('tab-' + btn.dataset.tab);
      target.classList.remove('hidden');
      target.classList.add('active');
    });
  });
}

// ── Sources ────────────────────────────────────────────────────────────────
async function loadSources() {
  try {
    const data = await api('/api/sources');
    const isFirstLoad = state.sources.length === 0;
    state.sources = data;
    // Only default new/unseen sources to "checked" — periodic health
    // refreshes (see setInterval) must not silently re-enable a source the
    // user deliberately unchecked. If the URL already selected specific
    // sources, preserve that instead of checking everything.
    if (isFirstLoad && state.filters.sources.size === 0) {
      data.forEach(s => state.filters.sources.add(s.id));
      renderSourceLegend(); // static — render once, not on every health refresh
    }
    renderSourceFilters(data);
  } catch (e) {
    console.error('Failed to load sources', e);
  }
}

// Always-visible key for the health dots — without this, the only way to
// learn what a color means is hovering each dot individually, and several
// statuses (especially "unknown" vs "disabled") render as near-identical
// grey at 7px and are otherwise impossible to tell apart.
const STATUS_LABELS = [
  ['ok', 'active'],
  ['stale', 'stale'],
  ['degraded', 'degraded'],
  ['dead', 'dead'],
  ['unknown', 'pending first run'],
  ['disabled', 'disabled'],
];

function renderSourceLegend() {
  sourceLegend.innerHTML = '';
  STATUS_LABELS.forEach(([status, label]) => {
    const item = document.createElement('span');
    item.className = 'legend-item';
    const dot = document.createElement('span');
    dot.className = 'health-dot health-' + status;
    item.appendChild(dot);
    item.appendChild(document.createTextNode(label));
    item.title = STATUS_EXPLANATION[status];
    sourceLegend.appendChild(item);
  });
}

function renderSourceFilters(sources) {
  sourceFilters.innerHTML = '';
  sources.forEach(src => {
    const label = document.createElement('label');
    label.className = 'source-chip';
    const cb = document.createElement('input');
    cb.type = 'checkbox';
    cb.checked = state.filters.sources.has(src.id);
    cb.value = src.id;
    cb.addEventListener('change', () => {
      if (cb.checked) state.filters.sources.add(src.id);
      else state.filters.sources.delete(src.id);
      applyFilters();
    });
    label.appendChild(cb);
    label.appendChild(document.createTextNode(src.name));

    const dot = document.createElement('span');
    const status = sourceHealthStatus(src);
    dot.className = 'health-dot health-' + status;
    dot.title = healthTooltip(src, status);
    label.appendChild(dot);

    sourceFilters.appendChild(label);
  });
}

// Scraper types whose "fetched OK but parsed 0 items" almost always means a
// CSS selector drifted from the live markup, not "nothing new happened" —
// API/feed-based sources (mastodon, hibp, nitter, rss, ransomware_live) can
// legitimately go many ticks without new items, so empty-streak degradation
// only applies here.
const _SCRAPER_TYPES = new Set(['html_forum', 'tor_forum']);
// Repeated-empty threshold: a handful of genuinely-quiet ticks shouldn't
// flip the dot, but a long unbroken streak on a scraper is the signal that
// the page still returns 200 while the row/title/url selectors match nothing.
const _EMPTY_STREAK_THRESHOLD = 5;

// 'unknown' (never run yet), 'ok' (succeeded within ~3 intervals),
// 'stale' (succeeded before, but not recently — likely degraded),
// 'degraded' (scraper fetching 200s but parsing 0 rows — selector drift),
// 'dead' (3+ consecutive errors, or disabled with no success ever).
function sourceHealthStatus(src) {
  if (!src.enabled) return 'disabled';
  if (!src.last_run_at) return 'unknown';
  if (src.consecutive_errors >= 3) return 'dead';
  if (!src.last_success_at) return 'stale';
  if (_SCRAPER_TYPES.has(src.type) && src.consecutive_empty >= _EMPTY_STREAK_THRESHOLD) return 'degraded';
  const staleAfterMs = Math.max(src.interval_seconds, 60) * 3 * 1000;
  const age = Date.now() - new Date(src.last_success_at).getTime();
  return age > staleAfterMs ? 'stale' : 'ok';
}

// Plain-English headline per status — shown as the FIRST tooltip line so
// hovering a dot answers "what does this mean" without requiring the reader
// to already know the color/status vocabulary (see STATUS_LEGEND for the
// always-visible version of the same explanations).
const STATUS_EXPLANATION = {
  ok:       'Active — fetched successfully on schedule',
  stale:    'Stale — hasn\'t succeeded recently (check last success time below)',
  degraded: 'Degraded — fetching OK but parsing 0 items repeatedly (selectors may be broken)',
  dead:     '3+ fetch errors in a row',
  unknown:  'No run yet since the last restart — not an error, just hasn\'t ticked',
  disabled: 'Disabled in sources.yaml',
};

function healthTooltip(src, status) {
  const parts = [STATUS_EXPLANATION[status] || status];
  if (status === 'unknown' && src.next_run_at) parts.push(`first run scheduled: ${fmtTime(src.next_run_at)}`);
  if (src.last_success_at) parts.push(`last success: ${fmtTime(src.last_success_at)}`);
  if (src.last_error) parts.push(`last error: ${src.last_error}`);
  if (src.consecutive_errors) parts.push(`consecutive errors: ${src.consecutive_errors}`);
  if (status === 'degraded') parts.push(`${src.consecutive_empty} ticks in a row parsed 0 items`);
  return parts.join('\n');
}

// ── Classifier ─────────────────────────────────────────────────────────────
// Checks once at load whether the LLM classifier is enabled server-side
// (classifier_backend != "none") and reveals the UI for it only if so —
// otherwise every card would show a permanent "pending" dot for a feature
// nobody turned on.
async function initClassifierUi() {
  try {
    const h = await api('/api/classifier/health');
    state.classifierEnabled = h.backend !== 'none';
    if (state.classifierEnabled) {
      document.getElementById('show-filtered-row').classList.remove('hidden');
      document.getElementById('gauge-classifier-card').classList.remove('hidden');
      state.classifierPollSince = new Date().toISOString();
      setInterval(pollClassifierUpdates, 12000);
    }
  } catch (e) {
    console.error('Failed to check classifier status', e);
  }
}

function buildClassifierDot(item) {
  const dot = document.createElement('span');
  if (item.is_false_positive) {
    dot.className = 'health-dot cls-filtered';
    dot.title = 'Flagged as false positive' + (item.classifier_reasoning ? `: ${item.classifier_reasoning}` : '');
  } else if (item.classified) {
    dot.className = 'health-dot cls-reviewed';
    let tip = 'Reviewed by classifier';
    if (item.classifier_confidence != null) tip += ` (confidence ${Math.round(item.classifier_confidence * 100)}%)`;
    if (item.classifier_reasoning) tip += `: ${item.classifier_reasoning}`;
    dot.title = tip;
  } else {
    dot.className = 'health-dot cls-pending';
    dot.title = 'Pending classification';
  }
  return dot;
}

// Poll for verdicts that landed since the last check and patch already-
// rendered cards in place — avoids a full feed re-render (which would lose
// scroll position) just to reflect a classifier update.
async function pollClassifierUpdates() {
  try {
    const data = await api('/api/classifier/recent?since=' + encodeURIComponent(state.classifierPollSince));
    const updates = data.updates || [];
    if (!updates.length) return;
    state.classifierPollSince = updates[updates.length - 1].classified_at;
    updates.forEach(patchCardWithVerdict);
  } catch (e) {
    console.error('Failed to poll classifier updates', e);
  }
}

function patchCardWithVerdict(verdict) {
  const stateItem = state.items.find(i => i.id === verdict.id);
  if (stateItem) {
    stateItem.max_priority = verdict.max_priority;
    stateItem.is_false_positive = verdict.is_false_positive;
    stateItem.classified = true;
    stateItem.classifier_confidence = verdict.classifier_confidence;
    stateItem.classifier_reasoning = verdict.classifier_reasoning;
  }

  const card = feedList.querySelector(`[data-item-id="${verdict.id}"]`);
  if (!card) return; // not currently rendered — it'll reflect the verdict whenever it next is

  if (verdict.is_false_positive && !state.filters.showFiltered) {
    card.classList.add('fadeOut');
    setTimeout(() => card.remove(), 250);
    return;
  }

  if (stateItem) {
    const newCard = buildCard(stateItem);
    newCard.classList.add('flashUpdate');
    card.replaceWith(newCard);
  }
}

// ── Items ──────────────────────────────────────────────────────────────────
async function applyFilters() {
  state.offset = 0;
  state.pendingLive = [];
  newBanner.classList.add('hidden');
  pushFiltersToUrl();

  const params = buildParams(0, state.pageSize);
  let data;
  try {
    data = await api('/api/items?' + params, itemsFetchOpts());
  } catch (e) {
    if (state.filters.showFiltered) {
      // Admin token missing/invalid — revert the toggle instead of leaving
      // the feed blank, and retry as a normal (public) request.
      console.warn('Show filtered requires a valid admin token', e);
      state.filters.showFiltered = false;
      showFilteredCb.checked = false;
      return applyFilters();
    }
    throw e;
  }

  feedList.innerHTML = '';
  state.items = data.items || [];
  state.offset = state.items.length;
  state.hasMore = state.items.length < data.total;
  totalCount.textContent = `${data.total.toLocaleString()} items`;

  renderItems(state.items, false);
  feedEmpty.classList.toggle('hidden', state.items.length > 0);
  loadMoreBtn.classList.toggle('hidden', !state.hasMore);
}

async function loadMore() {
  const params = buildParams(state.offset, state.pageSize);
  const data = await api('/api/items?' + params, itemsFetchOpts());
  const newItems = data.items || [];
  state.items = state.items.concat(newItems);
  state.offset += newItems.length;
  state.hasMore = state.offset < data.total;
  renderItems(newItems, true);
  loadMoreBtn.classList.toggle('hidden', !state.hasMore);
}

function itemsFetchOpts() {
  return (state.filters.showFiltered && hasAdminToken()) ? { headers: adminHeaders() } : {};
}

function buildParams(offset, limit) {
  const f = state.filters;
  const p = new URLSearchParams();
  p.set('limit', limit);
  p.set('offset', offset);
  if (f.search)       p.set('search', f.search);
  if (f.priority)     p.set('priority', f.priority);
  if (f.matchedOnly)  p.set('matched_only', 'true');
  if (f.showFiltered) p.set('show_filtered', 'true');
  if (f.since)        p.set('since', toIsoUtc(f.since));
  if (f.until)        p.set('until', toIsoUtc(f.until));
  if (f.crimeType)    p.set('crime_type', f.crimeType);
  if (f.actor)        p.set('actor', f.actor);
  if (f.victim)       p.set('victim', f.victim);
  if (f.classified)   p.set('classified', f.classified);
  if (f.minConfidence > 0) p.set('min_confidence', String(f.minConfidence));
  if (f.cveId)        p.set('cve_id', f.cveId);
  if (f.ioc)          p.set('ioc', f.ioc);
  if (f.tag)          p.set('tag', f.tag);
  if (f.extraKey)     p.set('extra_key', f.extraKey);
  if (f.clusterSize)  p.set('cluster_size', f.clusterSize);
  // Only send source_id when it actually narrows the result (a subset of
  // known sources is checked) — when everything is checked this is
  // equivalent to no filter, and omitting it keeps the URL short and
  // matches the "no filter" total exactly.
  if (state.sources.length > 0 && f.sources.size < state.sources.length) {
    f.sources.forEach(id => p.append('source_id', id));
  }
  return p.toString();
}

// datetime-local values are local-time strings without timezone. Convert to
// ISO-8601 UTC so the server sees an unambiguous instant.
function toIsoUtc(localValue) {
  if (!localValue) return '';
  const d = new Date(localValue);
  return isNaN(d.getTime()) ? '' : d.toISOString();
}

function loadFiltersFromUrl() {
  const p = new URLSearchParams(location.search);
  const f = state.filters;
  f.search = p.get('search') || '';
  f.priority = p.get('priority') || '';
  f.matchedOnly = p.get('matched_only') === 'true';
  f.showFiltered = p.get('show_filtered') === 'true';
  f.since = p.get('since') || '';
  f.until = p.get('until') || '';
  f.crimeType = p.get('crime_type') || '';
  f.actor = p.get('actor') || '';
  f.victim = p.get('victim') || '';
  f.classified = p.get('classified') || '';
  f.minConfidence = parseFloat(p.get('min_confidence') || '0') || 0;
  f.cveId = p.get('cve_id') || '';
  f.ioc = p.get('ioc') || '';
  f.tag = p.get('tag') || '';
  f.extraKey = p.get('extra_key') || '';
  f.clusterSize = p.get('cluster_size') || '';
  const sourceIds = p.getAll('source_id');
  if (sourceIds.length) {
    f.sources = new Set(sourceIds);
  }
}

function syncFilterControls() {
  const f = state.filters;
  searchInput.value = f.search;
  document.querySelectorAll('input[name="priority"]').forEach(r => {
    r.checked = r.value === f.priority;
  });
  matchedOnlyCb.checked = f.matchedOnly;
  showFilteredCb.checked = f.showFiltered;
  sinceInput.value = f.since ? formatDatetimeLocal(f.since) : '';
  untilInput.value = f.until ? formatDatetimeLocal(f.until) : '';
  crimeTypeInput.value = f.crimeType;
  actorInput.value = f.actor;
  victimInput.value = f.victim;
  classifiedInput.value = f.classified;
  confidenceInput.value = f.minConfidence || 0;
  confidenceValue.textContent = f.minConfidence > 0 ? `≥ ${f.minConfidence}` : '';
  cveInput.value = f.cveId;
  iocInput.value = f.ioc;
  tagInput.value = f.tag;
  extraKeyInput.value = f.extraKey;
  clusterSizeInput.value = f.clusterSize;
}

function formatDatetimeLocal(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  // YYYY-MM-DDTHH:mm in local time
  const pad = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function pushFiltersToUrl() {
  const p = new URLSearchParams(buildParams(0, state.pageSize));
  p.delete('limit');
  p.delete('offset');
  const qs = p.toString();
  const url = qs ? `?${qs}` : location.pathname;
  history.replaceState(null, '', url);
}

function renderItems(items, append) {
  if (!append) feedList.innerHTML = '';
  items.forEach(item => feedList.appendChild(buildCard(item)));
}

// Source filtering for live (SSE) items only — those never go through the
// /api/items query, so they need the client-side check. Loaded/paginated
// items are now filtered server-side (see buildParams' source_id) so
// "load more"/offset math stays correct regardless of which sources are
// checked (the old client-only filter silently shrank rendered pages
// without adjusting offset, permanently skipping rows on "load more").
function passesClientFilter(item) {
  if (state.sources.length > 0 && !state.filters.sources.has(item.source_id)) return false;
  return true;
}

function buildCard(item) {
  const card = document.createElement('div');
  // A flagged false positive only ever reaches the client via "show
  // filtered" (admin) — style it distinctly rather than by its old regex/
  // classifier priority, which is no longer the operative signal.
  const prioClass = item.is_false_positive ? 'prio-filtered' : (item.max_priority ? 'prio-' + item.max_priority : '');
  card.className = 'item-card' + (prioClass ? ' ' + prioClass : '');
  card.dataset.itemId = item.id;

  const meta = document.createElement('div');
  meta.className = 'item-meta';

  const srcBadge = document.createElement('span');
  srcBadge.className = 'source-badge';
  srcBadge.textContent = item.source_name;
  meta.appendChild(srcBadge);

  const time = document.createElement('span');
  time.className = 'item-time';
  // Prefer the source's own publish/event date over ingest time whenever a
  // collector captured one (RSS, Mastodon, HIBP, ransomware.live, dated
  // forum posts — see collectors/*.py) — seen_at is "when our scraper saw
  // this," not "when it happened," and showing it as the headline date was
  // misleading for anything that isn't brand new. seen_at is always kept in
  // the tooltip so ingest lag is still visible on hover.
  if (item.published_at) {
    const label = item.source_tags && item.source_tags.includes('hibp') ? 'breached ' : '';
    time.textContent = label + fmtTime(item.published_at);
    time.title = 'ingested ' + fmtTime(item.seen_at);
  } else {
    time.textContent = fmtTime(item.seen_at);
    time.title = 'no publish date captured for this source — showing ingest time';
  }
  meta.appendChild(time);

  if (item.max_priority) {
    const prioChip = document.createElement('span');
    prioChip.className = 'tag-chip prio-' + item.max_priority;
    prioChip.textContent = item.max_priority.toUpperCase();
    meta.appendChild(prioChip);
  }

  // cluster_size > 1: this content_key was also seen from other sources —
  // a triage aid (this is the same incident, not N separate ones), never a
  // filter (see db.py:fetch_items — nothing is hidden server-side).
  if (item.cluster_size > 1) {
    const clusterChip = document.createElement('span');
    clusterChip.className = 'tag-chip cluster-chip';
    clusterChip.textContent = `↻ ${item.cluster_size} sources`;
    clusterChip.title = 'Also reported by other sources — likely the same underlying incident';
    meta.appendChild(clusterChip);
  }

  item.all_tags.forEach(tag => {
    const chip = document.createElement('span');
    chip.className = 'tag-chip';
    chip.textContent = tag;
    meta.appendChild(chip);
  });

  if (state.classifierEnabled) {
    meta.appendChild(buildClassifierDot(item));
  }

  card.appendChild(meta);

  const titleDiv = document.createElement('div');
  titleDiv.className = 'item-title';
  const a = document.createElement('a');
  a.href = isSafeUrl(item.url) ? item.url : '#';
  if (!isSafeUrl(item.url)) a.title = 'Unrecognized URL scheme — link disabled';
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  a.innerHTML = highlightText(item.title, item.matches, 'title', item.title.length);
  titleDiv.appendChild(a);
  card.appendChild(titleDiv);

  if (item.snippet) {
    const snip = document.createElement('div');
    snip.className = 'item-snippet';
    snip.innerHTML = highlightText(item.snippet, item.matches, 'snippet', item.title.length);
    card.appendChild(snip);
  }

  // Shown directly on the card (not just in the dot's hover tooltip) so the
  // classifier's call can be visually reviewed at a glance while scanning
  // the feed, rather than requiring a hover per item.
  if (state.classifierEnabled && item.classifier_reasoning) {
    const reasoning = document.createElement('div');
    reasoning.className = 'item-classifier-reasoning';
    reasoning.textContent = item.classifier_reasoning;
    card.appendChild(reasoning);
  }

  return card;
}

// Only allow http(s) and onion-friendly schemes through to href — blocks
// javascript: URLs sourced from attacker-controlled scraped content.
function isSafeUrl(url) {
  if (!url) return false;
  try {
    const u = new URL(url, location.href);
    return u.protocol === 'http:' || u.protocol === 'https:';
  } catch {
    return false;
  }
}

// ── Highlight ──────────────────────────────────────────────────────────────
// Spans come from server as offsets into title+'\n'+snippet (matcher.py).
// titleLen is the length of the *original* title field, so we can translate
// combined-haystack offsets back into the field actually being rendered:
// title spans are [0, titleLen); snippet spans start at titleLen+1 (the "\n").
function highlightText(text, matches, field, titleLen) {
  if (!matches || matches.length === 0) return escHtml(text);

  const sepOffset = titleLen + 1; // length of title + "\n" separator

  // Collect spans relevant to this field, translated to field-local offsets
  const spans = [];
  matches.forEach(m => {
    m.spans.forEach(([start, end]) => {
      let s, e;
      if (field === 'title') {
        if (start >= titleLen) return; // span is in the snippet, not here
        s = start;
        e = Math.min(end, titleLen);
      } else {
        if (end <= sepOffset) return; // span is in the title, not here
        s = Math.max(start - sepOffset, 0);
        e = end - sepOffset;
      }
      spans.push({ start: s, end: e, priority: m.priority });
    });
  });
  if (!spans.length) return escHtml(text);
  spans.sort((a, b) => a.start - b.start);

  let out = '';
  let prev = 0;
  for (const sp of spans) {
    if (sp.start >= text.length) break;
    if (sp.start < prev) continue; // overlapping — skip
    const end = Math.min(sp.end, text.length);
    out += escHtml(text.slice(prev, sp.start));
    out += `<mark class="prio-${sp.priority}">${escHtml(text.slice(sp.start, end))}</mark>`;
    prev = end;
  }
  out += escHtml(text.slice(prev));
  return out;
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── SSE ────────────────────────────────────────────────────────────────────
function connectSSE() {
  const es = new EventSource('/api/stream');

  es.onopen = () => {
    sseStatus.className = 'sse-status connected';
    sseStatus.title = 'Live feed connected';
  };

  es.onmessage = (ev) => {
    if (!ev.data) return;
    let payload;
    try { payload = JSON.parse(ev.data); } catch { return; }
    if (payload && payload.type === 'status') {
      handleStatusEvent(payload);
    } else {
      handleLiveItem(payload);
    }
  };

  es.onerror = () => {
    sseStatus.className = 'sse-status connecting';
    sseStatus.title = 'Reconnecting…';
    // EventSource auto-reconnects
  };
}

function handleLiveItem(item) {
  if (!passesClientFilter(item)) return;

  const atTop = feedList.scrollTop < 50;
  if (atTop) {
    const card = buildCard(item);
    card.classList.add('fadeIn');
    feedList.prepend(card);
    state.items.unshift(item);
    totalCount.textContent = `${(state.items.length).toLocaleString()} items`;
  } else {
    state.pendingLive.push(item);
    newBanner.classList.remove('hidden');
  }
}

// ── Admin token (central header input) ───────────────────────────────────────
// The token unlocks admin-gated features across tabs: keyword editing,
// filtered-item view, and the case deep-research trigger. It lives in the
// header toolbar so it is reachable from every tab.
const ADMIN_TOKEN_KEY = 'mm_admin_token';
let adminEnabledServerSide = true;

function initKeywordsAuth() {
  adminTokenInput.value = localStorage.getItem(ADMIN_TOKEN_KEY) || '';
  adminTokenInput.addEventListener('input', () => {
    localStorage.setItem(ADMIN_TOKEN_KEY, adminTokenInput.value);
    updateAdminUiState();
  });
  document.getElementById('kw-token-load').addEventListener('click', unlockKeywords);
  document.getElementById('kw-save').addEventListener('click', saveKeywords);
  updateAdminUiState();
}

function adminHeaders() {
  return { 'X-Admin-Token': adminTokenInput.value };
}

function hasAdminToken() {
  return adminEnabledServerSide && adminTokenInput.value.trim().length > 0;
}

function updateAdminUiState() {
  const token = adminTokenInput.value.trim();
  if (!adminEnabledServerSide) {
    adminTokenInput.classList.add('hidden');
    adminTokenStatus.classList.add('hidden');
    document.getElementById('show-filtered-row').classList.add('hidden');
    return;
  }
  adminTokenInput.classList.remove('hidden');
  if (token) {
    adminTokenStatus.textContent = '🔒 admin';
    adminTokenStatus.classList.remove('hidden', 'error');
  } else {
    adminTokenStatus.textContent = 'Admin token required for research/keywords';
    adminTokenStatus.classList.remove('hidden');
    adminTokenStatus.classList.add('error');
  }
  document.getElementById('show-filtered-row').classList.toggle('hidden', !token);
}

async function unlockKeywords() {
  const tokenStatus = document.getElementById('kw-token-status');
  const token = adminTokenInput.value;
  localStorage.setItem(ADMIN_TOKEN_KEY, token);
  tokenStatus.textContent = 'Loading…';
  try {
    const resp = await fetch('/api/keywords', { headers: adminHeaders() });
    if (!resp.ok) {
      tokenStatus.textContent = resp.status === 403 ? 'Invalid token' : `Error ${resp.status}`;
      return;
    }
    const data = await resp.json();
    document.getElementById('kw-editor').value = data.yaml || '';
    document.getElementById('kw-editor').disabled = false;
    document.getElementById('kw-save').disabled = false;
    tokenStatus.textContent = '✓ loaded';
  } catch (e) {
    tokenStatus.textContent = String(e);
  }
}

async function saveKeywords() {
  const btn = document.getElementById('kw-save');
  const status = document.getElementById('kw-status');
  const errBox = document.getElementById('kw-error');
  const yaml = document.getElementById('kw-editor').value;

  btn.disabled = true;
  status.textContent = 'Saving…';
  errBox.classList.add('hidden');

  try {
    const resp = await fetch('/api/keywords', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', ...adminHeaders() },
      body: JSON.stringify({ yaml }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      errBox.textContent = data.detail || 'Error';
      errBox.classList.remove('hidden');
      status.textContent = '';
    } else {
      status.textContent = '✓ ' + data.message;
      setTimeout(() => { status.textContent = ''; }, 3000);
    }
  } catch (e) {
    errBox.textContent = String(e);
    errBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
}

// ── Utilities ──────────────────────────────────────────────────────────────
async function api(path, opts = {}) {
  const resp = await fetch(path, opts);
  if (!resp.ok) {
    const err = new Error(`API ${path}: ${resp.status}`);
    err.status = resp.status;
    try {
      err.body = await resp.json();
    } catch {
      err.body = null;
    }
    throw err;
  }
  return resp.json();
}

function fmtTime(iso) {
  if (!iso) return '';
  // Append "Z" only when the string has no timezone info at all (no
  // trailing Z, no +HH:MM/-HH:MM offset). Health/classifier timestamps are
  // tz-aware (Python's datetime.now(timezone.utc).isoformat() — e.g.
  // "...+00:00") while older item rows may be naive (pre-tz-aware-migration
  // "...123456" with no suffix); blindly appending "Z" to an
  // already-offset-qualified string produces an invalid double-timezone
  // string that Date() silently parses as Invalid Date.
  const hasTz = /Z$|[+-]\d{2}:\d{2}$/.test(iso);
  const d = new Date(hasTz ? iso : iso + 'Z');
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

// ── Dashboard ──────────────────────────────────────────────────────────────
const dashCharts = {}; // canvas id -> Chart.js instance, kept around for .update()

const PRIO_COLORS = {
  critical: '#f85149',
  warn: '#e3b341',
  info: '#388bfd',
  none: '#30363d',
};

function initDashboard() {
  Chart.defaults.color = '#8b949e';
  Chart.defaults.borderColor = '#30363d';
  Chart.defaults.font.size = 11;
}

async function loadDashboard() {
  try {
    const calls = [
      api('/api/stats/timeseries?bucket=hour&since_hours=48'),
      api('/api/stats/by_priority'),
      api('/api/stats/by_priority?since_hours=24'),
      api('/api/stats/by_source'),
      api('/api/stats/top_actors?limit=8'),
    ];
    if (state.classifierEnabled) calls.push(api('/api/classifier/health'));
    const [timeseries, byPriority, byPriority24h, bySource, actors, classifierHealth] = await Promise.all(calls);

    document.getElementById('gauge-critical-24h').textContent = byPriority24h.critical;
    document.getElementById('gauge-critical-24h').className =
      'gauge-value' + (byPriority24h.critical > 0 ? ' prio-critical' : '');
    document.getElementById('gauge-total').textContent =
      (byPriority.none + byPriority.info + byPriority.warn + byPriority.critical).toLocaleString();
    const healthy = bySource.sources.filter(s => s.enabled && s.consecutive_errors === 0).length;
    document.getElementById('gauge-sources-ok').textContent = `${healthy}/${bySource.sources.filter(s => s.enabled).length}`;

    if (classifierHealth) {
      const el = document.getElementById('gauge-classifier-backlog');
      el.textContent = classifierHealth.backlog.toLocaleString();
      el.className = 'gauge-value' + (classifierHealth.consecutive_errors >= 3 ? ' prio-critical' : '');
      const backendLabel = classifierHealth.using_fallback
        ? `${classifierHealth.backend} (unreachable — using hermes-agent fallback)`
        : classifierHealth.backend;
      el.title = classifierHealth.last_error
        ? `backend: ${backendLabel}\nlast error: ${classifierHealth.last_error}`
        : `backend: ${backendLabel}`;
    }

    renderTimeseries(timeseries.buckets);
    renderPriorityDonut(byPriority);
    renderSourcesBar(bySource.sources);
    renderActorsBar(actors.actors);
  } catch (e) {
    console.error('Failed to load dashboard', e);
  }
}

function upsertChart(canvasId, config) {
  const existing = dashCharts[canvasId];
  if (existing) {
    existing.data = config.data;
    existing.options = config.options;
    existing.update();
    return existing;
  }
  const ctx = document.getElementById(canvasId).getContext('2d');
  const chart = new Chart(ctx, config);
  dashCharts[canvasId] = chart;
  return chart;
}

function renderTimeseries(buckets) {
  const labels = buckets.map(b => fmtTime(b.bucket));
  upsertChart('chart-timeseries', {
    type: 'bar',
    data: {
      labels,
      datasets: ['info', 'warn', 'critical'].map(p => ({
        label: p,
        data: buckets.map(b => b[p]),
        backgroundColor: PRIO_COLORS[p],
        stack: 'a',
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { x: { stacked: true, ticks: { maxTicksLimit: 12 } }, y: { stacked: true, beginAtZero: true } },
      plugins: { legend: { display: true, position: 'bottom' } },
    },
  });
}

function renderPriorityDonut(counts) {
  const labels = ['critical', 'warn', 'info', 'none'];
  upsertChart('chart-priority', {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: labels.map(l => counts[l]), backgroundColor: labels.map(l => PRIO_COLORS[l]) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'bottom' } },
    },
  });
}

function renderSourcesBar(sources) {
  const sorted = [...sources].sort((a, b) => b.total - a.total).slice(0, 12);
  upsertChart('chart-sources', {
    type: 'bar',
    data: {
      labels: sorted.map(s => s.source_name),
      datasets: [{
        label: 'items',
        data: sorted.map(s => s.total),
        backgroundColor: sorted.map(s => s.consecutive_errors > 0 ? PRIO_COLORS.warn : '#3fb950'),
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true } },
    },
  });
}

function renderActorsBar(actors) {
  upsertChart('chart-actors', {
    type: 'bar',
    data: {
      labels: actors.map(a => a.actor),
      datasets: [{ label: 'mentions', data: actors.map(a => a.count), backgroundColor: PRIO_COLORS.warn }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true } },
    },
  });
}

// expose for banner button
window.applyFilters = applyFilters;

// ── Cases ──────────────────────────────────────────────────────────────────
// Case-centric view on top of pipeline/correlate.py's deduplicated incidents
// — distinct from the raw Feed tab above. See /api/cases* (api/routes.py).
// Two-pane layout (rail | detail) with filters in a top toolbar — see
// style.css's "Cases tab" section for why this replaced the old three-column
// filter-sidebar/list/detail-sidebar split.
const casesState = {
  cases: [],
  offset: 0,
  pageSize: 50,
  hasMore: false,
  selectedId: null,
  filters: { search: '', significance: '', kevOnly: false, crimeType: '', since: '', until: '' },
};

const casesList        = document.getElementById('cases-list');
const casesEmpty       = document.getElementById('cases-empty');
const casesLoadMoreBtn = document.getElementById('cases-load-more');
const caseSearchInput  = document.getElementById('case-search-input');
const caseKevOnlyCb    = document.getElementById('case-kev-only');
const caseSignificanceSelect = document.getElementById('case-significance-select');
const caseCrimeTypeSelect    = document.getElementById('case-crime-type-select');
const caseSinceInput   = document.getElementById('case-since-input');
const caseUntilInput   = document.getElementById('case-until-input');
const caseFiltersClear = document.getElementById('case-filters-clear');
const caseDetailPane   = document.getElementById('case-detail');
const caseDetailEmpty  = document.getElementById('case-detail-empty');

function initCases() {
  caseSearchInput.addEventListener('input', debounce(() => {
    casesState.filters.search = caseSearchInput.value.trim();
    applyCaseFilters();
  }, 400));
  caseKevOnlyCb.addEventListener('change', () => {
    casesState.filters.kevOnly = caseKevOnlyCb.checked;
    applyCaseFilters();
  });
  caseSignificanceSelect.addEventListener('change', () => {
    casesState.filters.significance = caseSignificanceSelect.value;
    applyCaseFilters();
  });
  caseCrimeTypeSelect.addEventListener('change', () => {
    casesState.filters.crimeType = caseCrimeTypeSelect.value;
    applyCaseFilters();
  });
  caseSinceInput.addEventListener('change', () => {
    casesState.filters.since = caseSinceInput.value;
    applyCaseFilters();
  });
  caseUntilInput.addEventListener('change', () => {
    casesState.filters.until = caseUntilInput.value;
    applyCaseFilters();
  });
  caseFiltersClear.addEventListener('click', () => {
    casesState.filters = { search: '', significance: '', kevOnly: false, crimeType: '', since: '', until: '' };
    caseSearchInput.value = '';
    caseKevOnlyCb.checked = false;
    caseSignificanceSelect.value = '';
    caseCrimeTypeSelect.value = '';
    caseSinceInput.value = '';
    caseUntilInput.value = '';
    applyCaseFilters();
  });
  casesLoadMoreBtn.addEventListener('click', loadMoreCases);

  loadCaseStats();
  applyCaseFilters();
  setInterval(loadCaseStats, 30000);
}

function caseQueryParams(extra = {}) {
  const params = new URLSearchParams();
  if (casesState.filters.search) params.set('search', casesState.filters.search);
  if (casesState.filters.significance) params.set('min_significance', casesState.filters.significance);
  if (casesState.filters.kevOnly) params.set('in_kev', 'true');
  if (casesState.filters.crimeType) params.set('crime_type', casesState.filters.crimeType);
  if (casesState.filters.since) params.set('since', casesState.filters.since);
  if (casesState.filters.until) params.set('until', casesState.filters.until);
  Object.entries(extra).forEach(([k, v]) => params.set(k, v));
  return params.toString();
}

async function applyCaseFilters() {
  casesState.offset = 0;
  try {
    const data = await api('/api/cases?' + caseQueryParams({ limit: casesState.pageSize, offset: 0 }));
    casesState.cases = data.cases;
    casesState.hasMore = data.cases.length === casesState.pageSize && data.total > casesState.pageSize;
    renderCasesList();
  } catch (e) {
    console.error('Failed to load cases', e);
  }
}

async function loadMoreCases() {
  casesState.offset += casesState.pageSize;
  try {
    const data = await api('/api/cases?' + caseQueryParams({ limit: casesState.pageSize, offset: casesState.offset }));
    casesState.cases = casesState.cases.concat(data.cases);
    casesState.hasMore = data.cases.length === casesState.pageSize;
    renderCasesList();
  } catch (e) {
    console.error('Failed to load more cases', e);
  }
}

async function loadCaseStats() {
  try {
    const stats = await api('/api/stats/cases');
    document.getElementById('gauge-cases-total').textContent = stats.total.toLocaleString();
    document.getElementById('gauge-cases-kev').textContent = stats.in_kev.toLocaleString();
    populateCaseCrimeTypeSelect(stats.by_crime_type || []);
    // The Feed tab's crime-type filter dropdown is populated from the same
    // case-aggregated stats (crime types only become meaningful once
    // extraction has run) — kept from the original three-column layout.
    populateFeedCrimeTypeDropdown(stats.by_crime_type || []);
  } catch (e) {
    console.error('Failed to load case stats', e);
  }
}

function populateCaseCrimeTypeSelect(byCrimeType) {
  const current = casesState.filters.crimeType;
  caseCrimeTypeSelect.innerHTML = '<option value="">All crime types</option>';
  byCrimeType.forEach(({ crime_type, n }) => {
    const opt = document.createElement('option');
    opt.value = crime_type;
    opt.textContent = `${crime_type} (${n})`;
    caseCrimeTypeSelect.appendChild(opt);
  });
  caseCrimeTypeSelect.value = current || '';
}

function populateFeedCrimeTypeDropdown(byCrimeType) {
  const current = crimeTypeInput.value;
  crimeTypeInput.innerHTML = '<option value="">Any</option>';
  byCrimeType.forEach(({ crime_type }) => {
    const opt = document.createElement('option');
    opt.value = crime_type;
    opt.textContent = crime_type;
    crimeTypeInput.appendChild(opt);
  });
  crimeTypeInput.value = current || '';
}

function renderCasesList() {
  casesList.innerHTML = '';
  casesEmpty.classList.toggle('hidden', casesState.cases.length > 0);
  casesState.cases.forEach(c => casesList.appendChild(buildCaseCard(c)));
  casesLoadMoreBtn.classList.toggle('hidden', !casesState.hasMore);

  // Critical-count gauge is derived client-side from the loaded page rather
  // than a dedicated endpoint — good enough for an at-a-glance count without
  // adding another /api/stats/cases query param.
  const criticalCount = casesState.cases.filter(c => c.significance === 'critical').length;
  document.getElementById('gauge-cases-critical').textContent = criticalCount.toLocaleString();
}

function buildCaseCard(c) {
  const card = document.createElement('div');
  card.className = 'item-card' + (c.significance ? ' prio-' + c.significance : '');
  card.dataset.caseId = c.id;
  if (c.id === casesState.selectedId) card.classList.add('selected');

  const meta = document.createElement('div');
  meta.className = 'item-meta';

  if (c.significance) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip prio-' + c.significance;
    chip.textContent = c.significance.toUpperCase();
    meta.appendChild(chip);
  }

  const crimeChip = document.createElement('span');
  crimeChip.className = 'tag-chip';
  crimeChip.textContent = c.crime_type;
  meta.appendChild(crimeChip);

  if (c.in_kev) {
    const kevChip = document.createElement('span');
    kevChip.className = 'tag-chip prio-critical';
    kevChip.textContent = 'KEV';
    kevChip.title = 'A linked CVE is in CISA\'s Known Exploited Vulnerabilities catalog';
    meta.appendChild(kevChip);
  }

  if (c.source_count > 1) {
    const clusterChip = document.createElement('span');
    clusterChip.className = 'tag-chip cluster-chip';
    clusterChip.textContent = `↻ ${c.source_count} sources`;
    meta.appendChild(clusterChip);
  }

  const time = document.createElement('span');
  time.className = 'item-time';
  time.textContent = fmtTime(c.last_seen);
  time.title = 'last corroborating report';
  meta.appendChild(time);

  card.appendChild(meta);

  const titleDiv = document.createElement('div');
  titleDiv.className = 'item-title';
  titleDiv.textContent = c.title;
  card.appendChild(titleDiv);

  if (c.damaged_party || c.attribution) {
    const sub = document.createElement('div');
    sub.className = 'item-snippet';
    const bits = [];
    if (c.damaged_party) bits.push(`Victim: ${c.damaged_party}`);
    if (c.attribution) bits.push(`Attribution: ${c.attribution}`);
    if (c.cve_ids && c.cve_ids.length) bits.push(`CVEs: ${c.cve_ids.join(', ')}`);
    sub.textContent = bits.join(' · ');
    card.appendChild(sub);
  }

  card.addEventListener('click', () => selectCase(c.id));
  return card;
}

async function selectCase(id) {
  casesState.selectedId = id;
  document.querySelectorAll('[data-case-id]').forEach(el => {
    el.classList.toggle('selected', Number(el.dataset.caseId) === id);
  });
  try {
    const { case: c, items, research_runs, related_cases } = await api(`/api/cases/${id}`);
    renderCaseDetail(c, items, research_runs || [], related_cases || []);
  } catch (e) {
    console.error('Failed to load case detail', e);
  }
}

function renderCaseDetail(c, items, researchRuns, relatedCases) {
  caseDetailEmpty.classList.add('hidden');
  caseDetailPane.classList.remove('hidden');
  caseDetailPane.innerHTML = '';

  // ── Header ──
  const header = document.createElement('div');
  header.className = 'case-detail-header';
  const h = document.createElement('h2');
  h.textContent = c.title;
  header.appendChild(h);
  if (c.significance) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip prio-' + c.significance;
    chip.textContent = c.significance.toUpperCase();
    header.appendChild(chip);
  }
  caseDetailPane.appendChild(header);

  // ── Field grid ──
  const grid = document.createElement('div');
  grid.className = 'case-field-grid';
  const fields = [
    ['Crime type', c.crime_type],
    ['Victim', c.damaged_party],
    ['Sector', c.damaged_party_sector],
    ['Country', c.damaged_party_country],
    ['Attribution', c.attribution],
    ['Status', c.status],
    ['CVEs', (c.cve_ids || []).join(', ') || null],
    ['In KEV', c.in_kev ? 'yes' : 'no'],
    ['First seen', fmtTime(c.first_seen)],
    ['Last seen', fmtTime(c.last_seen)],
    ['Sources', String(c.source_count)],
  ];
  fields.forEach(([label, value]) => {
    if (!value) return;
    const row = document.createElement('div');
    row.className = 'hint';
    row.innerHTML = `<b>${escHtml(label)}:</b> ${escHtml(String(value))}`;
    grid.appendChild(row);
  });
  caseDetailPane.appendChild(grid);

  if (c.summary) {
    const summary = document.createElement('div');
    summary.className = 'item-snippet';
    summary.textContent = c.summary;
    caseDetailPane.appendChild(summary);
  }

  // ── IoCs ──
  if (c.iocs && c.iocs.length) {
    const iocHeader = document.createElement('h3');
    iocHeader.textContent = `Indicators of compromise (${c.iocs.length})`;
    caseDetailPane.appendChild(iocHeader);
    const row = document.createElement('div');
    row.className = 'ioc-chip-row';
    c.iocs.forEach(ioc => {
      const chip = document.createElement('span');
      chip.className = 'ioc-chip';
      chip.textContent = ioc;
      row.appendChild(chip);
    });
    caseDetailPane.appendChild(row);
  }

  // ── Research ──
  const showResearch = hasAdminToken();
  if (showResearch) {
    const researchHeader = document.createElement('h3');
    researchHeader.textContent = 'Autonomous research';
    caseDetailPane.appendChild(researchHeader);

    const researchRow = document.createElement('div');
    researchRow.className = 'research-status-row';
    const btn = document.createElement('button');
    btn.className = 'btn-deep-research';
    const pending = !!c.research_requested_at;
    const running = researchRuns.some(r => r.status === 'running');
    btn.textContent = pending || running ? 'Research queued…' : (researchRuns.length ? 'Re-research (fill gaps)' : 'Deep research');
    btn.disabled = pending || running;
    const researchStatus = document.createElement('span');
    researchStatus.className = 'research-status-msg';
    btn.addEventListener('click', () => requestCaseResearch(c.id, btn, researchStatus));
    researchRow.appendChild(btn);
    researchRow.appendChild(researchStatus);
    caseDetailPane.appendChild(researchRow);
  }

  if (researchRuns.length) {
    const list = document.createElement('div');
    list.className = 'research-run-list';
    researchRuns.slice(0, 5).forEach(r => {
      const row = document.createElement('div');
      row.className = 'research-run-row';
      const findings = r.findings && r.findings.summary ? r.findings.summary : '';
      row.innerHTML = `<b>${escHtml(r.status)}</b> · ${escHtml(fmtTime(r.started_at))}` +
        (findings ? `<br>${escHtml(findings)}` : '');
      list.appendChild(row);
    });
    caseDetailPane.appendChild(list);
  }

  // ── Feedback ──
  const feedbackHeader = document.createElement('h3');
  feedbackHeader.textContent = 'Your assessment';
  caseDetailPane.appendChild(feedbackHeader);
  const feedbackRow = document.createElement('div');
  feedbackRow.className = 'feedback-row';
  [['useful', '👍 Useful'], ['noise', '👎 Noise'], ['wrong_attribution', '⚑ Wrong attribution']].forEach(([verdict, label]) => {
    const fbtn = document.createElement('button');
    fbtn.className = 'feedback-btn';
    fbtn.textContent = label;
    fbtn.addEventListener('click', () => submitFeedback({ case_id: c.id, verdict }, fbtn, feedbackRow));
    feedbackRow.appendChild(fbtn);
  });
  caseDetailPane.appendChild(feedbackRow);

  // ── Related cases ──
  if (relatedCases.length) {
    const relHeader = document.createElement('h3');
    relHeader.textContent = `Related cases (${relatedCases.length})`;
    caseDetailPane.appendChild(relHeader);
    const relList = document.createElement('div');
    relList.className = 'related-case-list';
    relatedCases.forEach(r => {
      const rcard = document.createElement('button');
      rcard.className = 'related-case-card';
      rcard.innerHTML = `${escHtml(r.title)}` +
        `<div class="related-reasons">${escHtml((r.reasons || []).join(', '))} · score ${(r.score * 100).toFixed(0)}%</div>`;
      rcard.addEventListener('click', () => selectCase(r.case_id));
      relList.appendChild(rcard);
    });
    caseDetailPane.appendChild(relList);
  }

  // ── Timeline of corroborating reports ──
  const itemsHeader = document.createElement('h3');
  itemsHeader.textContent = `Timeline · corroborating reports (${items.length})`;
  caseDetailPane.appendChild(itemsHeader);

  const timeline = document.createElement('div');
  timeline.className = 'case-timeline';
  items.forEach(it => {
    const row = document.createElement('div');
    row.className = 'case-timeline-item';
    const a = document.createElement('a');
    a.href = isSafeUrl(it.url) ? it.url : '#';
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = it.title;
    row.appendChild(a);
    const meta = document.createElement('div');
    meta.className = 'item-time';
    meta.textContent = `${it.source_name} · ${fmtTime(it.published_at || it.seen_at)}`;
    if (it.published_at) {
      meta.title = `ingested ${fmtTime(it.seen_at)}`;
    }
    row.appendChild(meta);
    const fbRow = document.createElement('div');
    fbRow.className = 'feedback-row';
    [['useful', '👍'], ['noise', '👎']].forEach(([verdict, label]) => {
      const fbtn = document.createElement('button');
      fbtn.className = 'feedback-btn';
      fbtn.textContent = label;
      fbtn.title = verdict === 'useful' ? 'Useful' : 'Noise';
      fbtn.addEventListener('click', () => submitFeedback({ item_id: it.id, verdict }, fbtn, fbRow));
      fbRow.appendChild(fbtn);
    });
    row.appendChild(fbRow);
    timeline.appendChild(row);
  });
  caseDetailPane.appendChild(timeline);
}

async function requestCaseResearch(caseId, btn, statusEl) {
  statusEl.textContent = '';
  statusEl.className = 'research-status-msg';
  btn.disabled = true;
  btn.textContent = 'Queuing…';
  try {
    await api(`/api/cases/${caseId}/research`, { method: 'POST', headers: adminHeaders() });
    btn.textContent = 'Research queued…';
  } catch (e) {
    btn.textContent = 'Failed — retry';
    btn.disabled = false;
    let detail = '';
    if (e && e.status) {
      if (e.status === 403) {
        detail = 'Invalid admin token.';
      } else if (e.status === 404) {
        detail = 'Case not found.';
      } else if (e.status === 429) {
        detail = 'Rate limit exceeded — wait a moment.';
      } else {
        detail = `Server error ${e.status}.`;
      }
    } else {
      detail = 'Network or server error.';
    }
    statusEl.textContent = detail + ' Check the browser console for details.';
    statusEl.classList.add('error');
    console.error('Failed to request research', e);
  }
}

async function submitFeedback(body, btn, row) {
  const original = btn.textContent;
  try {
    await api('/api/feedback', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    row.querySelectorAll('.feedback-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
  } catch (e) {
    btn.textContent = '✗';
    setTimeout(() => { btn.textContent = original; }, 1500);
    console.error('Failed to submit feedback', e);
  }
}

// ── Real-time subsystem status bar ───────────────────────────────────────────
function initStatusBar() {
  updateStatusBar();
  setInterval(updateStatusBar, 10000);
}

async function updateStatusBar() {
  try {
    const s = await api('/api/status');
    renderStatusBar(s);
  } catch (e) {
    console.error('Failed to load status', e);
    setStatusPill('status-scheduler', 'status: unreachable', 'error');
  }
}

function renderStatusBar(s) {
  adminEnabledServerSide = !!(s.admin && s.admin.enabled);
  updateAdminUiState();

  const sched = s.scheduler || {};
  setStatusPill('status-scheduler', sched.running ? 'scheduler: running' : 'scheduler: stopped', sched.running ? 'ok' : 'error');

  const src = s.sources || {};
  const srcText = `sources: ${src.total - src.failing_count}/${src.total} healthy`;
  setStatusPill('status-sources', srcText, src.failing_count > 0 ? 'warn' : 'ok');

  const cls = s.classifier || {};
  const clsText = cls.backend === 'none'
    ? 'classifier: disabled'
    : cls.using_fallback
      ? `classifier: ${cls.backlog || 0} backlog (hermes fallback)`
      : `classifier: ${cls.backlog || 0} backlog`;
  const clsState = cls.consecutive_errors >= 3 ? 'error' : (cls.using_fallback ? 'warn' : (cls.backlog > 50 ? 'warn' : 'ok'));
  setStatusPill('status-classifier', clsText, clsState);

  const corr = s.correlation || {};
  const corrText = `correlator: ${corr.backlog || 0} backlog`;
  const corrState = corr.consecutive_errors >= 3 ? 'error' : (corr.backlog > 50 ? 'warn' : 'ok');
  setStatusPill('status-correlation', corrText, corrState);

  const res = s.research || {};
  const resText = res.running > 0
    ? `research: running (${res.running})`
    : `research: ${res.queued || 0} queued`;
  setStatusPill('status-research', resText, res.consecutive_errors >= 3 ? 'error' : (res.running > 0 ? 'active' : 'ok'));

  const heal = s.heal || {};
  const pending = (heal.proposals || {}).pending || 0;
  const healText = `heal: ${pending} pending`;
  setStatusPill('status-heal', healText, heal.consecutive_errors >= 3 ? 'error' : (pending > 0 ? 'active' : 'ok'));

  const kev = s.kev || {};
  const kevText = `KEV: ${(kev.count || 0).toLocaleString()}`;
  setStatusPill('status-kev', kevText, 'ok');
}

function setStatusPill(id, text, state) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  el.className = 'status-pill status-' + state;
}

// SSE may also push lightweight status events from background jobs.
function handleStatusEvent(payload) {
  // A full status payload mirrors /api/status; partial payloads update
  // individual subsystems. Refresh the bar from the server to keep it simple
  // and consistent.
  updateStatusBar();
}
