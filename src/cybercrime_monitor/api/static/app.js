'use strict';

// ── State ──────────────────────────────────────────────────────────────────
// Cap on state.items so long sessions (heavy load-more scrolling, or a busy
// SSE feed left open for hours) don't grow the array — and the DOM nodes
// rendered from it — without bound.
const MAX_FEED_ITEMS = 1000;

const state = {
  items: [],           // all loaded items (newest first), capped at MAX_FEED_ITEMS
  offset: 0,
  pageSize: 100,
  hasMore: false,
  pendingLive: [],     // items arrived via SSE while not at top
  sources: [],
  filters: {
    search: '',
    searchMode: 'keyword', // 'keyword' | 'semantic' — see initSearchModeToggle
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
const searchModeToggle = document.getElementById('search-mode-toggle');
const searchModeHint   = document.getElementById('search-mode-hint');
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
  initAdminAuth();
  setInterval(loadSources, 30000); // refresh source health dots

  initDashboard();
  setInterval(loadDashboard, 30000);

  initCases();
  initQueuesPanel();
  initTokenBurn();
  initActivity();
  initLandscape();
  initInvestigate();

  searchInput.addEventListener('input', debounce(() => {
    state.filters.search = searchInput.value.trim();
    applyFilters();
  }, 400));
  initSearchModeToggle(searchModeToggle, searchModeHint, mode => {
    state.filters.searchMode = mode;
    applyFilters();
  });
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
    // Cheap, sync re-render from the data we already have — keeps the
    // Activity tab's source leaderboard (issue #17) in step with this
    // existing 30s health refresh instead of needing its own poll loop.
    renderSourceLeaderboard();
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

// "access" (server-derived, sources/value.py's access_for) tells us
// whether "fetched OK but parsed 0 items" almost always means a CSS
// selector drifted from the live markup ("scrape"), vs. API/feed-based
// sources which can legitimately go many ticks without new items — so
// empty-streak degradation only applies to "scrape". This used to be a
// hardcoded type list here; now the backend is the single source of truth
// (it also drives the same threshold in the autonomous heal/prune loop —
// see settings.source_empty_streak_threshold).
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
  if (src.access === 'scrape' && src.consecutive_empty >= _EMPTY_STREAK_THRESHOLD) return 'degraded';
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
  if (src.value_classification) parts.push(`investigation value: ${src.value_classification}`);
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
    stateItem.all_tags = verdict.all_tags || [];
    stateItem.is_false_positive = verdict.is_false_positive;
    stateItem.classified = true;
    stateItem.classifier_confidence = verdict.classifier_confidence;
    stateItem.classifier_reasoning = verdict.classifier_reasoning;
    // Structured entities (also drive highlightEntities — see buildCard).
    stateItem.crime_type = verdict.crime_type;
    stateItem.victim = verdict.victim;
    stateItem.victim_sector = verdict.victim_sector;
    stateItem.victim_country = verdict.victim_country;
    stateItem.actor = verdict.actor;
    stateItem.cve_ids = verdict.cve_ids || [];
    stateItem.iocs = verdict.iocs || [];
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
// ── Search mode toggle (keyword/semantic) ───────────────────────────────────
// Shared by the Feed sidebar search and the Cases toolbar search. Two
// explicit, separately labeled modes rather than one blended search — a
// failed/unavailable semantic request must read as visibly different from
// "keyword found nothing" (see settings.embed_backend's docstring and
// api/routes.py's mode=semantic branch). semanticSearchEnabled mirrors
// /api/status's semantic_search.enabled (kept fresh by renderQueuesPanel) and
// only gates whether the Semantic button is clickable.
let semanticSearchEnabled = true;

function initSearchModeToggle(toggleEl, hintEl, onChange) {
  toggleEl.querySelectorAll('.search-mode-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      if (btn.disabled) return;
      toggleEl.querySelectorAll('.search-mode-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      hintEl.classList.add('hidden');
      onChange(btn.dataset.mode);
    });
  });
}

function syncSearchModeToggle(toggleEl, mode) {
  toggleEl.querySelectorAll('.search-mode-btn').forEach(b => b.classList.toggle('active', b.dataset.mode === mode));
}

function setSearchModeToggleEnabled(toggleEl, enabled) {
  const semanticBtn = toggleEl.querySelector('.search-mode-btn[data-mode="semantic"]');
  if (!semanticBtn) return;
  semanticBtn.disabled = !enabled;
  semanticBtn.title = enabled ? '' : 'Semantic search is disabled on this server (EMBED_BACKEND=none)';
}

function showSemanticUnavailableHint(hintEl) {
  hintEl.textContent = 'Semantic search unavailable right now — showing no results (not silently falling back to keyword).';
  hintEl.classList.remove('hidden');
}

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

  if (data.semantic_unavailable) showSemanticUnavailableHint(searchModeHint);

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
  state.items = state.items.concat(newItems).slice(0, MAX_FEED_ITEMS);
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
  if (f.searchMode === 'semantic') p.set('mode', 'semantic');
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
  f.searchMode = p.get('mode') === 'semantic' ? 'semantic' : 'keyword';
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
  syncSearchModeToggle(searchModeToggle, f.searchMode);
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
  a.innerHTML = highlightEntities(item.title, item);
  titleDiv.appendChild(a);
  card.appendChild(titleDiv);

  if (item.snippet) {
    const snip = document.createElement('div');
    snip.className = 'item-snippet';
    snip.innerHTML = highlightEntities(item.snippet, item);
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
// Entity highlighting: marks occurrences of the LLM extraction's structured
// entities (actor, victim, CVEs, IoCs) directly in the rendered text, found
// by case-insensitive substring search client-side. Replaces the old
// server-computed regex-span highlighting now that there's no regex
// matcher — an item has no entities to highlight until it's classified
// (see collectors/base.py's "pending" SSE payload), so this degrades
// gracefully to plain escaped text for unclassified items.
function highlightEntities(text, item) {
  if (!text) return escHtml(text);
  const needles = [];
  if (item.actor) needles.push(item.actor);
  if (item.victim) needles.push(item.victim);
  (item.cve_ids || []).forEach(v => needles.push(v));
  (item.iocs || []).forEach(v => needles.push(v));
  const terms = needles.map(n => String(n).trim()).filter(n => n.length >= 3);
  if (!terms.length) return escHtml(text);

  // Longest-first so a longer entity (e.g. a full domain) isn't pre-empted
  // by a shorter one that happens to be its substring.
  terms.sort((a, b) => b.length - a.length);

  const spans = [];
  const lowerText = text.toLowerCase();
  terms.forEach(term => {
    const lowerTerm = term.toLowerCase();
    let from = 0;
    while (true) {
      const idx = lowerText.indexOf(lowerTerm, from);
      if (idx === -1) break;
      spans.push({ start: idx, end: idx + term.length });
      from = idx + term.length;
    }
  });
  if (!spans.length) return escHtml(text);
  spans.sort((a, b) => a.start - b.start);

  let out = '';
  let prev = 0;
  for (const sp of spans) {
    if (sp.start < prev) continue; // overlapping — skip
    out += escHtml(text.slice(prev, sp.start));
    out += `<mark>${escHtml(text.slice(sp.start, sp.end))}</mark>`;
    prev = sp.end;
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
    } else if (payload && payload.type === 'activity') {
      handleLiveActivity(payload);
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
    if (state.items.length > MAX_FEED_ITEMS) state.items.length = MAX_FEED_ITEMS;
    totalCount.textContent = `${(state.items.length).toLocaleString()} items`;
  } else {
    state.pendingLive.push(item);
    newBanner.classList.remove('hidden');
  }
}

// ── Admin token (central header input) ───────────────────────────────────────
// The token unlocks admin-gated features across tabs: the targeted-
// investigation trigger, filtered-item view, and the case deep-research
// trigger. It lives in the header toolbar so it is reachable from every tab.
const ADMIN_TOKEN_KEY = 'mm_admin_token';
let adminEnabledServerSide = true;

function initAdminAuth() {
  adminTokenInput.value = localStorage.getItem(ADMIN_TOKEN_KEY) || '';
  adminTokenInput.addEventListener('input', () => {
    localStorage.setItem(ADMIN_TOKEN_KEY, adminTokenInput.value);
    updateAdminUiState();
  });
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
    adminTokenStatus.textContent = 'Admin token required for research/investigate';
    adminTokenStatus.classList.remove('hidden');
    adminTokenStatus.classList.add('error');
  }
  document.getElementById('show-filtered-row').classList.toggle('hidden', !token);
}

// ── Investigate tab ────────────────────────────────────────────────────────
// Investigator-triggered targeted research (POST /api/investigations) — see
// research/investigate.py. The investigator describes a case brief; Hermes
// researches existing source feeds + the open web, and (only if it finds a
// genuine match) the findings are integrated as feed items + a new case +
// any newly-discovered sources. Runs async; progress shows up in the
// Activity tab via subsystem="investigate", and this tab polls the
// investigation list for terminal status.
function initInvestigate() {
  document.getElementById('inv-submit').addEventListener('click', submitInvestigation);
  loadInvestigations();
  setInterval(loadInvestigations, 8000);
}

async function submitInvestigation() {
  const btn = document.getElementById('inv-submit');
  const status = document.getElementById('inv-status');
  const errBox = document.getElementById('inv-error');
  const brief = document.getElementById('inv-brief').value.trim();

  errBox.classList.add('hidden');
  if (!brief) {
    errBox.textContent = 'Describe the case before submitting.';
    errBox.classList.remove('hidden');
    return;
  }

  btn.disabled = true;
  status.textContent = 'Submitting…';
  try {
    const resp = await fetch('/api/investigations', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...adminHeaders() },
      body: JSON.stringify({ brief }),
    });
    const data = await resp.json();
    if (!resp.ok) {
      errBox.textContent = data.detail || 'Error';
      errBox.classList.remove('hidden');
      status.textContent = '';
    } else {
      status.textContent = '✓ queued — see below for progress';
      document.getElementById('inv-brief').value = '';
      setTimeout(() => { status.textContent = ''; }, 4000);
      loadInvestigations();
    }
  } catch (e) {
    errBox.textContent = String(e);
    errBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
  }
}

async function loadInvestigations() {
  if (!hasAdminToken()) return;
  const list = document.getElementById('inv-list');
  try {
    const data = await fetch('/api/investigations', { headers: adminHeaders() });
    if (!data.ok) return;
    const { investigations } = await data.json();
    list.innerHTML = '';
    if (!investigations || !investigations.length) {
      list.innerHTML = '<div class="empty-state">No investigations submitted yet.</div>';
      return;
    }
    investigations.forEach(inv => list.appendChild(buildInvestigationRow(inv)));
  } catch (e) {
    console.error('Failed to load investigations', e);
  }
}

function buildInvestigationRow(inv) {
  const row = document.createElement('div');
  row.className = 'investigation-row';

  const statusChip = document.createElement('span');
  statusChip.className = 'tag-chip inv-status-' + inv.status;
  statusChip.textContent = inv.status;
  row.appendChild(statusChip);

  const brief = document.createElement('span');
  brief.className = 'investigation-brief';
  brief.textContent = inv.brief.slice(0, 140) + (inv.brief.length > 140 ? '…' : '');
  row.appendChild(brief);

  const time = document.createElement('span');
  time.className = 'item-time';
  time.textContent = fmtTime(inv.created_at);
  row.appendChild(time);

  if (inv.case_id) {
    const link = document.createElement('button');
    link.className = 'link-button';
    link.textContent = 'View case →';
    link.addEventListener('click', () => openCaseFromInvestigation(inv.case_id));
    row.appendChild(link);
  }

  return row;
}

function openCaseFromInvestigation(caseId) {
  document.querySelector('.tab[data-tab="cases"]').click();
  selectCase(caseId);
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
  // Defensive: some legacy/external sources may store "YYYY-MM-DD HH:MM:SS"
  // (space-separated) instead of ISO's "T" separator; Date() doesn't accept
  // that form. Normalize it before the tz check below.
  iso = iso.replace(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2})/, '$1T$2');
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
  critical: '#e63946',
  warn: '#f4a261',
  info: '#2a9d8f',
  none: '#3f3f46',
};

// Cycled for Landscape's crime-type doughnut, which has an open-ended
// number of categories (unlike priority's fixed 4) — distinct enough hues
// to stay readable up to a dozen-ish slices.
const CHART_PALETTE = [
  '#f4a261', '#2a9d8f', '#e63946', '#c77dff', '#64dfdf',
  '#ff9ecd', '#7ee787', '#e76f51', '#9d4edd', '#56d4dd',
];

function initDashboard() {
  Chart.defaults.color = '#71717a';
  Chart.defaults.borderColor = '#27272a';
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
        backgroundColor: sorted.map(s => s.consecutive_errors > 0 ? PRIO_COLORS.warn : PRIO_COLORS.info),
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
      datasets: [{ label: 'cases', data: actors.map(a => a.count), backgroundColor: PRIO_COLORS.warn }],
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

// ── Landscape ──────────────────────────────────────────────────────────────
// Case-layer (deduplicated incident) situational-awareness view — see
// GET /api/stats/cases and /api/stats/cases/timeseries. Reuses dashCharts/
// upsertChart/PRIO_COLORS from the Feed tab's dashboard above.

const landscapeState = { windowDays: 30 };
const ACTOR_BAR_COLOR = '#c77dff';

const landscapeWindowSelect = document.getElementById('landscape-window-select');
const landscapeExportBtn = document.getElementById('landscape-export-btn');
const landscapeMapEl = document.getElementById('landscape-map');
const landscapeMapLegendEl = document.getElementById('landscape-map-legend');
const actorProfileOverlay = document.getElementById('actor-profile-overlay');
const actorProfileContent = document.getElementById('actor-profile-content');
const actorProfileClose = document.getElementById('actor-profile-close');

function initLandscape() {
  landscapeWindowSelect.addEventListener('change', () => {
    landscapeState.windowDays = landscapeWindowSelect.value ? parseInt(landscapeWindowSelect.value, 10) : null;
    loadLandscape();
  });
  actorProfileClose.addEventListener('click', closeActorProfile);
  actorProfileOverlay.addEventListener('click', (e) => {
    if (e.target === actorProfileOverlay) closeActorProfile();
  });
  landscapeExportBtn.addEventListener('click', () => {
    const params = landscapeWindowParams();
    params.set('trend_window_days', emergingTrendWindowDays());
    window.location.href = '/api/stats/landscape/export?' + params.toString();
  });
  loadLandscape();
}

function landscapeWindowParams() {
  const params = new URLSearchParams();
  if (landscapeState.windowDays) params.set('since_days', landscapeState.windowDays);
  else params.set('all_time', '1');
  return params;
}

async function loadLandscape() {
  try {
    const bucket = (landscapeState.windowDays && landscapeState.windowDays <= 60) ? 'day' : 'month';
    const statsParams = landscapeWindowParams();
    const tsParams = landscapeWindowParams();
    tsParams.set('bucket', bucket);

    const [stats, timeseries] = await Promise.all([
      api('/api/stats/cases' + (statsParams.toString() ? '?' + statsParams.toString() : '')),
      api('/api/stats/cases/timeseries?' + tsParams.toString()),
    ]);

    document.getElementById('landscape-gauge-total').textContent = stats.total.toLocaleString();
    document.getElementById('landscape-gauge-kev').textContent = stats.in_kev.toLocaleString();
    document.getElementById('landscape-gauge-sectors').textContent = stats.by_sector.length.toLocaleString();
    document.getElementById('landscape-gauge-actors').textContent = stats.by_actor.length.toLocaleString();

    renderLandscapeVolume(timeseries.buckets, bucket);
    renderLandscapeCrimeType(stats.by_crime_type);
    renderLandscapeCountry(stats.by_country);
    renderLandscapeSector(stats.by_sector);
    renderLandscapeActors(stats.by_actor);
    renderLandscapeMap(stats.by_country);
    renderEmergingPanels();
  } catch (e) {
    console.error('Failed to load landscape', e);
  }
}

function renderLandscapeVolume(buckets, bucketType) {
  upsertChart('chart-landscape-volume', {
    type: 'bar',
    data: {
      labels: buckets.map(b => b.bucket),
      datasets: ['info', 'warn', 'critical'].map(p => ({
        label: p,
        data: buckets.map(b => b[p] || 0),
        backgroundColor: PRIO_COLORS[p],
        stack: 'a',
      })),
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: { x: { stacked: true, ticks: { maxTicksLimit: 16 } }, y: { stacked: true, beginAtZero: true } },
      plugins: { legend: { display: true, position: 'bottom' } },
    },
  });
}

function renderLandscapeCrimeType(byCrimeType) {
  upsertChart('chart-landscape-crimetype', {
    type: 'doughnut',
    data: {
      labels: byCrimeType.map(r => r.crime_type),
      datasets: [{
        data: byCrimeType.map(r => r.n),
        backgroundColor: byCrimeType.map((_, i) => CHART_PALETTE[i % CHART_PALETTE.length]),
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'bottom' } },
    },
  });
}

function renderLandscapeCountry(byCountry) {
  const top = byCountry.slice(0, 12);
  upsertChart('chart-landscape-country', {
    type: 'bar',
    data: {
      labels: top.map(r => r.country),
      datasets: [{ label: 'victims', data: top.map(r => r.n), backgroundColor: PRIO_COLORS.warn }],
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

function renderLandscapeSector(bySector) {
  const top = bySector.slice(0, 12);
  upsertChart('chart-landscape-sector', {
    type: 'bar',
    data: {
      labels: top.map(r => r.sector),
      datasets: [{ label: 'cases', data: top.map(r => r.n), backgroundColor: PRIO_COLORS.info }],
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

function renderLandscapeActors(byActor) {
  const top = byActor.slice(0, 12);
  const chart = upsertChart('chart-landscape-actors', {
    type: 'bar',
    data: {
      labels: top.map(r => r.actor),
      datasets: [{ label: 'cases', data: top.map(r => r.n), backgroundColor: ACTOR_BAR_COLOR }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true } },
      onClick: (evt, elements) => {
        if (!elements.length) return;
        const actor = top[elements[0].index]?.actor;
        if (actor) openActorProfile(actor);
      },
      onHover: (evt, elements) => {
        evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
      },
    },
  });
  return chart;
}

// ── Emerging-trends panels ──────────────────────────────────────────────────
// Week-over-week (or whatever window the Landscape selector implies) actor/
// sector/CVE movement — see GET /api/stats/trends. Trend window is distinct
// from the Landscape volume/breakdown window above: those show "what's in
// this window," this shows "what's *changing* between this window and the
// one before it," which only makes sense at a bounded, comparable size (capped
// at 30 days — "all time vs. the all time before that" isn't meaningful).
const TREND_STATUS_LABEL = { emerging: 'NEW', rising: '▲', flat: '–', declining: '▼' };

function emergingTrendWindowDays() {
  const w = landscapeState.windowDays;
  if (!w || w > 30) return 7;
  return w;
}

async function renderEmergingPanels() {
  const windowDays = emergingTrendWindowDays();
  const row = document.getElementById('landscape-emerging-row');
  try {
    const [actorTrends, sectorTrends, cveTrends] = await Promise.all([
      api(`/api/stats/trends?dimension=actor&window_days=${windowDays}&limit=8`),
      api(`/api/stats/trends?dimension=sector&window_days=${windowDays}&limit=8`),
      api(`/api/stats/trends?dimension=cve&window_days=${windowDays}&limit=8`),
    ]);
    row.innerHTML = '';
    row.appendChild(buildEmergingPanel(`Actors (${windowDays}d vs prior)`, actorTrends.trends));
    row.appendChild(buildEmergingPanel(`Sectors (${windowDays}d vs prior)`, sectorTrends.trends));
    row.appendChild(buildEmergingPanel(`CVEs (${windowDays}d vs prior)`, cveTrends.trends, true));
  } catch (e) {
    console.error('Failed to load trends', e);
  }
}

function buildEmergingPanel(title, trends, showKev = false) {
  const panel = document.createElement('div');
  panel.className = 'emerging-panel';
  const h = document.createElement('h3');
  h.textContent = title;
  panel.appendChild(h);

  if (!trends.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = 'No activity in this window.';
    panel.appendChild(empty);
    return panel;
  }

  trends.forEach(t => {
    const row = document.createElement('div');
    row.className = 'emerging-row';

    const label = document.createElement('span');
    label.className = 'emerging-label';
    label.textContent = t.value + (showKev && t.in_kev ? ' ⚠ KEV' : '');
    row.appendChild(label);

    const delta = document.createElement('span');
    delta.className = 'emerging-delta trend-' + t.status;
    const deltaSign = t.delta > 0 ? '+' : '';
    delta.textContent = `${TREND_STATUS_LABEL[t.status] || ''} ${t.current} (${deltaSign}${t.delta})`;
    row.appendChild(delta);

    panel.appendChild(row);
  });
  return panel;
}

// ── Actor profile overlay ──────────────────────────────────────────────────
function closeActorProfile() {
  actorProfileOverlay.classList.add('hidden');
  // The sparkline's canvas is destroyed along with this innerHTML wipe —
  // drop its Chart.js instance too, or the next openActorProfile's
  // upsertChart('chart-actor-sparkline', ...) would try to .update() a
  // chart bound to a now-detached canvas instead of building a fresh one.
  if (dashCharts['chart-actor-sparkline']) {
    dashCharts['chart-actor-sparkline'].destroy();
    delete dashCharts['chart-actor-sparkline'];
  }
  actorProfileContent.innerHTML = '';
}

async function openActorProfile(actor) {
  actorProfileOverlay.classList.remove('hidden');
  if (dashCharts['chart-actor-sparkline']) {
    dashCharts['chart-actor-sparkline'].destroy();
    delete dashCharts['chart-actor-sparkline'];
  }
  actorProfileContent.innerHTML = '';
  const loading = document.createElement('p');
  loading.className = 'hint';
  loading.textContent = `Loading profile for ${actor}…`;
  actorProfileContent.appendChild(loading);

  try {
    const profile = await api(`/api/actors/${encodeURIComponent(actor)}`);
    renderActorProfile(profile);
  } catch (e) {
    actorProfileContent.innerHTML = '';
    const err = document.createElement('p');
    err.className = 'hint';
    err.textContent = `Failed to load profile: ${e}`;
    actorProfileContent.appendChild(err);
  }
}

function renderActorProfile(profile) {
  actorProfileContent.innerHTML = '';

  const h = document.createElement('h2');
  h.textContent = profile.actor;
  actorProfileContent.appendChild(h);

  const summary = document.createElement('div');
  summary.className = 'gauge-row actor-profile-stats';
  [
    ['Cases', profile.case_count],
    ['Victims', profile.victim_count],
    ['Sectors', profile.sectors.length],
    ['Countries', profile.countries.length],
    ['CVEs used', profile.cve_ids.length],
  ].forEach(([label, value]) => {
    const card = document.createElement('div');
    card.className = 'gauge-card';
    const v = document.createElement('div');
    v.className = 'gauge-value';
    v.textContent = value;
    const l = document.createElement('div');
    l.className = 'gauge-label';
    l.textContent = label;
    card.appendChild(v);
    card.appendChild(l);
    summary.appendChild(card);
  });
  actorProfileContent.appendChild(summary);

  if (profile.first_seen || profile.last_seen) {
    const range = document.createElement('p');
    range.className = 'hint';
    range.textContent = `Active ${fmtTime(profile.first_seen)} → ${fmtTime(profile.last_seen)}`;
    actorProfileContent.appendChild(range);
  }

  if (profile.sectors.length || profile.countries.length) {
    const chipsWrap = document.createElement('div');
    chipsWrap.className = 'item-meta';
    profile.sectors.forEach(s => {
      const chip = document.createElement('span');
      chip.className = 'tag-chip';
      chip.textContent = s;
      chipsWrap.appendChild(chip);
    });
    profile.countries.forEach(c => {
      const chip = document.createElement('span');
      chip.className = 'tag-chip cluster-chip';
      chip.textContent = c;
      chipsWrap.appendChild(chip);
    });
    actorProfileContent.appendChild(chipsWrap);
  }

  if (profile.activity && profile.activity.length) {
    const sparklineWrap = document.createElement('div');
    sparklineWrap.className = 'chart-canvas';
    sparklineWrap.style.height = '120px';
    sparklineWrap.style.marginTop = '14px';
    const canvas = document.createElement('canvas');
    canvas.id = 'chart-actor-sparkline';
    sparklineWrap.appendChild(canvas);
    actorProfileContent.appendChild(sparklineWrap);
    // Deferred one tick so the canvas is attached to the DOM (Chart.js needs
    // a laid-out element) before Chart.js measures it.
    setTimeout(() => {
      upsertChart('chart-actor-sparkline', {
        type: 'line',
        data: {
          labels: profile.activity.map(a => a.bucket),
          datasets: [{ data: profile.activity.map(a => a.n), borderColor: ACTOR_BAR_COLOR, tension: 0.3 }],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { y: { beginAtZero: true, ticks: { precision: 0 } } },
        },
      });
    }, 0);
  }

  const list = document.createElement('div');
  list.className = 'actor-profile-cases';
  profile.cases.forEach(c => {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'related-case-card';
    row.textContent = `${c.title} — ${c.damaged_party_sector || 'unknown sector'}, ${c.damaged_party_country || 'unknown country'}`;
    row.addEventListener('click', () => {
      closeActorProfile();
      document.querySelector('.tab[data-tab="cases"]').click();
      selectCase(c.id);
    });
    list.appendChild(row);
  });
  actorProfileContent.appendChild(list);
}

// expose for the actor leaderboard's onClick
window.openActorProfile = openActorProfile;

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
  filters: { search: '', searchMode: 'keyword', significance: '', kevOnly: false, crimeType: '', since: '', until: '', cveId: '', ioc: '', country: '' },
};
const CASE_FILTERS_DEFAULT = { ...casesState.filters };

const casesList        = document.getElementById('cases-list');
const casesEmpty       = document.getElementById('cases-empty');
const casesLoadMoreBtn = document.getElementById('cases-load-more');
const caseSearchInput  = document.getElementById('case-search-input');
const caseSearchModeToggle = document.getElementById('case-search-mode-toggle');
const caseSearchModeHint   = document.getElementById('case-search-mode-hint');
const caseKevOnlyCb    = document.getElementById('case-kev-only');
const caseSignificanceSelect = document.getElementById('case-significance-select');
const caseCrimeTypeSelect    = document.getElementById('case-crime-type-select');
const caseCountrySelect      = document.getElementById('case-country-select');
const caseSinceInput   = document.getElementById('case-since-input');
const caseUntilInput   = document.getElementById('case-until-input');
const caseFiltersClear = document.getElementById('case-filters-clear');
const caseDetailPane   = document.getElementById('case-detail');
const caseDetailEmpty  = document.getElementById('case-detail-empty');

// Native, zero-data country-code -> English-name lookup (avoids shipping a
// second name table alongside country.py's server-side one).
const countryDisplayNames = (() => {
  try {
    return new Intl.DisplayNames(['en'], { type: 'region' });
  } catch (e) {
    return null;
  }
})();
function countryLabel(code) {
  if (!code) return code;
  try {
    return (countryDisplayNames && countryDisplayNames.of(code)) || code;
  } catch (e) {
    return code;
  }
}

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
  caseCountrySelect.addEventListener('change', () => {
    casesState.filters.country = caseCountrySelect.value;
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
    casesState.filters = { ...CASE_FILTERS_DEFAULT };
    caseSearchInput.value = '';
    caseKevOnlyCb.checked = false;
    caseSignificanceSelect.value = '';
    caseCrimeTypeSelect.value = '';
    caseCountrySelect.value = '';
    caseSinceInput.value = '';
    caseUntilInput.value = '';
    syncSearchModeToggle(caseSearchModeToggle, casesState.filters.searchMode);
    caseSearchModeHint.classList.add('hidden');
    updateIndicatorPivotBanner();
    applyCaseFilters();
  });
  document.getElementById('case-pivot-clear').addEventListener('click', () => {
    casesState.filters.cveId = '';
    casesState.filters.ioc = '';
    updateIndicatorPivotBanner();
    applyCaseFilters();
  });
  casesLoadMoreBtn.addEventListener('click', loadMoreCases);
  initSearchModeToggle(caseSearchModeToggle, caseSearchModeHint, mode => {
    casesState.filters.searchMode = mode;
    applyCaseFilters();
  });

  loadCaseStats();
  applyCaseFilters();
  setInterval(loadCaseStats, 30000);
}

function caseQueryParams(extra = {}) {
  const params = new URLSearchParams();
  if (casesState.filters.search) params.set('search', casesState.filters.search);
  if (casesState.filters.searchMode === 'semantic') params.set('mode', 'semantic');
  if (casesState.filters.significance) params.set('min_significance', casesState.filters.significance);
  if (casesState.filters.kevOnly) params.set('in_kev', 'true');
  if (casesState.filters.crimeType) params.set('crime_type', casesState.filters.crimeType);
  if (casesState.filters.country) params.set('country', casesState.filters.country);
  if (casesState.filters.since) params.set('since', casesState.filters.since);
  if (casesState.filters.until) params.set('until', casesState.filters.until);
  if (casesState.filters.cveId) params.set('cve_id', casesState.filters.cveId);
  if (casesState.filters.ioc) params.set('ioc', casesState.filters.ioc);
  Object.entries(extra).forEach(([k, v]) => params.set(k, v));
  return params.toString();
}

// ── Indicator pivot (CVE/IoC chips in the case detail pane) ────────────────
// "Click a CVE/IoC -> every other case sharing it" — see GET /api/cases'
// cve_id/ioc filters (db._build_cases_where). Resets the other case filters
// so the pivot shows the complete picture rather than a stale, narrowed one.
function pivotCasesByIndicator(kind, value) {
  casesState.filters = { ...CASE_FILTERS_DEFAULT, [kind]: value };
  caseSearchInput.value = '';
  caseKevOnlyCb.checked = false;
  caseSignificanceSelect.value = '';
  caseCrimeTypeSelect.value = '';
  caseCountrySelect.value = '';
  caseSinceInput.value = '';
  caseUntilInput.value = '';
  syncSearchModeToggle(caseSearchModeToggle, casesState.filters.searchMode);
  caseSearchModeHint.classList.add('hidden');
  updateIndicatorPivotBanner();
  document.querySelector('.tab[data-tab="cases"]').click();
  applyCaseFilters();
}

function updateIndicatorPivotBanner() {
  const banner = document.getElementById('case-pivot-banner');
  const label = document.getElementById('case-pivot-label');
  const value = casesState.filters.cveId || casesState.filters.ioc;
  if (!value) {
    banner.classList.add('hidden');
    return;
  }
  label.textContent = `Showing cases sharing ${casesState.filters.cveId ? 'CVE' : 'IoC'}: ${value}`;
  banner.classList.remove('hidden');
}

async function applyCaseFilters() {
  casesState.offset = 0;
  try {
    const data = await api('/api/cases?' + caseQueryParams({ limit: casesState.pageSize, offset: 0 }));
    if (data.semantic_unavailable) showSemanticUnavailableHint(caseSearchModeHint);
    casesState.cases = data.cases;
    casesState.hasMore = data.cases.length === casesState.pageSize && data.total > casesState.pageSize;
    renderCasesList();
    loadCaseCountryOptions();
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

// ── Cases country dropdown ──────────────────────────────────────────────
// The Cases tab keeps only the <select> filter; the choropleth map itself
// now lives on the Landscape tab (see "Landscape world map" below).
async function loadCaseCountryOptions() {
  try {
    const data = await api('/api/cases/by-country?' + caseQueryParams());
    const counts = {};
    (data.by_country || []).forEach(({ country, n }) => { counts[country] = n; });
    populateCaseCountrySelect(counts);
  } catch (e) {
    console.error('Failed to load case country counts', e);
  }
}

function populateCaseCountrySelect(counts) {
  const current = casesState.filters.country;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  // Keep the active filter selectable even if it now matches zero cases
  // (e.g. combined with a search term) — otherwise the <select> silently
  // resets to "All countries" while casesState.filters.country is still set.
  if (current && !(current in counts)) entries.unshift([current, 0]);
  caseCountrySelect.innerHTML = '<option value="">All countries</option>';
  entries.forEach(([code, n]) => {
    const opt = document.createElement('option');
    opt.value = code;
    opt.textContent = `${countryLabel(code)} (${n})`;
    caseCountrySelect.appendChild(opt);
  });
  caseCountrySelect.value = current || '';
}

// Jump to the Cases tab filtered to a single victim country — used by the
// Landscape map's click-to-filter below.
function pivotCasesByCountry(code) {
  casesState.filters = { ...CASE_FILTERS_DEFAULT, country: code };
  caseSearchInput.value = '';
  caseKevOnlyCb.checked = false;
  caseSignificanceSelect.value = '';
  caseCrimeTypeSelect.value = '';
  caseSinceInput.value = '';
  caseUntilInput.value = '';
  syncSearchModeToggle(caseSearchModeToggle, casesState.filters.searchMode);
  caseSearchModeHint.classList.add('hidden');
  updateIndicatorPivotBanner();
  document.querySelector('.tab[data-tab="cases"]').click();
  applyCaseFilters();
}

// ── Landscape world map ──────────────────────────────────────────────────
// Vendored inline SVG (see static/world.svg, CC BY-SA 3.0 — credited in
// index.html) with <path id="xx">/<g id="xx"> keyed by lowercase ISO 3166-1
// alpha-2, matching the canonical codes country.py normalizes into
// damaged_party_country. Choropleth buckets are plain CSS classes toggled
// on those shapes — no charting/map library needed, consistent with the
// rest of this vanilla-JS app. Counts come from the same /api/stats/cases
// by_country breakdown that already feeds the "Victims by country" bar
// chart, so the map honors the Landscape window filter automatically.
// Clicking a country jumps to the Cases tab filtered to it (see
// pivotCasesByCountry above) rather than filtering in place.
let landscapeMapSvgPromise = null;
const LANDSCAPE_MAP_BUCKETS = 4;
let landscapeMapCounts = {};

function ensureLandscapeMapSvg() {
  if (!landscapeMapSvgPromise) {
    landscapeMapSvgPromise = fetch('/world.svg')
      .then(r => r.text())
      .then(svgText => {
        landscapeMapEl.innerHTML = svgText;
        const svg = landscapeMapEl.querySelector('svg');
        if (svg) {
          svg.removeAttribute('width');
          svg.removeAttribute('height');
          svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
        }
        landscapeMapEl.addEventListener('click', onLandscapeMapClick);
      })
      .catch(e => console.error('Failed to load world map', e));
  }
  return landscapeMapSvgPromise;
}

function onLandscapeMapClick(e) {
  const el = e.target.closest('path[id], g[id]');
  if (!el) return;
  const code = el.id.toUpperCase();
  if (code.length !== 2) return; // skip non-ISO "_named" territories
  if (!landscapeMapCounts[code]) return;
  pivotCasesByCountry(code);
}

async function renderLandscapeMap(byCountry) {
  const counts = {};
  (byCountry || []).forEach(({ country, n }) => { counts[country] = n; });
  landscapeMapCounts = counts;
  await ensureLandscapeMapSvg();
  const svg = landscapeMapEl.querySelector('svg');
  if (!svg) return;
  const max = Math.max(0, ...Object.values(counts));

  svg.querySelectorAll('path[id], g[id]').forEach(el => {
    const code = el.id.toUpperCase();
    if (code.length !== 2) return; // skip non-ISO "_named" territories
    // Some countries (e.g. AU/CA/CN/US) are <g id="xx"> groups of multiple
    // child <path>s rather than a single <path id="xx">; style every child
    // path so the whole country gets colored/hover-highlighted consistently.
    const paths = el.tagName.toLowerCase() === 'path' ? [el] : Array.from(el.querySelectorAll('path'));
    paths.forEach(path => path.classList.remove('q0', 'q1', 'q2', 'q3', 'q4'));
    const n = counts[code] || 0;
    const bucket = n === 0 ? 0 : Math.min(LANDSCAPE_MAP_BUCKETS, Math.ceil((n / max) * LANDSCAPE_MAP_BUCKETS));
    const title = el.querySelector(':scope > title');
    if (n > 0) {
      paths.forEach(path => path.classList.add('q' + bucket));
      const t = title || el.appendChild(document.createElementNS('http://www.w3.org/2000/svg', 'title'));
      t.textContent = `${countryLabel(code)} — ${n} case${n === 1 ? '' : 's'}`;
    } else {
      paths.forEach(path => path.classList.add('q' + bucket));
      if (title) title.remove();
    }
  });

  renderLandscapeMapLegend(max);
}

function renderLandscapeMapLegend(max) {
  landscapeMapLegendEl.innerHTML = '';
  if (max === 0) return;
  const swatches = [0, 1, 2, 3, 4];
  swatches.forEach(bucket => {
    const item = document.createElement('span');
    item.className = 'case-map-legend-item';
    const swatch = document.createElement('span');
    swatch.className = 'case-map-legend-swatch q' + bucket;
    item.appendChild(swatch);
    const label = document.createElement('span');
    label.textContent = bucket === 0 ? '0' : Math.ceil((bucket / LANDSCAPE_MAP_BUCKETS) * max);
    item.appendChild(label);
    landscapeMapLegendEl.appendChild(item);
  });
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
  titleDiv.textContent = `#${c.id} · ${c.title}`;
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

// Standard CVSS v3 qualitative severity bands — mirrors
// api/routes.py's _cvss_severity_label (cases.cvss_max stores only the
// numeric max, so the label is derived client-side for display).
function cvssSeverityLabel(score) {
  if (score >= 9.0) return 'Critical';
  if (score >= 7.0) return 'High';
  if (score >= 4.0) return 'Medium';
  if (score > 0.0) return 'Low';
  return 'None';
}

// Plain (non-pivotable) chip row for case-detail fields that don't have a
// backend filter to pivot through yet (CWE/MITRE — contrast with the CVE
// row below, which pivots via pivotCasesByIndicator).
function buildStaticChipRow(label, values) {
  const row = document.createElement('div');
  row.className = 'hint';
  const labelEl = document.createElement('b');
  labelEl.textContent = label + ': ';
  row.appendChild(labelEl);
  const chipWrap = document.createElement('span');
  chipWrap.className = 'ioc-chip-row inline-chip-row';
  values.forEach(v => {
    const chip = document.createElement('span');
    chip.className = 'ioc-chip';
    chip.textContent = v;
    chipWrap.appendChild(chip);
  });
  row.appendChild(chipWrap);
  return row;
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
  const idTag = document.createElement('span');
  idTag.className = 'case-id-tag';
  idTag.textContent = `#${c.id}`;
  idTag.title = 'Case ID — used for "Merge with case…"';
  header.appendChild(idTag);
  if (c.significance) {
    const chip = document.createElement('span');
    chip.className = 'tag-chip prio-' + c.significance;
    chip.textContent = c.significance.toUpperCase();
    header.appendChild(chip);
  }
  const exportLink = document.createElement('a');
  exportLink.className = 'link-button';
  exportLink.href = `/api/cases/${c.id}/export?format=md`;
  exportLink.textContent = 'Export (.md)';
  exportLink.setAttribute('download', '');
  header.appendChild(exportLink);

  if (hasAdminToken()) {
    const mergeBtn = document.createElement('button');
    mergeBtn.type = 'button';
    mergeBtn.className = 'btn-merge-case';
    mergeBtn.textContent = 'Merge with case…';
    mergeBtn.addEventListener('click', () => requestCaseMerge(c.id, mergeBtn));
    header.appendChild(mergeBtn);
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
    ['In KEV', c.in_kev ? 'yes' : 'no'],
    ['CVSS (max)', c.cvss_max != null ? `${c.cvss_max} (${cvssSeverityLabel(c.cvss_max)})` : null],
    ['EPSS (max)', c.epss_max != null ? c.epss_max.toFixed(3) : null],
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

  // CVEs get their own pivotable-chip row instead of a plain joined string —
  // each one is a click-through to every other case citing the same CVE.
  if (c.cve_ids && c.cve_ids.length) {
    const cveRow = document.createElement('div');
    cveRow.className = 'hint';
    const label = document.createElement('b');
    label.textContent = 'CVEs: ';
    cveRow.appendChild(label);
    const chipWrap = document.createElement('span');
    chipWrap.className = 'ioc-chip-row inline-chip-row';
    c.cve_ids.forEach(cveId => {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'ioc-chip ioc-chip-clickable';
      chip.textContent = cveId;
      chip.title = `Show every case citing ${cveId}`;
      chip.addEventListener('click', () => pivotCasesByIndicator('cveId', cveId));
      chipWrap.appendChild(chip);
    });
    cveRow.appendChild(chipWrap);
    grid.appendChild(cveRow);
  }

  if (c.cwe_ids && c.cwe_ids.length) {
    grid.appendChild(buildStaticChipRow('CWE', c.cwe_ids));
  }
  if (c.mitre_techniques && c.mitre_techniques.length) {
    grid.appendChild(buildStaticChipRow('MITRE ATT&CK', c.mitre_techniques));
  }

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
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'ioc-chip ioc-chip-clickable';
      chip.textContent = ioc;
      chip.title = `Show every case sharing this indicator`;
      chip.addEventListener('click', () => pivotCasesByIndicator('ioc', ioc));
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
      rcard.appendChild(document.createTextNode(`#${r.case_id} · ${r.title}`));
      const rreasons = document.createElement('div');
      rreasons.className = 'related-reasons';
      rreasons.textContent = `${(r.reasons || []).join(', ')} · score ${(r.score * 100).toFixed(0)}%`;
      rcard.appendChild(rreasons);
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

async function requestCaseMerge(caseId, btn) {
  const otherId = prompt('Enter the ID of the case to merge into this one:');
  if (!otherId || !otherId.trim()) return;
  const otherCaseId = parseInt(otherId.trim(), 10);
  if (!otherCaseId || otherCaseId === caseId) {
    alert('Please enter a different valid case ID.');
    return;
  }
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Merging…';
  try {
    await api(`/api/cases/${caseId}/merge/${otherCaseId}`, { method: 'POST', headers: adminHeaders() });
    btn.textContent = 'Merged';
    // Refresh the case list and reopen the surviving case.
    await applyCaseFilters();
    await selectCase(caseId);
  } catch (e) {
    btn.disabled = false;
    btn.textContent = originalText;
    let msg = 'Merge failed.';
    if (e && e.status) {
      if (e.status === 403) msg = 'Invalid admin token.';
      else if (e.status === 404) msg = 'Case not found.';
      else if (e.status === 400) msg = 'Cannot merge a case with itself.';
      else msg = `Server error ${e.status}.`;
    }
    alert(msg);
    console.error('Failed to merge cases', e);
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

// ── Real-time subsystem queues panel (Activity tab) ──────────────────────────
// Formerly a global status bar shown above every tab; the data now lives
// only in the Activity tab (#queues-panel). Still polled unconditionally
// from app bootstrap (not gated to the Activity tab being visible) because
// it also carries the admin/semantic-search availability flags every tab's
// UI depends on — same pattern as loadSources/loadDashboard's unconditional
// 30s polls elsewhere in this file.
function initQueuesPanel() {
  updateQueuesPanel();
  setInterval(updateQueuesPanel, 10000);
}

async function updateQueuesPanel() {
  try {
    const s = await api('/api/status');
    renderQueuesPanel(s);
  } catch (e) {
    console.error('Failed to load status', e);
  }
}

function renderQueuesPanel(s) {
  adminEnabledServerSide = !!(s.admin && s.admin.enabled);
  updateAdminUiState();

  semanticSearchEnabled = !!(s.semantic_search && s.semantic_search.enabled);
  setSearchModeToggleEnabled(searchModeToggle, semanticSearchEnabled);
  setSearchModeToggleEnabled(caseSearchModeToggle, semanticSearchEnabled);

  renderQueuesChart(s);
  renderQueuesSummary(s);
}

// Magnitude (not just ok/warn/error) is the point here — a pill saying
// "research: active" doesn't say whether that's 2 cases or 200, which was
// the whole complaint about the old status-pill row. A bar per queue
// depth makes that visible at a glance.
function renderQueuesChart(s) {
  const cls = s.classifier || {};
  const corr = s.correlation || {};
  const res = s.research || {};
  const heal = s.heal || {};
  const inv = s.investigate || {};

  const labels = ['Classifier backlog', 'Correlator backlog', 'Research running', 'Research queued', 'Investigate queued', 'Heal pending'];
  const data = [
    cls.backlog || 0,
    corr.backlog || 0,
    res.running || 0,
    res.queued || 0,
    inv.queued || 0,
    (heal.proposals || {}).pending || 0,
  ];
  const errorFlags = [
    cls.consecutive_errors >= 3, corr.consecutive_errors >= 3,
    res.consecutive_errors >= 3, res.consecutive_errors >= 3,
    inv.consecutive_errors >= 3, heal.consecutive_errors >= 3,
  ];
  const colors = errorFlags.map(err => err ? PRIO_COLORS.critical : PRIO_COLORS.warn);

  upsertChart('chart-queues', {
    type: 'bar',
    data: { labels, datasets: [{ label: 'queue depth', data, backgroundColor: colors }] },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, ticks: { precision: 0 } } },
    },
  });
}

function renderQueuesSummary(s) {
  const list = document.getElementById('queues-summary-list');
  list.innerHTML = '';

  const sched = s.scheduler || {};
  const src = s.sources || {};
  const cls = s.classifier || {};
  const kev = s.kev || {};

  const lines = [
    [sched.running ? 'scheduler: running' : 'scheduler: stopped', sched.running ? 'ok' : 'error'],
    [`sources: ${src.total - src.failing_count}/${src.total} healthy`, src.failing_count > 0 ? 'warn' : 'ok'],
    [
      cls.backend === 'none' ? 'classifier: disabled' : cls.using_fallback ? 'classifier: hermes fallback' : 'classifier: primary backend',
      cls.consecutive_errors >= 3 ? 'error' : (cls.using_fallback ? 'warn' : 'ok'),
    ],
    [`KEV catalog: ${(kev.count || 0).toLocaleString()}`, 'ok'],
  ];

  lines.forEach(([text, state]) => {
    const row = document.createElement('div');
    row.className = 'status-line status-' + state;
    row.textContent = text;
    list.appendChild(row);
  });
}

// SSE may also push lightweight status events from background jobs.
function handleStatusEvent(payload) {
  // A full status payload mirrors /api/status; partial payloads update
  // individual subsystems. Refresh the panel from the server to keep it
  // simple and consistent.
  updateQueuesPanel();
}

// ── Real-time token burn rate (Activity tab) ─────────────────────────────────
// Real (measured, not estimated) usage — see GET /api/tokens and
// db.token_usage's schema comment. Same unconditional-poll pattern as
// initQueuesPanel above.
function initTokenBurn() {
  updateTokenBurn();
  setInterval(updateTokenBurn, 10000);
}

async function updateTokenBurn() {
  try {
    const data = await api('/api/tokens');
    renderTokenBurn(data);
  } catch (e) {
    console.error('Failed to load token usage', e);
  }
}

function renderTokenBurn(data) {
  const burn = data.burn || {};
  document.getElementById('burn-tokens-per-hour').textContent =
    burn.tokens_per_hour != null ? Math.round(burn.tokens_per_hour).toLocaleString() : '—';
  document.getElementById('burn-input-tokens').textContent =
    burn.input_tokens != null ? burn.input_tokens.toLocaleString() : '—';
  document.getElementById('burn-output-tokens').textContent =
    burn.output_tokens != null ? burn.output_tokens.toLocaleString() : '—';

  renderTokenBurnChart(data.timeseries || []);
  // Deliberately no by-source/by-model breakdown here: which provider/model
  // hermes' config *names* as primary is frequently not what's actually
  // serving traffic once that provider is rate-limited/exhausted and hermes
  // falls through its own fallback chain — see hermes/usage_ingest.py's
  // docstring. The aggregate tokens/hour figure above is accurate regardless
  // of which provider served it; a per-model breakdown here would just be
  // misleading about "what's primary."
}

function renderTokenBurnChart(timeseries) {
  const labels = timeseries.map(b => fmtTime(new Date(b.t * 1000).toISOString()));
  const data = timeseries.map(b => b.tokens);
  upsertChart('chart-token-burn', {
    type: 'line',
    data: {
      labels,
      datasets: [{
        label: 'tokens',
        data,
        borderColor: PRIO_COLORS.warn,
        backgroundColor: 'transparent',
        tension: 0.25,
        pointRadius: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true } },
    },
  });
}

// ── AI Activity log ───────────────────────────────────────────────────────
// Public, no admin token — see GET /api/activity and db.py's ai_activity
// table docstring. Every row here is something an AI subsystem did fully
// autonomously; this tab is the transparency record, not a control surface
// (there is deliberately no approve/revert action here).

const activityState = {
  events: [],
  offset: 0,
  pageSize: 50,
  hasMore: false,
  pendingLive: [],
  filters: { subsystem: '', status: '' },
};
const ACTIVITY_MAX_LIVE_ROWS = 200; // prevent an unattended dashboard tab from growing forever

const activityList       = document.getElementById('activity-list');
const activityEmpty      = document.getElementById('activity-empty');
const activityLoadMoreBtn = document.getElementById('activity-load-more');
const activityNewBanner  = document.getElementById('activity-new-banner');
const activitySubsystemSelect = document.getElementById('activity-subsystem-select');
const activityStatusSelect    = document.getElementById('activity-status-select');
const activityFiltersClear    = document.getElementById('activity-filters-clear');

function initActivity() {
  activitySubsystemSelect.addEventListener('change', () => {
    activityState.filters.subsystem = activitySubsystemSelect.value;
    applyActivityFilters();
  });
  activityStatusSelect.addEventListener('change', () => {
    activityState.filters.status = activityStatusSelect.value;
    applyActivityFilters();
  });
  activityFiltersClear.addEventListener('click', () => {
    activityState.filters = { subsystem: '', status: '' };
    activitySubsystemSelect.value = '';
    activityStatusSelect.value = '';
    applyActivityFilters();
  });
  activityLoadMoreBtn.addEventListener('click', loadMoreActivity);
  applyActivityFilters();
  refreshSourceOverview();
}

// ── Source overview (issue #17) ─────────────────────────────────────────────
// A leaderboard + region/media_kind distribution for every configured
// source, surfaced in the Activity tab per the issue's "could be integrated
// into the activity tab" steer. The leaderboard renders straight from
// state.sources (already refreshed every 30s by loadSources — see
// app.js:76), so it stays current without its own poll loop; the
// distribution charts pull GET /api/stats/sources, a thin wrapper around
// sources/value.py's bucket_counts() already computed for the scoring
// engine's diversity component.
const SOURCE_VALUE_COLORS = { valuable: 'var(--prio-info)', marginal: 'var(--prio-warn)', dead: 'var(--prio-critical)' };
const SOURCE_BUCKET_COLORS = ['#f4a261', '#2a9d8f', '#e63946', '#9d4edd', '#64dfdf', '#c77dff'];

async function refreshSourceOverview() {
  renderSourceLeaderboard();
  try {
    const buckets = await api('/api/stats/sources');
    renderSourceBucketChart('chart-source-region', buckets.region);
    renderSourceBucketChart('chart-source-media-kind', buckets.media_kind);
  } catch (e) {
    console.error('Failed to load source distribution', e);
  }
}

function renderSourceLeaderboard() {
  const panel = document.getElementById('source-leaderboard');
  if (!panel) return;
  panel.querySelectorAll('.emerging-row, p.hint').forEach(el => el.remove());

  const ranked = [...state.sources]
    .filter(s => s.enabled)
    .sort((a, b) => (b.value_score ?? -1) - (a.value_score ?? -1));

  if (!ranked.length) {
    const empty = document.createElement('p');
    empty.className = 'hint';
    empty.textContent = state.sources.length ? 'No enabled sources.' : 'No sources configured.';
    panel.appendChild(empty);
    return;
  }

  ranked.forEach(src => {
    const row = document.createElement('div');
    row.className = 'emerging-row';

    const label = document.createElement('span');
    label.className = 'emerging-label';
    label.textContent = src.name;
    row.appendChild(label);

    const badge = document.createElement('span');
    const cls = src.value_classification;
    badge.className = 'emerging-delta';
    badge.style.color = SOURCE_VALUE_COLORS[cls] || 'var(--text-muted)';
    const scoreText = src.value_score != null ? src.value_score.toFixed(2) : '—';
    badge.textContent = cls ? `${cls} (${scoreText})` : 'unscored';
    row.appendChild(badge);

    panel.appendChild(row);
  });
}

function renderSourceBucketChart(canvasId, counts) {
  const labels = Object.keys(counts);
  const data = labels.map(l => counts[l]);
  upsertChart(canvasId, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data, backgroundColor: labels.map((_, i) => SOURCE_BUCKET_COLORS[i % SOURCE_BUCKET_COLORS.length]) }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: true, position: 'bottom' } },
    },
  });
}

function activityQueryParams(extra = {}) {
  const params = new URLSearchParams();
  if (activityState.filters.subsystem) params.set('subsystem', activityState.filters.subsystem);
  if (activityState.filters.status) params.set('status', activityState.filters.status);
  Object.entries(extra).forEach(([k, v]) => params.set(k, v));
  return params.toString();
}

async function applyActivityFilters() {
  activityState.offset = 0;
  activityNewBanner.classList.add('hidden');
  activityState.pendingLive = [];
  try {
    const data = await api('/api/activity?' + activityQueryParams({ limit: activityState.pageSize, offset: 0 }));
    activityState.events = data.events;
    activityState.hasMore = data.events.length === activityState.pageSize && data.total > activityState.pageSize;
    renderActivityList();
  } catch (e) {
    console.error('Failed to load activity', e);
  }
}

async function loadMoreActivity() {
  activityState.offset += activityState.pageSize;
  try {
    const data = await api(
      '/api/activity?' + activityQueryParams({ limit: activityState.pageSize, offset: activityState.offset })
    );
    activityState.events = activityState.events.concat(data.events);
    activityState.hasMore = data.events.length === activityState.pageSize;
    renderActivityList();
  } catch (e) {
    console.error('Failed to load more activity', e);
  }
}

function renderActivityList() {
  activityList.innerHTML = '';
  activityEmpty.classList.toggle('hidden', activityState.events.length > 0);
  activityState.events.forEach(ev => activityList.appendChild(buildActivityRow(ev)));
  activityLoadMoreBtn.classList.toggle('hidden', !activityState.hasMore);
}

function buildActivityRow(ev) {
  const row = document.createElement('div');
  row.className = 'item-card activity-row status-' + (ev.status || 'ok');

  const meta = document.createElement('div');
  meta.className = 'item-meta';

  const time = document.createElement('span');
  time.className = 'item-time';
  time.textContent = fmtTime(ev.ts);
  meta.appendChild(time);

  const subsystemChip = document.createElement('span');
  subsystemChip.className = 'tag-chip activity-subsystem-' + ev.subsystem;
  subsystemChip.textContent = ev.subsystem;
  meta.appendChild(subsystemChip);

  if (ev.status && ev.status !== 'ok') {
    const statusChip = document.createElement('span');
    statusChip.className = 'tag-chip prio-' + (ev.status === 'error' ? 'critical' : 'warn');
    statusChip.textContent = ev.status;
    meta.appendChild(statusChip);
  }

  if (ev.model) {
    const modelChip = document.createElement('span');
    modelChip.className = 'tag-chip';
    modelChip.textContent = ev.model;
    meta.appendChild(modelChip);
  }

  row.appendChild(meta);

  const summary = document.createElement('div');
  summary.className = 'item-title';
  summary.textContent = ev.summary;
  row.appendChild(summary);

  if (ev.ref_type === 'case' && ev.ref_id) {
    const link = document.createElement('button');
    link.className = 'link-button';
    link.type = 'button';
    link.textContent = `→ Open case #${ev.ref_id}`;
    link.addEventListener('click', () => {
      document.querySelector('.tab[data-tab="cases"]').click();
      selectCase(Number(ev.ref_id));
    });
    row.appendChild(link);
  }

  if (ev.detail && Object.keys(ev.detail).length > 0) {
    const details = document.createElement('details');
    details.className = 'activity-detail';
    const summaryEl = document.createElement('summary');
    summaryEl.textContent = 'Detail';
    details.appendChild(summaryEl);
    const pre = document.createElement('pre');
    pre.textContent = JSON.stringify(ev.detail, null, 2);
    details.appendChild(pre);
    row.appendChild(details);
  }

  return row;
}

function handleLiveActivity(ev) {
  const matchesSubsystem = !activityState.filters.subsystem || ev.subsystem === activityState.filters.subsystem;
  const matchesStatus = !activityState.filters.status || ev.status === activityState.filters.status;
  if (!matchesSubsystem || !matchesStatus) return;

  const scrollEl = document.getElementById('tab-activity');
  const atTop = (scrollEl ? scrollEl.scrollTop : 0) < 50;
  if (atTop) {
    const row = buildActivityRow(ev);
    row.classList.add('fadeIn');
    activityList.prepend(row);
    activityState.events.unshift(ev);
    if (activityState.events.length > ACTIVITY_MAX_LIVE_ROWS) {
      activityState.events.pop();
      if (activityList.lastElementChild) activityList.lastElementChild.remove();
    }
  } else {
    activityState.pendingLive.push(ev);
    activityNewBanner.classList.remove('hidden');
  }
}
