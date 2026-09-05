'use strict';
const report = window.INVESTIGATION;
const anomaly = report.anomalies[0];
const map = document.querySelector('#file-map');
const fragment = document.createDocumentFragment();
report.manifest.forEach((file) => {
  const cell = document.createElement('span');
  cell.className = `file-cell${file.different ? ' abnormal' : ''}`;
  cell.title = `${file.name} — ${file.different ? 'отличается: 16 → 42' : 'совпадает с большинством'}`;
  fragment.appendChild(cell);
});
map.appendChild(fragment);

function highlight(text, start, end, className) {
  const box = document.createDocumentFragment();
  box.appendChild(document.createTextNode(text.slice(0, start)));
  const mark = document.createElement('mark');
  mark.className = className;
  mark.textContent = text.slice(start, end);
  box.appendChild(mark);
  box.appendChild(document.createTextNode(text.slice(end)));
  return box;
}

function renderContext(hex) {
  [['#baseline-context', report.baseline.text, 'removed'], ['#anomaly-context', anomaly.text, 'added']].forEach(([selector, text, className]) => {
    const el = document.querySelector(selector);
    const start = hex ? 37 : 26;
    const end = hex ? 47 : 58;
    const before = hex ? Array.from(text.slice(start, 41)).map(ch => ch.charCodeAt(0).toString(16).toUpperCase()).join(' ') + ' ' : text.slice(start, 41);
    const changed = hex ? Array.from(text.slice(41, 43)).map(ch => ch.charCodeAt(0).toString(16).toUpperCase()).join(' ') : text.slice(41, 43);
    const after = hex ? ' ' + Array.from(text.slice(43, end)).map(ch => ch.charCodeAt(0).toString(16).toUpperCase()).join(' ') : text.slice(43, end);
    el.replaceChildren();
    const ellipsis = () => { const span = document.createElement('span'); span.className = 'ellipsis'; span.textContent = '…'; return span; };
    el.append(ellipsis(), document.createTextNode(before));
    const mark = document.createElement('mark'); mark.className = className; mark.textContent = changed;
    el.append(mark, document.createTextNode(after), ellipsis());
  });
  document.querySelector('#text-mode').classList.toggle('active', !hex);
  document.querySelector('#hex-mode').classList.toggle('active', hex);
  document.querySelector('#text-mode').setAttribute('aria-pressed', String(!hex));
  document.querySelector('#hex-mode').setAttribute('aria-pressed', String(hex));
}
document.querySelector('#text-mode').addEventListener('click', () => renderContext(false));
document.querySelector('#hex-mode').addEventListener('click', () => renderContext(true));
renderContext(false);
document.querySelector('#full-baseline').appendChild(highlight(report.baseline.text, 41, 43, 'removed'));
document.querySelector('#full-anomaly').appendChild(highlight(anomaly.text, 41, 43, 'added'));
document.querySelector('#show-full').addEventListener('click', (event) => {
  const full = document.querySelector('#full-comparison');
  full.hidden = !full.hidden;
  event.currentTarget.setAttribute('aria-expanded', String(!full.hidden));
  event.currentTarget.textContent = full.hidden ? 'Показать все 1002 символа +' : 'Свернуть полное содержимое −';
});

let toastTimer;
function toast(message) {
  const box = document.querySelector('#toast');
  box.textContent = message; box.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => { box.hidden = true; }, 3500);
}
document.querySelectorAll('[data-copy]').forEach(button => button.addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(button.dataset.copy); toast('SHA-256 скопирован'); }
  catch { toast('Не удалось скопировать. Выделите значение вручную.'); }
}));

let selectedArchive = 0;
document.querySelector('#archive-input').addEventListener('change', async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  const revision = ++selectedArchive;
  const status = document.querySelector('#archive-status');
  status.className = '';
  if (file.size > 20 * 1024 * 1024) {
    status.className = 'error';
    status.textContent = 'Файл больше 20 МБ. Исследованный test1.zip занимает 673 022 байта. Выберите исходный архив.';
    return;
  }
  if (!globalThis.crypto?.subtle) {
    status.textContent = 'Для проверки SHA-256 откройте сайт по HTTPS или воспользуйтесь скриптом Python из материалов.';
    return;
  }
  status.textContent = 'Вычисляем SHA-256 на вашем устройстве…';
  try {
    const bytes = await file.arrayBuffer();
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    if (revision !== selectedArchive) return;
    const hash = Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, '0')).join('');
    const matches = hash === report.archive.sha256;
    status.className = matches ? 'success' : 'error';
    status.textContent = matches ? 'Совпадение подтверждено. SHA-256 вашего файла совпадает с исследованным test1.zip.' : `SHA-256 не совпадает. Это другой экземпляр архива. Даже перепаковка тех же файлов меняет хеш ZIP; этот результат не доказывает различие текстов. SHA-256: ${hash}`;
  } catch {
    if (revision === selectedArchive) { status.className = 'error'; status.textContent = 'Не удалось прочитать файл. Выберите его снова или запустите скрипт Python.'; }
  }
});
