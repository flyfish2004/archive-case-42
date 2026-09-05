/** Local ZIP analysis. Content is compared without normalization or extraction to disk. */
export const LIMITS = Object.freeze({
  maxArchiveBytes: 20 * 1024 * 1024,
  maxEntries: 2000,
  maxFileBytes: 5 * 1024 * 1024,
  maxTotalBytes: 50 * 1024 * 1024,
});

const SIGNATURE = { local: 0x04034b50, central: 0x02014b50, end: 0x06054b50, descriptor: 0x08074b50 };
const CP437 = 'ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒáíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■ ';
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let remainder = value;
  for (let bit = 0; bit < 8; bit++) remainder = (remainder >>> 1) ^ ((remainder & 1) ? 0xedb88320 : 0);
  return remainder >>> 0;
});

function fail(message) { throw new Error(message); }
function checkAbort(signal) {
  if (signal?.aborted) throw new DOMException('Проверка отменена.', 'AbortError');
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (let index = 0; index < bytes.length; index++) crc = CRC_TABLE[(crc ^ bytes[index]) & 255] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
function hex32(value) { return value.toString(16).padStart(8, '0'); }
function equalBytes(left, right) {
  if (left.length !== right.length) return false;
  for (let index = 0; index < left.length; index++) if (left[index] !== right[index]) return false;
  return true;
}
function byteNameOrder(left, right) { return left < right ? -1 : left > right ? 1 : 0; }
function yieldToUI() { return new Promise(resolve => setTimeout(resolve, 0)); }
function readUtf8(bytes) { return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }

async function sha256(bytes) {
  if (!globalThis.crypto?.subtle) fail('Браузер не поддерживает SHA-256 в этом контексте. Откройте сайт по HTTPS или через localhost.');
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, value => value.toString(16).padStart(2, '0')).join('');
}

function parseExtras(bytes, context) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const fields = [];
  for (let cursor = 0; cursor < bytes.length;) {
    if (cursor + 4 > bytes.length) fail(`Повреждено дополнительное поле ZIP: ${context}.`);
    const type = view.getUint16(cursor, true);
    const size = view.getUint16(cursor + 2, true);
    cursor += 4;
    if (cursor + size > bytes.length) fail(`Обрезано дополнительное поле ZIP: ${context}.`);
    if (type === 0x0001) fail('ZIP64 не поддерживается. Создайте обычный ZIP в пределах указанных лимитов.');
    fields.push({ type, bytes: bytes.subarray(cursor, cursor + size) });
    cursor += size;
  }
  return fields;
}

function decodeName(raw, flags, fields) {
  let name;
  try {
    if (flags & 0x0800) name = readUtf8(raw);
    else {
      const unicodeField = fields.find(field => {
        if (field.type !== 0x7075 || field.bytes.length < 5 || field.bytes[0] !== 1) return false;
        const view = new DataView(field.bytes.buffer, field.bytes.byteOffset, field.bytes.byteLength);
        return view.getUint32(1, true) === crc32(raw);
      });
      name = unicodeField ? readUtf8(unicodeField.bytes.subarray(5)) : Array.from(raw, byte => byte < 128 ? String.fromCharCode(byte) : CP437[byte - 128]).join('');
    }
  } catch { fail('Имя файла помечено как UTF-8, но содержит недопустимую последовательность байтов.'); }
  if (!name || name.includes('\0')) fail('ZIP содержит пустое имя файла или нулевой символ в имени.');
  return name;
}

function parseZip(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const u16 = offset => view.getUint16(offset, true);
  const u32 = offset => view.getUint32(offset, true);
  if (bytes.length < 22) fail('Файл слишком короткий для ZIP или обрезан.');
  let end = -1;
  for (let cursor = bytes.length - 22, minimum = Math.max(0, bytes.length - 22 - 0xffff); cursor >= minimum; cursor--) {
    if (u32(cursor) === SIGNATURE.end && cursor + 22 + u16(cursor + 20) === bytes.length) { end = cursor; break; }
  }
  if (end < 0) fail('Не найден конец ZIP. Файл повреждён, обрезан или имеет другой формат.');
  if (end >= 20 && u32(end - 20) === 0x07064b50) fail('ZIP64 не поддерживается. Создайте обычный ZIP в пределах указанных лимитов.');
  const disk = u16(end + 4), centralDisk = u16(end + 6), diskEntries = u16(end + 8), count = u16(end + 10);
  const centralSize = u32(end + 12), centralStart = u32(end + 16);
  if (count === 0xffff || diskEntries === 0xffff || centralSize === 0xffffffff || centralStart === 0xffffffff) fail('ZIP64 не поддерживается.');
  if (disk !== 0 || centralDisk !== 0 || diskEntries !== count) fail('Многотомные ZIP-архивы не поддерживаются.');
  if (count > LIMITS.maxEntries) fail(`В ZIP больше ${LIMITS.maxEntries} записей. Уменьшите число файлов и папок.`);
  if (centralStart + centralSize !== end) fail('Некорректное положение центрального каталога ZIP или неподдерживаемые записи перед его концом.');
  if (count === 0) fail('ZIP пуст: файлов для сравнения нет.');
  let cursor = centralStart, totalSize = 0;
  const entries = [];
  for (let index = 0; index < count; index++) {
    if (cursor + 46 > end || u32(cursor) !== SIGNATURE.central) fail('Повреждён или обрезан центральный каталог ZIP.');
    const needed = u16(cursor + 6), flags = u16(cursor + 8), method = u16(cursor + 10);
    const dosTime = u16(cursor + 12), dosDate = u16(cursor + 14), crc = u32(cursor + 16);
    const compressedSize = u32(cursor + 20), size = u32(cursor + 24);
    const nameSize = u16(cursor + 28), extraSize = u16(cursor + 30), commentSize = u16(cursor + 32);
    const diskStart = u16(cursor + 34), attributes = u32(cursor + 38), localOffset = u32(cursor + 42);
    if (compressedSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff || diskStart === 0xffff) fail('ZIP64 не поддерживается.');
    if (diskStart !== 0) fail('Многотомные ZIP-архивы не поддерживаются.');
    if (flags & (0x0001 | 0x0040 | 0x2000)) fail('Архив содержит зашифрованные файлы. Сохраните ZIP без пароля.');
    if (flags & ~0x080e) fail('ZIP использует неподдерживаемые флаги формата.');
    if (method !== 0 && method !== 8) fail(`Метод сжатия ZIP № ${method} не поддерживается. Используйте Store или Deflate.`);
    if (needed > 20) fail(`Требуется неподдерживаемая версия ZIP ${Math.floor(needed / 10)}.${needed % 10}. Используйте обычный ZIP с Deflate.`);
    if (method === 0 && (flags & 6)) fail('У несжатой записи ZIP указаны несовместимые флаги сжатия.');
    if (size > LIMITS.maxFileBytes) fail('Размер одного из распакованных файлов превышает лимит 5 МиБ.');
    totalSize += size;
    if (totalSize > LIMITS.maxTotalBytes) fail('Общий размер распакованных файлов превышает лимит 50 МиБ.');
    if (method === 0 && compressedSize !== size) fail('Несогласованные размеры несжатой записи ZIP.');
    const next = cursor + 46 + nameSize + extraSize + commentSize;
    if (next > end) fail('Обрезана запись центрального каталога ZIP.');
    const rawName = bytes.subarray(cursor + 46, cursor + 46 + nameSize);
    const fields = parseExtras(bytes.subarray(cursor + 46 + nameSize, cursor + 46 + nameSize + extraSize), 'центральный каталог');
    const name = decodeName(rawName, flags, fields);
    const directory = name.endsWith('/') || Boolean(attributes & 0x10) || ((attributes >>> 16) & 0xf000) === 0x4000;
    if (directory && size !== 0) fail(`Запись папки «${name}» содержит данные; структура ZIP неоднозначна.`);
    if (localOffset + 30 > centralStart || u32(localOffset) !== SIGNATURE.local) fail(`Повреждён локальный заголовок: «${name}».`);
    const localFlags = u16(localOffset + 6), localMethod = u16(localOffset + 8);
    if (u16(localOffset + 4) !== needed || localFlags !== flags || localMethod !== method || u16(localOffset + 10) !== dosTime || u16(localOffset + 12) !== dosDate) fail(`Локальный заголовок не совпадает с каталогом: «${name}».`);
    const localCrc = u32(localOffset + 14), localCompressed = u32(localOffset + 18), localSize = u32(localOffset + 22);
    if (localCompressed === 0xffffffff || localSize === 0xffffffff) fail('ZIP64 не поддерживается.');
    if (flags & 8) {
      if ((localCrc !== 0 && localCrc !== crc) || (localCompressed !== 0 && localCompressed !== compressedSize) || (localSize !== 0 && localSize !== size)) fail(`Локальные CRC или размеры расходятся с каталогом: «${name}».`);
    } else if (localCrc !== crc || localCompressed !== compressedSize || localSize !== size) fail(`Локальные CRC или размеры расходятся с каталогом: «${name}».`);
    const localNameSize = u16(localOffset + 26), localExtraSize = u16(localOffset + 28);
    const dataStart = localOffset + 30 + localNameSize + localExtraSize;
    const dataEnd = dataStart + compressedSize;
    if (dataStart > centralStart || dataEnd > centralStart) fail(`Данные файла обрезаны или пересекают каталог: «${name}».`);
    if (!equalBytes(rawName, bytes.subarray(localOffset + 30, localOffset + 30 + localNameSize))) fail(`Имя в локальном заголовке не совпадает с каталогом: «${name}».`);
    const localFields = parseExtras(bytes.subarray(localOffset + 30 + localNameSize, dataStart), `локальный заголовок «${name}»`);
    const localUnicode = localFields.some(field => field.type === 0x7075);
    if (localUnicode && decodeName(rawName, flags, localFields) !== name) fail(`Unicode-имя в локальном заголовке не совпадает с каталогом: «${name}».`);
    let recordEnd = dataEnd;
    if (flags & 8) {
      const matches = offset => offset + 12 <= centralStart && u32(offset) === crc && u32(offset + 4) === compressedSize && u32(offset + 8) === size;
      if (dataEnd + 4 <= centralStart && u32(dataEnd) === SIGNATURE.descriptor && matches(dataEnd + 4)) recordEnd = dataEnd + 16;
      else if (matches(dataEnd)) recordEnd = dataEnd + 12;
      else fail(`Повреждён или отсутствует дескриптор данных: «${name}».`);
    }
    entries.push({ name, directory, method, size, compressedSize, crc, dataStart, dataEnd, localOffset, recordEnd });
    cursor = next;
  }
  if (cursor !== end) fail('Число записей или размер центрального каталога ZIP не совпадает с его содержимым.');
  const ranges = [...entries].sort((a, b) => a.localOffset - b.localOffset);
  for (let index = 1; index < ranges.length; index++) {
    if (ranges[index].localOffset < ranges[index - 1].recordEnd) fail('Записи ZIP пересекаются или ссылаются на один локальный заголовок.');
  }
  if (!entries.some(entry => !entry.directory)) fail('В ZIP есть только папки: файлов для сравнения нет.');
  return entries;
}

async function decompress(entry, archiveBytes, expandedSoFar, signal) {
  checkAbort(signal);
  const compressed = archiveBytes.subarray(entry.dataStart, entry.dataEnd);
  if (entry.method === 0) return compressed.slice();
  let transform;
  try { transform = new DecompressionStream('deflate-raw'); }
  catch { fail('Браузер не поддерживает распаковку Deflate. Обновите браузер или используйте ZIP без сжатия (Store).'); }
  const reader = new Blob([compressed]).stream().pipeThrough(transform).getReader();
  const chunks = [];
  let size = 0;
  const cancel = () => { reader.cancel().catch(() => {}); };
  signal?.addEventListener('abort', cancel, { once: true });
  try {
    while (true) {
      checkAbort(signal);
      const { value, done } = await reader.read();
      checkAbort(signal);
      if (done) break;
      size += value.byteLength;
      if (size > LIMITS.maxFileBytes || expandedSoFar + size > LIMITS.maxTotalBytes) fail('Распаковка остановлена: превышен допустимый объём данных.');
      if (size > entry.size) fail(`Распакованный размер превышает размер из каталога: «${entry.name}».`);
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error?.name === 'AbortError') throw error;
    fail(`Не удалось распаковать «${entry.name}»: ${error?.message || 'повреждён поток Deflate'}`);
  } finally {
    signal?.removeEventListener('abort', cancel);
    reader.releaseLock();
  }
  if (size !== entry.size) fail(`Распакованный размер не совпадает с каталогом: «${entry.name}».`);
  const output = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

function inspectText(bytes) {
  let text = null, utf8Text = null, utf8Valid = false, bom = null, encoding = 'Не определена';
  try { utf8Text = readUtf8(bytes); utf8Valid = true; } catch { /* Invalid UTF-8 is a format finding, not a ZIP error. */ }
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    bom = 'UTF-8';
    if (utf8Valid) { encoding = 'UTF-8'; text = utf8Text.slice(1); }
  } else if (bytes.length >= 2 && ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff))) {
    bom = bytes[0] === 0xff ? 'UTF-16LE' : 'UTF-16BE';
    try { text = new TextDecoder(bom.toLowerCase(), { fatal: true, ignoreBOM: true }).decode(bytes.subarray(2)); encoding = bom; }
    catch { /* A malformed UTF-16 file remains available for exact byte comparison. */ }
  } else if (utf8Valid) { encoding = 'UTF-8'; text = utf8Text; }
  const format = {
    encoding, bom, ascii: bytes.every(byte => byte < 128), utf8Valid,
    crlf: 0, lf: 0, cr: 0, tabs: 0, spaces: 0, trailingWhitespaceLines: 0, finalNewline: false, nonAscii: 0,
  };
  if (text !== null) {
    for (let index = 0; index < text.length; index++) {
      const code = text.charCodeAt(index);
      if (code === 13) { if (text.charCodeAt(index + 1) === 10) { format.crlf++; index++; } else format.cr++; }
      else if (code === 10) format.lf++;
      else if (code === 9) format.tabs++;
      else if (code === 32) format.spaces++;
    }
    for (const character of text) if (character.codePointAt(0) > 127) format.nonAscii++;
    format.trailingWhitespaceLines = (text.match(/[\t ]+(?=\r\n|\r|\n|$)/g) || []).length;
    format.finalNewline = /[\r\n]$/.test(text);
  }
  return { text, format };
}

/** Analyze all file records; UTF-8 decoding is never used as the equality criterion. */
export async function analyzeZip(input, options = {}) {
  const { name = 'archive.zip', onProgress = () => {}, signal } = options;
  checkAbort(signal);
  if (!(input instanceof ArrayBuffer) && !(input instanceof Uint8Array)) fail('Ожидается содержимое ZIP в формате ArrayBuffer или Uint8Array.');
  if (input.byteLength > LIMITS.maxArchiveBytes) fail('Размер ZIP превышает лимит 20 МиБ.');
  const archiveBytes = input instanceof Uint8Array ? input.slice() : new Uint8Array(input.slice(0));
  onProgress({ phase: 'read', done: 0, total: 1 });
  const entries = parseZip(archiveBytes);
  checkAbort(signal);
  const archive = { name, size: archiveBytes.byteLength, sha256: await sha256(archiveBytes) };
  onProgress({ phase: 'read', done: 1, total: 1 });
  const files = [];
  let totalExpanded = 0;
  for (let index = 0; index < entries.length; index++) {
    checkAbort(signal);
    const entry = entries[index];
    const bytes = await decompress(entry, archiveBytes, totalExpanded, signal);
    totalExpanded += bytes.length;
    if (bytes.length !== entry.size) fail(`Размер не совпадает с каталогом: «${entry.name}».`);
    if (crc32(bytes) !== entry.crc) fail(`CRC32 не совпадает: «${entry.name}». Данные повреждены или заголовок неверен.`);
    if (!entry.directory) {
      const { text, format } = inspectText(bytes);
      files.push({ id: files.length, name: entry.name, size: bytes.length, sha256: await sha256(bytes), crc32: hex32(entry.crc), groupId: 0, format, text, bytes });
    }
    onProgress({ phase: 'extract', done: index + 1, total: entries.length });
    if (index % 16 === 15) await yieldToUI();
  }
  // First partition: SHA-256. It is retained separately from the byte-based partition.
  const hashGroups = new Map();
  for (const file of files) {
    if (!hashGroups.has(file.sha256)) hashGroups.set(file.sha256, []);
    hashGroups.get(file.sha256).push(file.id);
  }
  // Second partition: size, then exact equality against representatives. No hash lookup.
  const sizeBuckets = new Map(), exactGroups = [];
  let comparisons = 0;
  for (let index = 0; index < files.length; index++) {
    checkAbort(signal);
    const file = files[index];
    const bucket = sizeBuckets.get(file.size) || [];
    let match = null;
    for (const group of bucket) {
      if (equalBytes(file.bytes, files[group.representativeId].bytes)) { match = group; break; }
      if (++comparisons % 32 === 0) { await yieldToUI(); checkAbort(signal); }
    }
    if (match) match.members.push(file.id);
    else {
      const group = { representativeId: file.id, members: [file.id] };
      bucket.push(group); exactGroups.push(group); sizeBuckets.set(file.size, bucket);
    }
    onProgress({ phase: 'compare', done: index + 1, total: files.length });
    if (index % 16 === 15) await yieldToUI();
  }
  // Choose deterministic representatives and IDs, independent of local record order.
  for (const group of exactGroups) {
    group.members.sort((a, b) => byteNameOrder(files[a].name, files[b].name) || a - b);
    group.representativeId = group.members[0];
  }
  exactGroups.sort((a, b) => b.members.length - a.members.length || byteNameOrder(files[a.representativeId].name, files[b.representativeId].name) || a.representativeId - b.representativeId);
  const groups = exactGroups.map((group, index) => {
    const id = index + 1, representative = files[group.representativeId];
    for (const fileId of group.members) files[fileId].groupId = id;
    return { id, count: group.members.length, representativeId: group.representativeId, names: group.members.map(fileId => files[fileId].name), sha256: representative.sha256, size: representative.size };
  });
  const hashToExact = new Map(), exactToHash = new Map();
  let independentGroupingAgrees = true;
  for (const file of files) {
    if ((hashToExact.has(file.sha256) && hashToExact.get(file.sha256) !== file.groupId) || (exactToHash.has(file.groupId) && exactToHash.get(file.groupId) !== file.sha256)) independentGroupingAgrees = false;
    hashToExact.set(file.sha256, file.groupId); exactToHash.set(file.groupId, file.sha256);
  }
  if (hashGroups.size !== groups.length) independentGroupingAgrees = false;
  const nameCounts = new Map();
  for (const file of files) nameCounts.set(file.name, (nameCounts.get(file.name) || 0) + 1);
  const duplicateNames = [...nameCounts].filter(([, count]) => count > 1).map(([fileName]) => fileName).sort(byteNameOrder);
  checkAbort(signal);
  onProgress({ phase: 'complete', done: files.length, total: files.length });
  return {
    schemaVersion: 1, archive, files, groups,
    majorityGroupId: groups[0].count > files.length / 2 ? groups[0].id : null,
    checks: { crcVerified: true, independentGroupingAgrees, duplicateNames }, limits: LIMITS,
  };
}

/** Keep evidence and metadata; omit file bodies and byte buffers from the downloadable JSON. */
export function serializeReport(report) {
  return {
    schemaVersion: report.schemaVersion,
    archive: { ...report.archive },
    files: report.files.map(({ bytes, text, ...metadata }) => ({ ...metadata, format: { ...metadata.format, textCountersApplicable: text !== null } })),
    groups: report.groups.map(group => ({ ...group, names: [...group.names] })),
    majorityGroupId: report.majorityGroupId,
    checks: { ...report.checks, duplicateNames: [...report.checks.duplicateNames] },
    limits: { ...report.limits },
  };
}
