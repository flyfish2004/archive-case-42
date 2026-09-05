/**
 * Bounded, dependency-free byte and decoded-Unicode comparison.
 * All offsets are zero based and all range ends are exclusive.
 * Exact alignment is a shortest insertion/deletion script; adjacent edits are
 * presented together as a replacement. A bounded result is explicitly only a
 * changed-range envelope. Decoded-text offsets count Unicode code points.
 */

const DEFAULTS = Object.freeze({
  maxByteHunks: 100,
  maxTextHunks: 100,
  previewBytes: 64,
  previewCodePoints: 96,
  maxWork: 2_000_000,
  maxTraceCells: 1_000_000,
  maxEditDistance: 2048,
  maxTextCodeUnits: 2_000_000,
});

function limitsFrom(options) {
  const limits = { ...DEFAULTS };
  for (const key of Object.keys(DEFAULTS)) {
    if (options[key] !== undefined) {
      if (!Number.isSafeInteger(options[key]) || options[key] < 0) {
        throw new TypeError(`${key} must be a nonnegative safe integer`);
      }
      limits[key] = options[key];
    }
  }
  // Keep a caller-supplied budget from creating an unbounded trace allocation.
  limits.maxTraceCells = Math.min(limits.maxTraceCells, 8_000_000);
  limits.maxEditDistance = Math.min(limits.maxEditDistance, 8192);
  return limits;
}

function range(beforeStart, beforeEnd, afterStart, afterEnd, exact = true) {
  return {
    type: beforeStart === beforeEnd ? 'insert' : afterStart === afterEnd ? 'delete' : 'replace',
    beforeStart, beforeEnd, afterStart, afterEnd, exact,
  };
}

function rangesFromTrace(trace, beforeLength, afterLength, prefix) {
  let x = beforeLength;
  let y = afterLength;
  const reverseSegments = [];
  for (let d = trace.length - 1; d > 0; d--) {
    const previous = trace[d - 1];
    const k = x - y;
    const index = (k + d) / 2;
    const insertion = index === 0 || (index !== d && previous[index - 1] < previous[index]);
    const previousK = insertion ? k + 1 : k - 1;
    const previousX = insertion ? previous[index] : previous[index - 1];
    const previousY = previousX - previousK;
    const afterEditX = previousX + (insertion ? 0 : 1);
    const afterEditY = previousY + (insertion ? 1 : 0);
    if (x > afterEditX) reverseSegments.push({ type: 'equal', length: x - afterEditX });
    reverseSegments.push({ type: insertion ? 'insert' : 'delete', length: 1 });
    x = previousX;
    y = previousY;
  }
  if (x > 0) reverseSegments.push({ type: 'equal', length: x });

  const hunks = [];
  let beforePosition = prefix;
  let afterPosition = prefix;
  let pending = null;
  for (let i = reverseSegments.length - 1; i >= 0; i--) {
    const segment = reverseSegments[i];
    if (segment.type === 'equal') {
      if (pending) {
        hunks.push(range(pending.beforeStart, beforePosition, pending.afterStart, afterPosition));
        pending = null;
      }
      beforePosition += segment.length;
      afterPosition += segment.length;
    } else {
      pending ??= { beforeStart: beforePosition, afterStart: afterPosition };
      if (segment.type === 'insert') afterPosition += segment.length;
      else beforePosition += segment.length;
    }
  }
  if (pending) hunks.push(range(pending.beforeStart, beforePosition, pending.afterStart, afterPosition));
  return hunks;
}

function align(before, after, limits) {
  const shorterLength = Math.min(before.length, after.length);
  let prefix = 0;
  while (prefix < shorterLength && before[prefix] === after[prefix]) prefix++;
  if (prefix === before.length && prefix === after.length) {
    return { hunks: [], alignment: 'exact', reason: null, editDistance: 0 };
  }
  let suffix = 0;
  while (suffix < shorterLength - prefix && before[before.length - suffix - 1] === after[after.length - suffix - 1]) suffix++;
  const beforeLength = before.length - prefix - suffix;
  const afterLength = after.length - prefix - suffix;
  if (!beforeLength || !afterLength) {
    return {
      hunks: [range(prefix, prefix + beforeLength, prefix, prefix + afterLength)],
      alignment: 'exact', reason: null, editDistance: beforeLength + afterLength,
    };
  }
  const bounded = (reason) => ({
    hunks: [range(prefix, prefix + beforeLength, prefix, prefix + afterLength, false)],
    alignment: 'bounded', reason, editDistance: null,
  });
  const trace = [];
  let traceCells = 0;
  let work = 0;
  const maximumDistance = Math.min(beforeLength + afterLength, limits.maxEditDistance);
  for (let d = 0; d <= maximumDistance; d++) {
    traceCells += d + 1;
    if (traceCells > limits.maxTraceCells) return bounded('maxTraceCells');
    const current = new Int32Array(d + 1);
    const previous = trace[d - 1];
    for (let index = 0; index <= d; index++) {
      if (++work > limits.maxWork) return bounded('maxWork');
      const k = -d + 2 * index;
      let x;
      if (d === 0) x = 0;
      else if (index === 0 || (index !== d && previous[index - 1] < previous[index])) x = previous[index];
      else x = previous[index - 1] + 1;
      let y = x - k;
      while (x < beforeLength && y < afterLength && before[prefix + x] === after[prefix + y]) {
        if (++work > limits.maxWork) return bounded('maxWork');
        x++;
        y++;
      }
      current[index] = x;
      if (x >= beforeLength && y >= afterLength) {
        trace.push(current);
        return {
          hunks: rangesFromTrace(trace, beforeLength, afterLength, prefix),
          alignment: 'exact', reason: null, editDistance: d,
        };
      }
    }
    trace.push(current);
  }
  return bounded('maxEditDistance');
}

/** Literal escape notation; even spaces and default-ignorable scalars are visible. */
export function escapeText(text) {
  let escaped = '';
  for (const character of text) {
    if (character === '\n') escaped += '\\n';
    else if (character === '\r') escaped += '\\r';
    else if (character === '\t') escaped += '\\t';
    else if (character === '\\') escaped += '\\\\';
    else if (character === '"') escaped += '\\"';
    else if (/[\p{White_Space}\p{Cc}\p{Cf}\p{Default_Ignorable_Code_Point}]/u.test(character)) {
      const point = character.codePointAt(0);
      escaped += point <= 0xffff ? `\\u${point.toString(16).toUpperCase().padStart(4, '0')}` : `\\u{${point.toString(16).toUpperCase()}}`;
    } else escaped += character;
  }
  return escaped;
}

function decoderFor(file) {
  if (typeof file.text !== 'string') return null;
  const encoding = String(file.format?.encoding || 'utf-8').toLowerCase().replace(/[^a-z0-9]/g, '');
  let label;
  if (encoding.startsWith('utf8')) label = 'utf-8';
  else if (encoding.startsWith('utf16le')) label = 'utf-16le';
  else if (encoding.startsWith('utf16be')) label = 'utf-16be';
  else if (encoding === 'ascii' || encoding === 'usascii') label = 'utf-8';
  else return null;
  return new TextDecoder(label, { fatal: true, ignoreBOM: true });
}

function bytePreview(file, start, end, maximum, decoder) {
  const preview = file.bytes.subarray(start, Math.min(end, start + maximum));
  let text = null;
  // UTF-16 byte offsets can bisect code units: do not decode such a fragment.
  const utf16Misaligned = decoder?.encoding.startsWith('utf-16') && (start % 2 !== 0 || preview.length % 2 !== 0);
  if (decoder && !utf16Misaligned) {
    try { text = escapeText(decoder.decode(preview)); } catch { /* Byte-level change cuts a Unicode scalar. */ }
  }
  return {
    hex: Array.from(preview, (byte) => byte.toString(16).toUpperCase().padStart(2, '0')).join(' '),
    text,
    truncated: end - start > maximum,
    previewLength: preview.length,
  };
}

function byteHunk(hunk, before, after, limits, beforeDecoder, afterDecoder) {
  const left = bytePreview(before, hunk.beforeStart, hunk.beforeEnd, limits.previewBytes, beforeDecoder);
  const right = bytePreview(after, hunk.afterStart, hunk.afterEnd, limits.previewBytes, afterDecoder);
  return {
    ...hunk,
    beforeHex: left.hex, afterHex: right.hex,
    beforeText: left.text, afterText: right.text,
    beforePreviewTruncated: left.truncated, afterPreviewTruncated: right.truncated,
    beforePreviewBytes: left.previewLength, afterPreviewBytes: right.previewLength,
    beforeLocation: null, afterLocation: null,
  };
}

function locationsAt(tokens, indices) {
  const wanted = new Set(indices);
  const found = new Map();
  let line = 1;
  let column = 1;
  for (let position = 0; position <= tokens.length; position++) {
    if (wanted.has(position)) found.set(position, { line, column });
    const token = tokens[position];
    if (token === '\n' || (token === '\r' && tokens[position + 1] !== '\n')) {
      line++;
      column = 1;
    } else column++;
  }
  return found;
}

function textHunks(hunks, before, after, limits) {
  const selected = hunks.slice(0, limits.maxTextHunks);
  const beforeLocations = locationsAt(before, selected.flatMap((hunk) => [hunk.beforeStart, hunk.beforeEnd]));
  const afterLocations = locationsAt(after, selected.flatMap((hunk) => [hunk.afterStart, hunk.afterEnd]));
  return selected.map((hunk) => ({
    ...hunk,
    beforeText: escapeText(before.slice(hunk.beforeStart, Math.min(hunk.beforeEnd, hunk.beforeStart + limits.previewCodePoints)).join('')),
    afterText: escapeText(after.slice(hunk.afterStart, Math.min(hunk.afterEnd, hunk.afterStart + limits.previewCodePoints)).join('')),
    beforePreviewTruncated: hunk.beforeEnd - hunk.beforeStart > limits.previewCodePoints,
    afterPreviewTruncated: hunk.afterEnd - hunk.afterStart > limits.previewCodePoints,
    beforeLocation: beforeLocations.get(hunk.beforeStart),
    beforeEndLocation: beforeLocations.get(hunk.beforeEnd),
    afterLocation: afterLocations.get(hunk.afterStart),
    afterEndLocation: afterLocations.get(hunk.afterEnd),
  }));
}

function summedLengths(hunks) {
  return hunks.reduce((sum, hunk) => ({
    removed: sum.removed + hunk.beforeEnd - hunk.beforeStart,
    added: sum.added + hunk.afterEnd - hunk.afterStart,
  }), { removed: 0, added: 0 });
}

/** See CONTRACT.md for exact result semantics and resource limits. */
export function compareFiles(baseFile, otherFile, options = {}) {
  if (!(baseFile?.bytes instanceof Uint8Array) || !(otherFile?.bytes instanceof Uint8Array)) {
    throw new TypeError('compareFiles expects two files with bytes: Uint8Array');
  }
  const limits = limitsFrom(options);
  const byteResult = align(baseFile.bytes, otherFile.bytes, limits);
  const byteLengths = summedLengths(byteResult.hunks);
  const beforeDecoder = decoderFor(baseFile);
  const afterDecoder = decoderFor(otherFile);
  const byteChanges = byteResult.hunks.slice(0, limits.maxByteHunks).map((hunk) => byteHunk(hunk, baseFile, otherFile, limits, beforeDecoder, afterDecoder));
  const textComparable = typeof baseFile.text === 'string' && typeof otherFile.text === 'string';
  const analysisLimits = [];
  if (byteResult.reason) analysisLimits.push({ analysis: 'bytes', limit: byteResult.reason, value: limits[byteResult.reason], effect: 'changed-range-envelope; shortest edit script not determined' });

  let textResult = null;
  let textChanges = null;
  let textLengths = null;
  let textAnalysisPerformed = false;
  if (textComparable) {
    if (baseFile.text === otherFile.text) {
      textResult = { hunks: [], alignment: 'exact', reason: null, editDistance: 0 };
      textChanges = [];
      textLengths = { removed: 0, added: 0 };
      textAnalysisPerformed = true;
    } else if (Math.max(baseFile.text.length, otherFile.text.length) > limits.maxTextCodeUnits) {
      analysisLimits.push({ analysis: 'text', limit: 'maxTextCodeUnits', value: limits.maxTextCodeUnits, effect: 'decoded-text diff skipped; byte analysis remains available' });
    } else {
      const beforeTokens = Array.from(baseFile.text);
      const afterTokens = Array.from(otherFile.text);
      textResult = align(beforeTokens, afterTokens, limits);
      textLengths = summedLengths(textResult.hunks);
      textChanges = textHunks(textResult.hunks, beforeTokens, afterTokens, limits);
      textAnalysisPerformed = true;
      if (textResult.reason) analysisLimits.push({ analysis: 'text', limit: textResult.reason, value: limits[textResult.reason], effect: 'changed-range-envelope; shortest edit script not determined' });
    }
  }
  const bytesExact = byteResult.alignment === 'exact';
  const textExact = textResult?.alignment === 'exact';
  return {
    equal: byteResult.hunks.length === 0,
    byteChanges,
    totalByteHunks: byteResult.hunks.length,
    byteHunksTruncated: byteResult.hunks.length > byteChanges.length,
    textComparable,
    textAnalysisPerformed,
    textEqual: textComparable ? baseFile.text === otherFile.text : null,
    textChanges,
    totalTextHunks: textResult ? textResult.hunks.length : null,
    textHunksTruncated: textResult ? textResult.hunks.length > textChanges.length : false,
    byteAlignment: byteResult.alignment,
    textAlignment: textResult?.alignment ?? null,
    alignment: bytesExact && (!textComparable || textExact) ? 'exact' : 'bounded',
    summary: {
      beforeBytes: baseFile.bytes.length,
      afterBytes: otherFile.bytes.length,
      byteLengthDelta: otherFile.bytes.length - baseFile.bytes.length,
      removedBytes: bytesExact ? byteLengths.removed : null,
      addedBytes: bytesExact ? byteLengths.added : null,
      rangeRemovedBytes: byteLengths.removed,
      rangeAddedBytes: byteLengths.added,
      removedCodePoints: textExact ? textLengths.removed : null,
      addedCodePoints: textExact ? textLengths.added : null,
      byteEditDistance: byteResult.editDistance,
      textEditDistance: textResult?.editDistance ?? null,
    },
    analysisLimits,
    limits,
  };
}
