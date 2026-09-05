import { analyzeZip, serializeReport } from './analyzer.mjs';
import { compareFiles } from './diff.mjs';
let report = null;
const cache = new Map();
function comparison(referenceId, groupId) {
  const key = referenceId + ':' + groupId;
  if (!cache.has(key)) {
    const group = report.groups.find(item => item.id === groupId);
    const reference = report.files.find(item => item.id === referenceId);
    if (!group || !reference) throw new Error('Файл или группа не найдены.');
    cache.set(key, compareFiles(reference, report.files[group.representativeId]));
  }
  return cache.get(key);
}
self.onmessage = async ({ data }) => {
  try {
    if (data.type === 'analyze') {
      report = null; cache.clear();
      let lastProgress = 0;
      report = await analyzeZip(data.buffer, { name: data.name, onProgress(progress) {
        const now = Date.now();
        if (now - lastProgress > 60 || progress.done === progress.total) {
          self.postMessage({ type: 'progress', ...progress }); lastProgress = now;
        }
      } });
      self.postMessage({ type: 'result', report: serializeReport(report) });
    } else if (data.type === 'compare') {
      if (!report) throw new Error('Сначала загрузите архив.');
      self.postMessage({ type: 'comparison', requestId: data.requestId,
        groupId: data.groupId, result: comparison(data.referenceId, data.groupId) });
    } else if (data.type === 'export') {
      if (!report) throw new Error('Сначала загрузите архив.');
      const output = serializeReport(report);
      output.referenceId = data.referenceId;
      output.comparisons = [];
      output.coordinateConvention = { byteOffsets: 'zero-based; end exclusive',
        textOffsets: 'zero-based Unicode code points; end exclusive',
        linesAndColumns: 'one-based Unicode code points; BOM excluded after decoding' };
      output.diffNotes = 'Non-minimal bounded envelopes, omitted hunks and shortened previews are explicitly marked in each comparison.';
      if (data.referenceId !== null) {
        const reference = report.files.find(file => file.id === data.referenceId);
        for (let index = 0; index < report.groups.length; index++) {
          const group = report.groups[index];
          if (group.id !== reference.groupId) output.comparisons.push({
            referenceId: data.referenceId, groupId: group.id,
            representativeId: group.representativeId,
            appliesToFileIds: report.files.filter(file => file.groupId === group.id).map(file => file.id),
            ...comparison(data.referenceId, group.id)
          });
          self.postMessage({ type: 'progress', phase: 'export', done: index + 1, total: report.groups.length });
          await new Promise(resolve => setTimeout(resolve, 0));
        }
      }
      self.postMessage({ type: 'exported', json: JSON.stringify(output, null, 2) });
    }
  } catch (error) {
    self.postMessage({ type: 'error', operation: data.type, requestId: data.requestId,
      message: error instanceof Error ? error.message : String(error) });
  }
};
