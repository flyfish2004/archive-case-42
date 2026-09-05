/** Node.js 24+: node analyze-archive.mjs input.zip report.json */
import { readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { analyzeZip, serializeReport } from './analyzer.mjs';
import { compareFiles } from './diff.mjs';
const input = process.argv[2];
if (!input) { console.error('Usage: node analyze-archive.mjs archive.zip [report.json] [reference-file-id]'); process.exit(1); }
const result = await analyzeZip(await readFile(input), { name: basename(input) });
const majority = result.groups.find(group => group.id === result.majorityGroupId);
const referenceId = process.argv[4] === undefined ? (majority?.representativeId ?? null) : Number(process.argv[4]);
const reference = result.files.find(file => file.id === referenceId);
if (referenceId !== null && !reference) throw new Error('Invalid reference file ID');
const output = serializeReport(result);
output.referenceId = referenceId;
output.comparisons = reference ? result.groups.filter(group => group.id !== reference.groupId).map(group => ({
  groupId: group.id, referenceId, representativeId: group.representativeId,
  appliesToFileIds: result.files.filter(file => file.groupId === group.id).map(file => file.id),
  ...compareFiles(reference, result.files[group.representativeId])
})) : [];
await writeFile(process.argv[3] || 'report.json', JSON.stringify(output, null, 2) + '\n');
console.log(JSON.stringify({ files: result.files.length, groups: result.groups.map(group => group.count), referenceId,
  independentGroupingAgrees: result.checks.independentGroupingAgrees }));
if (referenceId === null) console.log('No strict majority. Supply reference-file-id as the fourth command-line argument to compare.');
