import './data.js';
const $ = (selector) => document.querySelector(selector);
const example = window.INVESTIGATION;
const el = (tag, className, text) => { const node = document.createElement(tag); if (className) node.className = className; if (text !== undefined) node.textContent = text; return node; };
const fmt = value => Number(value).toLocaleString('ru-RU');
const counted = (n, forms) => fmt(n)+' '+forms[n%100>=11&&n%100<=14?2:n%10===1?0:n%10>=2&&n%10<=4?1:2];
const fileCount = n => counted(n,['файл','файла','файлов']);
const fileLabel = file => file.name+(report.checks.duplicateNames.includes(file.name)?' [запись '+(file.id+1)+']':'');
function highlighted(text, start, end, kind) { const result = document.createDocumentFragment(); result.append(document.createTextNode(text.slice(0,start)),el('mark',kind,text.slice(start,end)),document.createTextNode(text.slice(end))); return result; }
$('#case-full-before').append(highlighted(example.baseline.text,41,43,'removed'));
$('#case-full-after').append(highlighted(example.anomalies[0].text,41,43,'added'));
function caseView(hex) {
  [['#case-before',example.baseline.text,'removed'],['#case-after',example.anomalies[0].text,'added']].forEach(([selector,text,kind])=>{
    const part = (a,b) => hex ? Array.from(text.slice(a,b),c=>c.charCodeAt(0).toString(16).toUpperCase()).join(' ') : text.slice(a,b);
    $(selector).replaceChildren(document.createTextNode('…'+part(hex?37:26,41)+(hex?' ':'')),el('mark',kind,part(41,43)),document.createTextNode((hex?' ':'')+part(43,hex?47:58)+'…'));
  });
  ['text','hex'].forEach(mode=>{ $('#case-'+mode).classList.toggle('active',hex===(mode==='hex')); $('#case-'+mode).setAttribute('aria-pressed',String(hex===(mode==='hex'))); });
}
$('#case-text').onclick=()=>caseView(false); $('#case-hex').onclick=()=>caseView(true);
let worker=null, report=null, referenceId=null, selectedGroup=null, requestId=0, generation=0, busy=false, currentDiff=null;
function setBusy(value) { busy=value; $('#run-example').disabled=value; $('#archive-input').disabled=value; $('#download-report').disabled=value; $('#download-csv').disabled=value; $('#reference-select').disabled=value; }
function showError(message) { $('#analysis-error').textContent=message; $('#analysis-error').hidden=false; }
function progress(data) {
  $('#analysis-status').hidden=false;
  const phases={read:'Читаем структуру ZIP',extract:'Распаковываем и проверяем CRC-32',compare:'Независимо сравниваем байты',complete:'Проверка завершена',export:'Формируем сравнения для отчёта'};
  $('#status-text').textContent=(phases[data.phase]||data.phase)+' · '+fmt(data.done)+' / '+fmt(data.total);
  $('#analysis-progress').value=data.total ? data.done/data.total*100 : 0;
}
const downloadUrls = new Map();
function download(content,name,type) {
  const extension=name.split('.').pop();
  const previous=downloadUrls.get(extension);
  if(previous){ URL.revokeObjectURL(previous.url); previous.link.remove(); }
  const url=URL.createObjectURL(new Blob([content],{type})), link=el('a','ready-download');
  link.href=url; link.download=name; link.textContent='Сохранить '+name+' ↓';
  $('#ready-downloads').append(link); downloadUrls.set(extension,{url,link}); link.click();
}
function clearDownloads(){
  for(const item of downloadUrls.values()){URL.revokeObjectURL(item.url);item.link.remove();}
  downloadUrls.clear();
}
const outputName=extension => (report?.archive.name.replace(/\.zip$/i,'') || 'archive')+'-report.'+extension;
function startWorker(buffer,name,ticket) {
  worker=new Worker(new URL('./analysis-worker.mjs',import.meta.url),{type:'module'});
  worker.onerror=()=>{ if(ticket!==generation)return; showError('Не удалось запустить модуль анализа. Откройте сайт в актуальной версии Chrome, Edge, Firefox или Safari и повторите загрузку.'); setBusy(false); $('#analysis-status').hidden=true; };
  worker.onmessage=({data})=>{
    if(ticket!==generation)return;
    if(data.type==='progress')progress(data);
    if(data.type==='result'){report=data.report;referenceId=null;$('#analysis-status').hidden=true;setBusy(false);renderReport();}
    if(data.type==='comparison'&&data.requestId===requestId){currentDiff=data.result;renderDiff(data.result);}
    if(data.type==='exported'){download(data.json,outputName('json'),'application/json;charset=utf-8');setBusy(false);$('#analysis-status').hidden=true;}
    if(data.type==='error'){
      if(data.operation==='compare'&&data.requestId!==requestId)return;
      showError(data.message);setBusy(false);$('#analysis-status').hidden=true;
    }
  };
  worker.postMessage({type:'analyze',buffer,name},[buffer]);
}
async function analyzeFile(file) {
  if(!file)return;
  clearDownloads();
  const ticket=++generation;worker?.terminate();worker=null;report=null;currentDiff=null;
  $('#analysis-results').hidden=true;$('#analysis-error').hidden=true;$('#analysis-status').hidden=false;setBusy(true);
  $('#status-text').textContent='Читаем файл на вашем устройстве…';$('#analysis-progress').value=0;
  try{
    if(file.size>20*1024*1024)throw new Error('Размер архива превышает 20 МиБ.');
    if(!globalThis.crypto?.subtle||!globalThis.Worker)throw new Error('Нужен браузер с Web Crypto и Web Worker. Откройте сайт по HTTPS.');
    const buffer=await file.arrayBuffer();if(ticket!==generation)return;startWorker(buffer,file.name,ticket);
  }catch(error){if(ticket!==generation)return;showError(error.message);setBusy(false);$('#analysis-status').hidden=true;}
}
$('#archive-input').onchange=event=>{const file=event.target.files[0];event.target.value='';analyzeFile(file);};
$('#cancel-analysis').onclick=()=>{generation++;worker?.terminate();worker=null;report=null;setBusy(false);$('#analysis-status').hidden=true;$('#analysis-results').hidden=true;showError('Проверка отменена. Вы можете загрузить архив снова.');};
$('#run-example').onclick=async()=>{
  setBusy(true);$('#analysis-error').hidden=true;
  try{const response=await fetch(new URL('./downloads/test1.zip',import.meta.url));if(!response.ok)throw new Error('Не удалось загрузить пример. Выберите исходный test1.zip вручную.');await analyzeFile(new File([await response.blob()],'test1.zip',{type:'application/zip'}));}
  catch(error){showError(error.message);setBusy(false);}
};
const zone=$('#drop-zone');
['dragenter','dragover'].forEach(name=>zone.addEventListener(name,event=>{event.preventDefault();if(!busy)zone.classList.add('drag-over');}));
zone.addEventListener('dragleave',()=>zone.classList.remove('drag-over'));
zone.addEventListener('drop',event=>{event.preventDefault();zone.classList.remove('drag-over');if(busy)return;if(event.dataTransfer.files.length!==1){showError('Выберите один ZIP-архив за раз.');return;}analyzeFile(event.dataTransfer.files[0]);});
window.addEventListener('dragover',event=>event.preventDefault());
window.addEventListener('drop',event=>event.preventDefault());
function stat(label,value,note,color){const node=el('div','stat '+color);node.append(el('span','',label),el('strong','',value),el('small','',note));return node;}
function renderReport(){
  $('#analysis-results').hidden=false;$('#result-title').textContent=report.archive.name;
  const agreement=report.checks.independentGroupingAgrees;
  $('#result-validation').textContent=agreement?'✓ CRC и обе группировки проверены':'Группировки не совпали';
  $('#result-validation').className='status '+(agreement?'success':'');
  const majority=report.groups.find(group=>group.id===report.majorityGroupId);
  referenceId=majority?.representativeId??null;
  $('#result-stats').replaceChildren(stat('Проанализировано',fmt(report.files.length),'файлов','lavender'),stat('Групп содержимого',fmt(report.groups.length),'по точному равенству байтов','mint'),stat('Основная группа',majority?fmt(majority.count):'Нет',majority?'больше половины файлов':'большинство отсутствует','peach'),stat('Размер ZIP',fmt(report.archive.size),'байт','blue'));
  $('#result-warnings').replaceChildren();
  if(!agreement)$('#result-warnings').append(el('p','warning','Группировка по SHA-256 отличается от прямого сравнения. Результат требует отдельного разбора. Ниже используются группы по полным байтам; равенство хешей не считается доказательством равенства файлов.'));
  if(report.checks.duplicateNames.length)$('#result-warnings').append(el('p','warning','В ZIP есть повторяющиеся имена. Записи считаются отдельными файлами и отмечены номерами. Имена: '+report.checks.duplicateNames.join(', ')));
  const select=$('#reference-select');select.replaceChildren();
  if(!majority){const option=el('option','','Выберите группу для сравнения');option.value='';select.append(option);}
  report.groups.forEach(group=>{const file=report.files[group.representativeId];const option=el('option','','Группа '+group.id+' · '+fileLabel(file)+' · '+fileCount(group.count));option.value=String(file.id);select.append(option);});
  select.value=referenceId===null?'':String(referenceId);
  renderFormats();updateReference();
}
function updateReference(){
  clearDownloads();
  const base=report.files.find(file=>file.id===referenceId);
  if(report.files.length===1)$('#result-conclusion').textContent='В архиве один файл. Его формат и CRC проверены; для сравнения нужен ещё хотя бы один файл.';
  else if(report.groups.length===1)$('#result-conclusion').textContent='Файлов с одинаковым содержимым: '+fmt(report.files.length)+'. Различий нет.';
  else if(report.majorityGroupId!==null){const group=report.groups.find(item=>item.id===report.majorityGroupId);$('#result-conclusion').textContent='В основной группе совпадают все байты: '+fileCount(group.count)+'. Отличающихся файлов: '+fmt(report.files.length-group.count)+'. Других вариантов содержимого: '+fmt(report.groups.length-1)+'.';}
  else $('#result-conclusion').textContent='Ни одна группа не содержит больше половины файлов. Вариантов содержимого: '+fmt(report.groups.length)+'. Без выбранного эталона нельзя назвать один из них отклонением от большинства.';
  $('#reference-note').textContent=base?'Все сравнения выполняются с '+fileLabel(base)+'. Различие не означает повреждение файла.':'Выберите представителя группы. После выбора появятся точные отличия остальных групп от него.';
  renderGroups();
  selectedGroup=report.groups.find(group=>group.id!==base?.groupId)?.id??report.groups[0].id;
  selectGroup(selectedGroup);
}
$('#reference-select').onchange=event=>{referenceId=event.target.value===''?null:Number(event.target.value);updateReference();};
function renderGroups(){
  const list=$('#group-list');list.replaceChildren();const base=report.files.find(file=>file.id===referenceId);
  report.groups.forEach(group=>{
    const button=el('button','group-button');button.type='button';button.dataset.groupId=String(group.id);
    const heading=el('strong','','Группа '+group.id);heading.append(el('span','',fileCount(group.count)));
    button.append(heading,el('span','',report.files[group.representativeId].name+(base?.groupId===group.id?' · эталон':'')));
    button.onclick=()=>selectGroup(group.id);list.append(button);
  });
}
function groupHeader(group){
  const node=$('#group-detail');node.replaceChildren(el('h4','','Группа '+group.id+' · '+fileCount(group.count)));
  const members=el('details');members.open=group.count<=5;members.append(el('summary','','Файлы группы ('+fmt(group.count)+')'));
  const list=el('ul','member-list');
  report.files.filter(file=>file.groupId===group.id).forEach(file=>list.append(el('li','',fileLabel(file))));
  members.append(list);node.append(members);
  const hash=el('details');hash.append(el('summary','','SHA-256 группы'),el('code','full-code',group.sha256));node.append(hash);
  return node;
}
function selectGroup(id){
  selectedGroup=id;currentDiff=null;requestId++;
  document.querySelectorAll('.group-button').forEach(button=>{const selected=Number(button.dataset.groupId)===id;button.classList.toggle('selected',selected);button.setAttribute('aria-pressed',String(selected));});
  const group=report.groups.find(item=>item.id===id), node=groupHeader(group), base=report.files.find(file=>file.id===referenceId);
  if(!base){node.append(el('p','','Для просмотра отличий выберите эталон выше.'));return;}
  if(base.groupId===id){node.append(el('p','','Это эталонная группа. Все её файлы совпадают с выбранным эталоном до последнего байта.'));return;}
  node.append(el('p','','Сравниваем '+report.files[group.representativeId].name+' с '+base.name+'…'));
  worker.postMessage({type:'compare',referenceId,groupId:id,requestId});
}
function renderDiff(diff,mode){
  const group=report.groups.find(item=>item.id===selectedGroup),node=groupHeader(group),base=report.files.find(file=>file.id===referenceId),other=report.files[group.representativeId];
  node.append(el('p','','Эталон: '+fileLabel(base)+'. Сравниваем: '+fileLabel(other)+'. У всех файлов этой группы одни и те же отличия.'));
  node.append(el('p','','Размеры: '+fmt(diff.summary.beforeBytes)+' → '+fmt(diff.summary.afterBytes)+' байт.'));
  if(diff.analysisLimits.length)node.append(el('p','warning','Выравнивание ограничено ресурсами. Неточные диапазоны ниже охватывают изменённую область и могут включать совпадающие части; это не минимальный набор правок. Ограничения и усечения записаны в JSON.'));
  if(diff.textEqual&&!diff.equal)node.append(el('p','warning','Текст после декодирования совпадает, но байты различаются. Возможная причина — BOM или представление кодировки. Точные байтовые изменения показаны ниже.'));
  if(!diff.textComparable)node.append(el('p','small-note','Один из файлов не удалось строго декодировать как поддерживаемый текст. Сравнение выполнено по байтам.'));
  const canText=diff.textAnalysisPerformed&&diff.textChanges?.length>0;
  const currentMode=mode??(canText?'text':'bytes');
  const tabs=el('div','segmented');
  [['text','Текст и позиции'],['bytes','Байты · HEX']].forEach(([value,label])=>{
    const button=el('button',value===currentMode?'active':'',label);button.type='button';button.disabled=value==='text'&&!canText;button.setAttribute('aria-pressed',String(value===currentMode));button.onclick=()=>renderDiff(diff,value);tabs.append(button);
  });node.append(tabs);
  node.append(el('p','small-note',currentMode==='text'?'Строки и столбцы — с 1, по кодовым точкам Unicode. BOM исключён при декодировании. Пробел = \\u0020, TAB = \\t, LF = \\n, CR = \\r.':'Смещения байтов — с 0. Диапазоны [начало, конец) не включают правую границу. Пустая сторона означает вставку или удаление.'));
  const hunks=currentMode==='text'?diff.textChanges:diff.byteChanges;
  const total=currentMode==='text'?diff.totalTextHunks:diff.totalByteHunks;
  const truncated=currentMode==='text'?diff.textHunksTruncated:diff.byteHunksTruncated;
  hunks.forEach((hunk,index)=>{
    const box=el('div','hunk'),kind=hunk.exact?({replace:'Замена',insert:'Вставка',delete:'Удаление'}[hunk.type]):'Охватывающий диапазон · выравнивание ограничено';
    box.append(el('div','hunk-head',(index+1)+'. '+kind));
    const body=el('div','hunk-body');
    ['before','after'].forEach(side=>{
      const panel=el('div','hunk-side '+side);panel.append(el('span','',side==='before'?'Эталон · было':'Сравниваемая группа · стало'));
      const text=currentMode==='text'?hunk[side+'Text']:hunk[side+'Hex'];
      panel.append(el('code','',text===''?'∅ (пусто)':text??'Текст недоступен'));
      if(currentMode==='text'){
        const location=hunk[side+'Location'],end=hunk[side+'EndLocation'];
        if(location)panel.append(el('p','','Строка '+location.line+', столбец '+location.column+' → строка '+end.line+', столбец '+end.column+' (конец не включён)'));
      }else panel.append(el('p','','Байты ['+hunk[side+'Start']+', '+hunk[side+'End']+') · '+fmt(hunk[side+'End']-hunk[side+'Start'])+' байт'));
      if(hunk[side+'PreviewTruncated'])panel.append(el('p','','Предпросмотр сокращён; полный диапазон указан выше.'));
      body.append(panel);
    });box.append(body);node.append(box);
  });
  if(truncated)node.append(el('p','warning','Показаны первые '+hunks.length+' из '+total+' участков. Усечение отмечено и в JSON; диапазоны не скрываются за утверждением о полном списке.'));
}
function renderFormats(){
  const files=report.files, count=fn=>files.filter(fn).length;
  $('#format-summary').replaceChildren(...[
    'BOM: '+count(file=>file.format.bom),
    'Не декодировано: '+count(file=>file.format.encoding==='Не определена'),
    'Пробелы в конце строк: '+count(file=>file.format.trailingWhitespaceLines>0),
    'Перевод строки в конце: '+count(file=>file.format.finalNewline),
    'Не-ASCII символы: '+count(file=>file.format.nonAscii>0)
  ].map(text=>el('span','',text)));
  const body=$('#format-table tbody');body.replaceChildren();
  files.slice(0,200).forEach(file=>{
    const f=file.format,known=f.encoding!=='Не определена',row=el('tr');
    [fileLabel(file),fmt(file.size),f.encoding,f.bom||'Нет',known?[f.crlf,f.lf,f.cr].join(' / '):'Не вычислено',known?f.spaces+' / '+f.tabs:'Не вычислено'].forEach(value=>row.append(el('td','',value)));
    body.append(row);
  });
  $('#format-limit').textContent=(files.length>200?'Показаны первые 200 файлов. Все '+fmt(files.length)+' записей есть в JSON и CSV. ':'')+'Счётчики текста применимы только к успешно декодированным файлам. Для неизвестной кодировки нулевые значения в данных не означают отсутствие пробелов или переводов строк.';
}
$('#download-report').onclick=()=>{if(!report||!worker)return;setBusy(true);$('#analysis-error').hidden=true;progress({phase:'export',done:0,total:report.groups.length});worker.postMessage({type:'export',referenceId});};
function csvCell(value){let text=String(value??'');if(/^[=+\-@\t\r]/.test(text))text="'"+text;return '"'+text.replace(/"/g,'""')+'"';}
$('#download-csv').onclick=()=>{
  if(!report)return;
  const columns=['entry_id','name','bytes','group','reference_group','sha256','encoding','bom','text_counters_applicable','crlf','lf','cr','spaces','tabs','trailing_whitespace_lines','final_newline'];
  const base=report.files.find(file=>file.id===referenceId);
  const rows=report.files.map(file=>{const f=file.format,known=f.encoding!=='Не определена';return [file.id+1,file.name,file.size,file.groupId,base?file.groupId===base.groupId:'not_selected',file.sha256,f.encoding,f.bom,known,known?f.crlf:null,known?f.lf:null,known?f.cr:null,known?f.spaces:null,known?f.tabs:null,known?f.trailingWhitespaceLines:null,known?f.finalNewline:null];});
  download('\uFEFF'+[columns,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n'),outputName('csv'),'text/csv;charset=utf-8');
};

