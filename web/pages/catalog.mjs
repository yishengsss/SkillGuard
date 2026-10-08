import {api} from '../assets/api.mjs';import {renderShell,skillList,tell,statuses} from '../assets/shell.mjs';
async function init(){const {config,scope}=await renderShell('catalog');let rows=[];
 async function load(){try{rows=await api(scope('/api/skills'));document.querySelector('#total').textContent=rows.length;document.querySelector('#verified').textContent=rows.filter(r=>r.status===3).length;document.querySelector('#waiting').textContent=rows.filter(r=>r.status===2).length;filter()}catch(error){tell(error.message,true)}}
 function filter(){const query=document.querySelector('#search').value.trim().toLowerCase(),status=document.querySelector('#status').value;skillList(rows.filter(r=>(r.name.toLowerCase().includes(query)||r.publisher.toLowerCase().includes(query))&&(!status||r.status===Number(status))),document.querySelector('#skills'))}
 document.querySelector('#search').addEventListener('input',filter);document.querySelector('#status').addEventListener('change',filter);document.querySelector('#refresh').addEventListener('click',load);if(config.ready)await load();}
if(typeof document!=='undefined')init().catch(error=>tell(error.message,true));
