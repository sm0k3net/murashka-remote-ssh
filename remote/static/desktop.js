import RFB from '/static/vendor/novnc/core/rfb.js';
const id=Number(location.pathname.split('/').pop());
const requestedPort=Number(new URLSearchParams(location.search).get('port'));
const status=document.getElementById('desktop-status'),button=document.getElementById('desktop-disconnect'),screen=document.getElementById('desktop-screen');
let rfb,busy=false,connected=false,generation=0;
async function json(url,options){const r=await fetch(url,options);if(!r.ok)throw Error(r.status===401?'Workspace expired; create a new workspace link':(await r.text()).slice(0,300));return r.json()}
async function connect(){if(busy)return;busy=true;button.disabled=true;const mine=++generation;rfb?.disconnect();screen.replaceChildren();status.textContent='Connecting…';
 try{const session=await json('/api/session'),cfg=await json('/api/desktop/'+id),credentials=await json('/api/desktop/'+id+'/credentials',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':session.csrf},body:'{}'});if(mine!==generation)return;const url=new URL('/api/desktop/'+id+'/ws?port='+([5900,5901].includes(requestedPort)?requestedPort:cfg.port),location.href);url.protocol=location.protocol==='https:'?'wss:':'ws:';const client=new RFB(screen,url.href,{credentials:{password:requestedPort===5900?'':(credentials.password||'')}});rfb=client;client.scaleViewport=true;client.resizeSession=true;
 client.addEventListener('connect',()=>{if(client!==rfb)return;connected=true;busy=false;button.disabled=false;button.textContent='Disconnect';status.textContent='Connected · private SSH transport · use the desktop application menu'});
 client.addEventListener('disconnect',e=>{if(client!==rfb)return;connected=false;busy=false;button.disabled=false;button.textContent='Reconnect';status.textContent=e.detail.clean?'Disconnected. Your desktop keeps running. Click Reconnect.':'Connection closed. Click Reconnect; check workspace expiry if it persists.'});
 client.addEventListener('securityfailure',()=>status.textContent='VNC authentication failed');client.addEventListener('credentialsrequired',()=>{const password=prompt('VNC server password');if(password)client.sendCredentials({password})});
 }catch(e){busy=false;connected=false;button.disabled=false;button.textContent='Reconnect';status.textContent=e.message}}
button.onclick=()=>connected?rfb.disconnect():connect();
document.getElementById('desktop-keyboard').onclick=()=>document.getElementById('desktop-input').focus();
document.getElementById('desktop-input').oninput=e=>{if(e.isComposing)return;for(const char of e.target.value){const cp=char.codePointAt(0);rfb?.sendKey(cp<=255?cp:0x01000000|cp)}e.target.value=''};
document.getElementById('desktop-input').onkeydown=e=>{const codes={Backspace:0xff08,Enter:0xff0d,Tab:0xff09};if(codes[e.key]){rfb?.sendKey(codes[e.key]);e.preventDefault()}};
document.getElementById('desktop-fullscreen').onclick=()=>screen.requestFullscreen();document.getElementById('desktop-cad').onclick=()=>rfb?.sendCtrlAltDel();window.addEventListener('pagehide',()=>{generation++;rfb?.disconnect()});connect();
