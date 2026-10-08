export class ApiError extends Error{constructor(message,status,code){super(message);this.status=status;this.code=code}}
let csrfToken='',tokenPromise=null,walletAddress=null;
export function setWalletAddress(address){walletAddress=address}
export async function api(path,{method,body,zip,wallet=true}={}){
 method=method||(body!==undefined||zip!==undefined?'POST':'GET');
 if(method==='POST'&&!csrfToken){
  tokenPromise??=fetch('/api/session',{credentials:'same-origin'}).then(async response=>{const result=await response.json();if(!response.ok||!result.ok)throw new ApiError('无法建立本机会话',response.status);return result.data.csrfToken}).finally(()=>tokenPromise=null);
  csrfToken=await tokenPromise;
 }
 const headers={};if(wallet&&walletAddress)headers['X-SkillGuard-Wallet']=walletAddress;
 if(method==='POST'){headers['X-SkillGuard-Token']=csrfToken;headers['Content-Type']=zip!==undefined?'application/zip':'application/json'}
 const response=await fetch(path,{method,headers,credentials:'same-origin',body:method==='POST'?(zip??JSON.stringify(body??{})):undefined});
 const result=await response.json();
 if(!response.ok||!result.ok){if(result.code==='csrf')csrfToken='';throw new ApiError(result.error||'请求失败',response.status,result.code)}
 return result.data;
}
export function scoped(path,config,extra={}){const params=new URLSearchParams({chainId:String(config.chainId),registry:config.registry,...extra});return path+'?'+params}
