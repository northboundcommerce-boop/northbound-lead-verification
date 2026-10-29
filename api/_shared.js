const crypto = require('node:crypto');
const ORIGIN = 'https://northboundcommerce.co';
function guard(req,res){
  res.setHeader('Access-Control-Allow-Origin',ORIGIN);
  res.setHeader('Access-Control-Allow-Methods','POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type');
  res.setHeader('Vary','Origin');
  res.setHeader('Cache-Control','no-store');
  if(req.method==='OPTIONS'){res.status(204).end();return false;}
  if(req.method!=='POST'){res.status(405).json({error:'Method not allowed'});return false;}
  return true;
}
function problem(message,status=400){const e=new Error(message);e.status=status;return e;}
function fail(res,e){
  console.error('Verification endpoint:',e.message);
  res.status(e.status||500).json({error:e.status?e.message:'Verification service unavailable. Please try again shortly.'});
}
function clean(v,max=250){return typeof v==='string'?v.trim().slice(0,max):'';}
function phone(v){const digits=String(v||'').replace(/\D/g,'');if(digits.length===10)return '+1'+digits;if(digits.length===11&&digits.startsWith('1'))return '+'+digits;throw problem('Enter a valid US phone number.');}
function ip(req){return String(req.headers['x-forwarded-for']||'unknown').split(',')[0].trim();}
const secret=()=>process.env.SUPABASE_SERVICE_ROLE_KEY;
function otpHash(id,code){return crypto.createHmac('sha256',secret()).update(id+':'+code).digest('hex');}
async function db(path,method='GET',data){
 const key=secret();
 const headers={apikey:key,'Content-Type':'application/json',Prefer:'return=representation'};
 if(key.startsWith('eyJ'))headers.Authorization='Bearer '+key;
 const response=await fetch(process.env.SUPABASE_URL.replace(/\/$/,'')+'/rest/v1/'+path,{method,headers,body:data===undefined?undefined:JSON.stringify(data)});
 const body=await response.text();
 if(!response.ok){console.error('Supabase request failed:',response.status,body.slice(0,350));throw new Error('Database unavailable');}
 return body?JSON.parse(body):[];
}
async function captcha(token,address){
 if(!token)throw problem('Complete the security check.');
 const response=await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({secret:process.env.TURNSTILE_SECRET_KEY,response:token,remoteip:address})});
 const result=await response.json();
 if(!result.success){console.error('Turnstile verification failed:',JSON.stringify(result['error-codes']||[]));throw problem('Security check failed. Please refresh the page and try again.');}
 if(!['northboundcommerce.co','www.northboundcommerce.co'].includes(result.hostname)){console.error('Turnstile hostname mismatch:',result.hostname||'(missing)');throw problem('Security check configuration error. Please contact us.');}
}
async function limit(key,max,seconds){
 const key_hash=crypto.createHash('sha256').update(key).digest('hex');
 const cutoff=new Date(Date.now()-seconds*1000).toISOString();
 const entries=await db('michigan_otp_limits?key_hash=eq.'+key_hash+'&created_at=gte.'+encodeURIComponent(cutoff)+'&select=id');
 if(entries.length>=max)throw problem('Too many requests. Please try again later.',429);
 await db('michigan_otp_limits','POST',{key_hash});
}
async function sms(to,code){
 const response=await fetch('https://api.openphone.com/v1/messages',{method:'POST',headers:{Authorization:process.env.QUO_API_KEY,'Content-Type':'application/json'},body:JSON.stringify({from:process.env.QUO_PHONE_NUMBER_ID||'+12489491295',to:[to],content:'Your Northbound Commerce verification code is '+code+'. Expires in 10 minutes.'})});
 if(!response.ok){console.error('Quo SMS rejected:',response.status,(await response.text()).slice(0,350));throw new Error('SMS provider rejected request');}
}
module.exports={crypto,guard,problem,fail,clean,phone,ip,otpHash,db,captcha,limit,sms};
