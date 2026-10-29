const {crypto,guard,problem,fail,clean,ip,otpHash,db,captcha}=require('./_shared');
module.exports=async(req,res)=>{
 if(!guard(req,res))return;
 try{
  const d=req.body||{},id=clean(d.request_id,80),code=clean(d.code,10);
  if(!/^[0-9a-f-]{36}$/.test(id)||!/^[0-9]{6}$/.test(code))throw problem('Enter your six-digit code.');
  await captcha(d.turnstile_token,ip(req));
  const rows=await db('michigan_leads?id=eq.'+encodeURIComponent(id)+'&select=id,otp_hash,otp_attempts,expires_at,phone_verified');
  const row=rows[0];
  if(!row||row.phone_verified||Date.parse(row.expires_at)<Date.now()||row.otp_attempts>=5||!row.otp_hash)throw problem('Code expired or attempts exceeded. Request a new code.');
  const expected=Buffer.from(row.otp_hash,'hex'),actual=Buffer.from(otpHash(id,code),'hex');
  if(expected.length!==actual.length||!crypto.timingSafeEqual(expected,actual)){
   await db('michigan_leads?id=eq.'+encodeURIComponent(id),'PATCH',{otp_attempts:row.otp_attempts+1});
   throw problem('Incorrect code. Please try again.');
  }
  const event_id=crypto.randomUUID();
  await db('michigan_leads?id=eq.'+encodeURIComponent(id),'PATCH',{phone_verified:true,verified_at:new Date().toISOString(),status:'VERIFIED',otp_hash:null,event_id});
  res.status(200).json({success:true,verified:true,event_id});
 }catch(e){fail(res,e);}
};
