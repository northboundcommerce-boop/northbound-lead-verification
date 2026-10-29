const {crypto,guard,problem,fail,clean,phone,ip,otpHash,db,captcha,limit,sms}=require('./_shared');
module.exports=async(req,res)=>{
 if(!guard(req,res))return;
 try{
  const d=req.body||{},p=phone(d.phone),address=ip(req);
  await captcha(d.turnstile_token,address);
  const required=['full_name','business_name','email','location','service','budget','timeline'];
  if(required.some(k=>!clean(d[k])))throw problem('Please complete all required fields.');
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(d.email))throw problem('Enter a valid email address.');
  await limit('start-ip:'+address,10,3600);
  await limit('start-phone:'+p,4,3600);
  const id=crypto.randomUUID(),code=String(crypto.randomInt(1000000)).padStart(6,'0');
  const lead={id,full_name:clean(d.full_name),business_name:clean(d.business_name),email:clean(d.email).toLowerCase(),phone:p,website:clean(d.website)||null,location:clean(d.location),service:clean(d.service),budget:clean(d.budget),timeline:clean(d.timeline),decision_maker:d.decision_maker===true,marketing_consent:d.marketing_consent===true,attribution:d.attribution||{},landing_url:clean(d.landing_url,500)||null,phone_verified:false,status:'PENDING',expires_at:new Date(Date.now()+600000).toISOString(),otp_hash:otpHash(id,code),otp_attempts:0};
  await db('michigan_leads','POST',lead);
  try{await sms(p,code);}catch(e){await db('michigan_leads?id=eq.'+id,'DELETE');throw e;}
  res.status(200).json({request_id:id,expires_in_seconds:600});
 }catch(e){fail(res,e);}
};
