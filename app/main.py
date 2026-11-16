import os,secrets,hashlib,hmac,uuid
from datetime import datetime,timezone
from pathlib import Path
from typing import Optional
from fastapi import FastAPI,Depends,HTTPException,Request,Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field,EmailStr
from sqlalchemy import create_engine,String,Integer,Boolean,DateTime,ForeignKey,func
from sqlalchemy.orm import DeclarativeBase,Mapped,mapped_column,sessionmaker,Session
from itsdangerous import URLSafeTimedSerializer,BadSignature,SignatureExpired
ROOT=Path(__file__).resolve().parent
URL=os.getenv("DATABASE_URL","sqlite:///./globalglory.db")
if URL.startswith("postgres://"): URL=URL.replace("postgres://","postgresql+psycopg://",1)
elif URL.startswith("postgresql://"): URL=URL.replace("postgresql://","postgresql+psycopg://",1)
engine=create_engine(URL,connect_args={"check_same_thread":False} if URL.startswith("sqlite") else {})
DB=sessionmaker(bind=engine,autoflush=False,expire_on_commit=False)
signer=URLSafeTimedSerializer(os.getenv("SECRET_KEY","dev-only-"+secrets.token_urlsafe(32)),salt="gg-session")
class Base(DeclarativeBase):pass
class User(Base):
 __tablename__="users"
 id:Mapped[int]=mapped_column(primary_key=True);email:Mapped[str]=mapped_column(String(254),unique=True,index=True);pw:Mapped[str]=mapped_column(String(256));name:Mapped[str]=mapped_column(String(60));role:Mapped[str]=mapped_column(String(20),default="user");credits:Mapped[int]=mapped_column(Integer,default=0);active:Mapped[bool]=mapped_column(Boolean,default=True);created:Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))
class Guild(Base):
 __tablename__="guilds"
 id:Mapped[int]=mapped_column(primary_key=True);uid:Mapped[int]=mapped_column(ForeignKey("users.id"),index=True);code:Mapped[str]=mapped_column(String(40));name:Mapped[str]=mapped_column(String(80));level:Mapped[int]=mapped_column(Integer)
class Squad(Base):
 __tablename__="squads"
 id:Mapped[int]=mapped_column(primary_key=True);uid:Mapped[int]=mapped_column(ForeignKey("users.id"));label:Mapped[str]=mapped_column(String(80));status:Mapped[str]=mapped_column(String(20),default="started");created:Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))
class Glory(Base):
 __tablename__="glory"
 id:Mapped[int]=mapped_column(primary_key=True);uid:Mapped[int]=mapped_column(ForeignKey("users.id"));guild_id:Mapped[Optional[int]]=mapped_column(ForeignKey("guilds.id"),nullable=True);amount:Mapped[int]=mapped_column(Integer);note:Mapped[str]=mapped_column(String(240),default="");status:Mapped[str]=mapped_column(String(20),default="pending");created:Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))
class Payment(Base):
 __tablename__="payments"
 id:Mapped[int]=mapped_column(primary_key=True);uid:Mapped[int]=mapped_column(ForeignKey("users.id"));order:Mapped[str]=mapped_column(String(48),unique=True);txn:Mapped[str]=mapped_column(String(100));credits:Mapped[int]=mapped_column(Integer);status:Mapped[str]=mapped_column(String(20),default="pending");created:Mapped[datetime]=mapped_column(DateTime,default=lambda:datetime.now(timezone.utc))
Base.metadata.create_all(engine)
def dbdep():
 d=DB()
 try:yield d
 finally:d.close()
def pw_hash(p):
 s=secrets.token_bytes(16);return s.hex()+"$"+hashlib.pbkdf2_hmac("sha256",p.encode(),s,310000).hex()
def pw_ok(p,h):
 try:s,x=h.split("$");return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(s),310000).hex(),x)
 except:return False
def safe(u):return {"id":u.id,"email":u.email,"name":u.name,"role":u.role,"credits":u.credits}
def auth(r:Request,d:Session=Depends(dbdep)):
 try:u=d.get(User,int(signer.loads(r.cookies["gg_session"],max_age=604800)["uid"]))
 except (KeyError,BadSignature,SignatureExpired,ValueError,TypeError):raise HTTPException(401,"Please sign in")
 if not u or not u.active:raise HTTPException(401,"Account unavailable")
 return u
def admin(u:User=Depends(auth)):
 if u.role!="admin":raise HTTPException(403,"Admin only")
 return u
class Register(BaseModel):
 name:str=Field(min_length=2,max_length=60);email:EmailStr;password:str=Field(min_length=8,max_length=128)
class Login(BaseModel):email:EmailStr;password:str
class GuildIn(BaseModel):code:str=Field(min_length=2,max_length=40);name:str=Field(min_length=2,max_length=80);level:int=Field(ge=1,le=999)
class GloryIn(BaseModel):amount:int=Field(gt=0,le=10000000);guild_id:Optional[int]=None;note:str=Field(default="",max_length=240)
class SquadIn(BaseModel):label:str=Field(default="Manual squad session",min_length=2,max_length=80)
class BuyIn(BaseModel):credits:int=Field(ge=1,le=10000);txn:str=Field(min_length=3,max_length=100)
class Adjust(BaseModel):delta:int=Field(ge=-100000,le=100000);reason:str=Field(min_length=3,max_length=160)
app=FastAPI(title="Global Glory",version="1.0")
app.mount("/static",StaticFiles(directory=ROOT/"static"),name="static")
@app.get("/")
def home():return FileResponse(ROOT/"static"/"index.html")
@app.get("/health")
def health():return {"ok":True,"mode":"manual-demo"}
@app.on_event("startup")
def seed():
 e=os.getenv("ADMIN_EMAIL","").lower().strip();p=os.getenv("ADMIN_PASSWORD","")
 if e and p:
  d=DB()
  try:
   if not d.query(User).filter_by(email=e).first():d.add(User(email=e,pw=pw_hash(p),name="Platform Admin",role="admin"));d.commit()
  finally:d.close()
@app.post("/api/register")
def register(x:Register,res:Response,d:Session=Depends(dbdep)):
 e=str(x.email).lower()
 if d.query(User).filter_by(email=e).first():raise HTTPException(409,"Email already exists")
 u=User(email=e,pw=pw_hash(x.password),name=x.name.strip());d.add(u);d.commit();d.refresh(u);res.set_cookie("gg_session",signer.dumps({"uid":u.id}),httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","false")=="true",max_age=604800);return {"user":safe(u)}
@app.post("/api/login")
def login(x:Login,res:Response,d:Session=Depends(dbdep)):
 u=d.query(User).filter_by(email=str(x.email).lower()).first()
 if not u or not pw_ok(x.password,u.pw) or not u.active:raise HTTPException(401,"Invalid login")
 res.set_cookie("gg_session",signer.dumps({"uid":u.id}),httponly=True,samesite="lax",secure=os.getenv("COOKIE_SECURE","false")=="true",max_age=604800);return {"user":safe(u)}
@app.post("/api/logout")
def logout(res:Response):res.delete_cookie("gg_session");return {"ok":True}
@app.get("/api/me")
def me(u:User=Depends(auth)):return {"user":safe(u)}
@app.get("/api/dashboard")
def dashboard(u:User=Depends(auth),d:Session=Depends(dbdep)):
 gs=d.query(Guild).filter_by(uid=u.id).all();gl=d.query(Glory).filter_by(uid=u.id).order_by(Glory.id.desc()).limit(30).all();ss=d.query(Squad).filter_by(uid=u.id).order_by(Squad.id.desc()).limit(20).all()
 return {"user":safe(u),"guilds":[{"id":g.id,"code":g.code,"name":g.name,"level":g.level} for g in gs],"glory":[{"id":x.id,"amount":x.amount,"note":x.note,"status":x.status,"created":x.created.isoformat()} for x in gl],"squads":[{"id":s.id,"label":s.label,"status":s.status,"created":s.created.isoformat()} for s in ss],"approved":int(d.query(func.coalesce(func.sum(Glory.amount),0)).filter_by(uid=u.id,status="approved").scalar()),"pending":int(d.query(func.coalesce(func.sum(Glory.amount),0)).filter_by(uid=u.id,status="pending").scalar())}
@app.post("/api/guilds")
def add_guild(x:GuildIn,u:User=Depends(auth),d:Session=Depends(dbdep)):
 g=Guild(uid=u.id,code=x.code.strip(),name=x.name.strip(),level=x.level);d.add(g);d.commit();return {"ok":True}
@app.post("/api/squads")
def squad(x:SquadIn,u:User=Depends(auth),d:Session=Depends(dbdep)):
 if u.credits<1:raise HTTPException(402,"You need one demo credit")
 u.credits-=1;s=Squad(uid=u.id,label=x.label.strip());d.add(s);d.commit();return {"ok":True,"credits":u.credits,"notice":"Manual record created; no game is launched or controlled."}
@app.post("/api/squads/{sid}/finish")
def finish(sid:int,u:User=Depends(auth),d:Session=Depends(dbdep)):
 s=d.query(Squad).filter_by(id=sid,uid=u.id).first()
 if not s:raise HTTPException(404,"Session not found")
 s.status="completed";d.commit();return {"ok":True}
@app.post("/api/glory")
def add_glory(x:GloryIn,u:User=Depends(auth),d:Session=Depends(dbdep)):
 if x.guild_id and not d.query(Guild).filter_by(id=x.guild_id,uid=u.id).first():raise HTTPException(404,"Guild not found")
 d.add(Glory(uid=u.id,guild_id=x.guild_id,amount=x.amount,note=x.note.strip()));d.commit();return {"ok":True,"notice":"Manual record submitted for admin review."}
@app.post("/api/buy")
def buy(x:BuyIn,u:User=Depends(auth),d:Session=Depends(dbdep)):
 order="GG-"+uuid.uuid4().hex[:12].upper();d.add(Payment(uid=u.id,order=order,txn=x.txn.strip(),credits=x.credits));d.commit();return {"order":order,"amount_usd":x.credits,"credits":x.credits,"notice":"Demo only: no money collected; admin approval required."}
@app.get("/api/admin/overview")
def overview(a:User=Depends(admin),d:Session=Depends(dbdep)):
 return {"users":d.query(User).count(),"guilds":d.query(Guild).count(),"squads":d.query(Squad).count(),"pending_glory":d.query(Glory).filter_by(status="pending").count(),"pending_payments":d.query(Payment).filter_by(status="pending").count(),"approved_glory":int(d.query(func.coalesce(func.sum(Glory.amount),0)).filter_by(status="approved").scalar())}
@app.get("/api/admin/data")
def admin_data(a:User=Depends(admin),d:Session=Depends(dbdep)):
 return {"users":[{"id":u.id,"email":u.email,"role":u.role,"credits":u.credits,"active":u.active} for u in d.query(User).all()],"glory":[{"id:g.id,"email":u.email,"amount":g.amount,"note":g.note,"status":g.status} for g,u in d.query(Glory,User).join(User,User.id==Glory.uid).all()],"payments":[{"id:p.id,"email":u.email,"order":p.order,"txn":p.txn,"credits":p.credits,"status":p.status} for p,u in d.query(Payment,User).join(User,User.id==Payment.uid).all()]}
@app.post("/api/admin/glory/{gid}/{decision}")
def review(gid:int,decision:str,a:User=Depends(admin),d:Session=Depends(dbdep)):
 g=d.get(Glory,gid)
 if not g:raise HTTPException(404,"Not found")
 if g.status!="pending" or decision not in ("approve","reject"):raise HTTPException(409,"Invalid review")
 g.status="approved" if decision=="approve" else "rejected";d.commit();return {"ok":True}
@app.post("/api/admin/payment/{pid}/{decision}")
def review_payment(pid:int,decision:str,a:User=Depends(admin),d:Session=Depends(dbdep)):
 p=d.get(Payment,pid)
 if not p:raise HTTPException(404,"Not found")
 if p.status!="pending" or decision not in ("approve","reject"):raise HTTPException(409,"Invalid review")
 p.status="approved" if decision=="approve" else "rejected"
 if decision=="approve":u=d.get(User,p.uid);u.credits+=p.credits
 d.commit();return {"ok":True}
@app.post("/api/admin/user/{uid}/credits")
def adjust(uid:int,x:Adjust,a:User=Depends(admin),d:Session=Depends(dbdep)):
 u=d.get(User,uid)
 if not u or u.credits+x.delta<0:raise HTTPException(400,"Invalid user or balance")
 u.credits+=x.delta;d.commit();return {"credits":u.credits}
@app.post("/api/admin/user/{uid}/toggle")
def toggle(uid:int,a:User=Depends(admin),d:Session=Depends(dbdep)):
 u=d.get(User,uid)
 if not u or u.id==a.id:raise HTTPException(400,"Invalid user")
 u.active=not u.active;d.commit();return {"active":u.active}
