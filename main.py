import os, time, json, hmac, hashlib, secrets, datetime as dt
from collections import defaultdict, deque
from functools import wraps
import requests, jwt
from flask import Flask, request, Response, jsonify, send_from_directory
from sqlalchemy import create_engine, String, Integer, DateTime, Boolean, Text, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

E = os.environ.get
HERE = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY = E("SECRET_KEY") or secrets.token_hex(32)
SITE = (E("SITE_URL") or "http://127.0.0.1:8000").rstrip("/")
ADMIN_EMAIL = (E("ADMIN_EMAIL") or "").lower()
PG_ID, PG_SECRET = E("PLATEGA_MERCHANT_ID", ""), E("PLATEGA_SECRET", "")
PG_URL = E("PLATEGA_URL", "https://app.platega.io") + E("PLATEGA_PATH", "/transaction/process")
PG_METHOD = int(E("PLATEGA_METHOD", "10"))
db_url = E("DATABASE_URL", "sqlite:///" + os.path.join(HERE, "data.db")).replace("postgres://", "postgresql://", 1)
engine = create_engine(db_url, pool_pre_ping=True)
S = sessionmaker(engine, expire_on_commit=False)
now = lambda: dt.datetime.utcnow()

class B(DeclarativeBase): pass
class User(B):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    pw: Mapped[str] = mapped_column(String(200))
    admin: Mapped[bool] = mapped_column(Boolean, default=False)
    banned: Mapped[bool] = mapped_column(Boolean, default=False)
    plan: Mapped[str] = mapped_column(String(20), default="free")
    until: Mapped[dt.datetime | None] = mapped_column(DateTime, nullable=True)
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class Setting(B):
    __tablename__ = "settings"
    k: Mapped[str] = mapped_column(String(50), primary_key=True)
    v: Mapped[str] = mapped_column(Text)
class Payment(B):
    __tablename__ = "payments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    uid: Mapped[int] = mapped_column(Integer)
    plan: Mapped[str] = mapped_column(String(20))
    amount: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    created: Mapped[dt.datetime] = mapped_column(DateTime, default=now)
class Usage(B):
    __tablename__ = "usage"
    uid: Mapped[int] = mapped_column(primary_key=True)
    day: Mapped[str] = mapped_column(String(10), primary_key=True)
    n: Mapped[int] = mapped_column(Integer, default=0)
B.metadata.create_all(engine)

DEF_PLANS = {"free": dict(name="Free", price=0, days=0, daily=10),
             "basic": dict(name="Basic", price=199, days=30, daily=100),
             "pro": dict(name="Pro", price=499, days=30, daily=500)}
def get(k, d=""):
    with S() as s:
        r = s.get(Setting, k); return r.v if r else d
def put(k, v):
    with S() as s:
        r = s.get(Setting, k)
        if r: r.v = v
        else: s.add(Setting(k=k, v=v))
        s.commit()
def models():
    return [dict(id=a.strip(), name=(b.strip() or a.strip())) for a, _, b in (l.partition("|") for l in get("models", "mable|Mable 2").splitlines()) if a.strip()]
def plans(): return json.loads(get("plans", json.dumps(DEF_PLANS)))
def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.scrypt(p.encode(), salt=salt.encode(), n=2**14, r=8, p=1).hex()
def check_pw(p, h): return hmac.compare_digest(hash_pw(p, h.split("$")[0]), h)

class Err(Exception):
    def __init__(s, code, msg): s.code, s.msg = code, msg
app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 64_000
@app.errorhandler(Err)
def _err(e): return jsonify(detail=e.msg), e.code
@app.errorhandler(413)
def _big(e): return jsonify(detail="Слишком большой запрос"), 413

win = defaultdict(deque)
def limit(key, n, sec):
    q, t = win[key], time.time()
    while q and q[0] < t - sec: q.popleft()
    if len(q) >= n: raise Err(429, "Слишком много запросов, подожди немного")
    q.append(t)
def cip(): return (request.headers.get("X-Forwarded-For") or request.remote_addr or "?").split(",")[0].strip()
def J(): return request.get_json(silent=True) or {}

@app.after_request
def sec(r):
    r.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
        "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"})
    return r

def me():
    try: uid = jwt.decode(request.cookies.get("tk", ""), SECRET_KEY, algorithms=["HS256"])["uid"]
    except Exception: raise Err(401, "Войдите в аккаунт")
    with S() as s: u = s.get(User, uid)
    if not u or u.banned: raise Err(403, "Аккаунт заблокирован")
    return u
def need(adm=False):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = me()
            if adm and not u.admin: raise Err(403, "Только для админа")
            return f(u, *a, **k)
        return w
    return deco
def eff_plan(u): return u.plan if u.until and u.until > now() and u.plan in plans() else "free"
def used(uid):
    with S() as s:
        r = s.get(Usage, (uid, str(dt.date.today()))); return r.n if r else 0
def login_resp(u):
    tok = jwt.encode({"uid": u.id, "exp": time.time() + 30 * 86400}, SECRET_KEY, "HS256")
    r = jsonify(ok=True)
    r.set_cookie("tk", tok, httponly=True, secure=SITE.startswith("https"), samesite="Lax", max_age=30 * 86400)
    return r

@app.post("/api/register")
def register():
    limit("reg" + cip(), 5, 600)
    d = J(); em, pw = str(d.get("email", "")).strip().lower(), str(d.get("password", ""))
    if "@" not in em or len(em) > 120 or len(pw) < 8: raise Err(400, "Нужен email и пароль от 8 символов")
    with S() as s:
        if s.scalar(select(User).where(User.email == em)): raise Err(400, "Email уже занят")
        u = User(email=em, pw=hash_pw(pw), admin=(em == ADMIN_EMAIL)); s.add(u); s.commit()
    return login_resp(u)

@app.post("/api/login")
def login():
    limit("log" + cip(), 10, 300)
    d = J(); em = str(d.get("email", "")).strip().lower()
    with S() as s: u = s.scalar(select(User).where(User.email == em))
    if not u or not check_pw(str(d.get("password", "")), u.pw): raise Err(400, "Неверный email или пароль")
    return login_resp(u)

@app.post("/api/logout")
def logout():
    r = jsonify(ok=True); r.delete_cookie("tk"); return r
@app.get("/api/models")
def api_models(): return jsonify(models())
@app.get("/api/plans")
def api_plans(): return jsonify(plans())

@app.get("/api/me")
@need()
def api_me(u):
    p = eff_plan(u)
    return jsonify(email=u.email, plan=p, until=u.until.isoformat() if p != "free" else None,
                   used=used(u.id), limit=plans()[p]["daily"], admin=u.admin)

@app.post("/api/pay")
@need()
def pay(u):
    limit(f"pay{u.id}", 5, 300)
    code = J().get("plan"); pl = plans().get(code)
    if not pl or pl["price"] <= 0: raise Err(400, "Тариф недоступен")
    pid = secrets.token_hex(12)
    body = {"paymentMethod": PG_METHOD, "paymentDetails": {"amount": pl["price"], "currency": "RUB"},
            "description": f"Coude: {pl['name']}", "return": SITE + "/#plans", "failedUrl": SITE + "/#plans", "payload": pid}
    try:
        resp = requests.post(PG_URL, json=body, headers={"X-MerchantId": PG_ID, "X-Secret": PG_SECRET}, timeout=20)
        j = resp.json()
        if resp.status_code >= 300 or "redirect" not in j: raise ValueError
    except Exception: raise Err(502, "Платёжная система недоступна")
    with S() as s:
        s.add(Payment(id=j.get("transactionId") or pid, uid=u.id, plan=code, amount=pl["price"])); s.commit()
    return jsonify(url=j["redirect"])

@app.post("/api/platega/webhook")
def webhook():
    if not (PG_ID and hmac.compare_digest(request.headers.get("X-MerchantId", ""), PG_ID) and
            hmac.compare_digest(request.headers.get("X-Secret", ""), PG_SECRET)): raise Err(401, "denied")
    d = J(); tid = d.get("id") or d.get("transactionId")
    with S() as s:
        p = s.get(Payment, tid) if tid else None
        if p and d.get("status") == "CONFIRMED" and p.status != "CONFIRMED":
            p.status = "CONFIRMED"; u = s.get(User, p.uid); pl = plans()[p.plan]
            base = u.until if u.until and u.until > now() and u.plan == p.plan else now()
            u.plan, u.until = p.plan, base + dt.timedelta(days=pl["days"])
        elif p and d.get("status") == "CANCELED" and p.status == "PENDING": p.status = "CANCELED"
        s.commit()
    return jsonify(ok=True)

def sign(body):
    ts = str(int(time.time()))
    sig = hmac.new(get("api_secret").encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    return {"X-Ts": ts, "X-Sig": sig, "Content-Type": "application/json"}
def ssemsg(o): return ("data: " + json.dumps(o, ensure_ascii=False) + "\n\n").encode()

@app.post("/api/chat")
@need()
def chat(u):
    limit(f"chat{u.id}", 6, 60)
    if get("enabled", "1") != "1" or not get("api_url"): raise Err(503, "ИИ временно отключён")
    d = J(); msg = str(d.get("message", "")).strip()[:1500]
    if not msg: raise Err(400, "Пустое сообщение")
    p = eff_plan(u); lim = plans()[p]["daily"]; day = str(dt.date.today())
    with S() as s:
        us = s.get(Usage, (u.id, day)) or Usage(uid=u.id, day=day, n=0)
        if us.n >= lim: raise Err(429, f"Дневной лимит {lim} сообщений исчерпан")
        us.n += 1; s.merge(us); s.commit()
    think = bool(d.get("thinking")); effort = d.get("effort") if d.get("effort") in ("low", "medium", "high") else "medium"
    model = str(d.get("model", ""))[:30]
    if p == "free": think = False; effort = "medium" if effort == "high" else effort
    hist = [h for h in (d.get("history") or [])[-6:] if isinstance(h, dict)]
    body = json.dumps({"message": msg, "history": hist, "thinking": think, "effort": effort, "model": model}, ensure_ascii=False).encode()
    url = get("api_url").rstrip("/") + "/chat"
    def gen():
        try:
            with requests.post(url, data=body, headers=sign(body), stream=True, timeout=(10, 130)) as r:
                if r.status_code != 200:
                    yield ssemsg({"err": "busy" if r.status_code in (429, 503) else "down"}); return
                for ch in r.iter_content(chunk_size=None):
                    if ch: yield ch
        except Exception: yield ssemsg({"err": "down"})
    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})

@app.get("/api/admin/state")
@need(True)
def a_state(_):
    with S() as s:
        us = s.scalars(select(User).order_by(User.id.desc()).limit(50)).all()
        ps = s.scalars(select(Payment).order_by(Payment.created.desc()).limit(20)).all()
    return jsonify(api_url=get("api_url"), has_secret=bool(get("api_secret")), models=get("models", "mable|Mable 2"), enabled=get("enabled", "1") == "1", plans=plans(),
        users=[dict(email=x.email, plan=eff_plan(x), until=x.until and x.until.isoformat(), banned=x.banned) for x in us],
        payments=[dict(id=x.id[:8], uid=x.uid, plan=x.plan, amount=x.amount, status=x.status, at=x.created.isoformat()) for x in ps],
        revenue=sum(x.amount for x in ps if x.status == "CONFIRMED"))

@app.post("/api/hook/api-url")
def hook_url():
    limit("hook" + cip(), 10, 60)
    d = J(); url = str(d.get("url", "")).strip().rstrip("/"); ts = str(d.get("ts", "")); sec = get("api_secret")
    if not sec or not url.startswith("https://") or not ts.isdigit() or abs(time.time() - int(ts)) > 120: raise Err(400, "bad")
    exp = hmac.new(sec.encode(), (ts + "." + url).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(exp, str(d.get("sig", ""))): raise Err(401, "denied")
    put("api_url", url); return jsonify(ok=True)

@app.put("/api/admin/settings")
@need(True)
def a_set(_):
    d = J(); url = str(d.get("api_url", "")).strip().rstrip("/")
    if url and not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise Err(400, "Адрес должен начинаться с https:// (или http://127.0.0.1)")
    put("api_url", url); put("enabled", "1" if d.get("enabled") else "0")
    if "models" in d: put("models", str(d["models"])[:600])
    if d.get("api_secret"): put("api_secret", str(d["api_secret"]))
    return jsonify(ok=True)

@app.post("/api/admin/test")
@need(True)
def a_test(_):
    try:
        x = requests.get(get("api_url").rstrip("/") + "/health", headers=sign(b""), timeout=15)
        return jsonify(ok=x.status_code == 200, info=x.json() if x.status_code == 200 else x.status_code)
    except Exception as e: return jsonify(ok=False, info=type(e).__name__)

@app.put("/api/admin/plans")
@need(True)
def a_plans(_):
    d = J(); out = {}
    for k, v in plans().items():
        n = d.get(k, {})
        out[k] = dict(name=v["name"], price=max(0, int(n.get("price", v["price"]))),
                      days=max(0, int(n.get("days", v["days"]))), daily=max(1, int(n.get("daily", v["daily"]))))
    put("plans", json.dumps(out)); return jsonify(ok=True)

@app.post("/api/admin/user")
@need(True)
def a_user(_):
    d = J()
    with S() as s:
        u = s.scalar(select(User).where(User.email == str(d.get("email", "")).lower()))
        if not u: raise Err(404, "Пользователь не найден")
        if "banned" in d: u.banned = bool(d["banned"])
        if d.get("plan") in plans() and d["plan"] != "free":
            u.plan, u.until = d["plan"], now() + dt.timedelta(days=max(1, int(d.get("days", 30))))
        s.commit()
    return jsonify(ok=True)

@app.get("/")
def index(): return send_from_directory(os.path.join(HERE, "static"), "index.html")

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=int(E("PORT", "8000")), threads=8, send_bytes=1)
