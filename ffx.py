import hashlib, hmac, os, time, json, threading, sqlite3, secrets, re, base64, socket, ipaddress, html, io, urllib.request, urllib.error
import sys, unicodedata
if os.path.basename(os.path.abspath(__file__)) != "ffx.py" or __name__ not in ("__main__", "ffx"):
    sys.stderr.write("\n  This build only runs as ffx.py. Put the original file name back.\n\n")
    raise SystemExit(1)
from urllib.parse import urlparse, urljoin, quote
from flask import Flask, request, jsonify, Response, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, join_room, emit

_N = ((11, 28, 63, 89, 198), (44, 49, 220, 188, 206), (193, 210, 249, 131, 235, 155, 134), (226, 247, 230, 230, 153, 200, 162))
_V = ('e77ec182a3a43292', '971c43a3d5e0d43d', 'dfdcad4c124e7ce4', 'a6a84442a22fdf2f')


def _env(i, raw=False):
    n = bytes(b ^ ((i * 29 + j * 13 + 77) & 255) for j, b in enumerate(_N[i])).decode()
    if hashlib.sha256(n.encode()).hexdigest()[:16] != _V[i]:
        sys.stderr.write("\n  Build check failed.\n\n")
        raise SystemExit(1)
    v = os.environ.get(n) or ""
    return v if raw else v.strip()


app = Flask(__name__)
app.config["SECRET_KEY"] = (os.environ.get("SECRET_KEY") or "").strip() or secrets.token_hex(32)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*",
                    ping_interval=10, ping_timeout=25)

users = {}
history = {}
seqs = {}
calls = {}
lock = threading.RLock()

ROOM = "main"
GROUP_NAME = _env(0)[:30] or "Group"
GROUP_PIC = _env(1)
if not GROUP_PIC.lower().startswith(("http://", "https://")):
    GROUP_PIC = ""

GATE_PASS = _env(2, True)


def _norm_pw(v):
    v = unicodedata.normalize("NFKC", str(v if v is not None else ""))
    v = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", v)
    return v.strip().casefold()


GATE_N = _norm_pw(GATE_PASS)
GATE_H = hashlib.sha256(GATE_PASS.encode()).hexdigest() if GATE_PASS else ""


def _pw_ok(p):
    p = str(p if p is not None else "")
    if secrets.compare_digest(p.encode(), GATE_PASS.encode()):
        return True
    return bool(GATE_N) and secrets.compare_digest(_norm_pw(p).encode(), GATE_N.encode())


def _hours(name, default):
    try:
        return max(0.01, float(os.environ.get(name) or default))
    except ValueError:
        return float(default)


GATE_TTL = _hours("GATE_HOURS", 12) * 3600
PRESENT_GRACE = 300

PIC_CACHE = {"data": None, "mime": None}
_pic_try = [0.0]

def _fetch_pic():
    try:
        req = urllib.request.Request(GROUP_PIC, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as r:
            mime = r.headers.get_content_type()
            data = r.read(3000000)
        if mime.startswith("image/") and data:
            PIC_CACHE["data"], PIC_CACHE["mime"] = data, mime
    except Exception:
        pass

def _ensure_pic():
    if GROUP_PIC and not PIC_CACHE["data"] and time.time() - _pic_try[0] > 30:
        _pic_try[0] = time.time()
        threading.Thread(target=_fetch_pic, daemon=True).start()

_ensure_pic()

DB = os.path.join(os.environ.get("DATA_DIR", "."), "chat.db")

def db():
    c = sqlite3.connect(DB, timeout=15)
    c.row_factory = sqlite3.Row
    return c

with db() as _c:
    try:
        _c.execute("pragma journal_mode=wal")
    except sqlite3.DatabaseError:
        pass
    _c.execute("create table if not exists users(id integer primary key, username text unique, pw text, name text, avatar text)")
    _c.execute("create table if not exists sess(token text primary key, uid integer)")
    _c.execute("create table if not exists msgs(seq integer primary key autoincrement, room text, mid text, cid text, name text, text text, ts integer, pv text)")
    _c.execute("create index if not exists msgs_room on msgs(room, seq)")
    _c.execute("create table if not exists gate(uid integer primary key, h text)")
    _c.execute("create table if not exists audio(id integer primary key autoincrement, mime text, data blob)")
    _c.execute("create table if not exists reactions(mid text, uid integer, emoji text, ts integer, primary key(mid, uid))")
    _c.execute("create table if not exists dels(n integer primary key autoincrement, mid text)")
    _c.execute("create table if not exists bans(uname text primary key, uid integer, name text, ts integer)")
    for _col in ("ts integer", "seen integer"):
        try:
            _c.execute("alter table users add column " + _col)
        except sqlite3.OperationalError:
            pass
    for _col in ("ts integer", "seen integer"):
        try:
            _c.execute("alter table gate add column " + _col)
        except sqlite3.OperationalError:
            pass
    _now = int(time.time())
    _c.execute("update gate set ts=coalesce(ts,?), seen=coalesce(seen,?)", (_now, _now))
    for _col in ("au integer", "dur integer", "wv text", "cl text"):
        try:
            _c.execute("alter table msgs add column " + _col)
        except sqlite3.OperationalError:
            pass

def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


_hits = {}


def _client_ip():
    xf = request.headers.get("X-Forwarded-For", "")
    return (xf.split(",")[-1].strip() if xf else request.remote_addr) or "?"


def _blocked(key, limit, window):
    now = time.time()
    if len(_hits) > 5000:
        _hits.clear()
    fresh = [t for t in _hits.get(key, []) if now - t < window]
    _hits[key] = fresh
    return len(fresh) >= limit


def _hit(key):
    _hits.setdefault(key, []).append(time.time())


@app.after_request
def _safe_headers(r):
    r.headers.setdefault("X-Content-Type-Options", "nosniff")
    return r


def load_hist(room):
    with db() as c:
        rows = c.execute("select * from msgs where room=? order by seq desc", (room,)).fetchall()
        rxs = {}
        for x in c.execute("select r.mid, r.uid, r.emoji, coalesce(nullif(u.name,''), u.username) n "
                           "from reactions r join users u on u.id=r.uid order by r.ts"):
            rxs.setdefault(x["mid"], []).append([str(x["uid"]), x["emoji"], x["n"]])
    out = []
    for r in reversed(rows):
        m = {"mid": r["mid"], "cid": r["cid"], "name": r["name"], "text": r["text"], "ts": r["ts"], "seq": r["seq"]}
        if r["pv"]:
            try:
                m["pv"] = json.loads(r["pv"])
            except Exception:
                pass
        if r["au"]:
            m["au"], m["dur"] = r["au"], r["dur"] or 0
            if r["wv"]:
                m["wv"] = r["wv"]
        if r["cl"]:
            try:
                m["cl"] = json.loads(r["cl"])
            except Exception:
                pass
        if rxs.get(r["mid"]):
            m["rx"] = rxs[r["mid"]]
        out.append(m)
    return out

def get_hist(room):
    with lock:
        if room not in history:
            history[room] = load_hist(room)
        return history[room]

def user_by_token(t):
    if not t:
        return None
    with db() as c:
        return c.execute("select u.* from sess s join users u on u.id=s.uid where s.token=? "
                         "and lower(u.username) not in (select uname from bans)", (t,)).fetchone()

def me_json(r):
    return {"id": r["id"], "username": r["username"], "name": r["name"] or r["username"], "av": bool(r["avatar"])}

def new_session(uid):
    t = secrets.token_urlsafe(32)
    with db() as c:
        c.execute("insert into sess values(?,?)", (t, uid))
    return t

@app.post("/api/register")
def api_register():
    if _blocked("reg:" + _client_ip(), 60, 3600):
        return jsonify(error="Too many sign-ups from this network. Try again later."), 429
    d = request.get_json(silent=True) or {}
    u, p = re.sub(r"\s+", " ", (d.get("username") or "").strip()), d.get("password") or ""
    if not re.fullmatch(r"[A-Za-z0-9_. ]{3,20}", u):
        return jsonify(error="Username: 3-20 letters, numbers, spaces, . or _"), 400
    if len(p) < 6:
        return jsonify(error="Password must be at least 6 characters"), 400
    try:
        with db() as c:
            if c.execute("select 1 from bans where uname=lower(?)", (u,)).fetchone():
                return jsonify(error="banned"), 403
            if c.execute("select 1 from users where lower(username)=lower(?)", (u,)).fetchone():
                return jsonify(error="Username already taken"), 400
            now = int(time.time() * 1000)
            cur = c.execute("insert into users(username,pw,name,ts,seen) values(?,?,?,?,?)",
                            (u, generate_password_hash(p), u, now, now))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 400
    _hit("reg:" + _client_ip())
    tok = new_session(uid)
    return jsonify(token=tok, me=me_json(user_by_token(tok)))

@app.post("/api/login")
def api_login():
    d = request.get_json(silent=True) or {}
    ip = _client_ip() + ":" + re.sub(r"\s+", " ", str(d.get("username") or "").strip()).lower()[:20]
    if _blocked("login:" + ip, 10, 600):
        return jsonify(error="Too many attempts. Try again in a few minutes."), 429
    with db() as c:
        r = c.execute("select * from users where lower(username)=lower(?)",
                      (re.sub(r"\s+", " ", (d.get("username") or "").strip()),)).fetchone()
    if not r or not check_password_hash(r["pw"], str(d.get("password") or "")):
        _hit("login:" + ip)
        return jsonify(error="Wrong username or password"), 400
    with db() as c:
        if c.execute("select 1 from bans where uname=lower(?)", (r["username"],)).fetchone():
            return jsonify(error="banned"), 403
        c.execute("update users set seen=? where id=?", (int(time.time() * 1000), r["id"]))
    tok = new_session(r["id"])
    return jsonify(token=tok, me=me_json(r))

@app.post("/api/me")
def api_me():
    r = user_by_token((request.get_json(silent=True) or {}).get("token"))
    return (jsonify(me=me_json(r)), 200) if r else (jsonify(error="auth"), 401)

@app.post("/api/logout")
def api_logout():
    with db() as c:
        c.execute("delete from sess where token=?", ((request.get_json(silent=True) or {}).get("token"),))
    return jsonify(ok=True)

MAX_AUDIO = 4000000

@app.post("/api/voice")
def api_voice():
    r = user_by_token(request.headers.get("X-Token"))
    if not r:
        return jsonify(error="auth"), 401
    if not unlocked(r["id"]):
        return jsonify(error="locked"), 403
    mime = (request.mimetype or "").lower()
    if not mime.startswith("audio/"):
        return jsonify(error="Invalid audio"), 400
    if (request.content_length or 0) > MAX_AUDIO:
        return jsonify(error="Voice message too long"), 413
    data = request.get_data()
    if not data or len(data) > MAX_AUDIO:
        return jsonify(error="Voice message too long"), 413
    mid = (request.headers.get("X-Mid") or "")[:64] or secrets.token_hex(6)
    try:
        dur = max(0, min(int(float(request.headers.get("X-Dur") or 0)), 600))
    except ValueError:
        dur = 0
    wv = request.headers.get("X-Wave") or ""
    if re.fullmatch(r"[0-9]{1,3}(,[0-9]{1,3}){0,79}", wv):
        wv = ",".join(str(min(100, int(x))) for x in wv.split(","))
    else:
        wv = ""
    room, cid = ROOM, str(r["id"])
    name = (r["name"] or r["username"])[:20]
    with lock:
        h = get_hist(room)
        dup = next((m for m in h if m["mid"] == mid), None)
        if dup:
            return jsonify(ok=True, seq=dup["seq"])
        ts = int(time.time() * 1000)
        with db() as c:
            aid = c.execute("insert into audio(mime,data) values(?,?)", (mime, data)).lastrowid
            seq = c.execute("insert into msgs(room,mid,cid,name,text,ts,au,dur,wv) values(?,?,?,?,?,?,?,?,?)",
                            (room, mid, cid, name, "", ts, aid, dur, wv)).lastrowid
        m = {"mid": mid, "cid": cid, "name": name, "text": "", "ts": ts, "seq": seq, "au": aid, "dur": dur}
        if wv:
            m["wv"] = wv
        h.append(m)
    socketio.emit("msg", m, to=room)
    return jsonify(ok=True, seq=seq)

@app.get("/audio/<int:aid>")
def audio_file(aid):
    r = user_by_token(request.args.get("t"))
    if not r or not unlocked(r["id"]):
        return "", 403
    with db() as c:
        a = c.execute("select mime, data from audio where id=?", (aid,)).fetchone()
    if not a:
        return "", 404
    return send_file(io.BytesIO(a["data"]), mimetype=a["mime"], conditional=True, max_age=31536000)

@app.post("/api/profile")
def api_profile():
    d = request.get_json(silent=True) or {}
    r = user_by_token(d.get("token"))
    if not r:
        return jsonify(error="auth"), 401
    name = (d.get("name") or "").strip()[:20] or r["username"]
    av = d.get("avatar")
    if not isinstance(av, str) or len(av) > 200000 or not re.match(r"data:image/(png|jpeg|webp|gif);base64,", av):
        av = None
    else:
        try:
            base64.b64decode(av.split(",", 1)[1], validate=True)
        except Exception:
            av = None
    with db() as c:
        c.execute("update users set name=?, avatar=coalesce(?,avatar) where id=?", (name, av, r["id"]))
    return jsonify(me=me_json(user_by_token(d.get("token"))))

@app.get("/avatar/<int:uid>")
def avatar(uid):
    with db() as c:
        r = c.execute("select avatar from users where id=?", (uid,)).fetchone()
    if not r or not r["avatar"]:
        return "", 404
    head, b64 = r["avatar"].split(",", 1)
    mime = head[5:].split(";")[0]
    if mime not in ("image/png", "image/jpeg", "image/webp", "image/gif"):
        return "", 404
    try:
        raw = base64.b64decode(b64)
    except Exception:
        return "", 404
    return Response(raw, mimetype=mime, headers={"Cache-Control": "public, max-age=120"})

URL_RE = re.compile(r"https?://[^\s<]+")

class _NoRedir(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None

_opener = urllib.request.build_opener(_NoRedir)

def safe_fetch(url, limit=400000):
    for _ in range(4):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        try:
            for ai in socket.getaddrinfo(p.hostname, None):
                if not ipaddress.ip_address(ai[4][0]).is_global:
                    return None
        except Exception:
            return None
        req = urllib.request.Request(url, headers={"User-Agent": "facebookexternalhit/1.1", "Accept-Language": "en"})
        try:
            r = _opener.open(req, timeout=6)
            return r.geturl(), r.read(limit).decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308):
                url = urljoin(url, e.headers.get("Location", ""))
                continue
            return None
        except Exception:
            return None
    return None

def get_preview(url):
    host = (urlparse(url).hostname or "").replace("www.", "")
    pv = {"url": url, "site": host}
    oe = None
    if host.endswith("tiktok.com"):
        oe = "https://www.tiktok.com/oembed?url=" + quote(url, safe="")
    elif host.endswith("youtube.com") or host == "youtu.be":
        oe = "https://www.youtube.com/oembed?format=json&url=" + quote(url, safe="")
    if oe:
        r = safe_fetch(oe)
        try:
            d = json.loads(r[1])
            pv.update(title=d.get("title"), image=d.get("thumbnail_url"), site=d.get("provider_name") or host, desc=d.get("author_name"))
        except Exception:
            pass
    if not pv.get("title"):
        r = safe_fetch(url)
        if r:
            h = r[1]

            def og(k):
                m = (re.search(r'<meta[^>]+(?:property|name)=["\']%s["\'][^>]*content=["\']([^"\']*)' % k, h, re.I) or
                     re.search(r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:property|name)=["\']%s["\']' % k, h, re.I))
                return html.unescape(m.group(1)) if m else None
            pv["title"] = og("og:title") or og("twitter:title")
            pv["image"] = og("og:image") or og("twitter:image")
            pv["site"] = og("og:site_name") or host
            pv["desc"] = og("og:description")
            if not pv["title"]:
                t = re.search(r"<title[^>]*>(.*?)</title>", h, re.I | re.S)
                pv["title"] = html.unescape(t.group(1).strip()) if t else None
    for k in ("title", "desc", "site"):
        if pv.get(k):
            pv[k] = str(pv[k])[:160]
    if pv.get("image") and not str(pv["image"]).startswith("http"):
        pv["image"] = None
    return pv

def make_preview(room, m, url):
    try:
        pv = get_preview(url)
    except Exception:
        pv = {"url": url, "site": urlparse(url).hostname or ""}
    m["pv"] = pv
    try:
        with db() as c:
            c.execute("update msgs set pv=? where seq=?", (json.dumps(pv), m["seq"]))
    except Exception:
        pass
    socketio.emit("preview", {"mid": m["mid"], "pv": pv}, to=room)

def room_users(room):
    seen, out = set(), []
    for s, u in list(users.items()):
        if u["room"] == room and u["cid"] not in seen:
            seen.add(u["cid"])
            out.append({"id": s, "name": u["name"]})
    return out

def cstate(room):
    c = calls.get(room)
    if not c:
        return None
    return {"video": c["video"], "starter": c["starter_name"], "starter_id": c["starter"],
            "ringing": not c["connected"],
            "parts": [{"id": s, "name": users[s]["name"]} for s in c["parts"] if s in users]}

def push_state(room):
    socketio.emit("call_state", cstate(room), to=room)

def end_call(room, reason):
    c = calls.pop(room, None)
    if not c:
        return
    socketio.emit("call_ended", {"reason": reason}, to=room)
    push_state(room)
    log_call(room, c, reason)

def _fmt_dur(s):
    s = max(0, int(s))
    h, m, sec = s // 3600, s % 3600 // 60, s % 60
    return f"{h}:{m:02d}:{sec:02d}" if h else f"{m:02d}:{sec:02d}"

def log_call(room, c, reason):
    """adds the call log message once a call is over"""
    try:
        video = bool(c["video"])
        if c["connected"]:
            res, dur = "done", int(time.time() - (c.get("t0") or time.time()))
        elif reason == "declined":
            res, dur = "declined", 0
        elif reason == "no_answer":
            res, dur = "missed", 0
        else:
            res, dur = "cancel", 0
        kind = "video" if video else "voice"
        text = f"{kind.capitalize()} call \u00b7 {_fmt_dur(dur)}" if res == "done" else f"Missed {kind} call"
        cl = {"v": video, "r": res, "d": dur}
        ts = int(time.time() * 1000)
        mid = secrets.token_hex(6)
        with lock:
            h = get_hist(room)
            with db() as cx:
                seq = cx.execute("insert into msgs(room,mid,cid,name,text,ts,cl) values(?,?,?,?,?,?,?)",
                                 (room, mid, c["starter_cid"], c["starter_name"], text, ts,
                                  json.dumps(cl))).lastrowid
            m = {"mid": mid, "cid": c["starter_cid"], "name": c["starter_name"], "text": text,
                 "ts": ts, "seq": seq, "cl": cl}
            h.append(m)
            socketio.emit("msg", m, to=room)
    except Exception:
        pass

def leave_call(sid):
    u = users.get(sid)
    if not u:
        return
    room = u["room"]
    with lock:
        c = calls.get(room)
        if not c or sid not in c["parts"]:
            return
        c["parts"].discard(sid)
        socketio.emit("call_left", sid, to=room)
        if not c["parts"] or (c["connected"] and len(c["parts"]) <= 1) or \
           (not c["connected"] and sid == c["starter"]):
            end_call(room, "ended")
        else:
            push_state(room)

def ring_timeout(room, c):
    time.sleep(45)
    with lock:
        if calls.get(room) is c and not c["connected"]:
            end_call(room, "no_answer")

@socketio.on("join")
def on_join(data):
    data = data or {}
    r = user_by_token(data.get("token"))
    if not r:
        emit("auth_error")
        return
    if not unlocked(r["id"]):
        emit("need_pass")
        return
    name = (r["name"] or r["username"])[:20]
    room = ROOM
    cid = str(r["id"])
    with db() as c:
        c.execute("update users set seen=? where id=?", (int(time.time() * 1000), r["id"]))
    last = _int(data.get("last"))
    rejoin = request.sid in users
    dup = any(v["cid"] == cid and v["room"] == room and k != request.sid for k, v in list(users.items()))
    users[request.sid] = {"name": name, "room": room, "cid": cid}
    join_room(room)
    msgs = [m for m in get_hist(room) if m["seq"] > last]
    dl, dv = del_sync(_int(data.get("dv")), last == 0)
    _touch(r["id"], True)
    emit("joined", {"id": request.sid, "msgs": msgs, "call": cstate(room),
                    "rx": rx_map(room), "dels": dl, "dv": dv})
    if not rejoin and not dup:
        emit("system", {"text": f"{name} joined"}, to=room)
    emit("users", room_users(room), to=room)

@socketio.on("sync")
def on_sync(data):
    u = users.get(request.sid)
    if not u:
        return {"msgs": [], "call": None, "rejoin": True}
    _touch(u["cid"])
    last = _int((data or {}).get("last"))
    dl, dv = del_sync(_int((data or {}).get("dv")), last == 0)
    return {"msgs": [m for m in get_hist(u["room"]) if m["seq"] > last],
            "call": cstate(u["room"]), "rx": rx_map(u["room"]), "dels": dl, "dv": dv}

@socketio.on("msg")
def on_msg(data):
    data = data or {}
    u = users.get(request.sid)
    text = (data.get("text") or "").strip()[:1000]
    mid = str(data.get("mid") or "")[:64]
    if not u or not text:
        return {"ok": False}
    room = u["room"]
    mid = mid or secrets.token_hex(6)
    with lock:
        h = get_hist(room)
        dup = next((m for m in h if m["mid"] == mid), None)
        if dup:
            return {"ok": True, "seq": dup["seq"]}
        ts = int(time.time() * 1000)
        with db() as c:
            seq = c.execute("insert into msgs(room,mid,cid,name,text,ts) values(?,?,?,?,?,?)",
                            (room, mid, u["cid"], u["name"], text, ts)).lastrowid
        m = {"mid": mid, "cid": u["cid"], "name": u["name"], "text": text, "ts": ts, "seq": seq}
        h.append(m)
    emit("msg", m, to=room)
    url = URL_RE.search(text)
    if url:
        socketio.start_background_task(make_preview, room, m, url.group(0))
    return {"ok": True, "seq": m["seq"]}

def rx_map(room):
    return {m["mid"]: m["rx"] for m in get_hist(room) if m.get("rx")}

def del_sync(dv, fresh):
    """Which messages were deleted since the client last looked (so offline devices catch up)."""
    with db() as c:
        if fresh:
            return [], c.execute("select coalesce(max(n),0) from dels").fetchone()[0]
        rows = c.execute("select n, mid from dels where n>? order by n limit 500", (dv,)).fetchall()
    return [r["mid"] for r in rows], (rows[-1]["n"] if rows else dv)

@socketio.on("del")
def on_del(data):
    u = users.get(request.sid)
    mid = str((data or {}).get("mid") or "")[:64]
    if not u or not mid:
        return {"ok": False}
    room = u["room"]
    with lock:
        with db() as c:
            r = c.execute("select seq, cid, au from msgs where room=? and mid=?", (room, mid)).fetchone()
            if not r or r["cid"] != u["cid"]:
                return {"ok": False}
            c.execute("delete from msgs where seq=?", (r["seq"],))
            if r["au"]:
                c.execute("delete from audio where id=?", (r["au"],))
            c.execute("delete from reactions where mid=?", (mid,))
            c.execute("insert into dels(mid) values(?)", (mid,))
        h = get_hist(room)
        h[:] = [m for m in h if m["mid"] != mid]
    emit("del", {"mid": mid}, to=room)
    return {"ok": True}

@socketio.on("react")
def on_react(data):
    u = users.get(request.sid)
    d = data or {}
    mid = str(d.get("mid") or "")[:64]
    em = str(d.get("emoji") or "").strip()
    if not u or not mid or not em or len(em) > 16 or re.search(r"[A-Za-z0-9\s<>&\"']", em):
        return {"ok": False}
    room, uid = u["room"], int(u["cid"])
    with lock:
        with db() as c:
            if not c.execute("select 1 from msgs where room=? and mid=?", (room, mid)).fetchone():
                return {"ok": False}
            cur = c.execute("select emoji from reactions where mid=? and uid=?", (mid, uid)).fetchone()
            if cur and cur["emoji"] == em:
                c.execute("delete from reactions where mid=? and uid=?", (mid, uid))
            else:
                c.execute("insert or replace into reactions values(?,?,?,?)", (mid, uid, em, int(time.time() * 1000)))
            rows = c.execute("select r.uid, r.emoji, coalesce(nullif(u.name,''), u.username) n "
                             "from reactions r join users u on u.id=r.uid where r.mid=? order by r.ts", (mid,)).fetchall()
        rx = [[str(x["uid"]), x["emoji"], x["n"]] for x in rows]
        m = next((x for x in get_hist(room) if x["mid"] == mid), None)
        if m is not None:
            if rx:
                m["rx"] = rx
            else:
                m.pop("rx", None)
    emit("rx", {"mid": mid, "rx": rx}, to=room)
    return {"ok": True}

@socketio.on("call_start")
def on_call_start(data):
    data = data or {}
    u = users.get(request.sid)
    if not u:
        return {"err": "nouser"}
    room = u["room"]
    with lock:
        if room in calls:
            return {"err": "busy"}
        c = {"video": bool(data.get("video")), "starter": request.sid, "starter_name": u["name"],
             "parts": {request.sid}, "declined": set(), "connected": False,
             "starter_cid": u["cid"], "t0": 0}
        calls[room] = c
    push_state(room)
    emit("call_incoming", {"from": u["name"], "video": c["video"]}, to=room, skip_sid=request.sid)
    socketio.start_background_task(ring_timeout, room, c)
    return {"ok": True}

@socketio.on("call_accept")
def on_call_accept():
    u = users.get(request.sid)
    if not u:
        return
    room = u["room"]
    with lock:
        c = calls.get(room)
        if not c:
            return
        others = [s for s in c["parts"] if s != request.sid]
        c["parts"].add(request.sid)
        if not c["connected"]:
            c["t0"] = time.time()
        c["connected"] = True
    emit("call_peers", others)
    push_state(room)

@socketio.on("call_decline")
def on_call_decline():
    u = users.get(request.sid)
    if not u:
        return
    room = u["room"]
    with lock:
        c = calls.get(room)
        if not c:
            return
        c["declined"].add(request.sid)
        invitees = {s for s, x in users.items() if x["room"] == room} - c["parts"]
        if not c["connected"] and invitees <= c["declined"]:
            end_call(room, "declined")

@socketio.on("call_leave")
def on_call_leave():
    leave_call(request.sid)

@socketio.on("signal")
def on_signal(data):
    data = data or {}
    u, t = users.get(request.sid), users.get(data.get("to"))
    if u and t and u["room"] == t["room"]:
        emit("signal", {"from": request.sid, "data": data.get("data")}, to=data["to"])

@socketio.on("disconnect")
def on_disconnect():
    leave_call(request.sid)
    u = users.pop(request.sid, None)
    if not u:
        return
    try:
        with db() as c:
            c.execute("update users set seen=? where id=?", (int(time.time() * 1000), int(u["cid"])))
    except Exception:
        pass
    _touch(u["cid"], True)
    if not any(v["cid"] == u["cid"] and v["room"] == u["room"] for v in list(users.values())):
        emit("system", {"text": f"{u['name']} left"}, to=u["room"])
    emit("users", room_users(u["room"]), to=u["room"])

_cf = {"list": None, "at": 0.0, "try": 0.0}


def _cf_ice():
    kid = (os.environ.get("TURN_CF_ID") or "").strip()
    tok = (os.environ.get("TURN_CF_TOKEN") or "").strip()
    if not kid or not tok:
        return None
    now = time.time()
    with lock:
        if _cf["list"] and now - _cf["at"] < 6 * 3600:
            return _cf["list"]
        if now - _cf["try"] < 30:
            return _cf["list"]
        _cf["try"] = now
    try:
        req = urllib.request.Request(
            "https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate-ice-servers" % quote(kid, safe=""),
            data=json.dumps({"ttl": 86400}).encode(),
            headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=8) as r:
            d = json.loads(r.read().decode())
        ice = d.get("iceServers", d) if isinstance(d, dict) else d
        if isinstance(ice, dict):
            ice = [ice]
        ice = [x for x in ice if isinstance(x, dict) and x.get("urls")]
        if not any(x.get("credential") for x in ice):
            return _cf["list"]
        with lock:
            _cf["list"], _cf["at"] = ice, now
        return ice
    except Exception:
        return _cf["list"]


def ice_servers():
    cf = _cf_ice()
    if cf:
        return list(cf) + [{"urls": "stun:stun.l.google.com:19302"}]
    s = [{"urls": "stun:stun.l.google.com:19302"}, {"urls": "stun:stun1.l.google.com:19302"}]
    urls = [u.strip() for u in (os.environ.get("TURN_URL") or "").split(",") if u.strip()]
    if urls:
        s.append({"urls": urls,
                  "username": (os.environ.get("TURN_USER") or "").strip(),
                  "credential": (os.environ.get("TURN_PASS") or "").strip()})
    return s


_touched = {}


def _touch(uid, force=False):
    if not GATE_PASS:
        return
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return
    now = time.time()
    if not force and now - _touched.get(uid, 0) < 20:
        return
    _touched[uid] = now
    try:
        with db() as c:
            c.execute("update gate set seen=? where uid=?", (int(now), uid))
    except Exception:
        pass


def _connected(uid):
    cid = str(uid)
    return any(v["cid"] == cid for v in list(users.values()))


def _grant(uid):
    now = int(time.time())
    with db() as c:
        c.execute("insert or replace into gate(uid,h,ts,seen) values(?,?,?,?)", (uid, GATE_H, now, now))


def unlocked(uid):
    if not GATE_PASS:
        return True
    with db() as c:
        r = c.execute("select h, ts, seen from gate where uid=?", (uid,)).fetchone()
    now = time.time()
    if r and r["h"] == GATE_H and now - (r["ts"] or 0) < GATE_TTL:
        return True
    if _connected(uid) or (r and r["seen"] and now - r["seen"] < PRESENT_GRACE):
        try:
            _grant(uid)
        except Exception:
            pass
        return True
    return False

@app.post("/api/gate")
def api_gate():
    d = request.get_json(silent=True) or {}
    r = user_by_token(d.get("token"))
    if not r:
        return jsonify(error="auth"), 401
    if unlocked(r["id"]):
        return jsonify(ok=True)
    p = d.get("password")
    if p is None:
        return jsonify(need=True)
    if _blocked("gate:%s" % r["id"], 8, 600):
        return jsonify(error="Too many attempts. Try again in a few minutes."), 429
    if not _pw_ok(p):
        _hit("gate:%s" % r["id"])
        time.sleep(1)
        return jsonify(error="Wrong password"), 400
    _grant(r["id"])
    return jsonify(ok=True)

@app.get("/gpic")
def gpic():
    d = PIC_CACHE["data"]
    if not d:
        return "", 404
    return Response(d, mimetype=PIC_CACHE["mime"], headers={"Cache-Control": "public, max-age=86400"})

@app.route("/")
def index():
    _ensure_pic()
    pic, pre = GROUP_PIC, ""
    d = PIC_CACHE["data"]
    if d and len(d) <= 150000:
        pic = "data:%s;base64,%s" % (PIC_CACHE["mime"], base64.b64encode(d).decode())
    else:
        if d:
            pic = "/gpic?v=" + hashlib.md5(d).hexdigest()[:10]
        if pic:
            pre = '<link rel="preload" as="image" href="%s">' % html.escape(pic, quote=True)
    cfg = {"iceServers": ice_servers(), "group": GROUP_NAME, "pic": pic}
    resp = Response(HTML.replace("__ICE__", json.dumps(cfg).replace("<", "\\u003c"))
                    .replace("__GN__", html.escape(GROUP_NAME))
                    .replace("__PRE__", pre), mimetype="text/html")
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp

HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="theme-color" content="#050505">
<title>__GN__</title>__PRE__
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{--bg:#060a13;--s1:#0d1424;--s2:#172036;--tx:#eef2f8;--mu:#8b98b0;--ac:#2ee6a6;--ac2:#22b8d6;--rd:#ff4d6a;--g:linear-gradient(135deg,#2ee6a6,#22b8d6);--bd:#ffffff1a}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{height:100%;font-family:Inter,system-ui,sans-serif;background:var(--bg);color:var(--tx)}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-thumb{background:#ffffff22;border-radius:6px}
.i{width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer}

#login{position:relative;overflow:hidden;height:100%;display:flex;align-items:center;justify-content:center;padding:16px;background:var(--bg)}
#login::before,#login::after{content:"";position:absolute;width:420px;height:420px;border-radius:50%;filter:blur(90px);opacity:.55;animation:float 14s ease-in-out infinite alternate}
#login::before{background:#2ee6a6;left:-120px;top:-120px}
#login::after{background:#6d5dfc;right:-140px;bottom:-140px;animation-delay:-6s}
@keyframes float{to{transform:translate(70px,50px) scale(1.15)}}
.card{position:relative;z-index:1;width:100%;max-width:390px;padding:34px 26px 28px;border-radius:28px;background:linear-gradient(160deg,#ffffff1c,#ffffff08);border:1px solid #ffffff26;backdrop-filter:blur(26px) saturate(140%);-webkit-backdrop-filter:blur(26px) saturate(140%);box-shadow:0 30px 80px #000a,inset 0 1px 0 #ffffff2e;text-align:center;animation:rise .6s cubic-bezier(.2,.8,.2,1)}
@keyframes rise{from{opacity:0;transform:translateY(24px) scale(.97)}}
.logo{width:72px;height:72px;margin:0 auto 18px;border-radius:24px;display:flex;align-items:center;justify-content:center;background:var(--g);color:#032a20;box-shadow:0 12px 34px #2ee6a666;animation:bob 3.5s ease-in-out infinite}
@keyframes bob{50%{transform:translateY(-6px) rotate(-3deg)}}
.logo .i{width:36px;height:36px}
.card h1{font-size:28px;font-weight:700;margin-bottom:6px;letter-spacing:-.3px;background:linear-gradient(90deg,#fff,#9ff5dc);-webkit-background-clip:text;background-clip:text;color:transparent}
.card p{color:var(--mu);font-size:14px;margin-bottom:22px;line-height:1.5}
.fld{display:flex;align-items:center;gap:10px;background:#050912aa;border:1px solid var(--bd);border-radius:16px;padding:0 16px;margin-bottom:12px;color:var(--mu);transition:.2s}
.fld:focus-within{border-color:var(--ac);color:var(--ac);box-shadow:0 0 0 4px #2ee6a622}
.fld input{flex:1;background:none;border:0;outline:0;color:var(--tx);font:inherit;font-size:16px;padding:15px 0;min-width:0}
.fld input::placeholder{color:#6b7891}
.btn{width:100%;padding:15px;border-radius:16px;background:var(--g);color:#032a20;font-size:16px;font-weight:700;margin-top:8px;box-shadow:0 10px 28px #2ee6a640;transition:.2s}
.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}.btn:active{transform:scale(.98)}

#app{display:none;height:100%;max-width:920px;margin:0 auto;flex-direction:column;background:var(--bg);position:relative;box-shadow:0 0 80px #000}
header{position:relative;z-index:5;display:flex;align-items:center;gap:10px;padding:10px 12px;padding-top:calc(10px + env(safe-area-inset-top,0px));background:#0d1424e6;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-bottom:1px solid #ffffff12;box-shadow:0 4px 24px #0006}
.ib{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#b9c4d6;transition:.18s}
.ib:hover{background:#ffffff14;color:var(--ac)}.ib:active{background:#ffffff22;transform:scale(.92)}
.av{width:44px;height:44px;border-radius:50%;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:19px;flex:none;box-shadow:0 0 0 3px #2ee6a629}
.info{flex:1;min-width:0}.info b{display:block;font-size:16.5px;font-weight:600}
.info small{color:var(--ac);font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:block;opacity:.85}
#ban{display:none;align-items:center;gap:10px;padding:11px 14px;background:linear-gradient(90deg,#0b6b54,#0b5a78);font-size:14px;animation:rise .4s}
#ban span{flex:1}#ban button{background:#fff;color:#04382b;font-weight:700;padding:7px 18px;border-radius:20px}
#msgs{flex:1;overflow-y:auto;padding:16px 12px;display:flex;flex-direction:column;gap:6px;background:radial-gradient(circle at 85% 0,#153a45 0,transparent 45%),radial-gradient(circle at 0 100%,#221c4a 0,transparent 45%),var(--bg);scroll-behavior:smooth}
.m{position:relative;max-width:80%;padding:8px 12px 6px;border-radius:18px 18px 18px 5px;background:linear-gradient(160deg,#1e2a45,#172036);border:1px solid #ffffff0f;font-size:15px;line-height:1.45;word-wrap:break-word;white-space:pre-wrap;align-self:flex-start;box-shadow:0 2px 8px #0005;animation:pop .28s cubic-bezier(.2,.9,.3,1.2)}
@keyframes pop{from{opacity:0;transform:translateY(10px) scale(.94)}}
.m.me{background:linear-gradient(135deg,#0f9f83,#0a86a3);border-color:#ffffff1f;align-self:flex-end;border-radius:18px 18px 5px 18px;box-shadow:0 4px 14px #0a86a340}
.m.pd{opacity:.55}
.m .n{font-size:12.5px;font-weight:600;color:var(--ac);margin-bottom:3px}
.m .t{font-size:10.5px;color:#ffffff99;margin:4px 0 0 12px;float:right}
.sys{align-self:center;background:#ffffff10;border:1px solid #ffffff0d;color:var(--mu);font-size:12px;padding:4px 14px;border-radius:14px;margin:6px 0}
form{display:flex;gap:10px;padding:10px 12px;padding-bottom:calc(10px + env(safe-area-inset-bottom,0px));background:#0d1424e6;backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);border-top:1px solid #ffffff12}
form input{flex:1;padding:14px 20px;border:1px solid var(--bd);border-radius:28px;font-size:16px;outline:0;background:#050912aa;color:var(--tx);font-family:inherit;transition:.2s}
form input:focus{border-color:var(--ac);box-shadow:0 0 0 4px #2ee6a61c}
form button{width:50px;height:50px;border-radius:50%;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px #2ee6a640;transition:.2s}
form button:hover{transform:scale(1.06) rotate(-8deg)}form button:active{transform:scale(.9)}
#toast{position:fixed;left:50%;bottom:96px;transform:translateX(-50%);background:#0d1424f2;border:1px solid #ffffff22;padding:11px 20px;border-radius:22px;font-size:14px;z-index:200;display:none;box-shadow:0 10px 30px #000a;animation:rise .3s}

#ov{position:fixed;inset:0;z-index:100;display:none;flex-direction:column;background:radial-gradient(circle at 50% 0,#0f5a4a 0,transparent 55%),radial-gradient(circle at 100% 100%,#2a2360 0,transparent 50%),linear-gradient(#0a1019,#04070c);padding:env(safe-area-inset-top,0) 0 env(safe-area-inset-bottom,0)}
#ov.show{display:flex}
#rp{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px;text-align:center}
#ov.live #rp,#ov:not(.live) #grid,#ov:not(.live) #top{display:none}
#pav{width:140px;height:140px;border-radius:50%;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;font-size:58px;font-weight:700;margin-bottom:16px;animation:pl 1.8s infinite}
@keyframes pl{0%{box-shadow:0 0 0 0 #2ee6a680}100%{box-shadow:0 0 0 46px #2ee6a600}}
#pn{font-size:30px;font-weight:600}#pl{color:var(--mu);font-size:16px}
#top{text-align:center;padding:14px;color:#c7d0d6;font-size:14px;font-weight:500}
#grid{flex:1;display:grid;gap:8px;padding:8px;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));grid-auto-rows:1fr;position:relative;min-height:0}
#grid.duo{display:block}
.tile{position:relative;border-radius:22px;overflow:hidden;background:#141d2e;min-height:0;display:flex;align-items:center;justify-content:center;box-shadow:0 8px 24px #0007}
#grid.duo .tile{position:absolute;inset:8px}
#grid.duo .tile.me{inset:auto;right:16px;top:16px;width:104px;height:148px;z-index:3;border:2px solid #ffffff40;box-shadow:0 8px 24px #000a}
.tile video{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.tile.me video.mir{transform:scaleX(-1)}
.tile .ab{width:84px;height:84px;border-radius:50%;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;font-size:34px;font-weight:700}
.tile .tn{position:absolute;left:10px;bottom:8px;font-size:12.5px;background:#000a;backdrop-filter:blur(6px);padding:3px 11px;border-radius:12px;z-index:2}
.tile.novid video{display:none}
.bar{display:flex;justify-content:center;gap:18px;padding:18px 16px 26px}
#ov.in #cout,#ov:not(.in) #cin{display:none}
.cb{width:62px;height:62px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:#ffffff22;backdrop-filter:blur(12px);border:1px solid #ffffff1a;transition:.15s}
.cb:active{transform:scale(.9)}.cb.off{background:#fff;color:#111}
.cb.end,.cb.dec{background:var(--rd);box-shadow:0 8px 24px #ff4d6a66}.cb.acc{background:#22c55e;box-shadow:0 8px 24px #22c55e66;animation:ring 1.2s infinite}
@keyframes ring{50%{transform:scale(1.1)}}
.cb.end .i,.cb.dec .i{transform:rotate(135deg)}
.cb .i{width:26px;height:26px}

#auth,#prof,#home,#gate,#banned{display:none}
.tabs{display:flex;background:#050912aa;border:1px solid #ffffff12;border-radius:14px;padding:4px;margin-bottom:16px}
.tabs button{flex:1;padding:10px;border-radius:11px;color:var(--mu);font-weight:600;transition:.2s}.tabs .on{background:var(--g);color:#032a20}
.err{color:#ff8a9c;font-size:13px;min-height:18px;margin-bottom:4px}
.pfa{width:108px;height:108px;border-radius:50%;margin:0 auto 18px;background:#ffffff12 center/cover;border:2px dashed #ffffff44;display:flex;align-items:center;justify-content:center;color:var(--mu);cursor:pointer;font-size:44px;font-weight:700;overflow:hidden;transition:.2s}
.pfa:hover{border-color:var(--ac);color:var(--ac)}
.pfa .i{width:32px;height:32px}#hav{border:3px solid transparent;background-origin:border-box;background-clip:padding-box,border-box;font-style:normal;color:var(--tx);box-shadow:0 0 0 3px #2ee6a640,0 10px 30px #2ee6a633}
.gl{text-align:left;color:var(--mu);font-size:12px;margin:14px 4px 6px;letter-spacing:.4px;text-transform:uppercase}
.lo{margin-top:16px;color:var(--mu);font-size:14px;transition:.2s}.lo:hover{color:var(--rd)}
.mav{display:inline-block;position:relative;width:20px;height:20px;border-radius:50%;background:var(--g);vertical-align:-5px;margin-right:6px;overflow:hidden;font-size:11px;font-weight:700;text-align:center;line-height:20px;color:#032a20}
.mav img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.lnk{color:#7dd3fc;text-decoration:underline;word-break:break-all}
.pv{display:block;clear:both;white-space:normal;margin:8px 0 2px;border-radius:14px;overflow:hidden;background:#00000055;color:var(--tx);text-decoration:none;border-left:3px solid var(--ac);transition:.2s}
.pv:hover{background:#00000077}
.pv img{display:block;width:100%;max-height:220px;object-fit:cover}
.pv div{padding:9px 12px}.pv small{display:block;color:var(--ac);font-size:11.5px;font-weight:600;text-transform:uppercase}
.pv b{display:block;font-size:14px;font-weight:600;margin:2px 0;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.pv span{display:block;color:var(--mu);font-size:12.5px}
.gav,.av,#pav{position:relative;overflow:hidden}
.gav img,.av img,#pav img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.gav{width:108px;height:108px;border-radius:50%;margin:6px auto 12px;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;font-size:44px;font-weight:700;box-shadow:0 0 0 3px #2ee6a640,0 10px 30px #2ee6a633}
.gnm{font-size:22px;font-weight:700;margin-bottom:4px;word-break:break-word}
.cb.on{background:var(--ac);color:#032a20}
.tile.scr{order:-1;grid-column:1/-1;grid-row:span 2;background:#000}
.tile.scr .ab{display:none}
.tile.scr video{object-fit:contain}
@media(max-width:430px){.bar{gap:11px;padding-left:8px;padding-right:8px}.cb{width:56px;height:56px}}
.logo{position:relative;overflow:hidden}
.logo img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
header .av{margin-left:4px}.av,.info{cursor:pointer}
#mn{display:none;position:absolute;top:calc(66px + env(safe-area-inset-top,0px));left:12px;z-index:9;background:#0d1424f2;border:1px solid #ffffff22;border-radius:14px;overflow:hidden;box-shadow:0 10px 30px #000a}
#mn button{display:block;width:100%;padding:13px 24px;text-align:left;font-size:15px}
#mn button:hover{background:#ffffff14}#mn #lo:hover{color:var(--rd)}

header{gap:8px;padding:6px 10px;padding-top:calc(6px + env(safe-area-inset-top,0px));box-shadow:0 2px 14px #0005}
.ib{width:36px;height:36px}.ib .i{width:20px;height:20px}
header .av{width:34px;height:34px;font-size:15px;margin-left:2px;box-shadow:0 0 0 2px #2ee6a629}
.info b{font-size:15px;line-height:1.25}.info small{font-size:11.5px;line-height:1.25}
#mn{top:calc(48px + env(safe-area-inset-top,0px))}

.ld{position:relative;z-index:1;width:38px;height:38px;border-radius:50%;border:3px solid #ffffff22;border-top-color:var(--ac);animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}

.pwrap{position:relative;width:132px;height:132px;margin:4px auto 12px}
.pwrap .pfa{width:132px;height:132px;margin:0;border:0;background:var(--g) center/cover;color:#032a20;font-size:56px;box-shadow:0 0 0 4px #ffffff14,0 0 0 8px #2ee6a633,0 18px 44px #2ee6a640;transition:.25s}
.pwrap .pfa:hover{transform:scale(1.03);filter:brightness(1.06);color:#032a20}
.pwrap.has .pfa b{display:none}
.pbadge{position:absolute;right:2px;bottom:4px;width:40px;height:40px;border-radius:50%;background:#fff;color:#04382b;display:flex;align-items:center;justify-content:center;border:3px solid #141c30;box-shadow:0 6px 16px #0008;cursor:pointer;transition:.2s}
.pbadge:hover{transform:scale(1.1)}.pbadge .i{width:19px;height:19px}
.phint{color:var(--mu);font-size:12.5px;margin-bottom:20px}
.cnt{font-size:12px;color:#6b7891;flex:none}

form{gap:8px}
form button{width:46px;height:46px}
form button.mic{background:#ffffff14;color:var(--ac);box-shadow:none;border:1px solid var(--bd)}
form button.mic:hover{transform:scale(1.06)}
#f:not(.has) #sb{display:none}#f.has .mic{display:none}
#rec{display:none;flex:1;min-width:0;height:50px;align-items:center;gap:10px;padding:0 6px 0 14px;background:#050912aa;border:1px solid var(--bd);border-radius:28px}
form button.mic{touch-action:none;-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
#f.recm #txt{display:none}#f.recm #rec{display:flex}
#f.recm:not(.lk) .rb{display:none}#f.recm:not(.lk) #rec{padding-right:16px}
#f.lk .mic{display:none}
#f.recm:not(.lk) .mic{background:var(--rd);color:#fff;border-color:transparent;transform:scale(1.22);box-shadow:0 0 0 8px #ff4d6a30,0 0 0 16px #ff4d6a18;animation:mpl 1.2s infinite}
@keyframes mpl{50%{box-shadow:0 0 0 12px #ff4d6a26,0 0 0 24px #ff4d6a0d}}
#rec .rb:hover{transform:none}
.rb{width:46px;height:46px;border-radius:50%;display:flex;align-items:center;justify-content:center;flex:none;transition:.2s}
.rb:active{transform:scale(.9)}
.rb.rx{background:#ffffff14;color:var(--rd)}
.rb.rs{background:var(--g);color:#032a20;box-shadow:0 6px 18px #2ee6a640}
.rdot{width:10px;height:10px;border-radius:50%;background:var(--rd);flex:none;animation:blink 1s infinite}
@keyframes blink{50%{opacity:.25}}
#rtm{font-size:16px;font-weight:600;min-width:42px;font-variant-numeric:tabular-nums}
#rw{flex:1;min-width:0;height:34px}#rcv{display:block;width:100%;height:100%}
#rhint{flex:none;font-size:11.5px;color:var(--mu);white-space:nowrap;animation:nudge 1.6s ease-in-out infinite}
#f.lk #rhint{display:none}#f.cx #rhint{color:var(--rd)}
@keyframes nudge{50%{transform:translateX(-5px)}}
.m.v{min-width:250px}
.m.v .t{float:none;display:block;text-align:right;margin:3px 0 0}
.vm{display:flex;align-items:center;gap:10px;padding:2px 0}
.vp{width:36px;height:36px;border-radius:50%;background:#fff;color:#04382b;display:flex;align-items:center;justify-content:center;flex:none;box-shadow:0 3px 10px #0005}
.m:not(.me) .vp{background:var(--g)}
.vp .i{width:16px;height:16px;fill:currentColor;stroke:currentColor;stroke-width:1}
.vb{flex:1;min-width:0;height:32px;display:flex;align-items:center;gap:2px;cursor:pointer;touch-action:pan-y;overflow:hidden}
.vb i{flex:1;min-width:2px;border-radius:2px;background:#ffffff4d;transition:background .15s}
.vb i.on{background:#fff}.m:not(.me) .vb i.on{background:var(--ac)}
.vd{font-size:12px;min-width:34px;text-align:right;color:#ffffffcc;font-variant-numeric:tabular-nums}

.m{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
.m.sel{box-shadow:0 0 0 2px var(--ac),0 12px 34px #000b}
.m.gone{animation:gone .3s ease forwards}@keyframes gone{to{opacity:0;transform:scale(.7)}}
.rxs{display:flex;flex-wrap:wrap;gap:5px;clear:both;margin-top:6px;white-space:normal}
.rc{display:inline-flex;align-items:center;gap:5px;padding:2px 8px 2px 6px;border-radius:15px;background:#00000040;border:1px solid #ffffff1f;animation:pop .3s cubic-bezier(.2,1.6,.4,1)}
.rc.mine{background:#2ee6a62b;border-color:#2ee6a688}
.rc .re{font-size:15px;line-height:1}.rst{display:inline-flex}
.rav{position:relative;width:18px;height:18px;border-radius:50%;background:var(--g);color:#032a20;font-size:10px;font-weight:700;display:flex;align-items:center;justify-content:center;overflow:hidden;border:1.5px solid #17213a;margin-left:-6px}
.rav:first-child{margin-left:0}.rav img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.rn{font-size:11px;color:#ffffffcc}
#veil{position:fixed;inset:0;z-index:150;display:none}#veil.show{display:block}
#veil.dim{background:#000000a0;backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
#rbar{position:fixed;z-index:160;display:none;align-items:center;gap:2px;padding:6px 8px;border-radius:34px;background:linear-gradient(160deg,#283456f2,#121a2ef7);border:1px solid #ffffff2b;box-shadow:0 20px 50px #000c,inset 0 1px 0 #ffffff30;backdrop-filter:blur(22px);-webkit-backdrop-filter:blur(22px);animation:rbin .3s cubic-bezier(.2,1.3,.3,1)}
#rbar.show{display:flex}
#rbar.grid.show{display:grid;grid-template-columns:repeat(8,1fr);border-radius:24px;padding:10px;width:min(94vw,372px)}
@keyframes rbin{from{opacity:0;transform:translateY(10px) scale(.7)}}
#rbar button{width:42px;height:42px;border-radius:50%;font-size:26px;line-height:1;display:flex;align-items:center;justify-content:center;transition:transform .16s;animation:emo .45s cubic-bezier(.2,1.7,.4,1) both}
#rbar.grid button{width:100%;height:40px;font-size:24px}
#rbar button img{width:34px;height:34px;pointer-events:none;-webkit-user-drag:none}
#rbar button:hover,#rbar button:active{transform:scale(1.3) translateY(-5px)}
#rbar button.on{background:#2ee6a626;box-shadow:0 0 0 2px var(--ac)}
#rbar .more{font-size:22px;font-weight:700;color:var(--mu);background:#ffffff14;margin-left:4px}
@keyframes emo{from{opacity:0;transform:translateY(14px) scale(.3)}}
.burst{position:fixed;z-index:170;width:60px;height:60px;font-size:46px;text-align:center;pointer-events:none;animation:bst 1s ease-out forwards}
.burst img{width:100%;height:100%}
@keyframes bst{0%{transform:scale(.3);opacity:0}25%{transform:scale(1.5);opacity:1}100%{transform:translateY(-100px) scale(1);opacity:0}}
#sheet{position:fixed;left:0;right:0;bottom:0;z-index:160;max-width:520px;margin:0 auto;padding:10px 14px calc(16px + env(safe-area-inset-bottom,0px));border-radius:26px 26px 0 0;background:linear-gradient(180deg,#1a2440f7,#0d1424fa);border:1px solid #ffffff1f;border-bottom:0;box-shadow:0 -20px 60px #000c;transform:translateY(110%);visibility:hidden;transition:transform .32s cubic-bezier(.2,.9,.3,1),visibility .32s}
#sheet.show{transform:none;visibility:visible}
.sgrip{display:block;width:40px;height:4px;border-radius:2px;background:#ffffff33;margin:2px auto 12px}
.spv{padding:10px 14px;margin-bottom:10px;border-radius:14px;background:#ffffff0d;color:var(--mu);font-size:13.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sa{display:flex;align-items:center;gap:14px;width:100%;padding:15px 16px;border-radius:16px;font-size:16px;font-weight:500;text-align:left;transition:.15s}
.sa:active{background:#ffffff14}.sa .i{width:22px;height:22px;color:var(--ac)}
.sa.del,.sa.del .i{color:#ff7a8f}
.sdi{width:64px;height:64px;border-radius:50%;background:#ff4d6a26;color:var(--rd);display:flex;align-items:center;justify-content:center;margin:8px auto 12px}.sdi .i{width:28px;height:28px}
.sdt{text-align:center;font-size:18px;font-weight:600}.sds{text-align:center;color:var(--mu);font-size:13.5px;margin:6px 0 18px}
.sbr{display:flex;gap:10px}.sbr button{flex:1;padding:14px;border-radius:16px;font-weight:600;background:#ffffff14}
.sbr .sd{background:var(--rd);color:#fff;box-shadow:0 8px 22px #ff4d6a55}

#app{--ac:#ffffff;--g:linear-gradient(145deg,#ffffff,#c9c9c9);--mu:#8c8c8c;--bd:#ffffff1f;--bg:#000;max-width:760px;background:#000;box-shadow:0 0 0 1px #ffffff12,0 0 120px #000}

#app header{gap:12px;padding:10px 14px;padding-top:calc(10px + env(safe-area-inset-top,0px));background:linear-gradient(180deg,#0e0e0ef5,#050505f5);border-bottom:1px solid #ffffff14;box-shadow:0 12px 36px #000c;backdrop-filter:blur(24px) saturate(140%);-webkit-backdrop-filter:blur(24px) saturate(140%)}
#app header::after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,#ffffff55,transparent);pointer-events:none}
#app header .av{width:48px;height:48px;font-size:20px;margin-left:0;color:#000;background:linear-gradient(145deg,#fff,#bdbdbd);border:2px solid #050505;box-shadow:0 0 0 1.5px #ffffffcc,0 0 0 5px #ffffff14,0 8px 22px #ffffff1f;transition:transform .25s cubic-bezier(.2,.9,.3,1.3)}
#app header .av:active{transform:scale(.93)}
#app .info b{font-size:17px;font-weight:650;letter-spacing:.1px;line-height:1.2;color:#fff}
#app .info small{position:relative;padding-left:14px;margin-top:2px;font-size:12.5px;font-weight:500;line-height:1.3;color:#b5b5b5;opacity:1}
#app .info small:empty{display:none}
#app .info small::before{content:"";position:absolute;left:0;top:50%;width:7px;height:7px;margin-top:-3.5px;border-radius:50%;background:#fff;box-shadow:0 0 8px #fff;animation:onlw 2s infinite}
@keyframes onlw{0%{box-shadow:0 0 0 0 #ffffff88}70%,100%{box-shadow:0 0 0 7px #ffffff00}}
#app header .ib{width:44px;height:44px;color:#fff;background:linear-gradient(160deg,#1a1a1a,#0a0a0a);border:1px solid #ffffff26;box-shadow:inset 0 1px 0 #ffffff1f,0 6px 18px #000;transition:transform .18s,background .2s,color .2s,box-shadow .2s}
#app header .ib .i{width:21px;height:21px;stroke-width:1.8;color:inherit}
#app header .ib:hover{color:#000;background:#fff;border-color:#fff;box-shadow:0 0 22px #ffffff44}
#app header .ib:active{transform:scale(.88)}
#mn{top:calc(72px + env(safe-area-inset-top,0px));left:14px;border-radius:18px;background:#0b0b0bfa;border:1px solid #ffffff26;box-shadow:0 20px 50px #000,0 0 0 1px #000;animation:rbin .25s cubic-bezier(.2,1.2,.3,1);transform-origin:top left}
#mn button{padding:14px 26px;font-weight:500;color:#fff}
#mn button:hover{background:#ffffff14}

#app #msgs{padding:18px 14px 14px;gap:5px;background:
 radial-gradient(ellipse 80% 38% at 50% -8%,#ffffff17,transparent 70%),
 radial-gradient(ellipse 70% 40% at 50% 112%,#ffffff0d,transparent 70%),
 radial-gradient(circle at 1px 1px,#ffffff0b 1px,transparent 0) 0 0/24px 24px,
 #000}
#msgs::-webkit-scrollbar{width:0}
#app .sys{align-self:center;display:inline-flex;align-items:center;gap:8px;margin:10px 0 8px;padding:6px 16px;font-size:12.5px;font-weight:500;letter-spacing:.3px;color:#cfcfcf;background:linear-gradient(160deg,#181818,#0b0b0b);border:1px solid #ffffff22;border-radius:20px;box-shadow:0 6px 18px #000,inset 0 1px 0 #ffffff14;animation:pop .35s cubic-bezier(.2,.9,.3,1.2)}
#app .sys::before{content:"";width:5px;height:5px;border-radius:50%;background:#fff;box-shadow:0 0 8px #fff}

#app .m{max-width:82%;padding:9px 13px 7px;font-size:15.5px;line-height:1.5;letter-spacing:.05px;color:#f2f2f2;border-radius:20px 20px 20px 6px;background:linear-gradient(160deg,#1c1c1c,#0f0f0f);border:1px solid #ffffff1c;box-shadow:0 4px 16px #000c,inset 0 1px 0 #ffffff14}
#app .m.me{color:#0a0a0a;background:linear-gradient(145deg,#ffffff,#d9d9d9);border-color:#fff;border-radius:20px 20px 6px 20px;box-shadow:0 8px 24px #ffffff1f,0 2px 6px #000a,inset 0 1px 0 #fff}
#app .m .n{display:flex;align-items:center;font-size:13px;font-weight:650;letter-spacing:.2px;color:#fff;margin-bottom:4px}
#app .m .t{font-size:10.5px;font-weight:500;color:#ffffff80;margin:5px 0 0 14px}
#app .m.me .t{color:#00000088}
#app .mav{width:22px;height:22px;line-height:22px;margin-right:7px;vertical-align:middle;color:#000;box-shadow:0 0 0 1.5px #ffffff88}
#app .m.me .lnk{color:#000;font-weight:500}
#app .lnk{color:#fff}
#app .m.me .pv{background:#0000000d;color:#000;border-left-color:#000}
#app .m.me .pv small{color:#000}#app .m.me .pv span{color:#555}
#app .m.me .rc{background:#0000000f;border-color:#00000026}
#app .m.me .rc.mine{background:#00000024;border-color:#00000066}
#app .m.me .rn{color:#000}
#app .rc.mine{background:#ffffff22;border-color:#ffffff88}

#app .vp{width:40px;height:40px;color:#000;background:#fff;box-shadow:0 4px 12px #0008}
#app .m.me .vp{color:#fff;background:#000}
#app .m:not(.me) .vp{background:#fff}
#app .vb i{background:#ffffff40;border-radius:3px}
#app .m:not(.me) .vb i.on{background:#fff}
#app .m.me .vb i{background:#00000033}#app .m.me .vb i.on{background:#000}
#app .m.me .vd{color:#000000aa}

#app form{align-items:center;gap:10px;padding:10px 12px;padding-bottom:calc(12px + env(safe-area-inset-bottom,0px));background:linear-gradient(0deg,#000,#0a0a0af5);border-top:1px solid #ffffff14;box-shadow:0 -12px 32px #000;backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);position:relative}
#app form::before{content:"";position:absolute;left:0;right:0;top:-1px;height:1px;background:linear-gradient(90deg,transparent,#ffffff44,transparent);pointer-events:none}
#app form input{padding:0 22px;height:52px;border-radius:30px;font-size:16px;color:#fff;background:linear-gradient(160deg,#0b0b0b,#141414);border:1px solid #ffffff26;box-shadow:inset 0 2px 8px #000,0 1px 0 #ffffff0d;transition:border-color .25s,box-shadow .25s;caret-color:#fff}
#app form input::placeholder{color:#7a7a7a}
#app form input:focus{border-color:#ffffffcc;box-shadow:inset 0 2px 8px #000,0 0 0 4px #ffffff14,0 0 26px #ffffff1a}
#app form button{width:52px;height:52px;flex:none}
#app form button#sb{background:linear-gradient(145deg,#fff,#cfcfcf);color:#000;box-shadow:0 8px 24px #ffffff2e,inset 0 1px 0 #fff}
#app form button#sb .i{width:21px;height:21px;margin-left:-2px;margin-top:1px;stroke-width:2.2}
#app form button.mic{color:#fff;background:linear-gradient(160deg,#1a1a1a,#0a0a0a);border:1px solid #ffffff33;box-shadow:0 6px 18px #000,inset 0 1px 0 #ffffff1f}
#app form button.mic .i{width:23px;height:23px;stroke-width:1.8}
#app form button.mic:hover{background:#fff;color:#000;transform:scale(1.06)}
#app form button.mic:active,#app form button#sb:active{transform:scale(.9)}
#app #rec{height:52px;border-radius:30px;background:linear-gradient(160deg,#0b0b0b,#141414);border:1px solid #ffffff33;box-shadow:inset 0 2px 8px #000}
#app .rb.rs{background:#fff;color:#000;box-shadow:0 6px 18px #ffffff2e}
#app .rb.rx{background:#ffffff14;color:#fff}
#toast{background:linear-gradient(160deg,#181818f8,#080808f8);border:1px solid #ffffff2a;border-radius:24px;padding:12px 22px;font-weight:500;color:#fff;box-shadow:0 14px 40px #000}
@media(max-width:430px){
 #app header{padding:9px 10px;padding-top:calc(9px + env(safe-area-inset-top,0px));gap:10px}
 #app header .av{width:46px;height:46px}
 #app header .ib{width:42px;height:42px}
 #app .m{max-width:86%}
}
@media(prefers-reduced-motion:reduce){#app .info small::before,#app .m,#app .sys{animation:none}}

#app #msgs{padding:14px 10px 10px;gap:3px}
#app .m{max-width:76%;padding:6px 10px 4px;font-size:14px;line-height:1.38;letter-spacing:0;border-radius:16px 16px 16px 5px;box-shadow:0 2px 10px #000b,inset 0 1px 0 #ffffff12}
#app .m.me{border-radius:16px 16px 5px 16px;box-shadow:0 4px 14px #ffffff17,0 1px 4px #000a,inset 0 1px 0 #fff}
#app .m .n{font-size:11.5px;margin-bottom:2px}
#app .m .t{font-size:9.5px;margin:3px 0 0 10px}
#app .mav{width:18px;height:18px;line-height:18px;font-size:10px;margin-right:6px}
#app .m.v{min-width:210px}
#app .vp{width:34px;height:34px}
#app .vm{gap:8px;padding:0}
#app .vb{height:26px}
#app .vd{font-size:11px;min-width:30px}
#app .sys{font-size:11.5px;padding:5px 14px;margin:8px 0 6px}
#app .pv img{max-height:160px}
#app .pv div{padding:7px 10px}
#app .rxs{margin-top:4px;gap:4px}
#app .rc{padding:1px 7px 1px 4px;gap:4px}
#app .rc .re{display:inline-flex;width:20px;height:20px;align-items:center;justify-content:center;font-size:15px}
#app .rc .re img{width:20px;height:20px;display:block}
@media(max-width:430px){#app .m{max-width:80%}}

#rbar{gap:4px;padding:7px 10px;border-radius:36px;background:linear-gradient(160deg,#1a1a1af7,#050505fa);border:1px solid #ffffff30;box-shadow:0 22px 60px #000,0 0 0 1px #000,inset 0 1px 0 #ffffff26;transform-origin:bottom center;animation:rbin2 .42s cubic-bezier(.2,1.4,.3,1)}
@keyframes rbin2{0%{opacity:0;transform:translateY(16px) scale(.5)}100%{opacity:1;transform:none}}
#rbar.grid.show{border-radius:26px;padding:12px;max-height:60vh;overflow-y:auto}
#rbar button{width:46px;height:46px;transform-origin:50% 90%;animation:emo2 .55s cubic-bezier(.2,1.8,.4,1) both;transition:transform .18s cubic-bezier(.2,1.6,.4,1),background .2s}
#rbar button img{width:40px;height:40px;filter:drop-shadow(0 4px 6px #0009)}
@keyframes emo2{0%{opacity:0;transform:translateY(22px) scale(.2) rotate(-25deg)}60%{opacity:1;transform:translateY(-6px) scale(1.18) rotate(6deg)}100%{opacity:1;transform:none}}
#rbar button:hover,#rbar button:active{transform:scale(1.4) translateY(-8px)}
#rbar button.on{background:#ffffff1f;box-shadow:0 0 0 2px #fff}
#rbar button .fb,#rbar.grid button,#rbar button{}
#rbar.grid button{width:100%;height:42px;font-size:25px}
#rbar.grid button:not(.more){animation:emo2 .5s cubic-bezier(.2,1.8,.4,1) both,idle 2.4s ease-in-out infinite;animation-delay:var(--d,0s),calc(var(--d,0s) + .5s)}
@keyframes idle{0%,100%{transform:translateY(0) rotate(0)}25%{transform:translateY(-3px) rotate(-6deg)}75%{transform:translateY(-1px) rotate(6deg)}}
#rbar .more{font-size:24px;font-weight:600;color:#fff;background:#ffffff18;margin-left:2px;animation:emo2 .55s cubic-bezier(.2,1.8,.4,1) both}
#rbar button.fb-t{animation:emo2 .55s cubic-bezier(.2,1.8,.4,1) both,idle 2.2s ease-in-out infinite;animation-delay:var(--d,0s),calc(var(--d,0s) + .5s)}
.burst{width:84px;height:84px;font-size:64px}
.burst img{filter:drop-shadow(0 8px 14px #000a)}
@keyframes bst{0%{transform:scale(.2) rotate(-20deg);opacity:0}25%{transform:scale(1.7) rotate(6deg);opacity:1}70%{transform:translateY(-70px) scale(1.25);opacity:1}100%{transform:translateY(-130px) scale(1);opacity:0}}
#sheet{background:linear-gradient(180deg,#141414fa,#050505fc);border-color:#ffffff26}
.sa .i{color:#fff}.sa.del,.sa.del .i{color:#ff6b7f}

#app .sys{position:relative;overflow:hidden;flex:none;transition:opacity .45s ease,transform .45s cubic-bezier(.5,0,.75,0),height .4s ease .1s,margin .4s ease .1s,padding .4s ease .1s,filter .45s ease}
#app .sys::after{content:"";position:absolute;left:0;bottom:0;height:2px;width:100%;background:linear-gradient(90deg,#ffffff00,#fff,#ffffff00);transform-origin:left;animation:sysbar 3s linear forwards;opacity:.8}
@keyframes sysbar{to{transform:scaleX(0)}}
#app .sys.out{opacity:0;transform:scale(.6) translateY(-10px);filter:blur(4px);height:0!important;margin-top:0;margin-bottom:0;padding-top:0;padding-bottom:0;border-width:0;pointer-events:none}

@keyframes mIn{
 0%{opacity:0;transform:translateY(28px) scale(.5);filter:blur(7px);box-shadow:0 0 0 0 #ffffff99}
 55%{opacity:1;transform:translateY(-5px) scale(1.07);filter:blur(0);box-shadow:0 0 0 9px #ffffff12,0 0 38px #ffffff66}
 78%{transform:translateY(1px) scale(.985)}
 100%{opacity:1;transform:none;filter:blur(0)}}
#app .m{animation:none}
#app .m.gone{animation:gone .3s ease forwards}
#app .m.fx{animation:mIn .62s cubic-bezier(.2,.9,.3,1) both;transform-origin:0 100%}
#app .m.me.fx{transform-origin:100% 100%}
#app .sys{animation:mIn .62s cubic-bezier(.2,.9,.3,1) both}

#app #msgs{gap:2px;padding:12px 9px 8px}
#app .m{max-width:72%;padding:5px 9px 3px;font-size:13px;line-height:1.35;border-radius:14px 14px 14px 4px}
#app .m.me{border-radius:14px 14px 4px 14px}
#app .m .n{font-size:10.5px;margin-bottom:1px}
#app .m .t{font-size:9px;margin:2px 0 0 8px}
#app .mav{width:16px;height:16px;line-height:16px;font-size:9px;margin-right:5px}
#app .m.v{min-width:180px}
#app .vp{width:30px;height:30px}
#app .vp .i{width:13px;height:13px}
#app .vb{height:22px}
#app .vd{font-size:10px;min-width:26px}
#app .rc{padding:0 6px 0 3px}
#app .rc .re,#app .rc .re img{width:17px;height:17px}
#app .pv{margin:6px 0 2px}
#app .pv img{max-height:130px}
#app .pv b{font-size:13px}
@media(max-width:430px){#app .m{max-width:76%}}

#app header .av{border:3px solid #000;box-shadow:0 0 0 1px #ffffff40,0 0 0 4px #ffffff0f,0 8px 22px #000;transition:transform .25s cubic-bezier(.2,.9,.3,1.3)}
#app header .av::after{content:"";position:absolute;inset:0;border-radius:50%;box-shadow:inset 0 0 0 1px #ffffff33;pointer-events:none}

#app .info small{overflow:visible;text-overflow:clip;padding-left:16px}
#app .info small::before{animation:none;box-shadow:0 0 6px #ffffffaa}
#app .info small::after{content:"";position:absolute;left:0;top:50%;width:7px;height:7px;margin-top:-3.5px;border-radius:50%;border:1.5px solid #fff;box-sizing:border-box;pointer-events:none;animation:ripw 2.2s ease-out infinite}
@keyframes ripw{0%{transform:scale(1);opacity:.75}100%{transform:scale(3.2);opacity:0}}

:root{--bg:#000;--s1:#0b0b0b;--s2:#151515;--tx:#f5f5f5;--mu:#8c8c8c;--ac:#fff;--ac2:#cfcfcf;--g:linear-gradient(145deg,#fff,#c9c9c9);--bd:#ffffff24}
html,body{background:#000}
::-webkit-scrollbar-thumb{background:#ffffff2a}

.logo,.btn,.tabs .on,#pav,.tile .ab,.gav,.pwrap .pfa,.mav,.rav,.av,.rb.rs,.cb.on{color:#000}

#login{background:#000}
#login::before,#login::after{background:#fff;opacity:.10;filter:blur(110px)}
#login::after{opacity:.06}
.card{background:linear-gradient(160deg,#171717f2,#060606f7);border:1px solid #ffffff26;box-shadow:0 30px 80px #000,0 0 0 1px #000,inset 0 1px 0 #ffffff1f;backdrop-filter:blur(26px);-webkit-backdrop-filter:blur(26px)}
.card h1{background:linear-gradient(90deg,#fff,#b5b5b5);-webkit-background-clip:text;background-clip:text;color:transparent}
.logo{background:linear-gradient(145deg,#fff,#c9c9c9);box-shadow:0 12px 34px #ffffff26,inset 0 1px 0 #fff}
.fld{background:linear-gradient(160deg,#0a0a0a,#131313);border:1px solid #ffffff26;box-shadow:inset 0 2px 8px #000}
.fld:focus-within{border-color:#ffffffcc;color:#fff;box-shadow:inset 0 2px 8px #000,0 0 0 4px #ffffff14}
.fld input::placeholder{color:#7a7a7a}
.btn{background:linear-gradient(145deg,#fff,#cfcfcf);color:#000;box-shadow:0 10px 28px #ffffff26,inset 0 1px 0 #fff}
.tabs{background:#0a0a0a;border:1px solid #ffffff1c}
.tabs .on{background:linear-gradient(145deg,#fff,#cfcfcf);color:#000}
.pfa{border-color:#ffffff44}.pfa:hover{border-color:#fff;color:#fff}
.pwrap .pfa{background:linear-gradient(145deg,#fff,#c9c9c9) center/cover;color:#000;box-shadow:0 0 0 4px #ffffff14,0 0 0 8px #ffffff12,0 18px 44px #ffffff1a}
.pbadge{background:#fff;color:#000;border:3px solid #000}
.gav{box-shadow:0 0 0 3px #ffffff33,0 10px 30px #ffffff1a}
.ld{border-color:#ffffff22;border-top-color:#fff}
.cnt{color:#777}

#ban{background:linear-gradient(90deg,#1c1c1c,#0a0a0a);border-bottom:1px solid #ffffff1f;color:#fff}
#ban button{background:#fff;color:#000}

#ov{background:radial-gradient(ellipse 80% 45% at 50% -5%,#ffffff1f,transparent 65%),radial-gradient(ellipse 70% 40% at 50% 110%,#ffffff10,transparent 65%),#000}
#pav{background:linear-gradient(145deg,#fff,#c9c9c9);color:#000;animation:plw 1.8s infinite}
@keyframes plw{0%{box-shadow:0 0 0 0 #ffffff70}100%{box-shadow:0 0 0 46px #ffffff00}}
.tile{background:#0d0d0d;border:1px solid #ffffff14;box-shadow:0 8px 24px #000}
.tile .ab{background:linear-gradient(145deg,#fff,#c9c9c9)}
.tile .tn{background:#000000b3;border:1px solid #ffffff1f}
#grid.duo .tile.me{border:2px solid #ffffff55}
.cb{background:linear-gradient(160deg,#1c1c1c,#0a0a0a);border:1px solid #ffffff2b;box-shadow:inset 0 1px 0 #ffffff1f,0 6px 18px #000}
.cb.off{background:#fff;color:#000}
.cb.on{background:#fff;color:#000}
#tm,#top{color:#cfcfcf}
#pl{color:#8c8c8c}

.cb.end,.cb.dec{background:var(--rd);border-color:transparent;color:#fff}
.cb.acc{background:#22c55e;border-color:transparent;color:#fff}

.cb.vid-on{background:#fff;color:#000}
#bflip{animation:flipin .4s cubic-bezier(.2,1.5,.4,1) both}
@keyframes flipin{from{opacity:0;transform:scale(.4) rotate(-90deg)}}
#bflip .i{width:30px;height:30px;stroke-width:1.6}
#bflip:active .i{transform:rotate(180deg);transition:transform .3s}

#app .m.cl{min-width:220px}
#app .m.cl .t{float:none;display:block;text-align:right;margin:4px 0 0}
.clm{display:flex;align-items:center;gap:11px;padding:2px 0}
.cli{width:40px;height:40px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;background:#fff;color:#000;box-shadow:0 4px 12px #0008}
#app .m.me .cli{background:#000;color:#fff}
.cli .i{width:19px;height:19px}
.cli.bad{background:var(--rd)!important;color:#fff!important}
.clt{display:flex;flex-direction:column;min-width:0}
.clt b{font-size:14.5px;font-weight:600;line-height:1.25}
.clt b.bad{color:#ff6b7f}
.clt small{font-size:12px;opacity:.65;line-height:1.3;margin-top:1px}

#ov{overflow:hidden}
#ov>*{position:relative;z-index:1}
#ov.show{animation:ovin .5s cubic-bezier(.2,.9,.3,1)}
@keyframes ovin{from{opacity:0;transform:scale(1.05)}}
#ov:not(.live)::before{content:"";position:absolute;inset:-25%;z-index:0;pointer-events:none;
  background:radial-gradient(circle at 28% 30%,#ffffff21 0,#0000 38%),radial-gradient(circle at 76% 72%,#ffffff16 0,#0000 42%),radial-gradient(circle at 60% 15%,#ffffff10 0,#0000 30%);
  filter:blur(18px);animation:aur 14s ease-in-out infinite alternate}
@keyframes aur{to{transform:translate(7%,5%) rotate(10deg) scale(1.12)}}
#rp{gap:0}
#cpw{position:relative;width:148px;height:148px;margin-bottom:34px;display:flex;align-items:center;justify-content:center}
#cpw::before{content:"";position:absolute;inset:-46px;border-radius:50%;background:radial-gradient(circle,#ffffff30 0%,#ffffff0e 40%,#0000 68%);animation:ldhalo 2.8s ease-in-out infinite}
#cpw .rg{position:absolute;inset:0;border-radius:50%;border:1.5px solid #ffffff66;opacity:0;animation:rgx 3.3s cubic-bezier(.2,.6,.3,1) infinite}
#cpw .rg:nth-child(2){animation-delay:1.1s}#cpw .rg:nth-child(3){animation-delay:2.2s}
@keyframes rgx{0%{transform:scale(1);opacity:.75}100%{transform:scale(2.7);opacity:0}}
#cpw .arc{position:absolute;inset:-9px;border-radius:50%;background:conic-gradient(from 0deg,#fff0 0deg,#fff0 150deg,#ffffff55 260deg,#fff 358deg,#fff0 360deg);
  -webkit-mask:radial-gradient(farthest-side,#0000 calc(100% - 3px),#000 calc(100% - 2px));mask:radial-gradient(farthest-side,#0000 calc(100% - 3px),#000 calc(100% - 2px));animation:ldspin 2.8s linear infinite}
#rp #pav{width:148px;height:148px;margin:0;position:relative;z-index:2;font-size:62px;animation:pavb 3.2s ease-in-out infinite;
  box-shadow:0 22px 50px #000,0 0 44px #ffffff26,inset 0 1px 0 #fff}
@keyframes pavb{0%,100%{transform:scale(1)}50%{transform:scale(1.045)}}
#rp #pn{font-size:31px;font-weight:650;letter-spacing:.2px;max-width:86vw;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;animation:rpup .7s cubic-bezier(.2,.9,.3,1) .12s both}
#rp #pl{font-size:15px;font-weight:500;letter-spacing:.5px;margin-top:8px;animation:rpup .7s cubic-bezier(.2,.9,.3,1) .24s both,ldtext 2.6s linear infinite;
  background:linear-gradient(100deg,#8a8a8a 0%,#8a8a8a 38%,#fff 50%,#8a8a8a 62%,#8a8a8a 100%);background-size:260% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent}
@keyframes rpup{from{opacity:0;transform:translateY(16px)}}
#cin{gap:72px;padding:12px 16px 46px}
.cbw{display:flex;flex-direction:column;align-items:center;gap:12px;animation:rpup .7s cubic-bezier(.2,.9,.3,1) .36s both}
.cbw.a{animation-delay:.46s}
.cbw span{font-size:13px;font-weight:500;letter-spacing:.4px;color:#ffffffb3}
#cin .cb{position:relative;width:74px;height:74px;border:0;transition:transform .2s,opacity .35s,box-shadow .3s}
#cin .cb .i{width:29px;height:29px}
#cin .cb.dec{background:linear-gradient(145deg,#ff6b81,#e0203f);box-shadow:0 12px 30px #ff4d6a66,inset 0 1px 0 #ffffff66}
#cin .cb.acc{background:linear-gradient(145deg,#4ade80,#16a34a);box-shadow:0 12px 34px #22c55e77,inset 0 1px 0 #ffffff66;animation:accp 1.7s ease-in-out infinite}
#cin .cb.acc::after{content:"";position:absolute;inset:0;border-radius:50%;border:2px solid #4ade80;animation:accr 1.7s ease-out infinite;pointer-events:none}
#cin .cb.acc .i{animation:phk 1.7s ease-in-out infinite}
@keyframes accp{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}
@keyframes accr{0%{transform:scale(1);opacity:.85}100%{transform:scale(1.85);opacity:0}}
@keyframes phk{0%,55%,100%{transform:rotate(0)}8%{transform:rotate(-18deg)}16%{transform:rotate(16deg)}24%{transform:rotate(-14deg)}32%{transform:rotate(12deg)}40%{transform:rotate(-7deg)}48%{transform:rotate(4deg)}}
#cin .cb:active{transform:scale(.88)}

#ov.accepting #cin .cbw.d{opacity:0;transform:scale(.6);pointer-events:none;transition:opacity .3s,transform .35s}
#ov.accepting #cin .cb.acc{animation:none;transform:scale(1.12);box-shadow:0 0 0 10px #22c55e33,0 0 46px #22c55e99;pointer-events:none}
#ov.accepting #cin .cb.acc::after{animation:none;opacity:0}
#ov.accepting #cin .cb.acc .i{animation:none}
#ov.accepting #cpw .rg{animation-duration:1.2s}

#ov.live #grid{animation:gin .6s cubic-bezier(.2,.9,.3,1)}
#ov.live #top{animation:rpup .5s ease .15s both}
@keyframes gin{from{opacity:0;transform:scale(.94)}}
@media(prefers-reduced-motion:reduce){#ov:not(.live)::before,#cpw .rg,#cpw .arc,#cin .cb.acc,#cin .cb.acc::after,#cin .cb.acc .i,#rp #pav{animation:none}}

#login #ld{position:fixed;inset:0;z-index:10;width:auto;height:auto;margin:0;border:0;border-radius:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:30px;
  background:radial-gradient(ellipse at 50% 42%,#1a1a1a 0%,#0a0a0a 45%,#000 75%);animation:ldin .6s ease}
#login #ld.out{opacity:0;transition:opacity .45s ease;pointer-events:none}
#ld.out .ldm{transform:scale(1.18);transition:transform .45s cubic-bezier(.3,0,.2,1)}
.ldm{position:relative;width:104px;height:104px}
.ldm::before{content:"";position:absolute;inset:-46px;border-radius:50%;background:radial-gradient(circle,#ffffff2b 0%,#ffffff0d 38%,#0000 66%);animation:ldhalo 2.8s ease-in-out infinite}
.ldr{position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,#fff0 0deg,#fff0 80deg,#ffffff40 210deg,#fff 356deg,#fff0 360deg);
  -webkit-mask:radial-gradient(farthest-side,#0000 calc(100% - 3px),#000 calc(100% - 2px));mask:radial-gradient(farthest-side,#0000 calc(100% - 3px),#000 calc(100% - 2px));
  animation:ldspin 1.6s cubic-bezier(.45,.1,.55,.9) infinite}
.ldr.g{filter:blur(7px);opacity:.75}
.ldd{position:absolute;inset:11px;border-radius:50%;border:1px dashed #ffffff3d;animation:ldspin 14s linear infinite reverse}
.ldo{position:absolute;inset:0;animation:ldspin 2.6s linear infinite}
.ldo::after{content:"";position:absolute;top:-3px;left:50%;width:6px;height:6px;margin-left:-3px;border-radius:50%;background:#fff;box-shadow:0 0 12px 3px #ffffffaa}
.ldc{position:absolute;inset:23px;border-radius:21px;display:flex;align-items:center;justify-content:center;overflow:hidden;color:#fff;
  background:linear-gradient(155deg,#2b2b2b,#0b0b0b);border:1px solid #ffffff38;box-shadow:0 14px 34px #000,0 0 26px #ffffff1f,inset 0 1px 0 #ffffff40;animation:ldbreath 2.6s ease-in-out infinite}
.ldc::after{content:"";position:absolute;top:-25%;bottom:-25%;width:42%;left:-70%;background:linear-gradient(100deg,#fff0,#ffffff88,#fff0);transform:skewX(-18deg);animation:ldsheen 2.6s ease-in-out infinite}
.ldc .i{width:27px;height:27px;stroke-width:1.9;position:relative;z-index:1}
.ldc img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover}
.ldn{font:600 12px Inter,system-ui,sans-serif;letter-spacing:.36em;text-transform:uppercase;padding-left:.36em;max-width:80vw;text-align:center;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;
  background:linear-gradient(100deg,#6b6b6b 0%,#6b6b6b 38%,#fff 50%,#6b6b6b 62%,#6b6b6b 100%);background-size:260% 100%;-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent;animation:ldtext 2.6s linear infinite}
.ldb{position:relative;width:136px;height:2px;border-radius:2px;background:#ffffff1a;overflow:hidden}
.ldb i{position:absolute;top:0;bottom:0;left:0;width:38%;border-radius:2px;background:linear-gradient(90deg,#fff0,#fff,#fff0);animation:ldbar 1.6s cubic-bezier(.6,0,.4,1) infinite}
@keyframes ldin{from{opacity:0}}
@keyframes ldspin{to{transform:rotate(360deg)}}
@keyframes ldhalo{0%,100%{opacity:.55;transform:scale(.9)}50%{opacity:1;transform:scale(1.08)}}
@keyframes ldbreath{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}
@keyframes ldsheen{0%,25%{left:-70%}70%,100%{left:140%}}
@keyframes ldtext{from{background-position:130% 0}to{background-position:-130% 0}}
@keyframes ldbar{from{transform:translateX(-105%)}to{transform:translateX(265%)}}
@media(prefers-reduced-motion:reduce){.ldr,.ldd,.ldo,.ldc::after,.ldb i,.ldn,.ldm::before{animation-duration:8s}.ldc{animation:none}}

#login{overflow-x:hidden;overflow-y:auto;align-items:flex-start;-webkit-overflow-scrolling:touch}
#login::before,#login::after{position:fixed}
#login .card,#login .ld{margin:auto}
.perms{margin:4px 0 12px;text-align:left}
.perms .pt{font-size:11.5px;font-weight:600;letter-spacing:.7px;text-transform:uppercase;color:#8c8c8c;margin:0 4px 8px}
.pr{display:flex;align-items:center;gap:12px;width:100%;padding:10px 12px;margin-bottom:8px;border-radius:16px;text-align:left;color:#fff;background:linear-gradient(160deg,#121212,#070707);border:1px solid #ffffff1f;box-shadow:inset 0 1px 0 #ffffff12;transition:border-color .2s,transform .15s,background .2s}
.pr:active{transform:scale(.98)}
.pr.bad{border-color:#ffffff3a}.pr.bad:hover{border-color:#ffffff88}
.pr.ok{border-color:#ffffff14}
.pr .pi{width:38px;height:38px;border-radius:12px;flex:none;display:flex;align-items:center;justify-content:center;background:#ffffff14;color:#fff}
.pr.ok .pi{background:#ffffff0d;color:#cfcfcf}
.pr .pi .i{width:20px;height:20px}
.pr .pn{flex:1;min-width:0}
.pr .pn b{display:block;font-size:14.5px;font-weight:600;line-height:1.25}
.pr .pn small{display:block;font-size:12px;color:#8c8c8c;line-height:1.3;margin-top:1px}
.pr .ps{flex:none;line-height:0;width:28px;height:28px;display:flex;align-items:center;justify-content:center}
.pr .ps .i{width:24px;height:24px;stroke-width:1.9}
.pr.ok .ps{color:#fff}
.pr.bad .ps{color:#ff6b7f}
.pr.na .ps{color:#9a9a9a}
.pr.na{opacity:.55}
.pr.bad .ps{animation:wob 2.4s ease-in-out infinite}
@keyframes wob{0%,86%,100%{transform:rotate(0)}90%{transform:rotate(-12deg)}94%{transform:rotate(12deg)}98%{transform:rotate(-6deg)}}
@media(prefers-reduced-motion:reduce){.pr.bad .ps{animation:none}}
#rbar{max-width:calc(100vw - 16px)}
#rbar:not(.grid){gap:2px;padding:7px 8px}
#rbar:not(.grid) button img{width:88%;height:auto;max-width:none}
#rbar:not(.grid) .more{font-size:26px}
#rbar.grid.show{max-width:calc(100vw - 16px)}

#rbar{border-radius:40px;background:linear-gradient(165deg,#2c2c30f2 0%,#0d0d10f8 100%);border:1px solid #ffffff38;
  box-shadow:0 28px 70px #000,0 0 0 1px #000,0 0 46px #ffffff12,inset 0 1px 0 #ffffff46,inset 0 -10px 20px #00000088;
  backdrop-filter:blur(30px) saturate(170%);-webkit-backdrop-filter:blur(30px) saturate(170%)}
#rbar::after{content:"";position:absolute;left:16%;right:16%;top:0;height:1px;background:linear-gradient(90deg,#fff0,#fff,#fff0);opacity:.75;pointer-events:none}
#rbar:not(.grid){--bw:clamp(32px,calc((100vw - 40px) / 8),50px);width:max-content;padding:6px 8px;gap:1px}
#rbar:not(.grid) button{flex:none;width:var(--bw);height:var(--bw);min-width:0;position:relative;border-radius:50%;transition:transform .24s cubic-bezier(.2,1.9,.4,1),background .2s,box-shadow .25s}
#rbar:not(.grid) button:hover,#rbar:not(.grid) button:active{transform:scale(1.45) translateY(-10px);z-index:3;background:radial-gradient(circle at 50% 40%,#ffffff30,#ffffff00 72%)}
#rbar:not(.grid) button:active{transform:scale(1.2) translateY(-4px)}
#rbar:not(.grid) button.on{background:radial-gradient(circle at 50% 35%,#ffffff48,#ffffff14 72%);box-shadow:0 0 0 1.5px #ffffffd9,0 0 20px #ffffff5c,inset 0 1px 0 #ffffff66}
#rbar:not(.grid) button img{filter:drop-shadow(0 5px 7px #000b);animation:rfl 3.2s ease-in-out infinite;animation-delay:calc(var(--d,0s) * 4)}
@keyframes rfl{0%,100%{transform:translateY(0) rotate(0)}50%{transform:translateY(-2.5px) rotate(-5deg)}}
#rbar .more{background:linear-gradient(160deg,#ffffff2e,#ffffff0d);border:1px solid #ffffff38;color:#fff;font-weight:300;box-shadow:inset 0 1px 0 #ffffff3d,0 4px 12px #0008;margin-left:0!important}
#rbar .more:hover{transform:rotate(90deg) scale(1.15)!important;background:linear-gradient(160deg,#ffffff4d,#ffffff1a)}
#rbar.grid.show{padding:14px;gap:4px;scrollbar-width:none}
#rbar.grid.show::-webkit-scrollbar{display:none}
#rbar.grid button{border-radius:16px;transition:transform .2s cubic-bezier(.2,1.8,.4,1),background .2s}
#rbar.grid button:hover,#rbar.grid button:active{background:radial-gradient(circle,#ffffff2e,#ffffff08 75%);transform:scale(1.35)}
#rbar.grid button.on{background:radial-gradient(circle,#ffffff40,#ffffff10 75%);box-shadow:0 0 0 1.5px #ffffffcc}

#app .rc{border-radius:16px;background:linear-gradient(160deg,#ffffff24,#ffffff0a);border:1px solid #ffffff30;box-shadow:0 3px 10px #0008,inset 0 1px 0 #ffffff26;backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);transition:transform .18s cubic-bezier(.2,1.8,.4,1)}
#app .rc:active{transform:scale(.9)}
#app .rc.mine{background:linear-gradient(160deg,#ffffff45,#ffffff1c);border-color:#ffffffcc;box-shadow:0 0 14px #ffffff40,0 3px 10px #0008,inset 0 1px 0 #ffffff55}
#app .m.me .rc{box-shadow:0 2px 6px #0002;backdrop-filter:none}
#app .m.me .rc.mine{box-shadow:0 0 0 1px #000a,0 2px 6px #0002}

.burst::before{content:"";position:absolute;inset:-16px;border-radius:50%;border:2px solid #fff;opacity:0;animation:brg .85s ease-out}
.burst::after{content:"";position:absolute;inset:-30px;border-radius:50%;background:radial-gradient(circle,#ffffff55,#ffffff00 65%);opacity:0;animation:brg2 .9s ease-out}
@keyframes brg{0%{transform:scale(.3);opacity:.95}100%{transform:scale(1.9);opacity:0}}
@keyframes brg2{0%{transform:scale(.4);opacity:1}100%{transform:scale(1.6);opacity:0}}
@media(prefers-reduced-motion:reduce){#rbar:not(.grid) button img{animation:none}}
</style></head><body>
<svg width="0" height="0" style="position:absolute"><defs>
<symbol id="i-chat" viewBox="0 0 24 24"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></symbol>
<symbol id="i-user" viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></symbol>
<symbol id="i-hash" viewBox="0 0 24 24"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></symbol>
<symbol id="i-phone" viewBox="0 0 24 24"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></symbol>
<symbol id="i-video" viewBox="0 0 24 24"><polygon points="23 7 16 12 23 17 23 7"/><rect x="1" y="5" width="15" height="14" rx="2" ry="2"/></symbol>
<symbol id="i-videooff" viewBox="0 0 24 24"><path d="M16 16v1a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2h2m5.66 0H14a2 2 0 0 1 2 2v3.34l1 1L23 7v10"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
<symbol id="i-mic" viewBox="0 0 24 24"><path d="M12 1a3 3 0 0 0-3 3v8a3 3 0 0 0 6 0V4a3 3 0 0 0-3-3z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></symbol>
<symbol id="i-micoff" viewBox="0 0 24 24"><line x1="1" y1="1" x2="23" y2="23"/><path d="M9 9v3a3 3 0 0 0 5.12 2.12M15 9.34V4a3 3 0 0 0-5.94-.6"/><path d="M17 16.95A7 7 0 0 1 5 12v-2m14 0v2a7 7 0 0 1-.11 1.23"/><line x1="12" y1="19" x2="12" y2="23"/><line x1="8" y1="23" x2="16" y2="23"/></symbol>
<symbol id="i-send" viewBox="0 0 24 24"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></symbol>
<symbol id="i-pok" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10.2" fill="currentColor" stroke="none"/><path d="M7.4 12.4l3.2 3.2 6-6.6" stroke="var(--pk,#000)" stroke-width="2.4"/></symbol>
<symbol id="i-pbad" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" /><path d="M12 7.2v6"/><circle cx="12" cy="16.9" r=".6" fill="currentColor"/></symbol>
<symbol id="i-pchk" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M12 6.8V12l3.4 2"/></symbol>
<symbol id="i-pna" viewBox="0 0 24 24"><path d="M6 12h12"/></symbol>
<symbol id="i-flipcam" viewBox="0 0 24 24"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><path d="M8.37 11.91A4 4 0 0 1 15.63 11.91M13.93 11.29L15.63 11.91L16.24 10.22M15.63 15.29A4 4 0 0 1 8.37 15.29M10.07 15.91L8.37 15.29L7.76 16.98"/></symbol>
<symbol id="i-flip" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></symbol>
<symbol id="i-link" viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></symbol>
<symbol id="i-cam" viewBox="0 0 24 24"><path d="M23 19a2 2 0 0 1-2 2H3a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4l2-3h6l2 3h4a2 2 0 0 1 2 2z"/><circle cx="12" cy="13" r="4"/></symbol>
<symbol id="i-back" viewBox="0 0 24 24"><line x1="19" y1="12" x2="5" y2="12"/><polyline points="12 19 5 12 12 5"/></symbol>
<symbol id="i-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></symbol>
<symbol id="i-screen" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></symbol>
<symbol id="i-play" viewBox="0 0 24 24"><polygon points="6 4 20 12 6 20 6 4"/></symbol>
<symbol id="i-pause" viewBox="0 0 24 24"><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></symbol>
<symbol id="i-copy" viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></symbol>
<symbol id="i-bell" viewBox="0 0 24 24"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></symbol>
</defs></svg>
<div id="login">
<div class="ld" id="ld" role="status" aria-label="Loading"><div class="ldm"><i class="ldr g"></i><i class="ldr"></i><i class="ldd"></i><i class="ldo"></i><div class="ldc"><svg class="i"><use href="#i-chat"/></svg></div></div><div class="ldn">__GN__</div><div class="ldb"><i></i></div></div>
<div class="card" id="auth"><div class="logo"><svg class="i"><use href="#i-chat"/></svg></div>
<h1>__GN__</h1><p id="ap">Create your private account</p>
<div class="tabs"><button id="tup" class="on">Sign up</button><button id="tin">Log in</button></div>
<label class="fld"><svg class="i"><use href="#i-user"/></svg><input id="un" placeholder="Username" maxlength="20" autocapitalize="off" autocomplete="username"></label>
<label class="fld"><svg class="i"><use href="#i-lock"/></svg><input id="pw" type="password" placeholder="Password" autocomplete="current-password"></label>
<div class="err" id="ae"></div><button class="btn" id="ab">Create account</button></div>
<div class="card" id="prof"><h1 id="ph">Set up your profile</h1><p id="pp">Choose a photo and the name your friends will see</p>
<div class="pwrap" id="pwrap"><label class="pfa" id="pfa" for="pfile"><b id="pin">?</b></label><label class="pbadge" for="pfile" aria-label="Choose photo"><svg class="i"><use href="#i-cam"/></svg></label><input type="file" id="pfile" accept="image/*" hidden></div>
<div class="phint" id="phint">Tap to add a photo</div>
<label class="fld"><svg class="i"><use href="#i-user"/></svg><input id="dn" placeholder="Display name" maxlength="20" autocomplete="off"><span class="cnt" id="dc">0/20</span></label>
<div class="perms" id="perms"><div class="pt">Permissions</div>
<button type="button" class="pr" id="pm-mic" data-k="mic"><span class="pi"><svg class="i"><use href="#i-mic"/></svg></span><span class="pn"><b>Microphone</b><small></small></span><span class="ps"></span></button>
<button type="button" class="pr" id="pm-cam" data-k="cam"><span class="pi"><svg class="i"><use href="#i-video"/></svg></span><span class="pn"><b>Camera</b><small></small></span><span class="ps"></span></button>
<button type="button" class="pr" id="pm-ntf" data-k="ntf"><span class="pi"><svg class="i"><use href="#i-bell"/></svg></span><span class="pn"><b>Notifications</b><small></small></span><span class="ps"></span></button></div>
<div class="err" id="pe"></div><button class="btn" id="pb">Get started</button><button class="lo" id="pcx" style="display:none">Cancel</button></div>
<div class="card" id="gate"><h1>Password</h1><p>Enter the group password</p>
<label class="fld"><svg class="i"><use href="#i-lock"/></svg><input id="gp" type="password" placeholder="Password" autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"></label>
<div class="err" id="ge"></div><button class="btn" id="gb">Enter</button></div>
<div class="card" id="banned"><div class="logo" style="background:linear-gradient(135deg,#ff4d6a,#ff8a5c);color:#fff;box-shadow:0 12px 34px #ff4d6a66"><svg class="i"><use href="#i-lock"/></svg></div>
<h1 style="background:none;color:#fff;-webkit-text-fill-color:#fff">Account banned</h1><p>This account has been banned by the admin.<br>You can no longer use this chat.</p>
<button class="btn" id="bnb" style="background:#ffffff1a;color:#fff;box-shadow:none">Back</button></div>
</div>
<div id="app">
<header><div class="av" id="av">#</div>
<div class="info"><b id="rt"></b><small id="ol"></small></div>
<button class="ib" id="vc" aria-label="Video call"><svg class="i"><use href="#i-video"/></svg></button>
<button class="ib" id="ac" aria-label="Voice call"><svg class="i"><use href="#i-phone"/></svg></button></header>
<div id="ban"><span id="bt"></span><button id="bj">Join</button></div>
<div id="mn"><button id="mp">Edit profile</button><button id="lo">Log out</button></div>
<div id="msgs"></div>
<form id="f"><input id="txt" placeholder="Type a message" autocomplete="off"><div id="rec"><button type="button" class="rb rx" id="rx" aria-label="Cancel"><svg class="i"><use href="#i-trash"/></svg></button><span class="rdot"></span><span id="rtm">0:00</span><div id="rw"><canvas id="rcv"></canvas></div><span id="rhint">‹ Slide to cancel</span><button type="button" class="rb rs" id="rs" aria-label="Send voice message"><svg class="i"><use href="#i-send"/></svg></button></div><button type="button" class="mic" id="mic" aria-label="Voice message"><svg class="i"><use href="#i-mic"/></svg></button><button id="sb" aria-label="Send"><svg class="i"><use href="#i-send"/></svg></button></form>
</div>
<div id="ov">
<div id="top"><span id="tm">00:00</span></div>
<div id="rp"><div id="cpw"><i class="rg"></i><i class="rg"></i><i class="rg"></i><i class="arc"></i><div id="pav">?</div></div><div id="pn"></div><div id="pl"></div></div>
<div id="grid"></div>
<div class="bar" id="cin"><div class="cbw d"><button class="cb dec" id="bdec" aria-label="Decline"><svg class="i"><use href="#i-phone"/></svg></button><span>Decline</span></div><div class="cbw a"><button class="cb acc" id="bacc" aria-label="Accept"><svg class="i"><use href="#i-phone"/></svg></button><span>Accept</span></div></div>
<div class="bar" id="cout"><button class="cb" id="bmute"><svg class="i"><use href="#i-mic"/></svg></button><button class="cb" id="bcam" aria-label="Video on/off" title="Video"><svg class="i"><use href="#i-video"/></svg></button><button class="cb" id="bflip" aria-label="Switch front/back camera" title="Switch camera" style="display:none"><svg class="i"><use href="#i-flipcam"/></svg></button><button class="cb end" id="bend"><svg class="i"><use href="#i-phone"/></svg></button></div>
</div>
<div id="veil"></div><div id="rbar"></div><div id="sheet"></div>
<div id="toast"></div>
<script src="https://cdn.socket.io/4.7.5/socket.io.min.js"></script>
<script>window.io||document.write('<script src="https://cdn.jsdelivr.net/npm/socket.io-client@4.7.5/dist/socket.io.min.js"><\/script>')</script>
<script>
const $=id=>document.getElementById(id);
const CFG=__ICE__;const ICE={iceServers:CFG.iceServers,iceCandidatePoolSize:4};
const uid=()=>Date.now().toString(36)+Math.random().toString(36).slice(2,9);
const ic=n=>'<svg class="i"><use href="#i-'+n+'"/></svg>';
let cid=null,tok=null,me=null,S={};
const LS={get(k){try{return localStorage.getItem(k)}catch(e){return null}},set(k,v){try{localStorage.setItem(k,v)}catch(e){}},del(k){try{localStorage.removeItem(k)}catch(e){}}};
const ckGet=k=>{const m=document.cookie.match(new RegExp("(?:^|; )"+k+"=([^;]*)"));return m?decodeURIComponent(m[1]):null};
const ckSet=(k,v)=>{document.cookie=k+"="+encodeURIComponent(v)+";path=/;max-age=315360000;SameSite=Lax"};
const ckDel=k=>{document.cookie=k+"=;path=/;max-age=0"};

function loadS(){let x=null;
  try{x=JSON.parse(LS.get("ffx")||"null")}catch(e){}
  if(!x){try{x=JSON.parse(decodeURIComponent(escape(atob(ckGet("ffx")||""))))}catch(e){x=null}}
  S=x||{};delete S.g;if(!S.t&&LS.get("tok"))S.t=LS.get("tok")}
function saveS(){const j=JSON.stringify(S);LS.set("ffx",j);try{ckSet("ffx",btoa(unescape(encodeURIComponent(j))))}catch(e){}}
function clearS(){S={};LS.del("ffx");LS.del("ffx_av");LS.del("tok");ckDel("ffx")}
let bulk=false,socket,myId,myName,myRoom,lastSeq=0,lastDv=0,pending={},els={},ac=null;
let stream=null,peers={},pend={},inCall=false,cstate=null,dismissed=false,muted=false,camOff=false,facing="user",t0=0,ringing=null,rt=null,tmr=null;
function grpAv(el){el.textContent=(CFG.group[0]||"G").toUpperCase();
  if(CFG.pic){const i=new Image();i.referrerPolicy="no-referrer";i.onload=()=>el.appendChild(i);i.src=CFG.pic}}
(function(){const l=document.querySelector(".logo");
  if(l&&CFG.pic){const i=new Image();i.onload=()=>{l.textContent="";l.appendChild(i)};i.src=CFG.pic}})();
(function(){const c=document.querySelector(".ldc");
  if(c&&CFG.pic){const i=new Image();i.referrerPolicy="no-referrer";i.onload=()=>{c.textContent="";c.appendChild(i)};i.src=CFG.pic}})();
function setPav(k,txt){const p=$("pav");if(p.dataset.k===k+txt)return;p.dataset.k=k+txt;if(k==="g")grpAv(p);else p.textContent=txt}
function toast(t){const e=$("toast");e.textContent=t;e.style.display="block";clearTimeout(e._t);e._t=setTimeout(()=>e.style.display="none",2600)}
async function api(p,b){const r=await fetch("/api/"+p,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(Object.assign({token:tok},b||{}))});
  const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.error||"Error");return d}
function show(id){if(id==="prof"&&window.permRender)setTimeout(permRender,0);
  const L=$("ld");if(L&&!L._o){L._o=1;L.classList.add("out");setTimeout(()=>{L.style.display="none"},480)}
  ["auth","prof","gate","banned"].forEach(x=>$(x).style.display=x===id?"block":"none")}
function avImg(id,name){const s=document.createElement("span");s.className="mav";s.textContent=(name||"?")[0].toUpperCase();
  const i=new Image();i.src="/avatar/"+id;i.onload=()=>s.appendChild(i);return s}
let up=true,pfAv=null,editing=false;
$("tup").onclick=$("tin").onclick=e=>{up=e.currentTarget.id==="tup";$("tup").classList.toggle("on",up);$("tin").classList.toggle("on",!up);
  $("ab").textContent=up?"Create account":"Log in";$("ap").textContent=up?"Create your private account":"Welcome back"};
$("pw").onkeydown=e=>{if(e.key==="Enter")$("ab").click()};
$("ab").onclick=async()=>{$("ae").textContent="";
  const u=$("un").value.trim().replace(/\s+/g," "),p=$("pw").value;
  try{const d=await api(up?"register":"login",{username:u,password:p});
    tok=d.token;me=d.me;S={u:u,p:p,t:tok};saveS();
    if(up)openProf(false);else enter()}catch(e){if(e.message==="banned")return showBan();$("ae").textContent=e.message}};

function setPf(u){$("pfa").style.backgroundImage=u?"url("+u+")":"";$("pwrap").classList.toggle("has",!!u);
  $("phint").textContent=u?"Tap to change photo":"Tap to add a photo"}
function pin(){const v=$("dn").value;$("pin").textContent=(v.trim()[0]||"?").toUpperCase();$("dc").textContent=v.length+"/20"}
$("dn").oninput=pin;
$("dn").onkeydown=e=>{if(e.key==="Enter")$("pb").click()};
function openProf(edit){editing=edit;pfAv=null;$("pe").textContent="";
  $("dn").value=me.name||"";pin();setPf(edit&&me.av?"/avatar/"+me.id+"?v="+Date.now():null);
  $("ph").textContent=edit?"Edit profile":"Set up your profile";
  $("pp").textContent=edit?"Change your photo or display name":"Choose a photo and the name your friends will see";
  $("pb").textContent=edit?"Save changes":"Get started";$("pcx").style.display=edit?"inline-block":"none";
  show("prof");$("dn").focus()}
$("pfile").onchange=e=>{const f=e.target.files[0];if(!f)return;const im=new Image();
  im.onload=()=>{const c=document.createElement("canvas");c.width=c.height=256;const x=c.getContext("2d"),m=Math.min(im.width,im.height);
    x.drawImage(im,(im.width-m)/2,(im.height-m)/2,m,m,0,0,256,256);pfAv=c.toDataURL("image/jpeg",.82);setPf(pfAv);
    URL.revokeObjectURL(im.src);$("pe").textContent=""};
  im.onerror=()=>{$("pe").textContent="Could not read that image"};im.src=URL.createObjectURL(f)};
$("pb").onclick=async()=>{$("pe").textContent="";const b=$("pb");b.disabled=true;
  try{const d=await api("profile",{name:$("dn").value,avatar:pfAv});me=d.me;S.n=me.name;saveS();if(pfAv)LS.set("ffx_av",pfAv);
    if(editing)location.href="/";else enter()}
  catch(e){$("pe").textContent=e.message}b.disabled=false};
$("pcx").onclick=()=>{location.href="/"};

async function enter(){
  let g;
  try{g=await api("gate")}
  catch(e){if(e.message==="auth")return badTok();toast("Connection problem, retrying...");return setTimeout(enter,2500)}
  if(g.need){show("gate");$("gp").focus();return}
  go();
}
function showBan(){clearS();tok=null;if(socket){try{socket.disconnect()}catch(e){}socket=null}
  try{if(inCall)cleanup()}catch(e){}
  $("app").style.display="none";$("login").style.display="flex";show("banned")}
$("bnb").onclick=()=>{location.href="/"};
function badTok(){tok=null;S.t=null;saveS();autoIn()}
$("gb").onclick=async()=>{$("ge").textContent="";const p=$("gp").value;
  try{await api("gate",{password:p});$("gp").value="";go()}catch(e){$("ge").textContent=e.message}};
$("gp").onkeydown=e=>{if(e.key==="Enter")$("gb").click()};
$("lo").onclick=async()=>{try{await api("logout")}catch(e){}clearS();location.href="/"};
$("mp").onclick=()=>{location.href="/?edit=1"};

async function autoIn(){
  if(tok){
    try{const d=await api("me");me=d.me;return enter()}
    catch(e){if(e.message!=="auth"){toast("Connection problem, retrying...");return setTimeout(autoIn,2500)}tok=null}
  }
  if(S.u&&S.p){
    try{const d=await api("login",{username:S.u,password:S.p});tok=d.token;me=d.me;S.t=tok;saveS();return enter()}
    catch(e){
      if(e.message==="banned")return showBan();
      if(e.message!=="Wrong username or password"){toast("Connection problem, retrying...");return setTimeout(autoIn,2500)}
      try{const d=await api("register",{username:S.u,password:S.p});tok=d.token;me=d.me;S.t=tok;saveS();
        const av=LS.get("ffx_av");
        if(S.n||av){try{const r=await api("profile",{name:S.n||me.name,avatar:av});me=r.me}catch(_){}}
        return enter()}
      catch(e2){if(e2.message==="banned")return showBan();if(e2.message!=="Username already taken"){toast("Connection problem, retrying...");return setTimeout(autoIn,2500)}clearS()}
    }
  }
  show("auth");
}
loadS();tok=S.t||null;
if(location.search.indexOf("edit")>=0&&tok)api("me").then(d=>{me=d.me;openProf(true)}).catch(()=>autoIn());
else autoIn();
function linkify(p,text){const re=/https?:\/\/[^\s<]+/g;let i=0,m;
  while((m=re.exec(text))){p.appendChild(document.createTextNode(text.slice(i,m.index)));const a=document.createElement("a");
    a.href=m[0];a.textContent=m[0];a.target="_blank";a.rel="noopener noreferrer";a.className="lnk";p.appendChild(a);i=m.index+m[0].length}
  p.appendChild(document.createTextNode(text.slice(i)))}
function addPv(e,pv){if(!e||e.querySelector(".pv"))return;const a=document.createElement("a");a.className="pv";a.href=pv.url;a.target="_blank";a.rel="noopener noreferrer";
  if(pv.image){const i=new Image();i.referrerPolicy="no-referrer";i.src=pv.image;i.onerror=()=>i.remove();a.appendChild(i)}
  const d=document.createElement("div");
  [["small",pv.site],["b",pv.title],["span",pv.desc]].forEach(([t,v])=>{if(v){const n=document.createElement(t);n.textContent=v;d.appendChild(n)}});
  a.appendChild(d);const rxb=e.querySelector(".rxs");rxb?e.insertBefore(a,rxb):e.appendChild(a);const b=$("msgs");b.scrollTop=b.scrollHeight}
function go(){
  if(socket)return;
  if(typeof io==="undefined"){toast("Connection problem, retrying...");return setTimeout(()=>location.reload(),3000)}
  history.replaceState(null,"","/");
  const room=CFG.group;
  myName=me.name;myRoom=room;cid=String(me.id);
  try{ac=new(window.AudioContext||window.webkitAudioContext)()}catch(e){}
  try{Notification.requestPermission()}catch(e){}
  $("login").style.display="none";$("app").style.display="flex";
  $("rt").textContent=room;
  grpAv($("av"));
  socket=io({transports:["websocket","polling"],reconnection:true,reconnectionDelay:500,reconnectionDelayMax:3000});
  socket.on("connect",()=>socket.emit("join",{token:tok,room,last:lastSeq,dv:lastDv}));
  socket.on("auth_error",()=>{S.t=null;saveS();location.href="/"});
  socket.on("banned",showBan);
  socket.on("need_pass",()=>{location.href="/"});
  socket.on("joined",d=>{myId=d.id;bulk=true;d.msgs.forEach(addMsg);bulk=false;syncExtra(d);cstate=d.call;if(!cstate)dismissed=false;
    Object.values(pending).forEach(sendMsg);render()});
  socket.on("msg",m=>{addMsg(m);if(document.hidden&&m.cid!==cid)notify(m.name,m.au?"Voice message":m.text)});
  socket.on("preview",d=>addPv(els[d.mid],d.pv));
  socket.on("del",d=>delMsg(d.mid));socket.on("rx",d=>setRx(d.mid,d.rx));
  socket.on("system",d=>{const e=document.createElement("div");e.className="sys";e.textContent=d.text;push(e);
    setTimeout(()=>{e.style.height=e.offsetHeight+"px";void e.offsetHeight;e.classList.add("out");setTimeout(()=>e.remove(),700)},3000)});
  socket.on("users",l=>{$("ol").textContent=l.length+" online"});
  socket.on("call_state",s=>{cstate=s;if(!s)dismissed=false;render()});
  socket.on("call_incoming",d=>{if(document.hidden)notify(d.from,d.video?"Incoming video call":"Incoming voice call")});
  socket.on("call_peers",ids=>ids.forEach(id=>mk(id)));
  socket.on("call_left",id=>drop(id));
  socket.on("call_ended",d=>{if(inCall)cleanup();dismissed=false;toast(d.reason==="no_answer"?"No answer":d.reason==="declined"?"Call declined":"Call ended");render()});
  socket.on("signal",onSignal);
  setInterval(sync,12000);
  document.addEventListener("visibilitychange",()=>{if(!document.hidden)sync()});
  addEventListener("online",sync);addEventListener("focus",sync);
}
function sync(){
  if(!socket)return;
  if(!socket.connected){socket.connect();return}
  socket.emit("sync",{last:lastSeq,dv:lastDv},r=>{if(!r)return;if(r.rejoin)return socket.emit("join",{token:tok,room:myRoom,last:lastSeq,dv:lastDv});
    bulk=r.msgs.length>3;r.msgs.forEach(addMsg);bulk=false;syncExtra(r);cstate=r.call;if(!cstate)dismissed=false;render()});
}
function notify(t,b){try{if(Notification.permission==="granted")new Notification(t,{body:b})}catch(e){}}
function push(e){const b=$("msgs");const s=b.scrollHeight-b.scrollTop-b.clientHeight<150;b.appendChild(e);if(s)b.scrollTop=b.scrollHeight}
function fmtDur(s){s=Math.max(0,s|0);const h=Math.floor(s/3600),mm=Math.floor(s%3600/60),ss=s%60,p=n=>String(n).padStart(2,"0");return h?h+":"+p(mm)+":"+p(ss):p(mm)+":"+p(ss)}
function callEl(m,mine){
  const c=m.cl,k=c.v?"video":"voice",who=mine?"You":m.name,bad=!mine&&c.r!=="done";
  let ti,su;
  if(c.r==="done"){ti=(c.v?"Video":"Voice")+" call";su=who+" called \u00b7 "+fmtDur(c.d)}
  else if(mine){ti=(c.v?"Video":"Voice")+" call";su=c.r==="declined"?"Declined":c.r==="cancel"?"Cancelled":"No answer"}
  else{ti=(c.r==="declined"?"Declined ":"Missed ")+k+" call";su=m.name+" called"}
  const w=document.createElement("div");w.className="clm";
  const i=document.createElement("div");i.className="cli"+(bad?" bad":"");i.innerHTML=ic(c.v?"video":"phone");
  const tx=document.createElement("div");tx.className="clt";
  const b=document.createElement("b");b.textContent=ti;if(bad)b.className="bad";
  const sm=document.createElement("small");sm.textContent=su;
  tx.appendChild(b);tx.appendChild(sm);w.appendChild(i);w.appendChild(tx);return w;
}
function addMsg(m){
  if(m.seq&&m.seq>lastSeq)lastSeq=m.seq;
  const time=new Date(m.ts).toLocaleTimeString([],{hour:"2-digit",minute:"2-digit"});
  let e=els[m.mid];
  if(e){e.dataset.ts=m.ts;e.classList.remove("pd");e.querySelector(".t").textContent=time;delete pending[m.mid];if(m.pv)addPv(e,m.pv);return}
  e=document.createElement("div");e.className="m"+(m.cid===cid?" me":"")+(m.pd?" pd":"");e.dataset.ts=m.ts;e.dataset.mid=m.mid;e._own=m.cid===cid;e._txt=(m.au||m.cl)?"":m.text;e._au=!!m.au;e._cl=!!m.cl;
  if(m.cid!==cid){const n=document.createElement("div");n.className="n";n.appendChild(avImg(m.cid,m.name));n.appendChild(document.createTextNode(m.name));e.appendChild(n)}
  const t=document.createElement("span");t.className="t";t.textContent=time;
  if(m.cl){e.classList.add("cl");e.appendChild(callEl(m,m.cid===cid));e.appendChild(t)}
  else if(m.au){e.classList.add("v");e.appendChild(voiceEl(m));e.appendChild(t)}else{e.appendChild(t);linkify(e,m.text);if(m.pv)addPv(e,m.pv)}
  if(!bulk){e.classList.add("fx");e.addEventListener("animationend",ev=>{if(ev.target===e)e.classList.remove("fx")})}
  els[m.mid]=e;push(e);if(m.rx&&m.rx.length)setRx(m.mid,m.rx);
}
function sendMsg(p){socket.emit("msg",{mid:p.mid,text:p.text},r=>{if(r&&r.ok)delete pending[p.mid]})}
$("f").onsubmit=e=>{e.preventDefault();const v=$("txt").value.trim();if(!v)return;
  const p={mid:uid(),text:v};pending[p.mid]=p;
  addMsg({mid:p.mid,cid,name:myName,text:v,ts:Date.now(),pd:true});
  if(socket.connected)sendMsg(p);else socket.connect();
  $("txt").value="";$("f").classList.remove("has")};
$("txt").oninput=()=>$("f").classList.toggle("has",!!$("txt").value.trim());
$("av").onclick=e=>{e.stopPropagation();const m=$("mn");m.style.display=m.style.display==="block"?"none":"block"};
$("rt").parentNode.onclick=$("av").onclick;
document.addEventListener("click",()=>{$("mn").style.display="none"});

function syncExtra(d){(d.dels||[]).forEach(x=>delMsg(x,1));if(d.dv)lastDv=d.dv;applyRx(d.rx)}
function delMsg(mid,now){const e=els[mid];if(!e)return;delete els[mid];delete pending[mid];
  const v=e.querySelector(".vm");if(v&&v._stop)v._stop();
  if(e.classList.contains("sel"))closeAll();
  if(now){e.remove();return}
  e.classList.add("gone");setTimeout(()=>e.remove(),320)}
const RX=["❤️","😂","😮","😢","🔥","👍","🥰"];
const RXM="😀 😁 😆 😅 🤣 😊 😇 🙂 😉 😍 😘 😋 😎 🤩 🥳 😏 😒 😔 😭 😡 🤯 😱 🤔 🙄 😴 🤝 🙏 👏 🙌 💪 👎 👌 ✌️ 💔 💯 ✨ 🎉 🎁 🌹".split(" ");
const emoUrl=(em,x)=>"https://fonts.gstatic.com/s/e/notoemoji/latest/"+Array.from(em).map(c=>c.codePointAt(0).toString(16)).join("_")+"/512."+(x||"webp");
function emoImg(em,box){const im=new Image();im.alt=em;im.draggable=false;let t=0;
  im.onerror=()=>{if(!t++){im.src=emoUrl(em,"gif");return}im.remove();box.textContent=em;box.classList.add("fb-t")};
  im.src=emoUrl(em);return im}
RX.forEach(em=>{const p=new Image();p.src=emoUrl(em)});
function rAv(id,name){const s=document.createElement("span");s.className="rav";s.textContent=(name||"?")[0].toUpperCase();
  const i=new Image();i.src="/avatar/"+id;i.onload=()=>s.appendChild(i);return s}
function setRx(mid,list){
  const e=els[mid];if(!e)return;list=list||[];
  let box=e.querySelector(".rxs");
  if(!list.length){e._rx=[];if(box)box.remove();return}
  const sig=JSON.stringify(list);if(box&&box._sig===sig)return;
  e._rx=list;
  if(!box){box=document.createElement("div");box.className="rxs";e.appendChild(box)}
  box._sig=sig;box.textContent="";
  const g={};list.forEach(r=>(g[r[1]]=g[r[1]]||[]).push(r));
  Object.keys(g).forEach(em=>{
    const b=document.createElement("button");b.type="button";b.className="rc"+(g[em].some(r=>r[0]===cid)?" mine":"");b.dataset.em=em;
    const s=document.createElement("span");s.className="re";s.appendChild(emoImg(em,s));b.appendChild(s);
    const st=document.createElement("span");st.className="rst";
    g[em].slice(0,3).forEach(r=>st.appendChild(rAv(r[0],r[2])));b.appendChild(st);
    if(g[em].length>3){const c=document.createElement("span");c.className="rn";c.textContent="+"+(g[em].length-3);b.appendChild(c)}
    box.appendChild(b)});
  const ms=$("msgs");if(ms.scrollHeight-ms.scrollTop-ms.clientHeight<190)ms.scrollTop=ms.scrollHeight}
function applyRx(map){map=map||{};Object.keys(els).forEach(k=>{if(map[k]||(els[k]._rx&&els[k]._rx.length))setRx(k,map[k]||[])})}
function closeAll(){["rbar","sheet"].forEach(i=>$(i).classList.remove("show","grid"));$("veil").className="";
  document.querySelectorAll(".m.sel").forEach(x=>x.classList.remove("sel"))}
function place(bar,m){const r=m.getBoundingClientRect(),w=bar.offsetWidth,h=bar.offsetHeight;
  let top=r.top-h-10;if(top<64)top=Math.min(r.bottom+10,innerHeight-h-90);
  let left=m._own?r.right-w:r.left;left=Math.max(8,Math.min(innerWidth-w-8,left));
  bar.style.top=top+"px";bar.style.left=left+"px"}
function openRbar(m,full){
  closeAll();const bar=$("rbar");bar.textContent="";bar.classList.toggle("grid",!!full);
  const mine=(m._rx||[]).find(r=>r[0]===cid);
  (full?RXM:RX).forEach((em,i)=>{const b=document.createElement("button");b.type="button";
    b.className=mine&&mine[1]===em?"on":"";b.style.animationDelay=(i*35)+"ms";b.style.setProperty("--d",(i*35)+"ms");
    if(full)b.textContent=em;else b.appendChild(emoImg(em,b));
    b.onclick=ev=>{ev.stopPropagation();pickRx(m,em)};bar.appendChild(b)});
  if(!full){const mo=document.createElement("button");mo.type="button";mo.className="more";mo.textContent="+";
    mo.onclick=ev=>{ev.stopPropagation();openRbar(m,true)};bar.appendChild(mo)}
  m.classList.add("sel");$("veil").className="show";bar.classList.add("show");place(bar,m)}
function pickRx(m,em){const mine=(m._rx||[]).find(r=>r[0]===cid);closeAll();
  if(!mine||mine[1]!==em)burst(m,em);
  socket.emit("react",{mid:m.dataset.mid,emoji:em},r=>{if(!r||!r.ok)toast("Could not react")})}
function burst(m,em){const r=m.getBoundingClientRect(),d=document.createElement("div");d.className="burst";
  d.appendChild(emoImg(em,d));d.style.left=(r.left+r.width/2-30)+"px";d.style.top=(r.top+r.height/2-30)+"px";
  document.body.appendChild(d);setTimeout(()=>d.remove(),1050)}
function openSheet(m){
  if(m.classList.contains("pd")||$("sheet").classList.contains("show"))return;
  const acts=[];if(m._txt)acts.push(["copy","Copy","copy"]);if(m._own)acts.push(["del","Delete","trash"]);
  if(!acts.length)return openRbar(m);
  closeAll();const s=$("sheet");s.textContent="";
  const gr=document.createElement("i");gr.className="sgrip";s.appendChild(gr);
  const pv=document.createElement("div");pv.className="spv";pv.textContent=m._au?"Voice message":m._cl?"Call":(m._txt||"").slice(0,80);s.appendChild(pv);
  acts.forEach(a=>{const b=document.createElement("button");b.type="button";b.className="sa "+a[0];b.innerHTML=ic(a[2])+"<span></span>";
    b.lastChild.textContent=a[1];b.onclick=ev=>{ev.stopPropagation();a[0]==="copy"?doCopy(m):confDel(m)};s.appendChild(b)});
  m.classList.add("sel");$("veil").className="show dim";s.classList.add("show")}
function confDel(m){const s=$("sheet");
  s.innerHTML='<i class="sgrip"></i><div class="sdi">'+ic("trash")+'</div><div class="sdt">Delete this message?</div><div class="sds">It will be removed for everyone in the group.</div><div class="sbr"><button type="button" class="sc">Cancel</button><button type="button" class="sd">Delete</button></div>';
  s.querySelector(".sc").onclick=closeAll;
  s.querySelector(".sd").onclick=()=>{closeAll();socket.emit("del",{mid:m.dataset.mid},r=>{if(!r||!r.ok)toast("Could not delete")})}}
async function doCopy(m){closeAll();const t=m._txt;
  try{await navigator.clipboard.writeText(t)}
  catch(e){const a=document.createElement("textarea");a.value=t;a.style.cssText="position:fixed;opacity:0";document.body.appendChild(a);a.select();try{document.execCommand("copy")}catch(_){}a.remove()}
  toast("Copied")}
$("veil").onclick=closeAll;
addEventListener("keydown",e=>{if(e.key==="Escape")closeAll()});
let lpT=null,lpX=0,lpY=0,lpF=false;
const mE=$("msgs");
mE.addEventListener("pointerdown",ev=>{lpF=false;clearTimeout(lpT);
  const m=ev.target.closest(".m");if(!m||ev.target.closest(".rc"))return;
  lpX=ev.clientX;lpY=ev.clientY;
  lpT=setTimeout(()=>{lpF=true;navigator.vibrate&&navigator.vibrate(18);openSheet(m)},450)});
mE.addEventListener("pointermove",ev=>{if(lpT&&Math.hypot(ev.clientX-lpX,ev.clientY-lpY)>10)clearTimeout(lpT)});
["pointerup","pointercancel","pointerleave"].forEach(t=>mE.addEventListener(t,()=>clearTimeout(lpT)));
mE.addEventListener("scroll",()=>{clearTimeout(lpT);if($("rbar").classList.contains("show"))closeAll()},{passive:true});
mE.addEventListener("contextmenu",ev=>{const m=ev.target.closest(".m");if(m){ev.preventDefault();if(!lpF){lpF=true;openSheet(m)}}});
mE.addEventListener("click",ev=>{
  if(lpF){lpF=false;ev.stopPropagation();ev.preventDefault();return}
  const m=ev.target.closest(".m");if(!m)return;
  const ch=ev.target.closest(".rc");
  if(ch){socket.emit("react",{mid:m.dataset.mid,emoji:ch.dataset.em});return}
  if(ev.target.closest("a,.vp,.vb")||m.classList.contains("pd"))return;
  openRbar(m)},true);

const fmt=s=>{s=Math.max(0,Math.round(s||0));return Math.floor(s/60)+":"+String(s%60).padStart(2,"0")};
let vr=null,vch=[],vT=0,vI=null,vX=false,vS=null,curA=null,vAn=null,vSrc=null,vLv=[],vRaf=0,vHold=null,vStarting=false;
const VW=32;
function vUi(on){const f=$("f");f.classList.toggle("recm",on);if(!on)f.classList.remove("lk","cx");$("rhint").textContent="‹ Slide to cancel"}
function vLock(){$("f").classList.add("lk");vHold=null}

function vAnalyse(){
  const cv=$("rcv"),dpr=window.devicePixelRatio||1,W=cv.clientWidth,H=cv.clientHeight;
  cv.width=W*dpr;cv.height=H*dpr;const g=cv.getContext("2d");g.scale(dpr,dpr);
  if(!ac){try{ac=new(window.AudioContext||window.webkitAudioContext)()}catch(e){}}
  let buf=null;
  if(ac&&vS){try{ac.resume();vSrc=ac.createMediaStreamSource(vS);vAn=ac.createAnalyser();vAn.fftSize=512;vSrc.connect(vAn);buf=new Uint8Array(vAn.fftSize)}catch(e){vAn=null}}
  const bw=3,step=6,n=Math.max(8,Math.ceil(W/step)),hist=new Array(n).fill(0),SP=55,cy=H/2;
  let last=performance.now(),acc=0,pk=0;
  const grad=g.createLinearGradient(0,0,W,0);grad.addColorStop(0,"#22b8d633");grad.addColorStop(.55,"#22b8d6");grad.addColorStop(1,"#2ee6a6");
  const bar=(x,v)=>{const h=Math.max(bw,Math.pow(v,.75)*H*.92)-bw;g.beginPath();g.moveTo(x,cy-h/2);g.lineTo(x,cy+h/2);g.stroke()};
  const loop=t=>{
    vRaf=requestAnimationFrame(loop);acc+=t-last;last=t;
    let lv;
    if(vAn&&ac.state==="running"){vAn.getByteTimeDomainData(buf);let s=0;for(let i=0;i<buf.length;i++){const v=(buf[i]-128)/128;s+=v*v}lv=Math.min(1,Math.sqrt(s/buf.length)*3.4)}
    else lv=.15+Math.random()*.3;
    pk=Math.max(pk,lv);
    while(acc>=SP){acc-=SP;hist.shift();hist.push(pk);vLv.push(pk);pk=0}
    g.clearRect(0,0,W,H);g.strokeStyle=grad;g.lineWidth=bw;g.lineCap="round";
    const off=acc/SP*step;
    hist.forEach((v,i)=>bar(i*step+bw-off,v));
    bar(n*step+bw-off,pk);
  };
  loop(performance.now());
}

function vWave(a){if(!a.length)return "";const o=[];
  for(let i=0;i<VW;i++){const s=Math.floor(i*a.length/VW),e=Math.max(s+1,Math.floor((i+1)*a.length/VW));let m=0;for(let j=s;j<e&&j<a.length;j++)m=Math.max(m,a[j]);o.push(m)}
  const mx=Math.max(Math.max.apply(null,o),.05);return o.map(v=>Math.round(Math.max(10,Math.pow(v/mx,.8)*100))).join(",")}
async function vStart(){
  if(vr||vStarting)return false;
  if(!navigator.mediaDevices||!window.MediaRecorder){toast("Voice messages are not supported in this browser");return false}
  vStarting=true;
  try{vS=await navigator.mediaDevices.getUserMedia({audio:{channelCount:1,sampleRate:{ideal:48000},echoCancellation:false,noiseSuppression:true,autoGainControl:true}});permMark("mic")}
  catch(e){permMark("mic",e);vStarting=false;toast("Allow microphone access to send voice messages");return false}
  const mt=["audio/webm;codecs=opus","audio/mp4","audio/webm","audio/ogg;codecs=opus"].find(t=>MediaRecorder.isTypeSupported(t))||"";
  const bps=96000;
  try{vr=new MediaRecorder(vS,mt?{mimeType:mt,audioBitsPerSecond:bps}:{audioBitsPerSecond:bps})}
  catch(e){vS.getTracks().forEach(t=>t.stop());vS=null;vStarting=false;toast("Could not start recording");return false}
  vch=[];vX=false;vLv=[];
  vr.ondataavailable=e=>{if(e.data&&e.data.size)vch.push(e.data)};
  vr.onstop=()=>{
    clearInterval(vI);cancelAnimationFrame(vRaf);
    try{vSrc&&vSrc.disconnect()}catch(e){}vSrc=vAn=null;
    if(vS)vS.getTracks().forEach(t=>t.stop());vS=null;
    const dur=(Date.now()-vT)/1000,type=(vr&&vr.mimeType)||mt||"audio/webm",lv=vLv;vr=null;vUi(false);
    if(vX)return;
    if(dur<1||!vch.length)return toast("Recording too short");
    vSend(new Blob(vch,{type:type}),dur,vWave(lv))};
  vr.start(250);vT=Date.now();$("rtm").textContent="0:00";vUi(true);vAnalyse();
  vI=setInterval(()=>{const s=(Date.now()-vT)/1000;$("rtm").textContent=fmt(s);if(s>=180)vStop(false)},250);
  vStarting=false;return true;
}
function vStop(cancel){if(!vr)return;vX=cancel;try{vr.stop()}catch(e){}}
async function vSend(blob,dur,wave){
  toast("Sending voice message...");
  try{const r=await fetch("/api/voice",{method:"POST",headers:{"Content-Type":blob.type.split(";")[0],"X-Token":tok,"X-Mid":uid(),"X-Dur":String(Math.round(dur)),"X-Wave":wave||""},body:blob});
    if(!r.ok){const d=await r.json().catch(()=>({}));throw new Error(d.error||"Failed")}
    $("toast").style.display="none"}
  catch(e){toast("Could not send voice message")}
}

const mic=$("mic");
function finishHold(h,cancel){vHold=null;
  if(h.cx||cancel)return vStop(true);
  if(Date.now()-h.t>=550)return vStop(false);
  vLock()}
function micUp(cancel){const h=vHold;if(!h)return;h.up=true;if(!vr)return;finishHold(h,cancel)}
mic.addEventListener("contextmenu",e=>e.preventDefault());
mic.addEventListener("pointerdown",async e=>{
  e.preventDefault();if(vr||vStarting)return;
  if(ac&&ac.state==="suspended")ac.resume().catch(()=>{});
  try{mic.setPointerCapture(e.pointerId)}catch(_){}
  const h=vHold={t:Date.now(),x:e.clientX,up:false,cx:false};
  const ok=await vStart();
  if(!ok){if(vHold===h)vHold=null;return}
  if(h.up&&vHold===h)vLock()});
mic.addEventListener("pointermove",e=>{const h=vHold;if(!h||!vr)return;const cx=e.clientX-h.x<-70;
  if(cx!==h.cx){h.cx=cx;$("f").classList.toggle("cx",cx);$("rhint").textContent=cx?"Release to cancel":"‹ Slide to cancel"}});
mic.addEventListener("pointerup",()=>micUp(false));
mic.addEventListener("pointercancel",()=>micUp(true));
mic.addEventListener("keydown",e=>{if((e.key==="Enter"||e.key===" ")&&!vr){e.preventDefault();vStart().then(ok=>{if(ok)vLock()})}});
$("rx").onclick=()=>vStop(true);$("rs").onclick=()=>vStop(false);
function wvOf(m){
  if(m.wv){const a=String(m.wv).split(",").map(Number).filter(x=>x>=0);if(a.length>=8)return a}
  let h=0;const s=String(m.mid);for(let i=0;i<s.length;i++)h=(h*31+s.charCodeAt(i))|0;
  return Array.from({length:VW},(_,i)=>{h=(Math.imul(h,1103515245)+12345)|0;const r=((h>>>16)&255)/255;return 22+Math.round(Math.abs(Math.sin(i*.55+r*3))*55+r*20)})}
function voiceEl(m){
  const w=document.createElement("div");w.className="vm";
  const b=document.createElement("button");b.type="button";b.className="vp";b.innerHTML=ic("play");
  const bar=document.createElement("div");bar.className="vb";
  const bs=wvOf(m).map(v=>{const i=document.createElement("i");i.style.height=Math.max(12,Math.min(100,v))+"%";bar.appendChild(i);return i});
  const d=document.createElement("span");d.className="vd";d.textContent=fmt(m.dur);
  w.appendChild(b);w.appendChild(bar);w.appendChild(d);let a=null,raf=0,sk=false;
  const tot=()=>a&&isFinite(a.duration)&&a.duration>0?a.duration:(m.dur||1);
  const setP=p=>{const k=Math.round(p*bs.length);bs.forEach((x,i)=>x.classList.toggle("on",i<k))};
  const reset=()=>{cancelAnimationFrame(raf);b.innerHTML=ic("play");setP(0);d.textContent=fmt(m.dur)};
  const loop=()=>{if(!a||a.paused)return;setP(a.currentTime/tot());d.textContent=fmt(a.currentTime);raf=requestAnimationFrame(loop)};
  w._stop=()=>{if(a){a.pause();a.onended=null}};
  b.onclick=()=>{
    if(!a){a=new Audio("/audio/"+m.au+"?t="+encodeURIComponent(tok));a.preload="auto";
      a.ontimeupdate=()=>{if(a.paused){setP(a.currentTime/tot());d.textContent=fmt(a.currentTime)}};
      a.onplay=()=>{b.innerHTML=ic("pause");loop()};
      a.onpause=()=>{if(!a.ended)b.innerHTML=ic("play")};
      a.onended=reset;a.onerror=()=>{reset();toast("Could not play this voice message")}}
    if(a.paused){if(curA&&curA!==a)curA.pause();curA=a;a.play().catch(()=>toast("Could not play this voice message"))}
    else a.pause()};
  const seek=e=>{if(!a)return;const r=bar.getBoundingClientRect(),p=Math.min(1,Math.max(0,(e.clientX-r.left)/r.width));a.currentTime=tot()*p;setP(p)};
  bar.onpointerdown=e=>{e.stopPropagation();sk=true;try{bar.setPointerCapture(e.pointerId)}catch(_){}seek(e)};
  bar.onpointermove=e=>{if(sk)seek(e)};
  bar.onpointerup=bar.onpointercancel=()=>{sk=false};
  return w;
}

function tone(f,d,v=.12){if(!ac)return;ac.resume();const o=ac.createOscillator(),g=ac.createGain();o.frequency.value=f;g.gain.value=v;o.connect(g);g.connect(ac.destination);o.start();g.gain.setTargetAtTime(0,ac.currentTime+d-.06,.03);o.stop(ac.currentTime+d)}
function ringOn(k){ringOff();const f=k==="in"?()=>{tone(523,.35);setTimeout(()=>tone(659,.4),420);navigator.vibrate&&navigator.vibrate([300,150,300])}:()=>tone(425,1.2,.07);f();rt=setInterval(f,k==="in"?2600:3500)}
function ringOff(){clearInterval(rt);rt=null;navigator.vibrate&&navigator.vibrate(0)}

async function media(video){
  try{stream=await navigator.mediaDevices.getUserMedia({audio:{echoCancellation:true,noiseSuppression:true,autoGainControl:true},video:video?{facingMode:facing,width:{ideal:1280},height:{ideal:720}}:false});permMark("mic");if(video)permMark("cam");return true}
  catch(e){toast("Allow microphone / camera access");return false}
}
async function startCall(v){
  if(inCall||cstate)return;
  if(!await media(v))return;
  socket.emit("call_start",{video:v},r=>{
    if(r&&r.err){stopMedia();return toast("A call is already active")}
    setupLocal();inCall=true;render()});
}
async function joinCall(){
  if(inCall||!cstate)return;
  const ov=$("ov"),was=$("pl").textContent;ov.classList.add("accepting");$("pl").textContent="Connecting\u2026";
  if(!await media(cstate.video)){ov.classList.remove("accepting");$("pl").textContent=was;return}
  setupLocal();inCall=true;socket.emit("call_accept");render();
}
$("ac").onclick=()=>startCall(false);$("vc").onclick=()=>startCall(true);
$("bacc").onclick=joinCall;$("bj").onclick=joinCall;
$("bdec").onclick=()=>{dismissed=true;socket.emit("call_decline");render()};
$("bend").onclick=()=>{socket.emit("call_leave");cleanup();render()};
$("bmute").onclick=()=>{muted=!muted;stream.getAudioTracks().forEach(t=>t.enabled=!muted);
  $("bmute").classList.toggle("off",muted);$("bmute").innerHTML=ic(muted?"micoff":"mic")};
let camBusy=false,flipBusy=false;
function camUi(){
  const vt=stream&&stream.getVideoTracks()[0],on=!!vt&&vt.readyState==="live"&&!camOff;
  $("bcam").classList.toggle("off",!on);$("bcam").innerHTML=ic(on?"video":"videooff");
  $("bflip").style.display=on?"":"none";
  const t=$("t-me");if(t){t.classList.toggle("novid",!on);const v=t.querySelector("video");if(v)v.classList.toggle("mir",facing==="user")}
}
function camErr(e){toast(e&&e.name==="NotAllowedError"?"Camera is blocked - allow it in your browser's site settings":e&&e.name==="NotFoundError"?"No camera found on this device":"Can't start the camera")}
async function enableVideo(){
  if(camBusy||!stream)return;camBusy=true;
  try{
    const s=await navigator.mediaDevices.getUserMedia({video:{facingMode:facing,width:{ideal:1280},height:{ideal:720}}});
    const nt=s.getVideoTracks()[0];
    if(!stream||!inCall){nt.stop();return}
    stream.addTrack(nt);camOff=false;nt.enabled=true;
    Object.values(peers).forEach(pc=>{try{pc.addTrack(nt,stream)}catch(e){}});
    const v=$("t-me")&&$("t-me").querySelector("video");if(v){v.srcObject=stream;v.play().catch(()=>{})}
  }catch(e){camErr(e)}
  finally{camBusy=false;camUi()}
}
$("bcam").onclick=()=>{
  if(!stream)return;
  const vt=stream.getVideoTracks()[0];
  if(!vt||vt.readyState!=="live"){camOff=false;return enableVideo()}
  camOff=!camOff;vt.enabled=!camOff;camUi()};
$("bflip").onclick=async()=>{
  if(!stream||flipBusy)return;
  flipBusy=true;
  const nf=facing==="user"?"environment":"user",ot=stream.getVideoTracks()[0];
  if(ot)ot.stop();
  let nt=null;
  try{const s=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:nf},width:{ideal:1280},height:{ideal:720}}});nt=s.getVideoTracks()[0];facing=nf}
  catch(e){
    try{const s=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:facing}}});nt=s.getVideoTracks()[0];toast("Can't switch camera")}
    catch(e2){camErr(e2)}}
  if(nt){
    if(ot)stream.removeTrack(ot);stream.addTrack(nt);nt.enabled=!camOff;
    Object.values(peers).forEach(pc=>{const sn=pc.getSenders().find(x=>x.track&&x.track.kind==="video");sn&&sn.replaceTrack(nt).catch(()=>{})});
    const v=$("t-me")&&$("t-me").querySelector("video");if(v){v.srcObject=stream;v.play().catch(()=>{})}}
  flipBusy=false;camUi();
};
const scrIds={};let scr=null,scrT=null;
function addScr(id){const pc=peers[id];if(!pc||!scr||!scrT)return;
  pc._ss=pc.addTrack(scrT,scr);socket.emit("signal",{to:id,data:{scr:scr.id}})}
function rmScr(id){const t=$("t-s-"+id);if(t)t.remove();delete scrIds[id];render()}
function stopShare(){
  if(!scr)return;
  const s=scr;scr=null;scrT=null;
  s.getTracks().forEach(t=>{t.onended=null;t.stop()});
  Object.keys(peers).forEach(id=>{const pc=peers[id];
    if(pc._ss){try{pc.removeTrack(pc._ss)}catch(e){}pc._ss=null}
    socket.emit("signal",{to:id,data:{scr:null}})});

}

function stopMedia(){if(stream){stream.getTracks().forEach(t=>t.stop());stream=null}}
function tile(id,name,me){
  let t=$("t-"+id);
  if(!t){t=document.createElement("div");t.id="t-"+id;t.className="tile"+(me?" me":"");
    t.innerHTML='<div class="ab"></div><video autoplay playsinline></video><div class="tn"></div>';
    if(me){t.querySelector("video").muted=true}
    $("grid").appendChild(t)}
  t.querySelector(".tn").textContent=me?"You":name;t.querySelector(".ab").textContent=(name||"?")[0].toUpperCase();
  return t;
}
function setupLocal(){
  muted=camOff=false;$("bmute").className="cb";$("bmute").innerHTML=ic("mic");
  const t=tile("me",myName,true),v=t.querySelector("video");
  v.srcObject=stream;camUi();
}
function cleanup(){
  stopShare();stopMedia();Object.keys(peers).forEach(drop);$("grid").innerHTML="";inCall=false;t0=0;
}
function mk(id){
  if(peers[id])return peers[id];
  const pc=new RTCPeerConnection(ICE);peers[id]=pc;pc._mk=false;
  pc.onnegotiationneeded=async()=>{
    try{if(pc.signalingState!=="stable")return;pc._mk=true;await pc.setLocalDescription();
      socket.emit("signal",{to:id,data:{sdp:pc.localDescription}})}
    catch(e){}finally{pc._mk=false}};
  pc.onicecandidate=e=>{if(e.candidate)socket.emit("signal",{to:id,data:{ice:e.candidate}})};
  pc.oniceconnectionstatechange=()=>{const st=pc.iceConnectionState;
    if(st==="failed"){try{pc.restartIce()}catch(e){}}
    else if(st==="disconnected"){setTimeout(()=>{if(peers[id]===pc&&pc.iceConnectionState==="disconnected"){try{pc.restartIce()}catch(e){}}},4000)}};
  pc.ontrack=e=>{const s=e.streams[0];if(!s)return;
    const nm=((cstate&&cstate.parts.find(p=>p.id===id))||{}).name||"User";
    if(!pc._main&&scrIds[id]!==s.id)pc._main=s.id;
    if(s.id!==pc._main){
      const t=tile("s-"+id,nm+"'s screen",false);t.classList.add("scr");
      const v=t.querySelector("video");v.srcObject=s;v.play().catch(()=>{});render();return}
    const t=tile(id,nm,false),v=t.querySelector("video");v.srcObject=s;
    t.classList.toggle("novid",s.getVideoTracks().length===0);v.play().catch(()=>{});render()};
  if(stream)stream.getTracks().forEach(t=>pc.addTrack(t,stream));
  if(scr&&scrT)addScr(id);
  return pc;
}
async function onSignal({from,data}){
  if(!inCall)return;
  if("scr" in data){if(data.scr)scrIds[from]=data.scr;else rmScr(from);return}
  try{
    if(data.sdp){
      const pc=mk(from),polite=myId>from;
      if(data.sdp.type==="offer"&&(pc._mk||pc.signalingState!=="stable")&&!polite)return;
      await pc.setRemoteDescription(data.sdp);
      (pend[from]||[]).forEach(c=>pc.addIceCandidate(c).catch(()=>{}));pend[from]=[];
      if(data.sdp.type==="offer"){await pc.setLocalDescription();
        socket.emit("signal",{to:from,data:{sdp:pc.localDescription}})}
    }else if(data.ice){
      const pc=peers[from];
      if(pc&&pc.remoteDescription)pc.addIceCandidate(data.ice).catch(()=>{});
      else(pend[from]=pend[from]||[]).push(data.ice);
    }
  }catch(e){}
}
function drop(id){
  if(peers[id]){peers[id].close();delete peers[id]}
  [id,"s-"+id].forEach(k=>{const t=$("t-"+k);if(t)t.remove()});
  delete pend[id];delete scrIds[id];render();
}
function tick(){const s=Math.floor((Date.now()-t0)/1000);$("tm").textContent=String(Math.floor(s/60)).padStart(2,"0")+":"+String(s%60).padStart(2,"0")}
function render(){
  const c=cstate;let mode=null;
  if(inCall)mode=(c&&c.parts.length>1)?"live":"out";
  else if(c&&c.ringing&&!dismissed)mode="in";
  $("ov").className=mode?"show "+mode:"";
  $("ban").style.display=(c&&!inCall&&!mode)?"flex":"none";
  if(c&&!inCall)$("bt").textContent=(c.video?"Video":"Voice")+" call in progress";
  if(mode==="in"){$("pn").textContent=c.starter;$("pl").textContent=c.video?"Incoming video call":"Incoming voice call";setPav("u",(c.starter[0]||"?").toUpperCase());$("bacc").innerHTML=ic(c.video?"video":"phone")}
  if(mode==="out"){$("pn").textContent=myRoom;$("pl").textContent="Calling…";setPav("g","")}
  if(inCall)camUi();
  if(mode==="live"){$("grid").className=$("grid").children.length<=2?"duo":"";if(!t0){t0=Date.now();tmr=setInterval(tick,1000)}tick()}
  else{clearInterval(tmr);t0=0}
  const want=mode==="in"?"in":mode==="out"?"out":null;
  if(want!==ringing){ringing=want;want?ringOn(want):ringOff()}
}

const PERMS=[
 {k:"mic",n:"Voice messages & calls"},
 {k:"cam",n:"Video calls"},
 {k:"ntf",n:"New messages & incoming calls"}];

const PV={};
function permMark(k,e){
  if(!e){PV[k]="ok";return}
  const n=e&&e.name;
  PV[k]=(n==="NotAllowedError"||n==="SecurityError"||n==="PermissionDeniedError")?"fail":(n==="NotFoundError"||n==="DevicesNotFoundError")?"nodev":"ok"}
async function permProbe(k){
  try{const s=await navigator.mediaDevices.getUserMedia(k==="mic"?{audio:true}:{video:true});s.getTracks().forEach(t=>t.stop());permMark(k)}
  catch(e){permMark(k,e)}
}
async function permState(k){
  if(k==="ntf"){
    if(!("Notification" in window))return "na";
    const p=Notification.permission;return p==="default"?"prompt":p}
  if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia)return "na";
  const name=k==="mic"?"microphone":"camera";
  let q=null;
  try{
    const r=await navigator.permissions.query({name});
    r.onchange=()=>{delete PV[k];permRender()};
    q=r.state;
  }catch(e){}
  if(q==="denied")return "denied";
  if(q==="prompt"){delete PV[k];return "prompt"}
  if(PV[k]==="ok")return "granted";
  if(PV[k]==="fail")return "denied";
  if(PV[k]==="nodev")return "nodev";

  if(q==="granted"){
    if(inCall||vr||vStarting)return "granted";
    if(!($("prof").style.display==="block"&&!document.hidden))return "chk";
    await permProbe(k);
    return PV[k]==="fail"?"denied":PV[k]==="nodev"?"nodev":"granted";
  }
  return "prompt";
}
let permBusy=false;
async function permRender(){
  if(permBusy)return;permBusy=true;
  try{
    for(const p of PERMS){
      const st=await permState(p.k),el=$("pm-"+p.k);if(!el)continue;
      el.dataset.st=st;
      el.className="pr "+(st==="granted"?"ok":st==="na"||st==="chk"?"na":"bad");
      el.querySelector(".ps").innerHTML=ic(st==="granted"?"pok":st==="na"?"pna":st==="chk"?"pchk":"pbad");
      el.querySelector("small").textContent=p.n+" \u00B7 "+(st==="granted"?"Allowed":st==="denied"?"Blocked - tap for help":st==="nodev"?"No device found":st==="na"?"Not supported here":st==="chk"?"Checking\u2026":"Tap to allow");
    }
  }finally{permBusy=false}
}
async function permAsk(k){
  const st=await permState(k),lab=k==="mic"?"Microphone":k==="cam"?"Camera":"Notifications";
  if(st==="granted"){toast(lab+" is already allowed");return permRender()}
  if(st==="na")return toast(lab+" isn't supported on this browser");
  if(st==="nodev")return toast("No "+(k==="mic"?"microphone":"camera")+" found on this device");
  if(st==="denied")return toast(lab+" is blocked. Open your browser's site settings (lock icon by the address bar) and, if it still fails, your phone's app settings, and switch it to Allow");
  try{
    if(k==="ntf")await Notification.requestPermission();
    else{const s=await navigator.mediaDevices.getUserMedia(k==="mic"?{audio:true}:{video:true});s.getTracks().forEach(t=>t.stop());permMark(k)}
  }catch(e){
    if(k!=="ntf")permMark(k,e);
    toast(e&&e.name==="NotFoundError"?"No "+(k==="mic"?"microphone":"camera")+" found on this device":lab+" was not allowed")}
  permRender();
}
document.querySelectorAll(".pr").forEach(b=>b.onclick=()=>permAsk(b.dataset.k));
addEventListener("focus",()=>{["mic","cam"].forEach(k=>{if(PV[k]!=="ok")delete PV[k]});permRender()});
document.addEventListener("visibilitychange",()=>{if(!document.hidden){["mic","cam"].forEach(k=>{if(PV[k]!=="ok")delete PV[k]});permRender()}});
setInterval(()=>{if($("prof").style.display==="block"&&!document.hidden)permRender()},2000);
permRender();

(function(){
  const ua=navigator.userAgent||"",and=/Android/i.test(ua),ios=/iPhone|iPad|iPod/i.test(ua);
  document.addEventListener("click",ev=>{
    const a=ev.target.closest&&ev.target.closest("a[href]");if(!a)return;
    let u;try{u=new URL(a.href)}catch(e){return}
    if(!/^https?:$/.test(u.protocol)||!/(^|\.)tiktok\.com$/i.test(u.hostname))return;
    if(and){
      ev.preventDefault();
      location.href="intent://"+u.host+u.pathname+u.search+"#Intent;scheme=https;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;S.browser_fallback_url="+encodeURIComponent(u.href)+";end";
    }else if(ios){
      ev.preventDefault();
      location.href=u.href;
    }
  },true);
})();

</script></body></html>
"""

ADMIN_PASS = _env(3)
_ADM_KEY = (ADMIN_PASS + "|" + str(app.config["SECRET_KEY"])).encode()
_adm_fail = {}

def _adm_ip():
    return _client_ip()

def _adm_token(exp):
    return "%d.%s" % (exp, hmac.new(_ADM_KEY, str(exp).encode(), hashlib.sha256).hexdigest())

def _adm_ok():
    if not ADMIN_PASS:
        return False
    try:
        exp, sig = request.cookies.get("ffx_adm", "").split(".", 1)
        return int(exp) > time.time() and secrets.compare_digest(sig, _adm_token(int(exp)).split(".", 1)[1])
    except Exception:
        return False

def _adm_json(data, code=200):
    r = jsonify(data)
    r.status_code = code
    r.headers["Cache-Control"] = "no-store"
    return r

def _adm_delete_mids(mids):
    """Delete messages (and their voice files / reactions) and tell every connected device."""
    mids = [m for m in mids if m]
    if not mids:
        return 0
    with lock:
        with db() as c:
            for mid in mids:
                r = c.execute("select au from msgs where room=? and mid=?", (ROOM, mid)).fetchone()
                if not r:
                    continue
                c.execute("delete from msgs where room=? and mid=?", (ROOM, mid))
                if r["au"]:
                    c.execute("delete from audio where id=?", (r["au"],))
                c.execute("delete from reactions where mid=?", (mid,))
                c.execute("insert into dels(mid) values(?)", (mid,))
        gone = set(mids)
        h = get_hist(ROOM)
        h[:] = [m for m in h if m["mid"] not in gone]
    for mid in mids:
        socketio.emit("del", {"mid": mid}, to=ROOM)
    return len(mids)

def _adm_ban(username, del_msgs=False):
    """Ban a username: it can never log in or sign up again until unbanned. Connected devices are kicked out."""
    uname = re.sub(r"\s+", " ", (username or "").strip())
    if not re.fullmatch(r"[A-Za-z0-9_. ]{3,20}", uname):
        return None, "Invalid username"
    key = uname.lower()
    with db() as c:
        u = c.execute("select id, username, name from users where lower(username)=?", (key,)).fetchone()
        c.execute("insert or replace into bans(uname,uid,name,ts) values(?,?,?,?)",
                  (key, u["id"] if u else None, (u["name"] or u["username"]) if u else uname, int(time.time() * 1000)))
        if u:
            c.execute("delete from sess where uid=?", (u["id"],))
    deleted = 0
    if u:
        with lock:
            sids = [sid for sid, x in users.items() if x["cid"] == str(u["id"])]
            for sid in sids:
                leave_call(sid)
                users.pop(sid, None)
        for sid in sids:
            socketio.emit("banned", {}, to=sid)
        if sids:
            socketio.emit("users", room_users(ROOM), to=ROOM)
        if del_msgs:
            with db() as c:
                mids = [r["mid"] for r in c.execute("select mid from msgs where cid=?", (str(u["id"]),)).fetchall()]
            deleted = _adm_delete_mids(mids)
    return {"ok": True, "deleted": deleted, "existing": bool(u)}, None

@app.get("/admin")
@app.get("/admin/")
def admin_page():
    if not ADMIN_PASS:
        return Response("Admin is not enabled.", 404,
                        mimetype="text/plain", headers={"Cache-Control": "no-store"})
    return Response(ADMIN_HTML.replace("__GN__", html.escape(GROUP_NAME)), mimetype="text/html",
                    headers={"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"})

@app.post("/admin/api/login")
def admin_login():
    if not ADMIN_PASS:
        return _adm_json({"error": "Admin is not enabled"}, 404)
    ip, now = _adm_ip(), time.time()
    f = _adm_fail.get(ip)
    if f and now - f[1] > 600:
        _adm_fail.pop(ip, None)
        f = None
    if f and f[0] >= 5:
        return _adm_json({"error": "Too many attempts. Try again in a few minutes."}, 429)
    p = str((request.get_json(silent=True) or {}).get("password") or "")
    if not secrets.compare_digest(p.encode(), ADMIN_PASS.encode()):
        _adm_fail[ip] = [(f[0] if f else 0) + 1, f[1] if f else now]
        time.sleep(1)
        left = 5 - _adm_fail[ip][0]
        return _adm_json({"error": "Wrong admin password" + (" (%d attempts left)" % left if left > 0 else "")}, 401)
    _adm_fail.pop(ip, None)
    r = _adm_json({"ok": True})
    secure = request.is_secure or request.headers.get("X-Forwarded-Proto", "") == "https"
    r.set_cookie("ffx_adm", _adm_token(int(now) + 8 * 3600), max_age=8 * 3600, path="/admin",
                 httponly=True, samesite="Strict", secure=secure)
    return r

@app.post("/admin/api/logout")
def admin_logout():
    r = _adm_json({"ok": True})
    r.delete_cookie("ffx_adm", path="/admin")
    return r

@app.get("/admin/api/data")
def admin_data():
    if not _adm_ok():
        return _adm_json({"error": "auth"}, 401)
    with db() as c:
        n_msgs = c.execute("select count(*) from msgs where room=?", (ROOM,)).fetchone()[0]
        n_voice = c.execute("select count(*) from msgs where room=? and au is not null and au>0", (ROOM,)).fetchone()[0]
        us = c.execute(
            "select u.id, u.username, u.name, u.ts, u.seen, "
            "(select count(*) from msgs m where m.cid=cast(u.id as text)) n, "
            "exists(select 1 from bans b where b.uname=lower(u.username)) banned "
            "from users u order by coalesce(u.seen,0) desc, u.id desc limit 1000").fetchall()
        bn = c.execute("select b.uname, b.name, b.ts, u.id uid, u.username from bans b "
                       "left join users u on lower(u.username)=b.uname order by b.ts desc").fetchall()
        ms = c.execute("select mid, cid, name, text, ts, au from msgs where room=? order by seq desc limit 150", (ROOM,)).fetchall()
        n_users = c.execute("select count(*) from users").fetchone()[0]
    try:
        size = os.path.getsize(DB)
    except OSError:
        size = 0
    with lock:
        on = {u["cid"] for u in users.values()}
    return _adm_json({
        "group": GROUP_NAME, "now": int(time.time() * 1000), "online": len(on), "users_total": n_users,
        "msgs_total": n_msgs, "voice_total": n_voice, "db_mb": round(size / 1048576, 2), "banned_total": len(bn),
        "users": [{"id": u["id"], "username": u["username"], "name": u["name"] or u["username"], "ts": u["ts"],
                   "seen": u["seen"], "msgs": u["n"], "banned": bool(u["banned"]), "online": str(u["id"]) in on} for u in us],
        "bans": [{"uname": b["username"] or b["uname"], "name": b["name"], "ts": b["ts"], "uid": b["uid"]} for b in bn],
        "msgs": [{"mid": m["mid"], "cid": m["cid"], "name": m["name"], "text": m["text"], "ts": m["ts"], "voice": bool(m["au"])} for m in ms],
    })

@app.post("/admin/api/ban")
def admin_ban():
    if not _adm_ok():
        return _adm_json({"error": "auth"}, 401)
    d = request.get_json(silent=True) or {}
    res, err = _adm_ban(d.get("username"), bool(d.get("delete_msgs")))
    return _adm_json(res, 200) if res else _adm_json({"error": err}, 400)

@app.post("/admin/api/unban")
def admin_unban():
    if not _adm_ok():
        return _adm_json({"error": "auth"}, 401)
    key = re.sub(r"\s+", " ", str((request.get_json(silent=True) or {}).get("username") or "").strip()).lower()
    with db() as c:
        c.execute("delete from bans where uname=?", (key,))
    return _adm_json({"ok": True})

@app.post("/admin/api/delete_msg")
def admin_delete_msg():
    if not _adm_ok():
        return _adm_json({"error": "auth"}, 401)
    mid = str((request.get_json(silent=True) or {}).get("mid") or "")[:64]
    return _adm_json({"ok": True, "deleted": _adm_delete_mids([mid])})

@app.post("/admin/api/clear_msgs")
def admin_clear_msgs():
    if not _adm_ok():
        return _adm_json({"error": "auth"}, 401)
    if (request.get_json(silent=True) or {}).get("confirm") != "DELETE":
        return _adm_json({"error": "Not confirmed"}, 400)
    with db() as c:
        mids = [r["mid"] for r in c.execute("select mid from msgs where room=?", (ROOM,)).fetchall()]
    return _adm_json({"ok": True, "deleted": _adm_delete_mids(mids)})

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#060a13">
<title>Admin · __GN__</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root{--bg:#060a13;--s1:#0d1424;--s2:#172036;--tx:#eef2f8;--mu:#8b98b0;--ac:#2ee6a6;--ac2:#22b8d6;--rd:#ff4d6a;--g:linear-gradient(135deg,#2ee6a6,#22b8d6);--bd:#ffffff1a}
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent}
html,body{min-height:100%;font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--tx)}
button{font:inherit;color:inherit;border:0;background:none;cursor:pointer}
input{font:inherit}
.i{width:20px;height:20px;fill:none;stroke:currentColor;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;flex:none}
::-webkit-scrollbar{width:6px}::-webkit-scrollbar-thumb{background:#ffffff22;border-radius:6px}

#login{position:fixed;inset:0;display:flex;align-items:center;justify-content:center;padding:18px;overflow:hidden;background:var(--bg);z-index:5}
#login::before,#login::after,#login .orb{content:"";position:absolute;border-radius:50%;filter:blur(95px);opacity:.55;animation:float 15s ease-in-out infinite alternate}
#login::before{width:460px;height:460px;background:#2ee6a6;left:-140px;top:-140px}
#login::after{width:460px;height:460px;background:#6d5dfc;right:-160px;bottom:-160px;animation-delay:-7s}
#login .orb{width:300px;height:300px;background:#22b8d6;left:55%;top:8%;opacity:.28;animation-delay:-3s}
@keyframes float{to{transform:translate(80px,60px) scale(1.18)}}
#login .grid{position:absolute;inset:0;background-image:linear-gradient(#ffffff08 1px,transparent 1px),linear-gradient(90deg,#ffffff08 1px,transparent 1px);background-size:44px 44px;-webkit-mask-image:radial-gradient(circle at 50% 50%,#000 0,transparent 70%);mask-image:radial-gradient(circle at 50% 50%,#000 0,transparent 70%)}
.lc{position:relative;z-index:1;width:100%;max-width:400px;padding:38px 28px 26px;border-radius:30px;text-align:center;background:linear-gradient(160deg,#ffffff1f,#ffffff08);border:1px solid #ffffff2b;backdrop-filter:blur(28px) saturate(150%);-webkit-backdrop-filter:blur(28px) saturate(150%);box-shadow:0 40px 90px #000b,inset 0 1px 0 #ffffff36;animation:rise .7s cubic-bezier(.2,.8,.2,1)}
.lc.shake{animation:shake .45s}
@keyframes rise{from{opacity:0;transform:translateY(28px) scale(.96)}}
@keyframes shake{20%,60%{transform:translateX(-9px)}40%,80%{transform:translateX(9px)}}
.shield{position:relative;width:82px;height:82px;margin:0 auto 20px;border-radius:26px;display:flex;align-items:center;justify-content:center;background:var(--g);color:#032a20;box-shadow:0 14px 40px #2ee6a677;animation:bob 3.6s ease-in-out infinite}
.shield::after{content:"";position:absolute;inset:-7px;border-radius:32px;border:1px solid #2ee6a655;animation:ping 2.6s ease-out infinite}
@keyframes bob{50%{transform:translateY(-6px) rotate(-3deg)}}
@keyframes ping{0%{transform:scale(.92);opacity:.9}100%{transform:scale(1.22);opacity:0}}
.shield .i{width:40px;height:40px;stroke-width:2.2}
.lc h1{font-size:30px;font-weight:800;letter-spacing:-.5px;margin-bottom:6px;background:linear-gradient(90deg,#fff,#9ff5dc);-webkit-background-clip:text;background-clip:text;color:transparent}
.lc .sub{color:var(--mu);font-size:14px;line-height:1.5;margin-bottom:24px}
.lc .sub b{color:#cfe9e0;font-weight:600}
.fld{display:flex;align-items:center;gap:10px;background:#050912b3;border:1px solid var(--bd);border-radius:16px;padding:0 8px 0 16px;margin-bottom:10px;color:var(--mu);transition:.2s}
.fld:focus-within{border-color:var(--ac);color:var(--ac);box-shadow:0 0 0 4px #2ee6a622}
.fld input{flex:1;min-width:0;background:none;border:0;outline:0;color:var(--tx);font-size:16px;padding:16px 0}
.fld input::placeholder{color:#6b7891}
.eye{width:38px;height:38px;border-radius:12px;display:flex;align-items:center;justify-content:center;color:var(--mu);transition:.2s}
.eye:hover{background:#ffffff14;color:var(--tx)}
.hint{min-height:20px;font-size:13px;margin:2px 0 8px;text-align:left;padding-left:4px}
.hint.err{color:#ff8a9c}.hint.warn{color:#ffd166}
.btn{position:relative;width:100%;padding:16px;border-radius:16px;background:var(--g);color:#032a20;font-weight:700;font-size:16px;box-shadow:0 12px 30px #2ee6a640;transition:.2s;display:flex;align-items:center;justify-content:center;gap:10px}
.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}.btn:active{transform:scale(.98)}
.btn:disabled{opacity:.7;pointer-events:none}
.spin{width:18px;height:18px;border-radius:50%;border:2.5px solid #032a2055;border-top-color:#032a20;animation:sp .7s linear infinite;display:none}
.btn.load .spin{display:block}
@keyframes sp{to{transform:rotate(360deg)}}
.lf{margin-top:18px;color:#5f6c85;font-size:12px;display:flex;align-items:center;justify-content:center;gap:6px}
.lf .i{width:13px;height:13px}

#dash{display:none;max-width:980px;margin:0 auto;padding:0 14px 90px}
.hdr{position:sticky;top:0;z-index:20;display:flex;align-items:center;gap:12px;padding:12px 4px;margin-bottom:6px;background:#060a13e6;backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-bottom:1px solid #ffffff10}
.hlogo{width:40px;height:40px;border-radius:13px;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;box-shadow:0 6px 18px #2ee6a640}
.htx{flex:1;min-width:0}.htx b{display:block;font-size:16px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.htx small{color:var(--mu);font-size:12px;display:flex;align-items:center;gap:6px}
.live{width:7px;height:7px;border-radius:50%;background:var(--ac);box-shadow:0 0 0 0 #2ee6a680;animation:lv 1.8s infinite}
@keyframes lv{to{box-shadow:0 0 0 8px #2ee6a600}}
.ib{width:40px;height:40px;border-radius:12px;background:#ffffff10;display:flex;align-items:center;justify-content:center;color:#c2ccdc;transition:.18s}
.ib:hover{background:#ffffff1c;color:var(--ac)}.ib.sp .i{animation:sp .7s linear infinite}
.tabs{display:flex;gap:6px;overflow-x:auto;padding:10px 2px 12px;scrollbar-width:none}
.tabs::-webkit-scrollbar{display:none}
.tab{flex:none;display:flex;align-items:center;gap:8px;padding:10px 16px;border-radius:14px;background:#ffffff0d;border:1px solid transparent;color:var(--mu);font-weight:600;font-size:14px;transition:.2s}
.tab:hover{color:var(--tx)}
.tab.on{background:linear-gradient(135deg,#2ee6a626,#22b8d61f);border-color:#2ee6a655;color:var(--ac)}
.tab em{font-style:normal;font-size:11.5px;min-width:20px;padding:2px 7px;border-radius:10px;background:#ffffff18;color:var(--tx)}
.tab.on em{background:var(--g);color:#032a20}
.pane{display:none;animation:rise .35s}.pane.on{display:block}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:14px}
.st{position:relative;overflow:hidden;padding:16px;border-radius:18px;background:linear-gradient(160deg,#ffffff12,#ffffff05);border:1px solid var(--bd)}
.st::after{content:"";position:absolute;right:-24px;top:-24px;width:84px;height:84px;border-radius:50%;background:var(--c,#2ee6a6);opacity:.14;filter:blur(8px)}
.st b{display:block;font-size:28px;font-weight:800;letter-spacing:-.5px}
.st span{color:var(--mu);font-size:12.5px;font-weight:500}
.card{background:linear-gradient(160deg,#ffffff10,#ffffff04);border:1px solid var(--bd);border-radius:20px;padding:16px;margin-bottom:14px}
.card h2{font-size:15px;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:10px}
.card h2 span{flex:1}
.strip{display:flex;gap:14px;overflow-x:auto;padding-bottom:4px}
.chip{flex:none;width:64px;text-align:center;font-size:11.5px;color:var(--mu)}
.chip .av{margin:0 auto 6px}
.chip div:last-child{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.av{position:relative;flex:none;width:46px;height:46px;border-radius:50%;background:var(--g);color:#032a20;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:18px}
.av img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;border-radius:50%}
.av.big{width:56px;height:56px;font-size:22px}
.av .dot{position:absolute;right:0;bottom:0;width:13px;height:13px;border-radius:50%;background:var(--ac);border:2.5px solid #101a2e}
.av.off{filter:grayscale(.9) brightness(.7)}
.tool{display:flex;gap:10px;margin-bottom:12px;flex-wrap:wrap}
.search{flex:1;min-width:180px;display:flex;align-items:center;gap:10px;background:#050912b3;border:1px solid var(--bd);border-radius:14px;padding:0 14px;color:var(--mu)}
.search:focus-within{border-color:var(--ac);color:var(--ac)}
.search input{flex:1;background:none;border:0;outline:0;color:var(--tx);padding:13px 0;font-size:15px;min-width:0}
.seg{display:flex;background:#050912b3;border:1px solid var(--bd);border-radius:14px;padding:3px}
.seg button{padding:9px 14px;border-radius:11px;font-size:13.5px;font-weight:600;color:var(--mu)}
.seg .on{background:var(--g);color:#032a20}
.row{display:flex;align-items:center;gap:12px;padding:11px 6px;border-bottom:1px solid #ffffff0d;animation:rise .3s}
.row:last-child{border:0}
.row .m{flex:1;min-width:0}
.row .nm{display:flex;align-items:center;gap:8px;font-weight:600;font-size:15px}
.row .nm span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.row small{display:block;color:var(--mu);font-size:12.5px;margin-top:2px}
.row p{font-size:14.5px;word-break:break-word;margin-top:3px;line-height:1.4}
.tag{flex:none;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:8px;text-transform:uppercase;letter-spacing:.3px}
.tag.on{background:#2ee6a61f;color:var(--ac)}.tag.bn{background:#ff4d6a26;color:#ff8a9c}
.bt{flex:none;padding:9px 15px;border-radius:12px;font-size:13.5px;font-weight:700;transition:.15s}
.bt:active{transform:scale(.94)}
.bt.red{background:#ff4d6a24;color:#ff8a9c}.bt.red:hover{background:#ff4d6a3d}
.bt.grn{background:#2ee6a61f;color:var(--ac)}.bt.grn:hover{background:#2ee6a633}
.bt.solid{background:var(--rd);color:#fff;box-shadow:0 8px 22px #ff4d6a55}
.empty{color:var(--mu);text-align:center;padding:26px 8px;font-size:14px}
.addban{display:flex;gap:10px;margin-bottom:12px}
.addban .search{flex:1}

#mv{position:fixed;inset:0;z-index:60;display:none;align-items:center;justify-content:center;padding:18px;background:#000000b0;backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
#mv.show{display:flex}
.md{width:100%;max-width:380px;padding:24px 22px 20px;border-radius:26px;text-align:center;background:linear-gradient(180deg,#1a2440,#0d1424);border:1px solid #ffffff22;box-shadow:0 30px 80px #000c;animation:rise .3s cubic-bezier(.2,.9,.3,1.1)}
.md .av{margin:0 auto 12px}
.md .ic{width:60px;height:60px;border-radius:50%;background:#ff4d6a26;color:var(--rd);display:flex;align-items:center;justify-content:center;margin:0 auto 12px}
.md .ic .i{width:26px;height:26px}
.md h3{font-size:19px;font-weight:700;margin-bottom:6px}
.md p{color:var(--mu);font-size:14px;line-height:1.5;margin-bottom:16px}
.ck{display:flex;align-items:center;gap:10px;text-align:left;padding:12px 14px;margin-bottom:14px;border-radius:14px;background:#ffffff0d;font-size:14px;cursor:pointer}
.ck input{width:18px;height:18px;accent-color:var(--rd);flex:none}
.md .fld{padding:0 14px;margin-bottom:14px}.md .fld input{padding:13px 0}
.mb{display:flex;gap:10px}.mb button{flex:1;padding:14px;border-radius:15px;font-weight:700;background:#ffffff14}
#toast{position:fixed;left:50%;bottom:26px;transform:translateX(-50%) translateY(20px);opacity:0;pointer-events:none;background:#0d1424f7;border:1px solid #ffffff26;padding:12px 22px;border-radius:24px;font-size:14px;font-weight:500;z-index:80;box-shadow:0 12px 34px #000b;transition:.3s}
#toast.show{opacity:1;transform:translateX(-50%)}
@media(max-width:520px){.lc{padding:32px 20px 22px}.bt{padding:9px 12px}}

:root{--bg:#000;--s1:#0b0b0b;--s2:#151515;--tx:#f5f5f5;--mu:#8c8c8c;--ac:#fff;--ac2:#cfcfcf;--g:linear-gradient(145deg,#fff,#c9c9c9);--bd:#ffffff24}
html,body{background:#000}
#login{background:#000}
#login::before,#login::after,#login .orb{background:#fff;opacity:.09;filter:blur(110px)}
.lc{background:linear-gradient(160deg,#171717f2,#060606f7);border:1px solid #ffffff26;box-shadow:0 30px 80px #000,inset 0 1px 0 #ffffff1f}
.shield{background:linear-gradient(145deg,#fff,#c9c9c9);color:#000;box-shadow:0 14px 40px #ffffff26}
.shield::after{border-color:#ffffff55}
.lc h1{background:linear-gradient(90deg,#fff,#b5b5b5);-webkit-background-clip:text;background-clip:text;color:transparent}
.lc .sub b{color:#e6e6e6}
.fld{background:linear-gradient(160deg,#0a0a0a,#131313)}
.fld:focus-within{border-color:#ffffffcc;color:#fff;box-shadow:0 0 0 4px #ffffff14}
.btn{background:linear-gradient(145deg,#fff,#cfcfcf);color:#000;box-shadow:0 12px 30px #ffffff26}
.spin{border-color:#00000055;border-top-color:#000}
.hdr{background:#000000e6;border-bottom:1px solid #ffffff14}
.hlogo{background:linear-gradient(145deg,#fff,#c9c9c9);color:#000;box-shadow:0 6px 18px #ffffff26}
.live{background:#fff;animation:lvw 1.8s infinite}
@keyframes lvw{0%{box-shadow:0 0 0 0 #ffffff88}100%{box-shadow:0 0 0 8px #ffffff00}}
.ib{background:#ffffff12;color:#dcdcdc}.ib:hover{background:#fff;color:#000}
.tab.on{background:#ffffff1c;border-color:#ffffff66;color:#fff}
.tab.on em{background:#fff;color:#000}
.st{background:linear-gradient(160deg,#181818,#080808)}
.st::after{background:#fff;opacity:.08}
.card{background:linear-gradient(160deg,#151515,#080808)}
.av{background:linear-gradient(145deg,#fff,#c9c9c9);color:#000}
.av .dot{background:#fff;border-color:#000}
.search,.seg{background:linear-gradient(160deg,#0a0a0a,#131313)}
.search:focus-within{border-color:#ffffffcc;color:#fff}
.seg .on{background:linear-gradient(145deg,#fff,#cfcfcf);color:#000}
.tag.on{background:#ffffff1f;color:#fff}
.bt.grn{background:#ffffff1a;color:#fff}.bt.grn:hover{background:#ffffff30}
.md{background:linear-gradient(180deg,#181818,#070707);border-color:#ffffff26}
#toast{background:#0b0b0bf7}
</style></head><body>
<svg width="0" height="0" style="position:absolute"><defs>
<symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></symbol>
<symbol id="i-lock" viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></symbol>
<symbol id="i-eye" viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></symbol>
<symbol id="i-eyeoff" viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></symbol>
<symbol id="i-refresh" viewBox="0 0 24 24"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></symbol>
<symbol id="i-out" viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></symbol>
<symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></symbol>
<symbol id="i-ban" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></symbol>
<symbol id="i-trash" viewBox="0 0 24 24"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6M14 11v6"/></symbol>
</defs></svg>

<div id="login"><div class="grid"></div><div class="orb"></div>
<div class="lc" id="lc">
<div class="shield"><svg class="i"><use href="#i-shield"/></svg></div>
<h1>Admin Console</h1>
<div class="sub">Restricted area for <b>__GN__</b><br>Enter the admin password to continue</div>
<label class="fld"><svg class="i"><use href="#i-lock"/></svg><input id="pw" type="password" placeholder="Admin password" autocomplete="current-password" autofocus><button type="button" class="eye" id="eye" aria-label="Show password"><svg class="i"><use href="#i-eye"/></svg></button></label>
<div class="hint" id="hint"></div>
<button class="btn" id="go"><span class="spin"></span><span id="gt">Unlock</span></button>
<div class="lf"><svg class="i"><use href="#i-lock"/></svg>Encrypted session · auto-expires in 8 hours</div>
</div></div>

<div id="dash">
<div class="hdr"><div class="hlogo"><svg class="i"><use href="#i-shield"/></svg></div>
<div class="htx"><b id="gn">Admin</b><small><i class="live"></i><span id="lv">Live</span></small></div>
<button class="ib" id="rf" aria-label="Refresh"><svg class="i"><use href="#i-refresh"/></svg></button>
<button class="ib" id="lo" aria-label="Log out"><svg class="i"><use href="#i-out"/></svg></button></div>
<div class="tabs" id="tabs">
<button class="tab on" data-p="ov">Overview</button>
<button class="tab" data-p="us">Users <em id="c-us">0</em></button>
<button class="tab" data-p="bn">Banned <em id="c-bn">0</em></button>
<button class="tab" data-p="ms">Messages <em id="c-ms">0</em></button></div>

<div class="pane on" id="p-ov">
<div class="stats" id="stats"></div>
<div class="card"><h2><span>Online now</span></h2><div class="strip" id="onl"></div></div>
<div class="card"><h2><span>Newest members</span></h2><div class="strip" id="newu"></div></div>
</div>

<div class="pane" id="p-us"><div class="card">
<div class="tool"><label class="search"><svg class="i"><use href="#i-search"/></svg><input id="q" placeholder="Search name or username"></label>
<div class="seg" id="seg"><button data-f="all" class="on">All</button><button data-f="on">Online</button><button data-f="off">Offline</button></div></div>
<div id="users"></div></div></div>

<div class="pane" id="p-bn"><div class="card">
<div class="addban"><label class="search"><svg class="i"><use href="#i-ban"/></svg><input id="bu" placeholder="Ban a username" maxlength="20" autocapitalize="off"></label><button class="bt solid" id="bb">Ban</button></div>
<div id="bans"></div></div></div>

<div class="pane" id="p-ms"><div class="card">
<h2><span>Latest messages</span><button class="bt red" id="clr">Delete all</button></h2>
<div id="msgs"></div></div></div>
</div>

<div id="mv"><div class="md" id="md"></div></div>
<div id="toast"></div>
<script>
const $=id=>document.getElementById(id);
let D=null,filt="all",busy=false,tm=null;
function mk(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!=null)e.textContent=x;return e}
function ico(n){const s=document.createElementNS("http://www.w3.org/2000/svg","svg");s.setAttribute("class","i");const u=document.createElementNS("http://www.w3.org/2000/svg","use");u.setAttribute("href","#i-"+n);s.appendChild(u);return s}
function toast(t){const e=$("toast");e.textContent=t;e.classList.add("show");clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove("show"),2600)}
async function api(p,b){const r=await fetch("/admin/api/"+p,{method:p==="data"?"GET":"POST",headers:{"Content-Type":"application/json"},body:p==="data"?undefined:JSON.stringify(b||{}),credentials:"same-origin",cache:"no-store"});
  const d=await r.json().catch(()=>({}));if(!r.ok){const e=new Error(d.error||"Error");e.code=r.status;throw e}return d}
function avatar(id,name,cls,on){const a=mk("div","av"+(cls?" "+cls:""),(name||"?")[0].toUpperCase());
  if(id){const i=new Image();i.alt="";i.onload=()=>a.appendChild(i);i.src="/avatar/"+id+"?v="+Math.floor(Date.now()/60000)}
  if(on===true){a.appendChild(mk("i","dot"))}return a}
function ago(ts){if(!ts)return"never";const s=Math.max(0,Math.floor(((D?D.now:Date.now())-ts)/1000));
  if(s<60)return"just now";if(s<3600)return Math.floor(s/60)+" min ago";if(s<86400)return Math.floor(s/3600)+" hr ago";
  if(s<2592000)return Math.floor(s/86400)+" days ago";return new Date(ts).toLocaleDateString()}
function dt(ts){return ts?new Date(ts).toLocaleString([],{day:"numeric",month:"short",year:"numeric",hour:"2-digit",minute:"2-digit"}):"unknown"}

function showLogin(){$("dash").style.display="none";$("login").style.display="flex";$("pw").value="";$("pw").focus();clearInterval(tm)}
function hint(t,c){const h=$("hint");h.textContent=t||"";h.className="hint"+(c?" "+c:"")}
$("eye").onclick=()=>{const p=$("pw"),sh=p.type==="password";p.type=sh?"text":"password";$("eye").firstChild.firstChild.setAttribute("href",sh?"#i-eyeoff":"#i-eye");p.focus()};
$("pw").addEventListener("keydown",e=>{if(e.key==="Enter")$("go").click();if(e.getModifierState&&e.getModifierState("CapsLock"))hint("Caps Lock is on","warn");else if($("hint").classList.contains("warn"))hint("")});
$("pw").addEventListener("input",()=>{if($("hint").classList.contains("err"))hint("")});
$("go").onclick=async()=>{const b=$("go");if(!$("pw").value)return hint("Enter the admin password","err");
  hint("");b.classList.add("load");b.disabled=true;$("gt").textContent="Verifying...";
  try{await api("login",{password:$("pw").value});$("gt").textContent="Welcome";await load(true)}
  catch(e){hint(e.message,"err");const c=$("lc");c.classList.remove("shake");void c.offsetWidth;c.classList.add("shake");$("pw").select()}
  b.classList.remove("load");b.disabled=false;$("gt").textContent="Unlock"};
$("lo").onclick=async()=>{try{await api("logout")}catch(e){}showLogin()};

document.querySelectorAll(".tab").forEach(t=>t.onclick=()=>{document.querySelectorAll(".tab").forEach(x=>x.classList.toggle("on",x===t));
  document.querySelectorAll(".pane").forEach(p=>p.classList.toggle("on",p.id==="p-"+t.dataset.p))});
document.querySelectorAll("#seg button").forEach(b=>b.onclick=()=>{filt=b.dataset.f;document.querySelectorAll("#seg button").forEach(x=>x.classList.toggle("on",x===b));drawUsers()});
$("q").oninput=drawUsers;

async function load(first){
  if(busy)return;busy=true;$("rf").classList.add("sp");
  try{D=await api("data")}catch(e){busy=false;$("rf").classList.remove("sp");if(e.code===401){if(!first)toast("Session expired");return showLogin()}return toast(e.message)}
  busy=false;setTimeout(()=>$("rf").classList.remove("sp"),400);
  $("login").style.display="none";$("dash").style.display="block";$("gn").textContent="Admin · "+D.group;
  $("lv").textContent="Live · updated "+new Date().toLocaleTimeString([],{hour:"2-digit",minute:"2-digit",second:"2-digit"});
  $("c-us").textContent=D.users_total;$("c-bn").textContent=D.banned_total;$("c-ms").textContent=D.msgs_total;
  drawOv();drawUsers();drawBans();drawMsgs();
  clearInterval(tm);tm=setInterval(()=>{if(!document.hidden&&!$("mv").classList.contains("show"))load()},20000);
}
$("rf").onclick=()=>load();
function drawOv(){const st=$("stats");st.textContent="";
  [["Online now",D.online,"#2ee6a6"],["Total users",D.users_total,"#22b8d6"],["Banned",D.banned_total,"#ff4d6a"],["Messages",D.msgs_total,"#6d5dfc"],["Voice messages",D.voice_total,"#ffb347"],["Database (MB)",D.db_mb,"#8b98b0"]].forEach(([k,v,c])=>{
    const s=mk("div","st");s.style.setProperty("--c",c);s.appendChild(mk("b",0,v));s.appendChild(mk("span",0,k));st.appendChild(s)});
  const fill=(el,list,empty)=>{el.textContent="";if(!list.length)return el.appendChild(mk("div","empty",empty));
    list.slice(0,20).forEach(u=>{const c=mk("div","chip");c.appendChild(avatar(u.id,u.name,"",u.online));c.appendChild(mk("div",0,u.name));el.appendChild(c)})};
  fill($("onl"),D.users.filter(u=>u.online),"Nobody is online right now");
  fill($("newu"),D.users.filter(u=>u.ts).sort((a,b)=>b.ts-a.ts),"No members yet")}
function drawUsers(){const el=$("users");el.textContent="";const q=$("q").value.trim().toLowerCase();
  const l=D.users.filter(u=>(filt==="all"||(filt==="on")===u.online)&&(!q||u.name.toLowerCase().includes(q)||u.username.toLowerCase().includes(q)));
  if(!l.length)return el.appendChild(mk("div","empty",q||filt!=="all"?"No users match":"No users yet"));
  l.forEach(u=>{const r=mk("div","row");r.appendChild(avatar(u.id,u.name,u.banned?"off":"",u.online&&!u.banned));
    const m=mk("div","m"),n=mk("div","nm");n.appendChild(mk("span",0,u.name));
    if(u.banned)n.appendChild(mk("i","tag bn","Banned"));else if(u.online)n.appendChild(mk("i","tag on","Online"));
    m.appendChild(n);m.appendChild(mk("small",0,"@"+u.username+" · "+u.msgs+" messages"));
    m.appendChild(mk("small",0,"Joined "+dt(u.ts)+" · "+(u.online?"active now":"last seen "+ago(u.seen))));r.appendChild(m);
    const b=mk("button","bt "+(u.banned?"grn":"red"),u.banned?"Unban":"Ban");
    b.onclick=()=>u.banned?doUnban(u.username):askBan(u);r.appendChild(b);el.appendChild(r)})}
function drawBans(){const el=$("bans");el.textContent="";
  if(!D.bans.length)return el.appendChild(mk("div","empty","Ban list is empty"));
  D.bans.forEach(b=>{const r=mk("div","row");r.appendChild(avatar(b.uid,b.name||b.uname,"off"));
    const m=mk("div","m"),n=mk("div","nm");n.appendChild(mk("span",0,b.name||b.uname));n.appendChild(mk("i","tag bn","Banned"));
    m.appendChild(n);m.appendChild(mk("small",0,"@"+b.uname+" · banned "+dt(b.ts)));r.appendChild(m);
    const x=mk("button","bt grn","Unban");x.onclick=()=>doUnban(b.uname);r.appendChild(x);el.appendChild(r)})}
function drawMsgs(){const el=$("msgs");el.textContent="";
  if(!D.msgs.length)return el.appendChild(mk("div","empty","No messages"));
  D.msgs.forEach(x=>{const r=mk("div","row");r.appendChild(avatar(x.cid,x.name));
    const m=mk("div","m");m.appendChild(mk("div","nm",null)).appendChild(mk("span",0,x.name));
    m.appendChild(mk("small",0,dt(x.ts)));m.appendChild(mk("p",0,x.voice?"🎤 Voice message":x.text));r.appendChild(m);
    const b=mk("button","bt red");b.appendChild(ico("trash"));b.setAttribute("aria-label","Delete");
    b.onclick=async()=>{const a=await ask({icon:"trash",title:"Delete this message?",sub:"It will be removed for everyone in the group.",btn:"Delete"});if(!a)return;
      try{await api("delete_msg",{mid:x.mid});toast("Message deleted");load()}catch(e){toast(e.message)}};
    r.appendChild(b);el.appendChild(r)})}

function ask(o){return new Promise(res=>{const md=$("md");md.textContent="";
  if(o.user)md.appendChild(avatar(o.user.id,o.user.name,"big"));else{const i=mk("div","ic");i.appendChild(ico(o.icon||"ban"));md.appendChild(i)}
  md.appendChild(mk("h3",0,o.title));md.appendChild(mk("p",0,o.sub||""));
  let ck=null,ti=null;
  if(o.check){const l=mk("label","ck");ck=document.createElement("input");ck.type="checkbox";l.appendChild(ck);l.appendChild(mk("span",0,o.check));md.appendChild(l)}
  if(o.type){const f=mk("label","fld");ti=document.createElement("input");ti.placeholder='Type '+o.type;ti.autocomplete="off";f.appendChild(ti);md.appendChild(f)}
  const bar=mk("div","mb"),c=mk("button",0,"Cancel"),k=mk("button","bt solid",o.btn||"Confirm");bar.appendChild(c);bar.appendChild(k);md.appendChild(bar);
  const done=v=>{$("mv").classList.remove("show");res(v)};
  c.onclick=()=>done(false);$("mv").onclick=e=>{if(e.target===$("mv"))done(false)};
  k.onclick=()=>{if(ti&&ti.value!==o.type){ti.focus();return toast("Type "+o.type+" to confirm")}done(o.check?{del:ck.checked}:true)};
  $("mv").classList.add("show");if(ti)ti.focus()})}
async function askBan(u){const a=await ask({user:u,title:"Ban "+u.name+"?",sub:"@"+u.username+" will be logged out immediately and can never log in or sign up again until you unban this username.",check:"Also delete all their messages",btn:"Ban user"});
  if(a)doBan(u.username,a.del)}
async function doBan(name,del){try{const d=await api("ban",{username:name,delete_msgs:!!del});toast("@"+name+" banned"+(d.deleted?" · "+d.deleted+" messages deleted":""));load()}catch(e){toast(e.message)}}
async function doUnban(name){try{await api("unban",{username:name});toast("@"+name+" unbanned");load()}catch(e){toast(e.message)}}
$("bb").onclick=async()=>{const v=$("bu").value.trim();if(!v)return;
  const a=await ask({icon:"ban",title:"Ban @"+v+"?",sub:"This username will be blocked from logging in or signing up.",check:"Also delete all their messages",btn:"Ban user"});
  if(a){await doBan(v,a.del);$("bu").value=""}};
$("bu").onkeydown=e=>{if(e.key==="Enter")$("bb").click()};
$("clr").onclick=async()=>{const a=await ask({icon:"trash",title:"Delete ALL messages?",sub:"Every text and voice message will be erased for everyone. This cannot be undone.",type:"DELETE",btn:"Delete all"});
  if(!a)return;try{const d=await api("clear_msgs",{confirm:"DELETE"});toast(d.deleted+" messages deleted");load()}catch(e){toast(e.message)}};
load(true);
</script></body></html>
"""

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)),
                 allow_unsafe_werkzeug=True)
