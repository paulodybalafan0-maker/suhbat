import hashlib
import json
import mimetypes
import os
import re
import secrets
import sqlite3
import time

from fastapi import FastAPI, Header, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "suhbat.db"))

DATABASE_URL = os.environ.get("DATABASE_URL", "")
IS_PG = bool(DATABASE_URL)


class Cur:
    def __init__(self, cur, rid=None):
        self.cur = cur
        self.lastrowid = rid
        self.rowcount = cur.rowcount

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    def __iter__(self):
        return iter(self.cur.fetchall())


class PG:
    """Postgres (Neon) ulanishi: uzilsa avtomatik qayta ulanadi."""

    def __init__(self, url):
        self.url = url
        self.c = None

    def execute(self, sql, args=()):
        import psycopg
        from psycopg.rows import dict_row

        sql = sql.replace("%", "%%").replace("?", "%s")
        low = sql.lstrip().lower()
        ins = low.startswith("insert into users") or low.startswith("insert into msgs")
        if ins:
            sql += " returning id"
        for attempt in (0, 1):
            try:
                if self.c is None or self.c.closed:
                    self.c = psycopg.connect(self.url, autocommit=True, row_factory=dict_row)
                cur = self.c.execute(sql, args)
                rid = cur.fetchone()["id"] if ins else None
                return Cur(cur, rid)
            except (psycopg.OperationalError, psycopg.InterfaceError):
                self.c = None
                if attempt:
                    raise

    def commit(self):
        pass


if IS_PG:
    con = PG(DATABASE_URL)
    for stmt in (
        "create table if not exists users(id serial primary key, name text, salt text, pw text, bio text, bday text, phone text, priv text)",
        "create unique index if not exists users_name_lower on users (lower(name))",
        "create table if not exists tokens(token text primary key, uid integer)",
        "create table if not exists msgs(id serial primary key, room text, uid integer, text text, ts bigint, re_name text, re_text text, file text)",
        "create index if not exists i_room on msgs(room, id)",
        "create table if not exists files(id text primary key, data bytea, name text)",
    ):
        con.execute(stmt)
else:
    con = sqlite3.connect(DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.executescript(
        """
create table if not exists users(
  id integer primary key, name text unique collate nocase, salt text, pw text);
create table if not exists tokens(token text primary key, uid integer);
create table if not exists msgs(
  id integer primary key, room text, uid integer, text text, ts integer,
  re_name text, re_text text);
create index if not exists i_room on msgs(room, id);
"""
    )
    for tbl, col in (("msgs", "file"), ("users", "bio"), ("users", "bday"), ("users", "phone"), ("users", "priv")):
        try:
            con.execute("alter table " + tbl + " add column " + col + " text")
            con.commit()
        except sqlite3.OperationalError:
            pass

UP = os.path.join(BASE, "uploads")
os.makedirs(UP, exist_ok=True)
INLINE_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp3", ".m4a", ".webm", ".ogg", ".wav", ".mp4", ".mov"}

GROUPS = {"g:umumiy": "Umumiy guruh", "g:texno": "Texnologiya", "g:dostlar": "Doʻstlar"}
NAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")

app = FastAPI(title="Suhbat")


class Auth(BaseModel):
    name: str
    password: str


def hash_pw(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()


def new_token(uid: int) -> str:
    t = secrets.token_hex(24)
    con.execute("insert into tokens(token, uid) values(?, ?)", (t, uid))
    con.commit()
    return t


def user_of(token: str):
    if not token:
        return None
    return con.execute(
        "select u.id, u.name from tokens t join users u on u.id = t.uid where t.token = ?",
        (token,),
    ).fetchone()


def need_user(token: str):
    u = user_of(token)
    if not u:
        raise HTTPException(401, "Kirish talab qilinadi")
    return u


def allowed(room: str, name: str) -> bool:
    if room in GROUPS:
        return True
    if room.startswith("d:"):
        return name.lower() in room[2:].split("|")
    return False


def row_to_msg(r) -> dict:
    return {
        "type": "msg", "id": r["id"], "room": r["room"], "name": r["name"],
        "text": r["text"], "ts": r["ts"],
        "file": json.loads(r["file"]) if r["file"] else None,
        "re": {"name": r["re_name"], "text": r["re_text"]} if r["re_name"] else None,
    }


@app.post("/api/register")
async def register(a: Auth):
    name = a.name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(400, "Login 3-20 ta harf, raqam yoki _ boʻlishi kerak")
    if len(a.password) < 6:
        raise HTTPException(400, "Parol kamida 6 belgi boʻlsin")
    if con.execute("select 1 from users where lower(name) = lower(?)", (name,)).fetchone():
        raise HTTPException(400, "Bu login band")
    salt = secrets.token_hex(16)
    cur = con.execute(
        "insert into users(name, salt, pw) values(?, ?, ?)", (name, salt, hash_pw(a.password, salt))
    )
    con.commit()
    return {"token": new_token(cur.lastrowid), "name": name}


@app.post("/api/login")
async def login(a: Auth):
    r = con.execute("select * from users where lower(name) = lower(?)", (a.name.strip(),)).fetchone()
    if not r or not secrets.compare_digest(r["pw"], hash_pw(a.password, r["salt"])):
        raise HTTPException(400, "Login yoki parol notoʻgʻri")
    return {"token": new_token(r["id"]), "name": r["name"]}


@app.get("/api/me")
async def me(x_token: str = Header("")):
    return {"name": need_user(x_token)["name"]}


@app.get("/api/users")
async def users(q: str = "", x_token: str = Header("")):
    u = need_user(x_token)
    q = q.strip().replace("%", "").replace("_", "")
    rows = con.execute(
        "select name from users where lower(name) like lower(?) and id != ? order by name limit 15",
        (q + "%", u["id"]),
    ).fetchall()
    return [r["name"] for r in rows]


@app.get("/api/dms")
async def dms(x_token: str = Header("")):
    u = need_user(x_token)
    me_l = u["name"].lower()
    peers = []
    for r in con.execute("select distinct room from msgs where room like 'd:%'"):
        pair = r["room"][2:].split("|")
        if me_l in pair:
            other = pair[0] if pair[1] == me_l else pair[1]
            row = con.execute("select name from users where lower(name) = lower(?)", (other,)).fetchone()
            if row:
                peers.append(row["name"])
    return peers


@app.get("/api/history")
async def history(room: str, x_token: str = Header("")):
    u = need_user(x_token)
    if not allowed(room, u["name"]):
        raise HTTPException(403, "Ruxsat yoʻq")
    rows = con.execute(
        "select m.*, u.name as name from msgs m join users u on u.id = m.uid "
        "where m.room = ? order by m.id desc limit 100",
        (room,),
    ).fetchall()
    return [row_to_msg(r) for r in reversed(rows)]


clients = {}  # WebSocket -> {"uid": int, "name": str}


async def broadcast(room: str, payload: dict):
    dead = []
    for ws, info in clients.items():
        if allowed(room, info["name"]):
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
    for ws in dead:
        clients.pop(ws, None)


async def push_online():
    names = sorted({i["name"] for i in clients.values()})
    for w in list(clients):
        try:
            await w.send_json({"type": "online", "names": names})
        except Exception:
            clients.pop(w, None)


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query("")):
    u = user_of(token)
    if not u:
        await ws.close(code=4401)
        return
    await ws.accept()
    clients[ws] = {"uid": u["id"], "name": u["name"]}
    await push_online()
    try:
        while True:
            d = await ws.receive_json()
            if d.get("type") == "rtc":
                to = str(d.get("to", "")).lower()
                for w, i in list(clients.items()):
                    if i["name"].lower() == to:
                        await w.send_json({"type": "rtc", "from": u["name"], "data": d.get("data")})
                continue
            room = str(d.get("room", ""))
            if not allowed(room, u["name"]):
                continue
            if d.get("type") == "typing":
                await broadcast(room, {"type": "typing", "room": room, "name": u["name"]})
                continue
            if d.get("type") == "send":
                text = str(d.get("text", "")).strip()[:2000]
                fl = d.get("file")
                fjson = None
                if isinstance(fl, dict) and str(fl.get("url", "")).startswith("/files/"):
                    sz = fl.get("size")
                    fjson = json.dumps({"url": str(fl["url"])[:60], "name": str(fl.get("name", ""))[:80],
                                        "type": str(fl.get("type", ""))[:60], "size": sz if isinstance(sz, int) else 0, "kind": str(fl.get("kind", ""))[:8]})
                if not text and not fjson:
                    continue
                re_ = d.get("re") or {}
                cur = con.execute(
                    "insert into msgs(room, uid, text, ts, re_name, re_text, file) values(?,?,?,?,?,?,?)",
                    (room, u["id"], text, int(time.time() * 1000),
                     str(re_.get("name", ""))[:30] or None, str(re_.get("text", ""))[:100] or None, fjson),
                )
                con.commit()
                r = con.execute(
                    "select m.*, u.name as name from msgs m join users u on u.id = m.uid where m.id = ?",
                    (cur.lastrowid,),
                ).fetchone()
                await broadcast(room, row_to_msg(r))
            elif d.get("type") == "del":
                mid = int(d.get("id", 0))
                cur = con.execute("delete from msgs where id = ? and uid = ?", (mid, u["id"]))
                con.commit()
                if cur.rowcount:
                    await broadcast(room, {"type": "del", "id": mid, "room": room})
    except (WebSocketDisconnect, Exception):
        pass
    finally:
        clients.pop(ws, None)
        await push_online()


class Prof(BaseModel):
    bio: str = ""
    bday: str = ""
    phone: str = ""
    priv: dict = {}


@app.get("/api/profile")
async def get_profile(name: str = "", x_token: str = Header("")):
    me_ = need_user(x_token)
    r = con.execute("select name, bio, bday, phone, priv from users where lower(name) = lower(?)", (name or me_["name"],)).fetchone()
    if not r:
        raise HTTPException(404, "Topilmadi")
    pv = json.loads(r["priv"] or "{}")
    own = r["name"].lower() == me_["name"].lower()
    out = {"name": r["name"], "bio": r["bio"] or "", "own": own}
    if own or not pv.get("hide_phone"):
        out["phone"] = r["phone"] or ""
    if own or not pv.get("hide_bday"):
        out["bday"] = r["bday"] or ""
    if own:
        out["priv"] = pv
    return out


@app.post("/api/profile")
async def set_profile(p: Prof, x_token: str = Header("")):
    u = need_user(x_token)
    pv = {"hide_phone": bool(p.priv.get("hide_phone")), "hide_bday": bool(p.priv.get("hide_bday"))}
    con.execute("update users set bio=?, bday=?, phone=?, priv=? where id=?",
                (p.bio[:200], p.bday[:20], p.phone[:20], json.dumps(pv), u["id"]))
    con.commit()
    return {"ok": True}


@app.post("/api/upload")
async def upload(request: Request, x_token: str = Header(""), x_name: str = Header("file")):
    need_user(x_token)
    data = await request.body()
    if not data or len(data) > 15_000_000:
        raise HTTPException(413, "Fayl 15 MB dan oshmasin")
    from urllib.parse import unquote
    name = unquote(x_name)[:80] or "fayl"
    ext = os.path.splitext(name)[1].lower()
    ext = ext if ext in INLINE_EXT else ".bin"
    fid = secrets.token_hex(16) + ext
    if IS_PG:
        con.execute("insert into files(id, data, name) values(?,?,?)", (fid, data, name))
    else:
        with open(os.path.join(UP, fid), "wb") as f:
            f.write(data)
    ctype = request.headers.get("x-type", "application/octet-stream")[:60]
    return {"url": "/files/" + fid, "name": name, "type": ctype, "size": len(data)}


@app.get("/files/{fid}")
async def get_file(fid: str, request: Request):
    if not re.fullmatch(r"[0-9a-f]{32}(\.[a-z0-9]{2,5})?", fid):
        raise HTTPException(404)
    hdr = {"X-Content-Type-Options": "nosniff", "Accept-Ranges": "bytes"}
    if IS_PG:
        r = con.execute("select data from files where id = ?", (fid,)).fetchone()
        if not r:
            raise HTTPException(404)
        data = bytes(r["data"])
        total = len(data)
        ctype = mimetypes.guess_type(fid)[0] or "application/octet-stream"
        if fid.endswith(".bin"):
            hdr["Content-Disposition"] = 'attachment; filename="fayl"'
        m = re.match(r"bytes=(\d*)-(\d*)", request.headers.get("range", ""))
        if m and (m.group(1) or m.group(2)):
            a = int(m.group(1)) if m.group(1) else max(total - int(m.group(2)), 0)
            b = int(m.group(2)) if m.group(1) and m.group(2) else total - 1
            b = min(b, total - 1)
            hdr["Content-Range"] = "bytes %d-%d/%d" % (a, b, total)
            return Response(data[a:b + 1], status_code=206, headers=hdr, media_type=ctype)
        return Response(data, headers=hdr, media_type=ctype)
    p = os.path.join(UP, fid)
    if not os.path.isfile(p):
        raise HTTPException(404)
    if fid.endswith(".bin"):
        return FileResponse(p, filename="fayl", headers=hdr)
    return FileResponse(p, headers=hdr)


@app.api_route("/health", methods=["GET", "HEAD"])
async def health():
    return {"ok": True}


@app.api_route("/", methods=["GET", "HEAD"])
async def index():
    return FileResponse(os.path.join(BASE, "index.html"))
