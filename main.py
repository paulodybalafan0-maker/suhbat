import hashlib
import os
import re
import secrets
import sqlite3
import time

from fastapi import FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "suhbat.db"))

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
        "re": {"name": r["re_name"], "text": r["re_text"]} if r["re_name"] else None,
    }


@app.post("/api/register")
async def register(a: Auth):
    name = a.name.strip()
    if not NAME_RE.match(name):
        raise HTTPException(400, "Login 3-20 ta harf, raqam yoki _ boʻlishi kerak")
    if len(a.password) < 6:
        raise HTTPException(400, "Parol kamida 6 belgi boʻlsin")
    if con.execute("select 1 from users where name = ?", (name,)).fetchone():
        raise HTTPException(400, "Bu login band")
    salt = secrets.token_hex(16)
    cur = con.execute(
        "insert into users(name, salt, pw) values(?, ?, ?)", (name, salt, hash_pw(a.password, salt))
    )
    con.commit()
    return {"token": new_token(cur.lastrowid), "name": name}


@app.post("/api/login")
async def login(a: Auth):
    r = con.execute("select * from users where name = ?", (a.name.strip(),)).fetchone()
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
        "select name from users where name like ? and id != ? order by name limit 15",
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
            row = con.execute("select name from users where name = ?", (other,)).fetchone()
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


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket, token: str = Query("")):
    u = user_of(token)
    if not u:
        await ws.close(code=4401)
        return
    await ws.accept()
    clients[ws] = {"uid": u["id"], "name": u["name"]}
    try:
        while True:
            d = await ws.receive_json()
            room = str(d.get("room", ""))
            if not allowed(room, u["name"]):
                continue
            if d.get("type") == "send":
                text = str(d.get("text", "")).strip()[:2000]
                if not text:
                    continue
                re_ = d.get("re") or {}
                cur = con.execute(
                    "insert into msgs(room, uid, text, ts, re_name, re_text) values(?,?,?,?,?,?)",
                    (room, u["id"], text, int(time.time() * 1000),
                     str(re_.get("name", ""))[:30] or None, str(re_.get("text", ""))[:100] or None),
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


@app.get("/")
async def index():
    return FileResponse(os.path.join(BASE, "index.html"))
