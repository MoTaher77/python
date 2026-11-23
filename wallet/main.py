import hashlib
import hmac
import os
import re
import secrets
from decimal import Decimal, InvalidOperation
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import db

app = FastAPI(title="Wallet", description="محفظة إلكترونية على غرار جيب")
STATIC = Path(__file__).parent / "static"

PHONE_RE = re.compile(r"^\d{9,15}$")
SCALE = 100  # balances are stored as integer hundredths
MAX_AMOUNT = 10_000_000

BILL_PROVIDERS = {"electricity": "الكهرباء", "water": "المياه", "internet": "الإنترنت"}
TOPUP_PROVIDERS = {"yemenmobile": "يمن موبايل", "sabafon": "سبأفون", "you": "واي", "y": "يو"}


@app.on_event("startup")
def _startup():
    db.init_db()


# ---------- helpers ----------
def hash_pin(pin: str, salt: bytes) -> str:
    return hashlib.scrypt(pin.encode(), salt=salt, n=2**14, r=8, p=1).hex()


def to_minor(amount: float | str) -> int:
    try:
        d = Decimal(str(amount))
    except InvalidOperation:
        raise HTTPException(400, "مبلغ غير صالح")
    if d <= 0 or d > MAX_AMOUNT or d != d.quantize(Decimal("0.01")):
        raise HTTPException(400, "مبلغ غير صالح (أكبر من صفر وبحد أقصى خانتين عشريتين)")
    return int(d * SCALE)


def fmt(minor: int) -> float:
    return minor / SCALE


def current_user(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(401, "غير مصرح")
    with db.connect() as conn:
        row = conn.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?",
            (token,),
        ).fetchone()
    if not row:
        raise HTTPException(401, "الجلسة منتهية")
    return dict(row)


def check_pin(user: dict, pin: str):
    if not hmac.compare_digest(hash_pin(pin, bytes.fromhex(user["pin_salt"])), user["pin_hash"]):
        raise HTTPException(403, "الرمز السري غير صحيح")


def record(conn, user_id, kind, amount, balance_after, counterparty=None, note=None):
    conn.execute(
        "INSERT INTO transactions (user_id, kind, amount, counterparty, note, balance_after) "
        "VALUES (?,?,?,?,?,?)",
        (user_id, kind, amount, counterparty, note, balance_after),
    )


def debit(conn, user_id: int, amount: int) -> int:
    row = conn.execute("SELECT balance FROM users WHERE id=?", (user_id,)).fetchone()
    if row["balance"] < amount:
        raise HTTPException(400, "الرصيد غير كافٍ")
    new = row["balance"] - amount
    conn.execute("UPDATE users SET balance=? WHERE id=?", (new, user_id))
    return new


def credit(conn, user_id: int, amount: int) -> int:
    row = conn.execute("SELECT balance FROM users WHERE id=?", (user_id,)).fetchone()
    new = row["balance"] + amount
    conn.execute("UPDATE users SET balance=? WHERE id=?", (new, user_id))
    return new


# ---------- models ----------
class Register(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    phone: str
    pin: str = Field(pattern=r"^\d{4}$")


class Login(BaseModel):
    phone: str
    pin: str


class Amount(BaseModel):
    amount: float


class PinAmount(BaseModel):
    amount: float
    pin: str


class Transfer(PinAmount):
    to_phone: str
    note: str | None = Field(default=None, max_length=100)


class Bill(PinAmount):
    provider: str
    reference: str = Field(min_length=3, max_length=30)


class Topup(PinAmount):
    provider: str
    phone: str


# ---------- auth ----------
@app.post("/api/register", status_code=201)
def register(body: Register):
    if not PHONE_RE.match(body.phone):
        raise HTTPException(400, "رقم الهاتف غير صالح")
    salt = os.urandom(16)
    with db.tx() as conn:
        if conn.execute("SELECT 1 FROM users WHERE phone=?", (body.phone,)).fetchone():
            raise HTTPException(409, "الرقم مسجل مسبقاً")
        conn.execute(
            "INSERT INTO users (phone, name, pin_hash, pin_salt) VALUES (?,?,?,?)",
            (body.phone, body.name.strip(), hash_pin(body.pin, salt), salt.hex()),
        )
    return {"ok": True}


@app.post("/api/login")
def login(body: Login):
    with db.tx() as conn:
        user = conn.execute("SELECT * FROM users WHERE phone=?", (body.phone,)).fetchone()
        if not user:
            raise HTTPException(401, "رقم الهاتف أو الرمز غير صحيح")
        if not hmac.compare_digest(
            hash_pin(body.pin, bytes.fromhex(user["pin_salt"])), user["pin_hash"]
        ):
            raise HTTPException(401, "رقم الهاتف أو الرمز غير صحيح")
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO sessions (token, user_id) VALUES (?,?)", (token, user["id"]))
    return {"token": token}


@app.post("/api/logout")
def logout(authorization: str = Header(default=""), user=Depends(current_user)):
    with db.tx() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (authorization.removeprefix("Bearer ").strip(),))
    return {"ok": True}


@app.get("/api/me")
def me(user=Depends(current_user)):
    return {"name": user["name"], "phone": user["phone"], "balance": fmt(user["balance"])}


# ---------- money ----------
@app.post("/api/deposit")
def deposit(body: Amount, user=Depends(current_user)):
    amt = to_minor(body.amount)
    with db.tx() as conn:
        bal = credit(conn, user["id"], amt)
        record(conn, user["id"], "deposit", amt, bal, note="إيداع")
    return {"balance": fmt(bal)}


@app.post("/api/withdraw")
def withdraw(body: PinAmount, user=Depends(current_user)):
    check_pin(user, body.pin)
    amt = to_minor(body.amount)
    with db.tx() as conn:
        bal = debit(conn, user["id"], amt)
        record(conn, user["id"], "withdraw", amt, bal, note="سحب")
    return {"balance": fmt(bal)}


@app.post("/api/transfer")
def transfer(body: Transfer, user=Depends(current_user)):
    check_pin(user, body.pin)
    amt = to_minor(body.amount)
    if body.to_phone == user["phone"]:
        raise HTTPException(400, "لا يمكن التحويل لنفسك")
    with db.tx() as conn:
        target = conn.execute("SELECT id, name FROM users WHERE phone=?", (body.to_phone,)).fetchone()
        if not target:
            raise HTTPException(404, "المستلم غير موجود")
        bal = debit(conn, user["id"], amt)
        tbal = credit(conn, target["id"], amt)
        record(conn, user["id"], "transfer_out", amt, bal, body.to_phone, body.note)
        record(conn, target["id"], "transfer_in", amt, tbal, user["phone"], body.note)
    return {"balance": fmt(bal), "to": target["name"]}


@app.post("/api/bills")
def pay_bill(body: Bill, user=Depends(current_user)):
    if body.provider not in BILL_PROVIDERS:
        raise HTTPException(400, "مزود غير معروف")
    check_pin(user, body.pin)
    amt = to_minor(body.amount)
    with db.tx() as conn:
        bal = debit(conn, user["id"], amt)
        record(conn, user["id"], "bill", amt, bal, body.reference, BILL_PROVIDERS[body.provider])
    return {"balance": fmt(bal)}


@app.post("/api/topup")
def topup(body: Topup, user=Depends(current_user)):
    if body.provider not in TOPUP_PROVIDERS:
        raise HTTPException(400, "مزود غير معروف")
    if not PHONE_RE.match(body.phone):
        raise HTTPException(400, "رقم الهاتف غير صالح")
    check_pin(user, body.pin)
    amt = to_minor(body.amount)
    with db.tx() as conn:
        bal = debit(conn, user["id"], amt)
        record(conn, user["id"], "topup", amt, bal, body.phone, TOPUP_PROVIDERS[body.provider])
    return {"balance": fmt(bal)}


@app.get("/api/providers")
def providers():
    return {"bills": BILL_PROVIDERS, "topup": TOPUP_PROVIDERS}


@app.get("/api/transactions")
def transactions(limit: int = 50, user=Depends(current_user)):
    limit = max(1, min(limit, 200))
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, kind, amount, counterparty, note, balance_after, created_at "
            "FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT ?",
            (user["id"], limit),
        ).fetchall()
    return [
        {**dict(r), "amount": fmt(r["amount"]), "balance_after": fmt(r["balance_after"])}
        for r in rows
    ]


# ---------- frontend ----------
@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


app.mount("/static", StaticFiles(directory=STATIC), name="static")
