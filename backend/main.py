from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import shutil
import sqlite3
import threading
import time
import json
import mimetypes
import re
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Literal

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
DATA_DIR = Path(os.getenv("JAABE_DATA_DIR", str(BASE_DIR))).resolve()
DB_PATH = Path(os.getenv("JAABE_DB_PATH", str(DATA_DIR / "shop.db"))).resolve()
UPLOAD_DIR = Path(os.getenv("JAABE_UPLOAD_DIR", str(DATA_DIR / "uploads"))).resolve()
FRONTEND_DIR = Path(os.getenv("JAABE_FRONTEND_DIR", str(PROJECT_DIR / "frontend" / "dist"))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
CUSTOMER_LOGO_RETENTION_DAYS = 10
CUSTOMER_LOGO_CLEANUP_INTERVAL = 6 * 60 * 60

DEFAULT_SITE_SETTINGS = {
    "production_name": "حک نگار",
    "manager_name": "آقای رضازاده",
    "phone": "09399506609",
    "address": "بهبهان، سه‌راهی گود چَهَک، کوچه درویش‌ها، تولیدی حک نگار",
    "about": "تولیدی حک نگار، تولیدکننده جعبه‌های جواهرات و ارائه‌دهنده خدمات حکاکی اختصاصی برای طلافروشی‌هاست.",
    "services": "تولید مستقیم و فروش عمده\nحکاکی نام و نشان فروشگاه\nتنوع جعبه‌های انگشتر، مدال و گوشواره\nهماهنگی سفارش پیش از تولید و ارسال",
    "working_hours": "شنبه تا پنج‌شنبه، ۹ تا ۱۹",
    "sales_type": "فروش عمده، ویژه طلافروشی‌ها",
    "footer_note": "قیمت و موجودی محصولات از طریق مدیریت مجموعه به‌روز می‌شود.",
}
OWNER_MOBILE = "09399506609"

app = FastAPI(title="Hakkar Jewelry Boxes API", version="1.0.0")
allowed_origins = ["http://localhost:5173", "http://127.0.0.1:5173"]
allowed_origins.extend(
    origin.strip().rstrip("/")
    for origin in os.getenv("JAABE_ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return f"{salt.hex()}:{digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest = stored.split(":", 1)
    return hmac.compare_digest(password_hash(password, bytes.fromhex(salt_hex)), stored)


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS categories (
              id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, sort_order INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS products (
              id INTEGER PRIMARY KEY AUTOINCREMENT, category_id INTEGER NOT NULL REFERENCES categories(id),
              name TEXT NOT NULL, dimensions TEXT NOT NULL, unit_price INTEGER NOT NULL CHECK(unit_price >= 0),
              units_per_pack INTEGER NOT NULL CHECK(units_per_pack > 0), stock_packs INTEGER NOT NULL CHECK(stock_packs >= 0),
              description TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS product_images (
              id INTEGER PRIMARY KEY AUTOINCREMENT, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
              url TEXT NOT NULL, sort_order INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS orders (
              id INTEGER PRIMARY KEY AUTOINCREMENT, order_number TEXT NOT NULL UNIQUE, mobile TEXT NOT NULL,
              shop_name TEXT NOT NULL, address TEXT NOT NULL, city TEXT NOT NULL, shop_phone TEXT NOT NULL,
              instagram TEXT NOT NULL DEFAULT '', logo_url TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
              logo_expires_at TEXT NOT NULL DEFAULT '', logo_downloaded_at TEXT NOT NULL DEFAULT '',
              logo_deleted_at TEXT NOT NULL DEFAULT '', logo_delete_reason TEXT NOT NULL DEFAULT '',
              payment_method TEXT NOT NULL, payment_status TEXT NOT NULL, status TEXT NOT NULL,
              total_price INTEGER NOT NULL, estimated_ready_date TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS order_items (
              id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
              product_id INTEGER NOT NULL, product_name TEXT NOT NULL, packs INTEGER NOT NULL,
              units_per_pack INTEGER NOT NULL, unit_price INTEGER NOT NULL, line_total INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS customer_uploads (
              url TEXT PRIMARY KEY, created_at TEXT NOT NULL, order_id INTEGER REFERENCES orders(id) ON DELETE SET NULL,
              linked_at TEXT NOT NULL DEFAULT '', deleted_at TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS admins (
              id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_sessions (
              token TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_users (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mobile TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
              active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, created_by TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS admin_mobile_sessions (
              token TEXT PRIMARY KEY, admin_user_id INTEGER NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
              created_at TEXT NOT NULL, expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS admin_otp_codes (
              id INTEGER PRIMARY KEY AUTOINCREMENT, mobile TEXT NOT NULL, code_hash TEXT NOT NULL,
              expires_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, consumed INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sms_settings (
              id INTEGER PRIMARY KEY CHECK(id=1), api_key TEXT NOT NULL DEFAULT '', template_id INTEGER NOT NULL DEFAULT 0,
              parameter_name TEXT NOT NULL DEFAULT 'Code', enabled INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS visitor_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT, request_number TEXT NOT NULL UNIQUE, shop_name TEXT NOT NULL,
              mobile TEXT NOT NULL, address TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'site', bale_chat_id TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'new', created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS site_settings (
              key TEXT PRIMARY KEY, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bale_settings (
              id INTEGER PRIMARY KEY CHECK(id=1), bot_token TEXT NOT NULL DEFAULT '', site_url TEXT NOT NULL DEFAULT '',
              enabled INTEGER NOT NULL DEFAULT 0, webhook_secret TEXT NOT NULL, bot_username TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS payment_settings (
              id INTEGER PRIMARY KEY CHECK(id=1), merchant_id TEXT NOT NULL DEFAULT '',
              site_url TEXT NOT NULL DEFAULT 'https://jaabehaknegar.ir', enabled INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bale_sessions (
              chat_id TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT '', data_json TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bale_carts (
              chat_id TEXT NOT NULL, product_id INTEGER NOT NULL, packs INTEGER NOT NULL DEFAULT 0,
              updated_at TEXT NOT NULL, PRIMARY KEY(chat_id,product_id)
            );            """
        )
        category_columns = {row["name"] for row in conn.execute("PRAGMA table_info(categories)")}
        if "active" not in category_columns:
            conn.execute("ALTER TABLE categories ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
        order_columns = {row["name"] for row in conn.execute("PRAGMA table_info(orders)")}
        if "estimated_ready_date" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN estimated_ready_date TEXT NOT NULL DEFAULT ''")
        if "bale_chat_id" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN bale_chat_id TEXT NOT NULL DEFAULT ''")
        if "logo_expires_at" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN logo_expires_at TEXT NOT NULL DEFAULT ''")
        if "logo_downloaded_at" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN logo_downloaded_at TEXT NOT NULL DEFAULT ''")
        if "logo_deleted_at" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN logo_deleted_at TEXT NOT NULL DEFAULT ''")
        if "logo_delete_reason" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN logo_delete_reason TEXT NOT NULL DEFAULT ''")
        if "payment_authority" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN payment_authority TEXT NOT NULL DEFAULT ''")
        if "payment_ref_id" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN payment_ref_id TEXT NOT NULL DEFAULT ''")
        if "payment_amount" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN payment_amount INTEGER NOT NULL DEFAULT 0")
        if "payment_verified_at" not in order_columns:
            conn.execute("ALTER TABLE orders ADD COLUMN payment_verified_at TEXT NOT NULL DEFAULT ''")
        conn.execute("""UPDATE orders SET logo_expires_at=strftime('%Y-%m-%dT%H:%M:%f+00:00',created_at,'+10 days')
          WHERE logo_url<>'' AND logo_expires_at=''""")
        conn.execute("INSERT OR IGNORE INTO bale_settings(id,webhook_secret,updated_at) VALUES (1,?,?)", (secrets.token_urlsafe(24), datetime.now(timezone.utc).isoformat()))
        bale_columns = {row["name"] for row in conn.execute("PRAGMA table_info(bale_settings)")}
        if "last_update_id" not in bale_columns:
            conn.execute("ALTER TABLE bale_settings ADD COLUMN last_update_id INTEGER NOT NULL DEFAULT 0")
        if "payment_token" not in bale_columns:
            conn.execute("ALTER TABLE bale_settings ADD COLUMN payment_token TEXT NOT NULL DEFAULT ''")
        if "admin_mobile" not in bale_columns:
            conn.execute("ALTER TABLE bale_settings ADD COLUMN admin_mobile TEXT NOT NULL DEFAULT '09399506609'")
        if "admin_chat_id" not in bale_columns:
            conn.execute("ALTER TABLE bale_settings ADD COLUMN admin_chat_id TEXT NOT NULL DEFAULT ''")
        if "manager_link_code" not in bale_columns:
            conn.execute("ALTER TABLE bale_settings ADD COLUMN manager_link_code TEXT NOT NULL DEFAULT ''")
        conn.execute("UPDATE bale_settings SET admin_mobile=COALESCE(NULLIF(admin_mobile,''),'09399506609'), manager_link_code=COALESCE(NULLIF(manager_link_code,''),?) WHERE id=1", (str(secrets.randbelow(900000)+100000),))
        session_columns = {row["name"] for row in conn.execute("PRAGMA table_info(bale_sessions)")}
        if "data_json" not in session_columns:
            conn.execute("ALTER TABLE bale_sessions ADD COLUMN data_json TEXT NOT NULL DEFAULT '{}'")
        for key, value in DEFAULT_SITE_SETTINGS.items():
            conn.execute("INSERT OR IGNORE INTO site_settings(key,value) VALUES (?,?)", (key, value))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute("INSERT OR IGNORE INTO admin_users(mobile,role,active,created_at,created_by) VALUES (?,?,?,?,?)", (OWNER_MOBILE, "owner", 1, now, "system"))
        conn.execute("INSERT OR IGNORE INTO sms_settings(id,updated_at) VALUES (1,?)", (now,))
        conn.execute("INSERT OR IGNORE INTO payment_settings(id,updated_at) VALUES (1,?)", (now,))
        conn.execute("UPDATE payment_settings SET site_url='https://jaabehaknegar.ir' WHERE site_url='https://jaabehakenegar.ir'")
        sms_columns = {row["name"] for row in conn.execute("PRAGMA table_info(sms_settings)")}
        if "verified" not in sms_columns:
            conn.execute("ALTER TABLE sms_settings ADD COLUMN verified INTEGER NOT NULL DEFAULT 0")
        if "line_number" not in sms_columns:
            conn.execute("ALTER TABLE sms_settings ADD COLUMN line_number TEXT NOT NULL DEFAULT ''")
        if not conn.execute("SELECT 1 FROM admins").fetchone():
            conn.execute("INSERT INTO admins(username,password_hash) VALUES (?,?)", ("admin", password_hash("admin123")))
        if not conn.execute("SELECT 1 FROM categories").fetchone():
            seed = {
                "جعبه انگشتری": [
                    ("جعبه انگشتر گرد", "۶ در ۶", 40000, 24, 18),
                    ("جعبه انگشتر مربع مخملی", "۵ در ۵", 38000, 24, 25),
                    ("جعبه انگشتر چرمی لوکس", "۶ در ۶", 45000, 24, 12),
                ],
                "جعبه مدالی": [
                    ("جعبه مدالی مخملی", "۸ در ۸", 50000, 20, 10),
                    ("جعبه مدالی کلاسیک", "۷ در ۷", 48000, 24, 17),
                    ("جعبه مدالی چرمی", "۹ در ۷", 55000, 20, 8),
                ],
                "جعبه گوشواره": [
                    ("جعبه گوشواره صدفی", "۷ در ۷", 42000, 24, 20),
                    ("جعبه گوشواره مخمل سبز", "۷ در ۷", 46000, 24, 14),
                    ("جعبه گوشواره زرشکی", "۷ در ۷", 46000, 24, 11),
                ],
            }
            for order, (category, products) in enumerate(seed.items()):
                cid = conn.execute("INSERT INTO categories(name,sort_order) VALUES (?,?)", (category, order)).lastrowid
                for product in products:
                    pid = conn.execute(
                        "INSERT INTO products(category_id,name,dimensions,unit_price,units_per_pack,stock_packs,created_at) VALUES (?,?,?,?,?,?,?)",
                        (cid, *product, datetime.now(timezone.utc).isoformat()),
                    ).lastrowid
                    conn.execute("INSERT INTO product_images(product_id,url,sort_order) VALUES (?,?,0)", (pid, "/jewelry-box.png"))


def customer_logo_file_path(url: str) -> Path | None:
    if not url or not url.startswith("/uploads/"):
        return None
    filename = Path(url).name
    if not filename or filename in {".", ".."}:
        return None
    candidate = (UPLOAD_DIR / filename).resolve()
    if candidate.parent != UPLOAD_DIR.resolve():
        return None
    return candidate


def delete_customer_logo(conn: sqlite3.Connection, order, reason: str) -> str:
    deleted_at = datetime.now(timezone.utc).isoformat()
    logo_url = order["logo_url"] or ""
    if logo_url:
        used_by_product = conn.execute("SELECT 1 FROM product_images WHERE url=? LIMIT 1", (logo_url,)).fetchone()
        used_by_order = conn.execute("SELECT 1 FROM orders WHERE logo_url=? AND id<>? LIMIT 1", (logo_url, order["id"])).fetchone()
        if not used_by_product and not used_by_order:
            file_path = customer_logo_file_path(logo_url)
            if file_path:
                file_path.unlink(missing_ok=True)
    conn.execute(
        "UPDATE orders SET logo_url='',logo_deleted_at=?,logo_delete_reason=? WHERE id=?",
        (deleted_at, reason, order["id"]),
    )
    if logo_url:
        conn.execute("UPDATE customer_uploads SET deleted_at=? WHERE url=?", (deleted_at, logo_url))
    return deleted_at


def cleanup_expired_customer_logos() -> int:
    now = datetime.now(timezone.utc).isoformat()
    removed = 0
    with db() as conn:
        expired = list(conn.execute(
            "SELECT * FROM orders WHERE logo_url<>'' AND logo_expires_at<>'' AND logo_expires_at<=?",
            (now,),
        ))
        for order in expired:
            delete_customer_logo(conn, order, "expired")
            removed += 1
    return removed


def cleanup_abandoned_customer_uploads() -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(days=CUSTOMER_LOGO_RETENTION_DAYS)).isoformat()
    removed = 0
    with db() as conn:
        abandoned = list(conn.execute(
            "SELECT * FROM customer_uploads WHERE order_id IS NULL AND deleted_at='' AND created_at<=?",
            (cutoff,),
        ))
        for upload in abandoned:
            url = upload["url"]
            used_by_product = conn.execute("SELECT 1 FROM product_images WHERE url=? LIMIT 1", (url,)).fetchone()
            used_by_order = conn.execute("SELECT 1 FROM orders WHERE logo_url=? LIMIT 1", (url,)).fetchone()
            if not used_by_product and not used_by_order:
                file_path = customer_logo_file_path(url)
                if file_path:
                    file_path.unlink(missing_ok=True)
                conn.execute("DELETE FROM customer_uploads WHERE url=?", (url,))
                removed += 1
    return removed


def customer_logo_cleanup_loop():
    while True:
        try:
            cleanup_expired_customer_logos()
            cleanup_abandoned_customer_uploads()
        except Exception:
            pass
        time.sleep(CUSTOMER_LOGO_CLEANUP_INTERVAL)


_customer_logo_cleanup_thread = None

init_db()


class LoginInput(BaseModel):
    username: str
    password: str


class MobileLoginInput(BaseModel):
    mobile: str = Field(min_length=10, max_length=20)


class OtpVerifyInput(BaseModel):
    mobile: str = Field(min_length=10, max_length=20)
    code: str = Field(min_length=4, max_length=8)


class AdminUserInput(BaseModel):
    mobile: str = Field(min_length=10, max_length=20)


class SmsSettingsInput(BaseModel):
    api_key: str = Field(default="", max_length=500)
    enabled: bool = False


class VisitorRequestInput(BaseModel):
    shop_name: str = Field(min_length=2, max_length=120)
    mobile: str = Field(min_length=10, max_length=20)
    address: str = Field(min_length=5, max_length=500)
    source: Literal["site", "bale"] = "site"
    bale_chat_id: str = Field(default="", max_length=80)

class SiteSettingsInput(BaseModel):
    production_name: str = Field(min_length=2, max_length=120)
    manager_name: str = Field(min_length=2, max_length=120)
    phone: str = Field(min_length=5, max_length=30)
    address: str = Field(min_length=5, max_length=500)
    about: str = Field(min_length=5, max_length=1000)
    services: str = Field(min_length=2, max_length=1500)
    working_hours: str = Field(min_length=2, max_length=200)
    sales_type: str = Field(min_length=2, max_length=200)
    footer_note: str = Field(min_length=2, max_length=500)

class BaleSettingsInput(BaseModel):
    bot_token: str = Field(default="", max_length=300)
    payment_token: str = Field(default="", max_length=300)
    admin_mobile: str = Field(default="09399506609", pattern=r"^09\d{9}$")
    site_url: str = Field(default="", max_length=500)
    enabled: bool = False


class PaymentSettingsInput(BaseModel):
    merchant_id: str = Field(default="", max_length=100)
    site_url: str = Field(default="https://jaabehaknegar.ir", max_length=500)
    enabled: bool = False


class CategoryInput(BaseModel):
    name: str = Field(min_length=2, max_length=80)


class ProductInput(BaseModel):
    category_id: int
    name: str = Field(min_length=2, max_length=120)
    dimensions: str = Field(min_length=1, max_length=80)
    unit_price: int = Field(ge=0)
    units_per_pack: int = Field(gt=0)
    stock_packs: int = Field(ge=0)
    description: str = ""
    active: bool = True
    images: list[str] = []


class OrderItemInput(BaseModel):
    product_id: int
    packs: int = Field(gt=0)


class OrderInput(BaseModel):
    mobile: str = Field(pattern=r"^09\d{9}$")
    shop_name: str = Field(min_length=2, max_length=120)
    address: str = Field(min_length=5, max_length=500)
    city: str = Field(min_length=2, max_length=80)
    shop_phone: str = Field(min_length=5, max_length=200)
    instagram: str = ""
    logo_url: str = ""
    notes: str = ""
    bale_chat_id: str = Field(default="", max_length=80)
    payment_method: Literal["online", "cod", "deposit"]
    items: list[OrderItemInput] = Field(min_length=1)


def normalize_mobile(value: str) -> str:
    translated = value.strip().translate(str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789"))
    translated = re.sub(r"[^0-9+]", "", translated)
    if translated.startswith("+98"):
        translated = "0" + translated[3:]
    elif translated.startswith("98") and len(translated) == 12:
        translated = "0" + translated[2:]
    if not re.fullmatch(r"09\d{9}", translated):
        raise HTTPException(400, "شماره موبایل معتبر نیست")
    return translated


ZARINPAL_REQUEST_URL = "https://api.zarinpal.com/pg/v4/payment/request.json"
ZARINPAL_VERIFY_URL = "https://api.zarinpal.com/pg/v4/payment/verify.json"
ZARINPAL_GATEWAY_URL = "https://www.zarinpal.com/pg/StartPay/"


def get_payment_settings() -> dict:
    with db() as conn:
        row = conn.execute("SELECT * FROM payment_settings WHERE id=1").fetchone()
    return dict(row) if row else {"merchant_id": "", "site_url": "https://jaabehaknegar.ir", "enabled": 0}


def zarinpal_post(url: str, payload: dict) -> dict:
    request_data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=request_data, headers={"Content-Type": "application/json", "Accept": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            result = json.loads(exc.read().decode("utf-8"))
            errors = result.get("errors") or {}
            message = errors.get("message") if isinstance(errors, dict) else ""
        except Exception:
            message = ""
        raise HTTPException(502, message or "زرین‌پال درخواست را نپذیرفت؛ تنظیمات درگاه را بررسی کنید") from exc
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise HTTPException(502, "ارتباط با زرین‌پال برقرار نشد؛ چند دقیقه دیگر دوباره تلاش کنید") from exc
    return result


def request_zarinpal_payment(merchant_id: str, amount_toman: int, callback_url: str, description: str, mobile: str) -> tuple[str, str]:
    result = zarinpal_post(ZARINPAL_REQUEST_URL, {
        "merchant_id": merchant_id,
        "amount": int(amount_toman) * 10,
        "callback_url": callback_url,
        "description": description,
        "metadata": {"mobile": mobile},
    })
    data = result.get("data") or {}
    if data.get("code") != 100 or not data.get("authority"):
        raise HTTPException(502, data.get("message") or "ایجاد تراکنش زرین‌پال ناموفق بود")
    authority = str(data["authority"])
    return authority, ZARINPAL_GATEWAY_URL + urllib.parse.quote(authority)

def require_admin(authorization: str = Header(default="")):
    token = authorization.removeprefix("Bearer ")
    if not token:
        raise HTTPException(401, "ورود مدیر لازم است")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        identity = conn.execute("""SELECT u.id,u.mobile,u.role FROM admin_mobile_sessions s
          JOIN admin_users u ON u.id=s.admin_user_id
          WHERE s.token=? AND s.expires_at>? AND u.active=1""", (token, now)).fetchone()
        if identity:
            return dict(identity)
        legacy = conn.execute("SELECT 1 FROM admin_sessions WHERE token=?", (token,)).fetchone()
        sms = conn.execute("SELECT api_key,line_number,enabled,verified FROM sms_settings WHERE id=1").fetchone()
    sms_ready = bool(sms and sms["enabled"] and sms["verified"] and sms["api_key"] and sms["line_number"])
    if legacy and not sms_ready:
        return {"id": 0, "mobile": OWNER_MOBILE, "role": "owner"}
    raise HTTPException(401, "نشست مدیریت منقضی شده؛ دوباره وارد شوید")


def require_owner(identity=Depends(require_admin)):
    if identity.get("role") != "owner":
        raise HTTPException(403, "این بخش فقط در اختیار مدیر اصلی است")
    return identity


def get_sms_settings():
    with db() as conn:
        row = conn.execute("SELECT * FROM sms_settings WHERE id=1").fetchone()
    return dict(row) if row else {"api_key": "", "line_number": "", "enabled": 0, "verified": 0}


def sms_ir_request(path: str, api_key: str, payload: dict | None = None):
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    request = urllib.request.Request("https://api.sms.ir/v1/" + path, data=data, headers={"Content-Type": "application/json", "Accept": "application/json", "X-API-KEY": api_key}, method="POST" if payload is not None else "GET")
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("message", "خطا در ارتباط با SMS.ir")
        except Exception:
            detail = "خطا در ارتباط با SMS.ir"
        raise HTTPException(502, detail) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise HTTPException(502, "ارتباط با SMS.ir برقرار نشد") from exc
    if int(result.get("status", 0)) != 1:
        raise HTTPException(502, result.get("message") or "درخواست SMS.ir ناموفق بود")
    return result.get("data")


def get_sms_ir_line(api_key: str) -> str:
    lines = sms_ir_request("line", api_key) or []
    if not lines:
        raise HTTPException(502, "هیچ خط ارسال فعالی در پنل SMS.ir این API Key پیدا نشد")
    first = lines[0]
    if isinstance(first, dict):
        first = first.get("lineNumber") or first.get("number") or first.get("line")
    if not first:
        raise HTTPException(502, "شماره خط ارسال از پاسخ SMS.ir تشخیص داده نشد")
    return str(first)


def send_sms_ir_code(mobile: str, code: str):
    settings = get_sms_settings()
    if not settings.get("enabled") or not settings.get("api_key"):
        raise HTTPException(503, "سرویس پیامک هنوز توسط مدیر اصلی تنظیم و فعال نشده است")
    line_number = str(settings.get("line_number") or "")
    if not line_number:
        line_number = get_sms_ir_line(settings["api_key"])
        with db() as conn:
            conn.execute("UPDATE sms_settings SET line_number=?,updated_at=? WHERE id=1", (line_number, datetime.now(timezone.utc).isoformat()))
    message = f"کد ورود پنل حک نگار: {code}\nاعتبار این کد ۵ دقیقه است."
    sms_ir_request("send/bulk", settings["api_key"], {"lineNumber": int(line_number), "MessageText": message, "Mobiles": [mobile], "SendDateTime": None})

def serialize_product(conn, row):
    data = dict(row)
    data["active"] = bool(data["active"])
    data["pack_price"] = data["unit_price"] * data["units_per_pack"]
    data["images"] = [r["url"] for r in conn.execute("SELECT url FROM product_images WHERE product_id=? ORDER BY sort_order,id", (row["id"],))]
    return data


BALE_API_BASE = "https://tapi.bale.ai/bot{token}/{method}"
ORDER_STATUS_FA = {"new": "جدید", "confirmed": "تأیید شده", "production": "در حال تولید", "shipped": "ارسال شده", "delivered": "تحویل شده", "cancelled": "لغو شده"}
PAYMENT_FA = {"online": "پرداخت آنلاین", "cod": "پرداخت هنگام تحویل", "deposit": "بیعانه ۱۰ درصد"}


def get_bale_settings():
    with db() as conn:
        row = conn.execute("SELECT * FROM bale_settings WHERE id=1").fetchone()
    return dict(row) if row else {"bot_token": "", "site_url": "", "enabled": 0, "webhook_secret": "", "bot_username": ""}


def bale_api(method: str, payload: dict | None = None, token: str | None = None):
    token = token or get_bale_settings().get("bot_token", "")
    if not token:
        raise RuntimeError("توکن بازوی بله ثبت نشده است")
    request_data = json.dumps(payload or {}, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(BALE_API_BASE.format(token=token, method=method), data=request_data, headers={"Content-Type": "application/json; charset=utf-8"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            detail = json.loads(exc.read().decode("utf-8")).get("description", str(exc))
        except Exception:
            detail = str(exc)
        raise RuntimeError(detail) from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError("ارتباط با سرویس بله برقرار نشد") from exc
    if not result.get("ok"):
        raise RuntimeError(result.get("description") or "پاسخ ناموفق از بله")
    return result.get("result")


def bale_send(chat_id: str, text: str, reply_markup: dict | None = None):
    payload = {"chat_id": chat_id, "text": text}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    return bale_api("sendMessage", payload)


def bale_main_menu(chat_id: str):
    settings = get_bale_settings()
    keyboard = []
    if settings.get("site_url"):
        shop_url = settings["site_url"].rstrip("/") + f"/?bale_chat_id={chat_id}"
        keyboard.append([{"text": "🛍 ورود به فروشگاه کامل", "web_app": {"url": shop_url}}])
    keyboard.extend([
        [{"text": "📦 پیگیری سفارش", "callback_data": "track_order"}, {"text": "📋 محصولات موجود", "callback_data": "catalog"}],
        [{"text": "🚗 درخواست مراجعه ویزیتور (ویژه بهبهان)", "callback_data": "visitor_request"}],
        [{"text": "ℹ️ درباره ما", "callback_data": "about"}, {"text": "☎️ تماس با ما", "callback_data": "contact"}],
    ])
    return bale_send(chat_id, "به بازوی فروش عمده جعبه جواهرات حک نگار خوش آمدید.\nاز منوی زیر خدمت موردنظر را انتخاب کنید.", {"inline_keyboard": keyboard})


def format_tracking(order: dict) -> str:
    ready = order.get("estimated_ready_date") or "هنوز تعیین نشده"
    return (f"📦 وضعیت سفارش {order['order_number']}\n"
            f"فروشگاه: {order['shop_name']}\n"
            f"وضعیت: {ORDER_STATUS_FA.get(order['status'], order['status'])}\n"
            f"روش پرداخت: {PAYMENT_FA.get(order['payment_method'], order['payment_method'])}\n"
            f"مبلغ کل: {order['total_price']:,} تومان\n"
            f"آماده‌شدن تقریبی: {ready}")


def notify_bale_order(chat_id: str, text: str):
    settings = get_bale_settings()
    if not chat_id or not settings.get("enabled") or not settings.get("bot_token"):
        return
    try:
        bale_send(chat_id, text)
    except RuntimeError:
        pass

def notify_admin_new_order(order_number: str, total: int, payload: OrderInput, lines: list):
    settings = get_bale_settings()
    chat_id = settings.get("admin_chat_id", "")
    if not chat_id or not settings.get("enabled") or not settings.get("bot_token"):
        return
    source = "بازوی بله" if payload.bale_chat_id else "سایت"
    items = "\n".join(f"• {product['name']}: {packs} بسته" for product, packs, _ in lines)
    text = (f"🔔 سفارش جدید از طریق {source}\n"
            f"کد سفارش: {order_number}\n"
            f"روش پرداخت: {PAYMENT_FA.get(payload.payment_method, payload.payment_method)}\n"
            f"اقلام:\n{items}\n"
            f"مبلغ کل: {total:,} تومان\n"
            f"جزئیات کامل در پنل مدیریت سایت قابل مشاهده است.")
    try:
        bale_send(chat_id, text)
    except RuntimeError:
        pass


def notify_admin_visitor_request(visitor: dict):
    settings = get_bale_settings()
    chat_id = settings.get("admin_chat_id", "")
    if not chat_id or not settings.get("enabled") or not settings.get("bot_token"):
        return
    source = "بازوی بله" if visitor.get("source") == "bale" else "سایت"
    text = (f"🚗 درخواست مراجعه ویزیتور از طریق {source}\n"
            f"کد درخواست: {visitor['request_number']}\n"
            f"نام مغازه: {visitor['shop_name']}\n"
            f"شماره موبایل: {visitor['mobile']}\n"
            f"آدرس: {visitor['address']}\n"
            f"در پنل مدیریت نیز ثبت شد.")
    try:
        bale_send(chat_id, text)
    except RuntimeError:
        pass
@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.get("/api/admin/auth/status")
def admin_auth_status():
    settings = get_sms_settings()
    return {"sms_ready": bool(settings.get("enabled") and settings.get("verified") and settings.get("api_key") and settings.get("line_number")), "provider": "sms.ir"}


@app.post("/api/admin/auth/request-code")
def request_admin_code(payload: MobileLoginInput):
    mobile = normalize_mobile(payload.mobile)
    now = datetime.now(timezone.utc)
    with db() as conn:
        user = conn.execute("SELECT * FROM admin_users WHERE mobile=? AND active=1", (mobile,)).fetchone()
        if not user:
            raise HTTPException(403, "این شماره اجازه دسترسی به پنل ادمین را نداره")
        recent = conn.execute("SELECT 1 FROM admin_otp_codes WHERE mobile=? AND created_at>?", (mobile, (now - timedelta(seconds=60)).isoformat())).fetchone()
        if recent:
            raise HTTPException(429, "برای درخواست دوباره کد، یک دقیقه صبر کنید")
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    send_sms_ir_code(mobile, code)
    with db() as conn:
        conn.execute("UPDATE sms_settings SET verified=1,updated_at=? WHERE id=1", (datetime.now(timezone.utc).isoformat(),))
        conn.execute("UPDATE admin_otp_codes SET consumed=1 WHERE mobile=? AND consumed=0", (mobile,))
        conn.execute("INSERT INTO admin_otp_codes(mobile,code_hash,expires_at,created_at) VALUES (?,?,?,?)", (mobile, password_hash(code), (now + timedelta(minutes=5)).isoformat(), now.isoformat()))
    return {"ok": True, "expires_in": 300}


@app.post("/api/admin/auth/verify-code")
def verify_admin_code(payload: OtpVerifyInput):
    mobile = normalize_mobile(payload.mobile)
    now = datetime.now(timezone.utc)
    with db() as conn:
        otp = conn.execute("SELECT * FROM admin_otp_codes WHERE mobile=? AND consumed=0 ORDER BY id DESC LIMIT 1", (mobile,)).fetchone()
        user = conn.execute("SELECT * FROM admin_users WHERE mobile=? AND active=1", (mobile,)).fetchone()
        if not user:
            raise HTTPException(403, "این شماره اجازه دسترسی به پنل ادمین را نداره")
        if not otp or otp["expires_at"] <= now.isoformat():
            raise HTTPException(400, "کد ورود منقضی شده است؛ کد جدید دریافت کنید")
        if otp["attempts"] >= 5:
            raise HTTPException(429, "تعداد تلاش ناموفق بیش از حد مجاز است؛ کد جدید دریافت کنید")
        if not verify_password(payload.code.strip(), otp["code_hash"]):
            conn.execute("UPDATE admin_otp_codes SET attempts=attempts+1 WHERE id=?", (otp["id"],))
            conn.commit()
            raise HTTPException(400, "کد ورود نادرست است")
        conn.execute("UPDATE admin_otp_codes SET consumed=1 WHERE id=?", (otp["id"],))
        token = secrets.token_urlsafe(32)
        conn.execute("INSERT INTO admin_mobile_sessions(token,admin_user_id,created_at,expires_at) VALUES (?,?,?,?)", (token, user["id"], now.isoformat(), (now + timedelta(hours=12)).isoformat()))
    return {"token": token, "mobile": mobile, "role": user["role"]}


@app.get("/api/admin/me")
def admin_me(identity=Depends(require_admin)):
    return identity


@app.get("/api/admin/sms-settings")
def admin_sms_settings(identity=Depends(require_owner)):
    settings = get_sms_settings()
    return {"provider": "sms.ir", "has_api_key": bool(settings.get("api_key")), "line_number": settings.get("line_number", ""), "enabled": bool(settings.get("enabled")), "verified": bool(settings.get("verified"))}


@app.put("/api/admin/sms-settings")
def update_sms_settings(payload: SmsSettingsInput, identity=Depends(require_owner)):
    with db() as conn:
        current = conn.execute("SELECT api_key FROM sms_settings WHERE id=1").fetchone()
        api_key = payload.api_key.strip() or (current["api_key"] if current else "")
        if payload.enabled and not api_key:
            raise HTTPException(400, "برای فعال‌سازی، کلید API سرویس SMS.ir لازم است")
        changed = not current or api_key != current["api_key"]
        conn.execute("UPDATE sms_settings SET api_key=?,enabled=?,line_number=CASE WHEN ? THEN '' ELSE line_number END,verified=CASE WHEN ? THEN 0 ELSE verified END,updated_at=? WHERE id=1", (api_key, int(payload.enabled), int(changed), int(changed), datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "has_api_key": bool(api_key)}
@app.get("/api/admin/users")
def list_admin_users(identity=Depends(require_owner)):
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT id,mobile,role,active,created_at FROM admin_users WHERE active=1 ORDER BY CASE role WHEN 'owner' THEN 0 ELSE 1 END,id")]


@app.post("/api/admin/users")
def add_admin_user(payload: AdminUserInput, identity=Depends(require_owner)):
    mobile = normalize_mobile(payload.mobile)
    if mobile == OWNER_MOBILE:
        raise HTTPException(409, "این شماره مدیر اصلی است")
    now = datetime.now(timezone.utc).isoformat()
    with db() as conn:
        existing = conn.execute("SELECT * FROM admin_users WHERE mobile=?", (mobile,)).fetchone()
        if existing and existing["active"]:
            raise HTTPException(409, "این شماره قبلاً اجازه ورود دارد")
        if existing:
            conn.execute("UPDATE admin_users SET active=1,role='admin',created_at=?,created_by=? WHERE id=?", (now, identity["mobile"], existing["id"]))
            user_id = existing["id"]
        else:
            user_id = conn.execute("INSERT INTO admin_users(mobile,role,active,created_at,created_by) VALUES (?,?,?,?,?)", (mobile, "admin", 1, now, identity["mobile"])).lastrowid
    return {"id": user_id, "mobile": mobile, "role": "admin", "active": 1, "created_at": now}


@app.delete("/api/admin/users/{user_id}")
def remove_admin_user(user_id: int, identity=Depends(require_owner)):
    with db() as conn:
        user = conn.execute("SELECT * FROM admin_users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not user:
            raise HTTPException(404, "ادمین پیدا نشد")
        if user["role"] == "owner" or user["mobile"] == OWNER_MOBILE:
            raise HTTPException(400, "مدیر اصلی قابل حذف نیست")
        conn.execute("UPDATE admin_users SET active=0 WHERE id=?", (user_id,))
        conn.execute("DELETE FROM admin_mobile_sessions WHERE admin_user_id=?", (user_id,))
    return {"ok": True}


def save_visitor_request(payload: VisitorRequestInput):
    mobile = normalize_mobile(payload.mobile)
    created_at = datetime.now(timezone.utc).isoformat()
    request_number = f"VZ-{datetime.now().strftime('%y%m%d')}-{secrets.randbelow(9000)+1000}"
    with db() as conn:
        while conn.execute("SELECT 1 FROM visitor_requests WHERE request_number=?", (request_number,)).fetchone():
            request_number = f"VZ-{datetime.now().strftime('%y%m%d')}-{secrets.randbelow(9000)+1000}"
        cursor = conn.execute("INSERT INTO visitor_requests(request_number,shop_name,mobile,address,source,bale_chat_id,created_at) VALUES (?,?,?,?,?,?,?)", (request_number, payload.shop_name.strip(), mobile, payload.address.strip(), payload.source, payload.bale_chat_id.strip(), created_at))
    result = {"id": cursor.lastrowid, "request_number": request_number, "shop_name": payload.shop_name.strip(), "mobile": mobile, "address": payload.address.strip(), "source": payload.source, "status": "new", "created_at": created_at}
    notify_admin_visitor_request(result)
    return result


@app.post("/api/visitor-requests")
def create_visitor_request(payload: VisitorRequestInput):
    return save_visitor_request(payload)


@app.get("/api/admin/visitor-requests", dependencies=[Depends(require_admin)])
def admin_visitor_requests():
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM visitor_requests ORDER BY created_at DESC,id DESC")]


class VisitorRequestUpdate(BaseModel):
    status: Literal["new", "contacted", "scheduled", "done", "cancelled"]


@app.patch("/api/admin/visitor-requests/{request_id}", dependencies=[Depends(require_admin)])
def update_visitor_request(request_id: int, payload: VisitorRequestUpdate):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM visitor_requests WHERE id=?", (request_id,)).fetchone():
            raise HTTPException(404, "درخواست مراجعه پیدا نشد")
        conn.execute("UPDATE visitor_requests SET status=? WHERE id=?", (payload.status, request_id))
    return {"ok": True}

@app.get("/api/settings")
def site_settings():
    with db() as conn:
        values = {row["key"]: row["value"] for row in conn.execute("SELECT key,value FROM site_settings")}
    return {**DEFAULT_SITE_SETTINGS, **values}


@app.put("/api/admin/settings", dependencies=[Depends(require_owner)])
def update_site_settings(payload: SiteSettingsInput):
    with db() as conn:
        for key, value in payload.model_dump().items():
            conn.execute("INSERT INTO site_settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value.strip()))
    return {"ok": True}


@app.get("/api/admin/payment-settings", dependencies=[Depends(require_owner)])
def admin_payment_settings():
    settings = get_payment_settings()
    return {"has_merchant_id": bool(settings.get("merchant_id")), "site_url": settings.get("site_url", "https://jaabehaknegar.ir"), "enabled": bool(settings.get("enabled"))}


@app.put("/api/admin/payment-settings", dependencies=[Depends(require_owner)])
def update_payment_settings(payload: PaymentSettingsInput):
    site_url = payload.site_url.strip().rstrip("/")
    if not site_url.startswith("https://"):
        raise HTTPException(400, "آدرس سایت برای درگاه باید با HTTPS شروع شود")
    supplied_merchant = payload.merchant_id.strip()
    if supplied_merchant and not re.fullmatch(r"[0-9a-fA-F-]{36}", supplied_merchant):
        raise HTTPException(400, "مرچنت آیدی زرین‌پال باید کد ۳۶ کاراکتری معتبر باشد")
    with db() as conn:
        current = conn.execute("SELECT merchant_id FROM payment_settings WHERE id=1").fetchone()
        merchant_id = supplied_merchant or (current["merchant_id"] if current else "")
        if payload.enabled and not merchant_id:
            raise HTTPException(400, "ابتدا مرچنت آیدی زرین‌پال را وارد کنید")
        conn.execute("UPDATE payment_settings SET merchant_id=?,site_url=?,enabled=?,updated_at=? WHERE id=1", (merchant_id, site_url, int(payload.enabled), datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "has_merchant_id": bool(merchant_id), "enabled": payload.enabled, "site_url": site_url}

@app.get("/api/admin/bale-settings", dependencies=[Depends(require_owner)])
def admin_bale_settings():
    settings = get_bale_settings()
    return {
        "site_url": settings.get("site_url", ""), "enabled": bool(settings.get("enabled")),
        "bot_username": settings.get("bot_username", ""), "has_token": bool(settings.get("bot_token")), "has_payment_token": bool(settings.get("payment_token")), "admin_mobile": settings.get("admin_mobile", "09399506609"), "manager_connected": bool(settings.get("admin_chat_id")), "manager_link_code": settings.get("manager_link_code", ""),
        "webhook_url": (settings.get("site_url", "").rstrip("/") + "/api/bale/webhook/" + settings.get("webhook_secret", "")) if settings.get("site_url") else "",
    }


@app.put("/api/admin/bale-settings", dependencies=[Depends(require_owner)])
def update_bale_settings(payload: BaleSettingsInput):
    site_url = payload.site_url.strip().rstrip("/")
    if site_url and not site_url.startswith(("https://", "http://localhost", "http://127.0.0.1")):
        raise HTTPException(400, "آدرس سایت باید HTTPS باشد")
    with db() as conn:
        current = conn.execute("SELECT bot_token,payment_token FROM bale_settings WHERE id=1").fetchone()
        token = payload.bot_token.strip() or (current["bot_token"] if current else "")
        payment_token = payload.payment_token.strip() or (current["payment_token"] if current else "")
        conn.execute("UPDATE bale_settings SET bot_token=?,payment_token=?,admin_mobile=?,site_url=?,enabled=?,updated_at=? WHERE id=1", (token, payment_token, payload.admin_mobile.strip(), site_url, int(payload.enabled), datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "has_token": bool(token), "has_payment_token": bool(payment_token)}


@app.post("/api/admin/bale/test", dependencies=[Depends(require_owner)])
def test_bale_connection():
    try:
        me = bale_api("getMe")
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    username = me.get("username", "") if isinstance(me, dict) else ""
    with db() as conn:
        conn.execute("UPDATE bale_settings SET bot_username=?,updated_at=? WHERE id=1", (username, datetime.now(timezone.utc).isoformat()))
    return {"ok": True, "username": username, "name": me.get("first_name", "") if isinstance(me, dict) else ""}


@app.post("/api/admin/bale/connect", dependencies=[Depends(require_owner)])
def connect_bale_webhook():
    settings = get_bale_settings()
    if not settings.get("site_url") or not settings["site_url"].startswith("https://"):
        raise HTTPException(400, "برای اتصال وب‌هوک، آدرس عمومی HTTPS سایت را وارد کنید")
    webhook_url = settings["site_url"].rstrip("/") + "/api/bale/webhook/" + settings["webhook_secret"]
    try:
        bale_api("setWebhook", {"url": webhook_url})
        info = bale_api("getWebhookInfo")
    except RuntimeError as exc:
        raise HTTPException(400, str(exc)) from exc
    with db() as conn:
        conn.execute("UPDATE bale_settings SET enabled=1,updated_at=? WHERE id=1", (datetime.now(timezone.utc).isoformat(),))
    return {"ok": True, "webhook_url": webhook_url, "info": info}


def set_bale_session(chat_id: str, state: str, data: dict | None = None):
    with db() as conn:
        conn.execute("INSERT INTO bale_sessions(chat_id,state,data_json,updated_at) VALUES (?,?,?,?) ON CONFLICT(chat_id) DO UPDATE SET state=excluded.state,data_json=excluded.data_json,updated_at=excluded.updated_at", (chat_id, state, json.dumps(data or {}, ensure_ascii=False), datetime.now(timezone.utc).isoformat()))


def get_bale_session(chat_id: str):
    with db() as conn:
        row = conn.execute("SELECT state,data_json FROM bale_sessions WHERE chat_id=?", (chat_id,)).fetchone()
    if not row:
        return "", {}
    try:
        data = json.loads(row["data_json"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return row["state"], data


def clear_bale_session(chat_id: str):
    with db() as conn:
        conn.execute("DELETE FROM bale_sessions WHERE chat_id=?", (chat_id,))


def set_cart_quantity(chat_id: str, product_id: int, packs: int):
    with db() as conn:
        product = conn.execute("SELECT stock_packs FROM products WHERE id=? AND active=1", (product_id,)).fetchone()
        if not product:
            return 0
        packs = max(0, min(int(packs), int(product["stock_packs"])))
        if packs:
            conn.execute("INSERT INTO bale_carts(chat_id,product_id,packs,updated_at) VALUES (?,?,?,?) ON CONFLICT(chat_id,product_id) DO UPDATE SET packs=excluded.packs,updated_at=excluded.updated_at", (chat_id, product_id, packs, datetime.now(timezone.utc).isoformat()))
        else:
            conn.execute("DELETE FROM bale_carts WHERE chat_id=? AND product_id=?", (chat_id, product_id))
    return packs


def get_cart_quantity(chat_id: str, product_id: int) -> int:
    with db() as conn:
        row = conn.execute("SELECT packs FROM bale_carts WHERE chat_id=? AND product_id=?", (chat_id, product_id)).fetchone()
    return int(row["packs"]) if row else 0


def clear_bale_cart(chat_id: str):
    with db() as conn:
        conn.execute("DELETE FROM bale_carts WHERE chat_id=?", (chat_id,))


def product_caption(product: dict, packs: int, index: int, total: int) -> str:
    pack_price = product["unit_price"] * product["units_per_pack"]
    return (f"📦 محصول {index + 1} از {total}\n"
            f"{product['name']}\n"
            f"سایز: {product['dimensions']}\n"
            f"قیمت هر عدد: {product['unit_price']:,} تومان\n"
            f"تعداد در هر بسته: {product['units_per_pack']} عدد\n"
            f"قیمت هر بسته: {pack_price:,} تومان\n"
            f"تعداد انتخاب‌شده: {packs} بسته")


def product_keyboard(product_id: int, packs: int):
    return {"inline_keyboard": [
        [{"text": "-", "callback_data": f"qty:{product_id}:-"}, {"text": f"{packs} بسته", "callback_data": "noop"}, {"text": "+", "callback_data": f"qty:{product_id}:+"}],
        [{"text": "✏️ وارد کردن تعداد بسته", "callback_data": f"qty_input:{product_id}"}],
    ]}


def local_product_image(url: str) -> Path | None:
    if not url:
        return None
    if url.startswith("/uploads/"):
        path = UPLOAD_DIR / Path(url).name
    elif url.startswith("/"):
        path = BASE_DIR.parent / "frontend" / "public" / url.lstrip("/")
    else:
        path = Path(url)
    return path if path.exists() and path.is_file() else None


def bale_multipart(method: str, fields: dict, file_field: str, file_path: Path):
    token = get_bale_settings().get("bot_token", "")
    boundary = "----HakkarBale" + secrets.token_hex(12)
    chunks = []
    for key, value in fields.items():
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{key}\"\r\n\r\n{value}\r\n".encode("utf-8"))
    mime = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"{file_path.name}\"\r\nContent-Type: {mime}\r\n\r\n".encode("utf-8"))
    chunks.append(file_path.read_bytes())
    chunks.append(f"\r\n--{boundary}--\r\n".encode("utf-8"))
    req = urllib.request.Request(BALE_API_BASE.format(token=token, method=method), data=b"".join(chunks), headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise RuntimeError("ارسال تصویر محصول به بله ناموفق بود") from exc
    if not result.get("ok"):
        raise RuntimeError(result.get("description") or "ارسال تصویر ناموفق بود")
    return result.get("result")


def send_product_card(chat_id: str, product: dict, index: int, total: int):
    packs = get_cart_quantity(chat_id, product["id"])
    caption = product_caption(product, packs, index, total)
    keyboard = product_keyboard(product["id"], packs)
    image_url = product.get("images", [""])[0] if product.get("images") else ""
    try:
        if image_url.startswith(("http://", "https://")):
            bale_api("sendPhoto", {"chat_id": chat_id, "photo": image_url, "caption": caption, "reply_markup": keyboard})
        elif local_product_image(image_url):
            bale_multipart("sendPhoto", {"chat_id": chat_id, "caption": caption, "reply_markup": keyboard}, "photo", local_product_image(image_url))
        else:
            bale_send(chat_id, caption, keyboard)
    except RuntimeError:
        bale_send(chat_id, caption, keyboard)


def show_bale_categories(chat_id: str):
    with db() as conn:
        categories = conn.execute("""SELECT c.id,c.name,COUNT(p.id) AS product_count FROM categories c
          JOIN products p ON p.category_id=c.id AND p.active=1 AND p.stock_packs>0
          WHERE c.active=1 GROUP BY c.id,c.name ORDER BY c.sort_order,c.id""").fetchall()
    if not categories:
        bale_send(chat_id, "در حال حاضر محصول موجودی ثبت نشده است.")
        return
    buttons = [[{"text": f"{row['name']} ({row['product_count']})", "callback_data": f"category:{row['id']}"}] for row in categories]
    bale_send(chat_id, "دسته‌بندی موردنظر را انتخاب کنید:", {"inline_keyboard": buttons})


def show_bale_category(chat_id: str, category_id: int):
    with db() as conn:
        category = conn.execute("SELECT name FROM categories WHERE id=? AND active=1", (category_id,)).fetchone()
        products = [serialize_product(conn, row) for row in conn.execute("SELECT * FROM products WHERE category_id=? AND active=1 AND stock_packs>0 ORDER BY id", (category_id,))]
    if not category or not products:
        bale_send(chat_id, "در این دسته محصول موجودی ثبت نشده است.")
        show_bale_categories(chat_id)
        return
    set_bale_session(chat_id, "shopping", {"category_id": category_id})
    bale_send(chat_id, f"محصولات دسته «{category['name']}»؛ تعداد بسته هر مدل را انتخاب کنید:")
    for index, product in enumerate(products):
        send_product_card(chat_id, product, index, len(products))
    bale_send(chat_id, "پس از انتخاب تعداد محصولات، ادامه دهید یا دسته‌بندی دیگری را مشاهده کنید.", {"inline_keyboard": [
        [{"text": "✅ تکمیل سفارش", "callback_data": "checkout_start"}],
        [{"text": "📋 مشاهده محصولات موجود", "callback_data": "catalog"}],
    ]})

def cart_rows(chat_id: str):
    with db() as conn:
        return [dict(row) for row in conn.execute("""SELECT p.id,p.name,p.unit_price,p.units_per_pack,p.stock_packs,c.packs,
          p.unit_price*p.units_per_pack*c.packs AS line_total FROM bale_carts c JOIN products p ON p.id=c.product_id
          WHERE c.chat_id=? AND c.packs>0 AND p.active=1 ORDER BY p.id""", (chat_id,))]


def show_bale_cart(chat_id: str):
    rows = cart_rows(chat_id)
    if not rows:
        bale_send(chat_id, "سبد خرید شما خالی است. ابتدا از محصولات تعداد بسته انتخاب کنید.", {"inline_keyboard": [[{"text": "مشاهده محصولات", "callback_data": "catalog"}]]})
        return
    total = sum(row["line_total"] for row in rows)
    lines = ["🛒 سبد خرید شما"] + [f"• {r['name']}: {r['packs']} بسته — {r['line_total']:,} تومان" for r in rows] + [f"\nجمع کل: {total:,} تومان"]
    bale_send(chat_id, "\n".join(lines), {"inline_keyboard": [[{"text": "✅ ادامه و ثبت اطلاعات", "callback_data": "checkout_start"}], [{"text": "🔄 شروع دوباره انتخاب محصولات", "callback_data": "catalog_reset"}]]})


def edit_product_quantity(callback: dict, product_id: int, delta: int):
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id", ""))
    current = get_cart_quantity(chat_id, product_id)
    packs = set_cart_quantity(chat_id, product_id, current + delta)
    with db() as conn:
        product_row = conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
        products = [row["id"] for row in conn.execute("SELECT id FROM products WHERE category_id=(SELECT category_id FROM products WHERE id=?) AND active=1 AND stock_packs>0 ORDER BY id", (product_id,))]
    if not product_row or product_id not in products:
        return
    product = dict(product_row)
    index = products.index(product_id)
    bale_api("editMessageCaption", {"chat_id": chat_id, "message_id": message.get("message_id"), "caption": product_caption(product, packs, index, len(products)), "reply_markup": product_keyboard(product_id, packs)})


def prompt_payment(chat_id: str, data: dict):
    set_bale_session(chat_id, "payment", data)
    bale_send(chat_id, "روش پرداخت را انتخاب کنید:", {"inline_keyboard": [
        [{"text": "💳 پرداخت کامل آنلاین", "callback_data": "pay:online"}],
        [{"text": "📍 پرداخت هنگام تحویل؛ ویژه بهبهان", "callback_data": "pay:cod"}],
        [{"text": "💰 بیعانه ۱۰ درصد", "callback_data": "pay:deposit"}],
    ]})


def download_bale_customer_file(message: dict) -> str:
    file_id, original_name = "", "logo.jpg"
    if message.get("photo"):
        file_id = message["photo"][-1].get("file_id", "")
    elif message.get("document"):
        file_id = message["document"].get("file_id", "")
        original_name = message["document"].get("file_name") or "logo.pdf"
    if not file_id:
        raise ValueError("لطفاً تصویر یا فایل PDF ارسال کنید")
    info = bale_api("getFile", {"file_id": file_id})
    file_path = info.get("file_path", "") if isinstance(info, dict) else ""
    if not file_path:
        raise ValueError("دریافت فایل از بله ممکن نشد")
    suffix = Path(original_name).suffix.lower() or Path(file_path).suffix.lower() or ".jpg"
    if suffix not in {".jpg", ".jpeg", ".png", ".webp", ".pdf"}:
        suffix = ".jpg"
    token = get_bale_settings().get("bot_token", "")
    url = f"https://tapi.bale.ai/file/bot{token}/{file_path.lstrip('/')}"
    with urllib.request.urlopen(url, timeout=30) as response:
        content = response.read(5 * 1024 * 1024 + 1)
    if len(content) > 5 * 1024 * 1024:
        raise ValueError("حجم فایل باید کمتر از ۵ مگابایت باشد")
    destination = UPLOAD_DIR / f"{secrets.token_hex(16)}{suffix}"
    destination.write_bytes(content)
    url = f"/uploads/{destination.name}"
    with db() as conn:
        conn.execute("INSERT OR IGNORE INTO customer_uploads(url,created_at) VALUES (?,?)", (url, datetime.now(timezone.utc).isoformat()))
    return url


def register_bale_order(chat_id: str, method: str, data: dict):
    rows = cart_rows(chat_id)
    if not rows:
        bale_send(chat_id, "سبد خرید خالی است و سفارش ثبت نشد.")
        return
    if method == "cod" and data.get("city", "").strip().replace("‌", "") != "بهبهان":
        bale_send(chat_id, "پرداخت هنگام تحویل فقط برای شهر بهبهان فعال است. روش دیگری انتخاب کنید.")
        prompt_payment(chat_id, data)
        return
    payload = OrderInput(mobile=data["mobile"], shop_name=data["shop_name"], address=data["address"], city=data["city"], shop_phone=data["shop_phone"], instagram=data.get("instagram", ""), logo_url=data.get("logo_url", ""), notes=data.get("notes", ""), bale_chat_id=chat_id, payment_method=method, items=[OrderItemInput(product_id=row["id"], packs=row["packs"]) for row in rows])
    result = create_order(payload)
    clear_bale_cart(chat_id)
    clear_bale_session(chat_id)
    if method == "cod":
        bale_send(chat_id, f"✅ سفارش {result['order_number']} ثبت شد.\nپرداخت هنگام تحویل برای سفارش شما انتخاب شد.")
        return
    settings = get_bale_settings()
    payment_token = settings.get("payment_token", "")
    if not payment_token:
        bale_send(chat_id, f"✅ سفارش {result['order_number']} ثبت شد؛ اما توکن پرداخت کیف پول در پنل مدیریت وارد نشده است. برای پرداخت با شما هماهنگ خواهد شد.")
        return
    amount_toman = result["payable_now"] if method == "deposit" else result["total_price"]
    invoice_payload = f"order:{result['order_number']}:{method}"
    try:
        bale_api("sendInvoice", {"chat_id": chat_id, "title": "سفارش جعبه حک نگار", "description": f"{'بیعانه ۱۰ درصد' if method == 'deposit' else 'پرداخت کامل'} سفارش {result['order_number']}", "payload": invoice_payload, "provider_token": payment_token, "prices": [{"label": "مبلغ قابل پرداخت", "amount": int(amount_toman * 10)}]})
    except RuntimeError as exc:
        bale_send(chat_id, f"سفارش {result['order_number']} ثبت شد اما ارسال درخواست پرداخت ناموفق بود: {exc}")


def handle_commerce_callback(callback: dict) -> bool:
    action = callback.get("data", "")
    message = callback.get("message") or {}
    chat_id = str((message.get("chat") or {}).get("id", ""))
    if not chat_id:
        return False
    commerce = action == "catalog" or action.startswith(("category:", "catalog_", "qty:", "qty_input:", "cart_", "checkout_", "pay:", "noop"))
    if not commerce:
        return False
    bale_api("answerCallbackQuery", {"callback_query_id": callback.get("id")})
    if action == "noop":
        return True
    if action in {"catalog", "catalog_reset"}:
        if action == "catalog_reset":
            clear_bale_cart(chat_id)
        set_bale_session(chat_id, "shopping", {})
        show_bale_categories(chat_id)
    elif action.startswith("category:"):
        show_bale_category(chat_id, int(action.split(":", 1)[1]))
    elif action.startswith("qty:"):
        _, product_id, operation = action.split(":", 2)
        edit_product_quantity(callback, int(product_id), 1 if operation == "+" else -1)
    elif action.startswith("qty_input:"):
        product_id = int(action.split(":", 1)[1])
        set_bale_session(chat_id, "quantity_input", {"product_id": product_id, "message_id": message.get("message_id")})
        bale_send(chat_id, "تعداد بسته موردنیاز را فقط به‌صورت عدد ارسال کنید؛ مثال: 3")
    elif action == "cart_checkout":
        show_bale_cart(chat_id)
    elif action == "checkout_start":
        rows = cart_rows(chat_id)
        if not rows:
            bale_send(chat_id, "سبد خرید شما خالی است. ابتدا حداقل یک محصول انتخاب کنید.")
            show_bale_categories(chat_id)
        else:
            total = sum(row["line_total"] for row in rows)
            summary = ["🛒 اقلام انتخاب‌شده:"] + [f"• {r['name']}: {r['packs']} بسته" for r in rows] + [f"جمع کل: {total:,} تومان"]
            bale_send(chat_id, "\n".join(summary))
            set_bale_session(chat_id, "contact_mobile", {})
            bale_send(chat_id, "شماره موبایل جهت هماهنگی:\nشماره‌ای مانند 09123456789 وارد کنید.")
    elif action.startswith("pay:"):
        state, data = get_bale_session(chat_id)
        if state != "payment":
            bale_send(chat_id, "اطلاعات سفارش کامل نیست. لطفاً فرایند خرید را دوباره انجام دهید.")
        else:
            register_bale_order(chat_id, action.split(":", 1)[1], data)
    return True

def handle_commerce_message(chat_id: str, message: dict) -> bool:
    state, data = get_bale_session(chat_id)
    text_value = (message.get("text") or "").strip()
    if state == "visitor_shop_name":
        if len(text_value) < 2:
            bale_send(chat_id, "نام مغازه را کامل‌تر وارد کنید.")
            return True
        data["shop_name"] = text_value
        set_bale_session(chat_id, "visitor_mobile", data)
        bale_send(chat_id, "شماره موبایل جهت هماهنگی:\nشماره‌ای مانند 09123456789 وارد کنید.")
        return True
    if state == "visitor_mobile":
        if not re.fullmatch(r"09\d{9}", text_value):
            bale_send(chat_id, "شماره موبایل معتبر نیست؛ شماره‌ای مانند 09123456789 وارد کنید.")
            return True
        data["mobile"] = text_value
        set_bale_session(chat_id, "visitor_address", data)
        bale_send(chat_id, "آدرس کامل مغازه در بهبهان را وارد کنید.")
        return True
    if state == "visitor_address":
        if len(text_value) < 5:
            bale_send(chat_id, "آدرس خیلی کوتاه است؛ آدرس کامل‌تری وارد کنید.")
            return True
        save_visitor_request(VisitorRequestInput(shop_name=data["shop_name"], mobile=data["mobile"], address=text_value, source="bale", bale_chat_id=chat_id))
        clear_bale_session(chat_id)
        bale_send(chat_id, "✅ ویزیتور ما در اسرع وقت میاد خدمتتون.")
        bale_main_menu(chat_id)
        return True
    if state == "quantity_input":
        if not text_value.isdigit():
            bale_send(chat_id, "لطفاً فقط عدد تعداد بسته را ارسال کنید.")
            return True
        packs = set_cart_quantity(chat_id, int(data["product_id"]), int(text_value))
        try:
            edit_product_quantity({"message": {"chat": {"id": chat_id}, "message_id": data.get("message_id")}}, int(data["product_id"]), 0)
        except RuntimeError:
            pass
        set_bale_session(chat_id, "shopping", {})
        bale_send(chat_id, f"تعداد {packs} بسته ثبت شد. اکنون می‌توانید محصولات دیگر را انتخاب یا سفارش را تکمیل کنید.", {"inline_keyboard": [[{"text": "✅ تکمیل سفارش", "callback_data": "checkout_start"}], [{"text": "📋 مشاهده محصولات موجود", "callback_data": "catalog"}]]})
        return True
    engraving_steps = {
        "city": ("city", "shop_name", "نام مغازه (جهت حکاکی روی درب جعبه):\nدر صورتی که نمیخواهید نام مغازه تان روی درب جعبه حکاکی شود بنویسید نمیخواهم"),
        "shop_name": ("shop_name", "address", "آدرس مغازه (جهت حکاکی روی درب جعبه):\nدر صورتی که نمیخواهید آدرسی روی درب جعبه حکاکی شود بنویسید نمیخواهم"),
        "address": ("address", "shop_phone", "شماره های تماس (جهت حکاکی روی درب جعبه):\nمی‌توانید چند شماره تماس وارد کنید. در صورتی که نمیخواهید شماره ای روی درب جعبه حکاکی شود بنویسید نمیخواهم"),
        "shop_phone": ("shop_phone", "instagram", "آدرس پیج اینستا (جهت حکاکی روی درب جعبه):\nدر صورتی که نمیخواهید آدرس پیج روی درب جعبه حکاکی شود بنویسید نمیخواهم"),
        "instagram": ("instagram", "customer_logo", "حالا عکس لوگو یا کارت ویزیت را به‌صورت تصویر یا PDF ارسال کنید؛ اگر ندارید بنویسید ندارم."),
    }
    if state == "contact_mobile":
        if not re.fullmatch(r"09\d{9}", text_value):
            bale_send(chat_id, "شماره موبایل معتبر نیست. شماره‌ای مانند 09123456789 وارد کنید.")
            return True
        data["mobile"] = text_value
        set_bale_session(chat_id, "city", data)
        bale_send(chat_id, "شهر:")
        return True
    if state in engraving_steps:
        if len(text_value) < 2:
            bale_send(chat_id, "لطفاً پاسخ این بخش را وارد کنید؛ اگر تمایلی به حکاکی آن ندارید بنویسید نمیخواهم.")
            return True
        field, next_state, prompt = engraving_steps[state]
        normalized = text_value.replace("‌", "")
        data[field] = "نمیخواهم" if normalized == "نمیخواهم" else text_value
        set_bale_session(chat_id, next_state, data)
        bale_send(chat_id, prompt)
        return True
    if state == "customer_logo":
        if text_value in {"ندارم", "-"}:
            data["logo_url"] = ""
        else:
            try:
                data["logo_url"] = download_bale_customer_file(message)
            except (ValueError, RuntimeError, urllib.error.URLError) as exc:
                bale_send(chat_id, f"فایل دریافت نشد: {exc}\nتصویر یا PDF دیگری ارسال کنید یا بنویسید ندارم.")
                return True
        set_bale_session(chat_id, "notes", data)
        bale_send(chat_id, "اگر توضیحات خاصی درباره سفارش خود مدنظر دارید بنویسید و اگر توضیحی ندارید بنویسید ندارم.")
        return True
    if state == "notes":
        data["notes"] = "" if text_value in {"ندارم", "-"} else text_value
        prompt_payment(chat_id, data)
        return True
    return state in {"shopping", "payment"}

def process_bale_update(update: dict):
    pre_checkout = update.get("pre_checkout_query") or {}
    if pre_checkout:
        try:
            payload = pre_checkout.get("invoice_payload", "")
            parts = payload.split(":")
            valid = len(parts) == 3 and parts[0] == "order"
            if valid:
                with db() as conn:
                    valid = bool(conn.execute("SELECT 1 FROM orders WHERE order_number=?", (parts[1],)).fetchone())
            bale_api("answerPreCheckoutQuery", {"pre_checkout_query_id": pre_checkout.get("id"), "ok": valid, **({} if valid else {"error_message": "سفارش معتبر نیست یا موجودی آن تغییر کرده است"})})
        except RuntimeError:
            pass
        return
    callback = update.get("callback_query") or {}
    message = update.get("message") or {}
    if callback:
        try:
            if handle_commerce_callback(callback):
                return
        except RuntimeError:
            return
        message = callback.get("message") or {}
        chat_id = str((message.get("chat") or {}).get("id", ""))
        action = callback.get("data", "")
        try:
            bale_api("answerCallbackQuery", {"callback_query_id": callback.get("id")})
            if action == "track_order":
                set_bale_session(chat_id, "awaiting_order_code", {})
                bale_send(chat_id, "کد سفارش خود را ارسال کنید؛ مثال: HJ-260101-1234")
            elif action == "visitor_request":
                set_bale_session(chat_id, "visitor_shop_name", {})
                bale_send(chat_id, "در صورتی تمایل دارید ویزیتور ما در اسرع وقت جهت نشان دادن مدل ها خدمت شما برسد لطفا اطلاعات و آدرس را ثبت کنید.\n\nنام مغازه را وارد کنید.")
            elif action == "about":
                values = site_settings()
                bale_send(chat_id, f"ℹ️ درباره {values['production_name']}\n{values['about']}\n\nخدمات:\n{values['services']}")
            elif action == "contact":
                values = site_settings()
                bale_send(chat_id, f"☎️ تماس با {values['manager_name']}\n{values['phone']}\n📍 {values['address']}\n⏰ {values['working_hours']}")
        except RuntimeError:
            pass
        return
    chat_id = str((message.get("chat") or {}).get("id", ""))
    text_value = (message.get("text") or "").strip()
    if not chat_id:
        return
    if text_value.startswith("/manager"):
        parts = text_value.split(maxsplit=1)
        settings = get_bale_settings()
        if len(parts) == 2 and secrets.compare_digest(parts[1].strip(), settings.get("manager_link_code", "")):
            new_code = str(secrets.randbelow(900000) + 100000)
            with db() as conn:
                conn.execute("UPDATE bale_settings SET admin_chat_id=?,manager_link_code=?,updated_at=? WHERE id=1", (chat_id, new_code, datetime.now(timezone.utc).isoformat()))
            try:
                bale_send(chat_id, f"✅ اعلان سفارش‌های جدید برای شماره {settings.get('admin_mobile','09399506609')} به این گفت‌وگو متصل شد.")
            except RuntimeError:
                pass
        else:
            try:
                bale_send(chat_id, "کد اتصال مدیر صحیح نیست. کد فعلی را از پنل مدیریت سایت بردارید.")
            except RuntimeError:
                pass
        return
    successful_payment = message.get("successful_payment") or {}
    if successful_payment:
        payload = successful_payment.get("invoice_payload", "")
        parts = payload.split(":")
        if len(parts) == 3 and parts[0] == "order":
            status = "deposit_paid" if parts[2] == "deposit" else "paid"
            with db() as conn:
                conn.execute("UPDATE orders SET payment_status=? WHERE order_number=?", (status, parts[1]))
            try:
                bale_send(chat_id, f"✅ پرداخت سفارش {parts[1]} با موفقیت انجام شد و در پنل مدیریت ثبت گردید.")
            except RuntimeError:
                pass
        return
    with db() as conn:
        session = conn.execute("SELECT state FROM bale_sessions WHERE chat_id=?", (chat_id,)).fetchone()
    try:
        if text_value.startswith("/start") or text_value in {"منو", "/menu"}:
            bale_main_menu(chat_id)
        elif text_value in {"/cancel", "لغو"}:
            clear_bale_session(chat_id)
            clear_bale_cart(chat_id)
            bale_send(chat_id, "فرایند خرید لغو شد.")
            bale_main_menu(chat_id)
        elif session and session["state"] == "awaiting_order_code":
            with db() as conn:
                row = conn.execute("SELECT * FROM orders WHERE UPPER(order_number)=UPPER(?)", (text_value,)).fetchone()
                conn.execute("DELETE FROM bale_sessions WHERE chat_id=?", (chat_id,))
            bale_send(chat_id, format_tracking(dict(row)) if row else "سفارشی با این کد پیدا نشد. دوباره از منوی پیگیری سفارش تلاش کنید.")
        elif handle_commerce_message(chat_id, message):
            pass
        elif text_value.upper().startswith("HJ-"):
            with db() as conn:
                row = conn.execute("SELECT * FROM orders WHERE UPPER(order_number)=UPPER(?)", (text_value,)).fetchone()
            bale_send(chat_id, format_tracking(dict(row)) if row else "سفارشی با این کد پیدا نشد.")
        else:
            bale_main_menu(chat_id)
    except (RuntimeError, ValueError):
        pass

@app.post("/api/bale/webhook/{secret}")
async def bale_webhook(secret: str, request: Request):
    settings = get_bale_settings()
    if not settings.get("enabled") or not secrets.compare_digest(secret, settings.get("webhook_secret", "")):
        raise HTTPException(404, "Not found")
    process_bale_update(await request.json())
    return {"ok": True}


_bale_poll_thread = None


def bale_polling_loop():
    prepared_token = ""
    while True:
        settings = get_bale_settings()
        token = settings.get("bot_token", "")
        local_mode = bool(settings.get("enabled") and token and not settings.get("site_url"))
        if not local_mode:
            prepared_token = ""
            time.sleep(3)
            continue
        try:
            if prepared_token != token:
                bale_api("deleteWebhook", {"drop_pending_updates": False}, token=token)
                prepared_token = token
            offset = int(settings.get("last_update_id") or 0) + 1
            updates = bale_api("getUpdates", {"offset": offset, "limit": 50, "timeout": 20}, token=token) or []
            for update in updates:
                process_bale_update(update)
                update_id = int(update.get("update_id", 0))
                with db() as conn:
                    conn.execute("UPDATE bale_settings SET last_update_id=? WHERE id=1", (update_id,))
        except Exception:
            time.sleep(3)


@app.on_event("startup")
def start_background_services():
    global _bale_poll_thread, _customer_logo_cleanup_thread
    cleanup_expired_customer_logos()
    cleanup_abandoned_customer_uploads()
    if _customer_logo_cleanup_thread is None or not _customer_logo_cleanup_thread.is_alive():
        _customer_logo_cleanup_thread = threading.Thread(target=customer_logo_cleanup_loop, name="customer-logo-cleanup", daemon=True)
        _customer_logo_cleanup_thread.start()
    if _bale_poll_thread is None or not _bale_poll_thread.is_alive():
        _bale_poll_thread = threading.Thread(target=bale_polling_loop, name="bale-polling", daemon=True)
        _bale_poll_thread.start()

@app.get("/api/catalog")
def catalog():
    with db() as conn:
        result = []
        for category in conn.execute("SELECT * FROM categories WHERE active=1 ORDER BY sort_order,id"):
            products = [serialize_product(conn, p) for p in conn.execute("SELECT * FROM products WHERE category_id=? AND active=1 ORDER BY id", (category["id"],))]
            result.append({"id": category["id"], "name": category["name"], "products": products})
        return result


@app.post("/api/uploads")
def upload(file: UploadFile = File(...), purpose: str = Form("product")):
    allowed = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp", "application/pdf": ".pdf"}
    if file.content_type not in allowed:
        raise HTTPException(400, "فقط تصویر یا PDF مجاز است")
    suffix = allowed[file.content_type]
    destination = UPLOAD_DIR / f"{secrets.token_hex(16)}{suffix}"
    with destination.open("wb") as output:
        shutil.copyfileobj(file.file, output)
    if destination.stat().st_size > 5 * 1024 * 1024:
        destination.unlink(missing_ok=True)
        raise HTTPException(400, "حداکثر حجم فایل ۵ مگابایت است")
    url = f"/uploads/{destination.name}"
    if purpose == "customer_logo":
        with db() as conn:
            conn.execute("INSERT OR IGNORE INTO customer_uploads(url,created_at) VALUES (?,?)", (url, datetime.now(timezone.utc).isoformat()))
    return {"url": url}


@app.post("/api/orders")
def create_order(payload: OrderInput):
    if payload.payment_method == "cod" and payload.city.strip().replace("‌", "") != "بهبهان":
        raise HTTPException(400, "پرداخت هنگام تحویل فقط برای شهر بهبهان فعال است")
    payment_url, payment_authority, payment_amount = "", "", 0
    with db() as conn:
        lines, total = [], 0
        for item in payload.items:
            product = conn.execute("SELECT * FROM products WHERE id=? AND active=1", (item.product_id,)).fetchone()
            if not product:
                raise HTTPException(404, "یکی از محصولات موجود نیست")
            if item.packs > product["stock_packs"]:
                raise HTTPException(409, f"موجودی {product['name']} کافی نیست")
            line_total = item.packs * product["units_per_pack"] * product["unit_price"]
            total += line_total
            lines.append((product, item.packs, line_total))
        order_number = f"HJ-{datetime.now():%y%m%d}-{secrets.randbelow(9000)+1000}"
        payment_status = {"online": "pending", "cod": "cod", "deposit": "deposit_pending"}[payload.payment_method]
        if payload.payment_method in {"online", "deposit"}:
            settings = conn.execute("SELECT * FROM payment_settings WHERE id=1").fetchone()
            if not settings or not settings["enabled"] or not settings["merchant_id"]:
                raise HTTPException(503, "درگاه زرین‌پال هنوز در پنل مدیریت فعال نشده است")
            payment_amount = (total + 5) // 10 if payload.payment_method == "deposit" else total
            callback_url = settings["site_url"].rstrip("/") + "/api/payments/zarinpal/callback?order=" + urllib.parse.quote(order_number)
            description = f"{'بیعانه سفارش' if payload.payment_method == 'deposit' else 'پرداخت سفارش'} {order_number} حک نگار"
            payment_authority, payment_url = request_zarinpal_payment(settings["merchant_id"], payment_amount, callback_url, description, payload.mobile)
        created_at = datetime.now(timezone.utc)
        logo_expires_at = (created_at + timedelta(days=CUSTOMER_LOGO_RETENTION_DAYS)).isoformat() if payload.logo_url else ""
        cursor = conn.execute(
            """INSERT INTO orders(order_number,mobile,shop_name,address,city,shop_phone,instagram,logo_url,notes,bale_chat_id,payment_method,payment_status,status,total_price,logo_expires_at,payment_authority,payment_amount,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (order_number, payload.mobile, payload.shop_name, payload.address, payload.city, payload.shop_phone, payload.instagram,
             payload.logo_url, payload.notes, payload.bale_chat_id.strip(), payload.payment_method, payment_status, "new", total, logo_expires_at, payment_authority, payment_amount, created_at.isoformat()),
        )
        if payload.logo_url:
            conn.execute("INSERT OR IGNORE INTO customer_uploads(url,created_at) VALUES (?,?)", (payload.logo_url, created_at.isoformat()))
            conn.execute("UPDATE customer_uploads SET order_id=?,linked_at=? WHERE url=?", (cursor.lastrowid, created_at.isoformat(), payload.logo_url))
        for product, packs, line_total in lines:
            conn.execute(
                "INSERT INTO order_items(order_id,product_id,product_name,packs,units_per_pack,unit_price,line_total) VALUES (?,?,?,?,?,?,?)",
                (cursor.lastrowid, product["id"], product["name"], packs, product["units_per_pack"], product["unit_price"], line_total),
            )
            conn.execute("UPDATE products SET stock_packs=stock_packs-? WHERE id=?", (packs, product["id"]))
    notify_admin_new_order(order_number, total, payload, lines)
    if payload.bale_chat_id.strip():
        notify_bale_order(payload.bale_chat_id.strip(), f"✅ سفارش شما با کد {order_number} ثبت شد.\nمبلغ کل: {total:,} تومان\nزمان آماده‌شدن سفارش حدود ۲۰ روز است.\nبرای پیگیری، کد سفارش را در همین گفت‌وگو ارسال کنید.")
    return {"order_number": order_number, "total_price": total, "payable_now": (total + 5) // 10 if payload.payment_method == "deposit" else total, "payment_status": payment_status, "payment_url": payment_url}


@app.get("/api/payments/zarinpal/callback")
def zarinpal_callback(order: str, Authority: str = "", Status: str = ""):
    result_path = "/payment-result?order=" + urllib.parse.quote(order)
    with db() as conn:
        current = conn.execute("SELECT * FROM orders WHERE order_number=?", (order,)).fetchone()
        if not current or current["payment_method"] not in {"online", "deposit"}:
            return RedirectResponse(result_path + "&result=not-found", status_code=303)
        if current["payment_status"] in {"paid", "deposit_paid"}:
            return RedirectResponse(result_path + "&result=success", status_code=303)
        if Status.upper() != "OK" or not Authority or not hmac.compare_digest(Authority, current["payment_authority"]):
            conn.execute("UPDATE orders SET payment_status='failed' WHERE id=?", (current["id"],))
            return RedirectResponse(result_path + "&result=cancelled", status_code=303)
        settings = conn.execute("SELECT * FROM payment_settings WHERE id=1").fetchone()
        if not settings or not settings["merchant_id"]:
            return RedirectResponse(result_path + "&result=error", status_code=303)
        try:
            verification = zarinpal_post(ZARINPAL_VERIFY_URL, {"merchant_id": settings["merchant_id"], "amount": int(current["payment_amount"]) * 10, "authority": Authority})
        except HTTPException:
            return RedirectResponse(result_path + "&result=error", status_code=303)
        data = verification.get("data") or {}
        if data.get("code") not in {100, 101}:
            conn.execute("UPDATE orders SET payment_status='failed' WHERE id=?", (current["id"],))
            return RedirectResponse(result_path + "&result=failed", status_code=303)
        paid_status = "deposit_paid" if current["payment_method"] == "deposit" else "paid"
        ref_id = str(data.get("ref_id") or current["payment_ref_id"] or "")
        verified_at = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE orders SET payment_status=?,payment_ref_id=?,payment_verified_at=? WHERE id=?", (paid_status, ref_id, verified_at, current["id"]))
        bale_chat_id = current["bale_chat_id"]
    if bale_chat_id:
        notify_bale_order(bale_chat_id, f"✅ پرداخت سفارش {order} با موفقیت تأیید شد.\nکد پیگیری زرین‌پال: {ref_id}")
    return RedirectResponse(result_path + "&result=success", status_code=303)

@app.get("/api/orders/track/{order_number}")
def track_order(order_number: str):
    with db() as conn:
        order = conn.execute("""SELECT id,order_number,shop_name,payment_method,payment_status,status,total_price,payment_amount,payment_ref_id,payment_verified_at,
          estimated_ready_date,created_at FROM orders WHERE UPPER(order_number)=UPPER(?)""", (order_number.strip(),)).fetchone()
        if not order:
            raise HTTPException(404, "سفارشی با این کد پیدا نشد")
        data = dict(order)
        data["items"] = [dict(item) for item in conn.execute(
            "SELECT product_name,packs,units_per_pack,unit_price,line_total FROM order_items WHERE order_id=? ORDER BY id", (order["id"],)
        )]
        data.pop("id", None)
        return data
@app.post("/api/admin/login")
def login(payload: LoginInput):
    settings = get_sms_settings()
    if settings.get("enabled") and settings.get("verified") and settings.get("api_key") and settings.get("line_number"):
        raise HTTPException(403, "ورود رمز ثابت غیرفعال است؛ با شماره موبایل و کد پیامکی وارد شوید")
    with db() as conn:
        admin = conn.execute("SELECT * FROM admins WHERE username=?", (payload.username,)).fetchone()
    if not admin or not verify_password(payload.password, admin["password_hash"]):
        raise HTTPException(401, "نام کاربری یا رمز عبور نادرست است")
    token = secrets.token_urlsafe(32)
    with db() as conn:
        conn.execute("INSERT INTO admin_sessions(token,admin_id,created_at) VALUES (?,?,?)", (token, admin["id"], datetime.now(timezone.utc).isoformat()))
    return {"token": token, "mobile": OWNER_MOBILE, "role": "owner"}


@app.post("/api/admin/logout")
def logout_admin(authorization: str = Header(default=""), identity=Depends(require_admin)):
    token = authorization.removeprefix("Bearer ")
    with db() as conn:
        conn.execute("DELETE FROM admin_mobile_sessions WHERE token=?", (token,))
        conn.execute("DELETE FROM admin_sessions WHERE token=?", (token,))
    return {"ok": True}
@app.get("/api/admin/categories", dependencies=[Depends(require_admin)])
def admin_categories():
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM categories WHERE active=1 ORDER BY sort_order,id")]


@app.post("/api/admin/categories", dependencies=[Depends(require_admin)])
def add_category(payload: CategoryInput):
    name = payload.name.strip()
    with db() as conn:
        existing = conn.execute("SELECT * FROM categories WHERE name=?", (name,)).fetchone()
        if existing:
            if existing["active"]:
                raise HTTPException(409, "این دسته‌بندی قبلاً ثبت شده است")
            conn.execute("UPDATE categories SET active=1 WHERE id=?", (existing["id"],))
            return {"id": existing["id"], "name": name, "sort_order": existing["sort_order"]}
        sort_order = conn.execute("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM categories").fetchone()[0]
        cursor = conn.execute("INSERT INTO categories(name,sort_order) VALUES (?,?)", (name, sort_order))
        return {"id": cursor.lastrowid, "name": name, "sort_order": sort_order}

@app.delete("/api/admin/categories/{category_id}", dependencies=[Depends(require_admin)])
def delete_category(category_id: int):
    with db() as conn:
        category = conn.execute("SELECT * FROM categories WHERE id=? AND active=1", (category_id,)).fetchone()
        if not category:
            raise HTTPException(404, "دسته‌بندی پیدا نشد")
        conn.execute("UPDATE categories SET active=0 WHERE id=?", (category_id,))
    return {"ok": True}

@app.get("/api/admin/products", dependencies=[Depends(require_admin)])
def admin_products():
    with db() as conn:
        return [serialize_product(conn, p) for p in conn.execute("SELECT * FROM products ORDER BY id DESC")]


@app.post("/api/admin/products", dependencies=[Depends(require_admin)])
def add_product(payload: ProductInput):
    with db() as conn:
        cursor = conn.execute(
            "INSERT INTO products(category_id,name,dimensions,unit_price,units_per_pack,stock_packs,description,active,created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (payload.category_id, payload.name, payload.dimensions, payload.unit_price, payload.units_per_pack, payload.stock_packs, payload.description, int(payload.active), datetime.now(timezone.utc).isoformat()),
        )
        for index, url in enumerate(payload.images or ["/jewelry-box.png"]):
            conn.execute("INSERT INTO product_images(product_id,url,sort_order) VALUES (?,?,?)", (cursor.lastrowid, url, index))
        return {"id": cursor.lastrowid}


@app.put("/api/admin/products/{product_id}", dependencies=[Depends(require_admin)])
def edit_product(product_id: int, payload: ProductInput):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM products WHERE id=?", (product_id,)).fetchone():
            raise HTTPException(404, "محصول پیدا نشد")
        conn.execute(
            "UPDATE products SET category_id=?,name=?,dimensions=?,unit_price=?,units_per_pack=?,stock_packs=?,description=?,active=? WHERE id=?",
            (payload.category_id, payload.name, payload.dimensions, payload.unit_price, payload.units_per_pack, payload.stock_packs, payload.description, int(payload.active), product_id),
        )
        if payload.images:
            conn.execute("DELETE FROM product_images WHERE product_id=?", (product_id,))
            for index, url in enumerate(payload.images):
                conn.execute("INSERT INTO product_images(product_id,url,sort_order) VALUES (?,?,?)", (product_id, url, index))
        return {"ok": True}


@app.delete("/api/admin/products/{product_id}", dependencies=[Depends(require_admin)])
def delete_product(product_id: int):
    with db() as conn:
        conn.execute("UPDATE products SET active=0 WHERE id=?", (product_id,))
    return {"ok": True}


@app.get("/api/admin/orders/{order_id}/logo", dependencies=[Depends(require_admin)])
def download_order_logo(order_id: int):
    with db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            raise HTTPException(404, "سفارش پیدا نشد")
        if not order["logo_url"]:
            raise HTTPException(410, "فایل لوگو قبلاً حذف شده یا برای این سفارش ثبت نشده است")
        file_path = customer_logo_file_path(order["logo_url"])
        if not file_path or not file_path.exists():
            delete_customer_logo(conn, order, "missing")
            raise HTTPException(410, "فایل لوگو روی فضای ذخیره‌سازی موجود نیست")
        downloaded_at = datetime.now(timezone.utc).isoformat()
        conn.execute("UPDATE orders SET logo_downloaded_at=? WHERE id=?", (downloaded_at, order_id))
        download_name = f"{order['order_number']}-logo{file_path.suffix.lower()}"
        media_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
    return FileResponse(file_path, media_type=media_type, filename=download_name)


@app.delete("/api/admin/orders/{order_id}/logo", dependencies=[Depends(require_admin)])
def delete_order_logo(order_id: int):
    with db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not order:
            raise HTTPException(404, "سفارش پیدا نشد")
        if not order["logo_url"]:
            return {"ok": True, "deleted_at": order["logo_deleted_at"], "reason": order["logo_delete_reason"]}
        deleted_at = delete_customer_logo(conn, order, "manual")
    return {"ok": True, "deleted_at": deleted_at, "reason": "manual"}

@app.get("/api/admin/orders", dependencies=[Depends(require_admin)])
def orders():
    cleanup_expired_customer_logos()
    cleanup_abandoned_customer_uploads()
    with db() as conn:
        result = []
        for order in conn.execute("SELECT * FROM orders ORDER BY created_at DESC, id DESC"):
            data = dict(order)
            data["items"] = [dict(i) for i in conn.execute("SELECT * FROM order_items WHERE order_id=?", (order["id"],))]
            result.append(data)
        return result


class OrderUpdateInput(BaseModel):
    status: Literal["new", "confirmed", "production", "shipped", "delivered", "cancelled"] | None = None
    estimated_ready_date: str | None = None


@app.patch("/api/admin/orders/{order_id}", dependencies=[Depends(require_admin)])
def update_order(order_id: int, payload: OrderUpdateInput):
    updates, values = [], []
    if payload.status is not None:
        updates.append("status=?")
        values.append(payload.status)
    if payload.estimated_ready_date is not None:
        updates.append("estimated_ready_date=?")
        values.append(payload.estimated_ready_date)
    if not updates:
        raise HTTPException(400, "حداقل یک مقدار برای ویرایش لازم است")
    values.append(order_id)
    with db() as conn:
        existing = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
        if not existing:
            raise HTTPException(404, "سفارش پیدا نشد")
        conn.execute(f"UPDATE orders SET {', '.join(updates)} WHERE id=?", values)
        updated = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    if updated["bale_chat_id"]:
        notify_bale_order(updated["bale_chat_id"], "🔔 سفارش شما به‌روزرسانی شد.\n" + format_tracking(dict(updated)))
    return {"ok": True}


# The production deployment serves the compiled React application from the
# same process and domain as the API. API and upload routes above keep priority.
if FRONTEND_DIR.is_dir():
    frontend_assets = FRONTEND_DIR / "assets"
    if frontend_assets.is_dir():
        app.mount("/assets", StaticFiles(directory=frontend_assets), name="frontend-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def serve_frontend(full_path: str):
        requested = (FRONTEND_DIR / full_path).resolve()
        try:
            requested.relative_to(FRONTEND_DIR)
        except ValueError:
            raise HTTPException(404, "فایل پیدا نشد")
        if full_path and requested.is_file():
            return FileResponse(requested)
        return FileResponse(FRONTEND_DIR / "index.html")
