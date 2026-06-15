"""
accounts.py
ชั้น business logic ของระบบบัญชีผู้ใช้
ทำหน้าที่เชื่อม security.py (รหัสผ่าน) เข้ากับ storage.py (เก็บข้อมูล)
แยกออกมาเป็น module เดี่ยว ๆ ตั้งแต่ EP.7 (Refactoring)

หลักการ: app.py (routes) จะเรียกใช้ฟังก์ชันในไฟล์นี้เท่านั้น
ไม่ยุ่งกับ storage หรือ security ตรง ๆ
"""

from datetime import datetime, timedelta

import security
import storage

# กติกาการล็อกบัญชี (กัน brute-force)
MAX_FAILED_ATTEMPTS = 5          # ผิดติดต่อกันครบเท่านี้ -> ล็อก
LOCK_DURATION_MINUTES = 15       # ล็อกนานเท่านี้


class AccountError(Exception):
    """error กลางของระบบบัญชี ใช้ส่งข้อความให้ผู้ใช้เห็น"""
    pass


def register_user(username: str, password: str) -> None:
    """สมัครสมาชิกใหม่"""
    username = (username or "").strip()
    if not username:
        raise AccountError("กรุณากรอกชื่อผู้ใช้")
    if not password:
        raise AccountError("กรุณากรอกรหัสผ่าน")

    users = storage.load_users()
    if username in users:
        raise AccountError("ชื่อผู้ใช้นี้ถูกใช้แล้ว")

    users[username] = {
        "password_hash": security.hash_password(password),
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    storage.save_users(users)


def _is_locked(user: dict) -> bool:
    """บัญชีนี้กำลังถูกล็อกอยู่หรือไม่ (locked_until ยังอยู่ในอนาคต)"""
    locked_until = user.get("locked_until")
    if not locked_until:
        return False
    return datetime.now() < datetime.fromisoformat(locked_until)


def authenticate(username: str, password: str) -> bool:
    """
    ตรวจสอบ login ว่า username/password ถูกต้องหรือไม่
    พร้อมกลไกล็อกบัญชีชั่วคราวเมื่อใส่รหัสผิดติดต่อกันหลายครั้ง (กัน brute-force)

    - คืน True เมื่อ login สำเร็จ (และรีเซ็ตตัวนับ failed_attempts เป็น 0)
    - คืน False เมื่อรหัสผิดแต่ยังไม่ถึงเกณฑ์ล็อก / ไม่พบผู้ใช้
    - raise AccountError เมื่อบัญชีกำลังถูกล็อกอยู่ (แม้รหัสจะถูกก็เข้าไม่ได้)
    """
    username = (username or "").strip()
    users = storage.load_users()
    user = users.get(username)
    if not user:
        return False

    # ถูกล็อกอยู่ -> ปฏิเสธทันที แม้รหัสจะถูก
    if _is_locked(user):
        raise AccountError(
            f"บัญชีถูกล็อกชั่วคราว เนื่องจากใส่รหัสผิดหลายครั้ง "
            f"กรุณาลองใหม่ภายหลัง (ล็อก {LOCK_DURATION_MINUTES} นาที)"
        )

    if security.verify_password(password, user["password_hash"]):
        # login สำเร็จ -> รีเซ็ตตัวนับและล้างสถานะล็อก
        user["failed_attempts"] = 0
        user["locked_until"] = None
        storage.save_users(users)
        return True

    # รหัสผิด -> นับเพิ่ม และล็อกถ้าครบเกณฑ์
    user["failed_attempts"] = user.get("failed_attempts", 0) + 1
    if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        user["locked_until"] = (
            datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES)
        ).isoformat(timespec="seconds")
    storage.save_users(users)
    return False


def change_password(username: str, old_password: str, new_password: str) -> None:
    """เปลี่ยนรหัสผ่าน: ต้องยืนยันรหัสเดิมให้ถูกก่อน"""
    username = (username or "").strip()
    users = storage.load_users()
    user = users.get(username)
    if not user:
        raise AccountError("ไม่พบผู้ใช้นี้")

    if not security.verify_password(old_password, user["password_hash"]):
        raise AccountError("รหัสผ่านเดิมไม่ถูกต้อง")

    if not new_password:
        raise AccountError("กรุณากรอกรหัสผ่านใหม่")

    user["password_hash"] = security.hash_password(new_password)
    storage.save_users(users)
