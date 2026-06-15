"""
test_lockout.py
เทสต์สำหรับ feature: ล็อกบัญชีชั่วคราวเมื่อ login ผิดหลายครั้ง (กัน brute-force)

กติกา (ตาม Acceptance Criteria):
- login ผิดติดต่อกันครบ 5 ครั้ง -> ล็อกบัญชีนั้นชั่วคราว 15 นาที
- ระหว่างถูกล็อก แม้ใส่รหัสถูก ก็ยังเข้าไม่ได้ และต้องแจ้งว่าบัญชีถูกล็อก
- login สำเร็จเมื่อใด ให้รีเซ็ตตัวนับ failed_attempts กลับเป็น 0
- ข้อมูล failed_attempts / locked_until เก็บไว้กับ user แต่ละคนใน users.json

เขียนแบบ TDD: ต้องแดงก่อน แล้วค่อย implement ให้เขียว
รัน:  pytest tests/test_lockout.py -v
"""

import os
import sys
from datetime import datetime, timedelta

import pytest

# ให้ test มองเห็น module ในโฟลเดอร์โปรเจกต์ (ขึ้นไป 1 ระดับ)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import storage  # noqa: E402
import accounts  # noqa: E402

PASSWORD = "pass1234"
WRONG = "wrongpass"
MAX_FAILED = 5


@pytest.fixture
def db(tmp_path):
    """ฐานข้อมูลชั่วคราวต่อเทสต์ + ผู้ใช้ทดสอบ 1 คนที่สมัครไว้แล้ว"""
    storage.DB_PATH = str(tmp_path / "users.json")
    accounts.register_user("somchai", PASSWORD)
    return storage.DB_PATH


def _fail_n_times(n):
    """พยายาม login ด้วยรหัสผิด n ครั้ง"""
    for _ in range(n):
        try:
            accounts.authenticate("somchai", WRONG)
        except accounts.AccountError:
            # ถ้าโดนล็อกระหว่างทางก็ปล่อยผ่าน (เทสต์แต่ละตัวเช็คเองว่าควรล็อกตอนไหน)
            pass


# ---------- การนับครั้งที่ผิด ----------

def test_failed_attempts_increments_on_wrong_password(db):
    accounts.authenticate("somchai", WRONG)
    users = storage.load_users()
    assert users["somchai"]["failed_attempts"] == 1


def test_failed_attempts_reset_after_successful_login(db):
    # ผิด 4 ครั้ง (ยังไม่ถึงเกณฑ์ล็อก) แล้วครั้งที่ 5 ใส่ถูก
    _fail_n_times(4)
    assert accounts.authenticate("somchai", PASSWORD) is True
    users = storage.load_users()
    assert users["somchai"]["failed_attempts"] == 0


# ---------- การล็อกบัญชี ----------

def test_account_locks_after_5_failed_attempts(db):
    _fail_n_times(MAX_FAILED)
    users = storage.load_users()
    assert users["somchai"].get("locked_until")


def test_locked_account_rejects_even_correct_password(db):
    # ผิดครบ 5 ครั้ง -> ครั้งที่ 6 ใส่ถูก ต้องโดนปฏิเสธ พร้อมข้อความว่าถูกล็อก
    _fail_n_times(MAX_FAILED)
    with pytest.raises(accounts.AccountError) as exc:
        accounts.authenticate("somchai", PASSWORD)
    assert "ล็อก" in str(exc.value)


def test_four_failures_then_correct_still_allows_login(db):
    # ผิด 4 ครั้ง ยังไม่ล็อก -> ครั้งที่ 5 ใส่ถูก ต้องเข้าได้
    _fail_n_times(4)
    assert accounts.authenticate("somchai", PASSWORD) is True


def test_lock_expires_after_duration(db):
    # จำลองว่าเวลาล็อกผ่านไปแล้ว (locked_until อยู่ในอดีต) -> ต้องเข้าได้อีกครั้ง
    _fail_n_times(MAX_FAILED)
    users = storage.load_users()
    users["somchai"]["locked_until"] = (
        datetime.now() - timedelta(minutes=1)
    ).isoformat(timespec="seconds")
    storage.save_users(users)

    assert accounts.authenticate("somchai", PASSWORD) is True
