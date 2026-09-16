from flask import Flask, jsonify, request, send_from_directory
import os
import sqlite3
import uuid
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__, static_folder=".", static_url_path="")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


def get_db():
    db = sqlite3.connect("database.db")
    db.row_factory = sqlite3.Row
    return db


def user_info(user):
    row = dict(user) if isinstance(user, sqlite3.Row) else (user or {})
    return {
        "firstName": row.get("first_name") or "",
        "lastName": row.get("last_name") or "",
        "email": row.get("email") or "",
        "dateOfBirth": row.get("date_of_birth") or "",
        "phone": row.get("phone") or "",
        "address": row.get("address") or "",
        "gender": row.get("gender") or "",
        "role": (row.get("role") or "student").lower(),
        "accountStatus": row.get("account_status") or "Active",
        "profilePicture": row.get("profile_picture") or "gela.jpeg"
    }


def ensure_db_schema():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                date_of_birth TEXT NOT NULL,
                phone TEXT NOT NULL,
                address TEXT NOT NULL,
                gender TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'student',
                profile_picture TEXT NOT NULL DEFAULT 'gela.jpeg'
            )
        """)
        columns = [column["name"] for column in db.execute("PRAGMA table_info(users)")]
        if "role" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'")
        if "profile_picture" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN profile_picture TEXT NOT NULL DEFAULT 'gela.jpeg'")
        if "account_status" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN account_status TEXT NOT NULL DEFAULT 'Active'")
        db.execute("""
            CREATE TABLE IF NOT EXISTS attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                attendance_date TEXT NOT NULL,
                status TEXT NOT NULL,
                UNIQUE(email, attendance_date)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS subject_attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                attendance_date TEXT NOT NULL,
                subject TEXT NOT NULL,
                status TEXT NOT NULL,
                UNIQUE(email, attendance_date, subject)
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                day_of_week INTEGER NOT NULL,
                start_time TEXT NOT NULL
            )
        """)
        if db.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 0:
            db.executemany("INSERT INTO subjects (name, day_of_week, start_time) VALUES (?, ?, ?)", [
                ("Mathematics", 1, "08:00"), ("English", 1, "09:00"),
                ("Science", 2, "08:00"), ("Filipino", 3, "08:00"),
                ("Computer", 4, "08:00"), ("Physical Education", 5, "08:00")
            ])


ensure_db_schema()


@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()

    if not data:
        return jsonify(success=False, message="No data received."), 400

    required = [
        "firstName", "lastName", "email",
        "dateOfBirth", "phone", "address",
        "gender", "password", "role"
    ]

    if not all(data.get(x) for x in required):
        return jsonify(success=False, message="Please complete all fields."), 400

    role = data["role"].lower()
    # Administrator accounts must be created directly in the database, not from
    # the public sign-up form.
    if role not in ("student", "staff"):
        return jsonify(success=False, message="Please select Student or Staff."), 400
    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO users
                (first_name, last_name, email, date_of_birth,
                 phone, address, gender, password, role)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data["firstName"],
                data["lastName"],
                data["email"],
                data["dateOfBirth"],
                data["phone"],
                data["address"],
                data["gender"],
                generate_password_hash(data["password"]),
                role
            ))

        return jsonify(
            success=True,
            message="Account created successfully!"
        )

    except sqlite3.IntegrityError:
        return jsonify(
            success=False,
            message="Email is already registered."
        ), 400


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return jsonify(
            success=False,
            message="No data received."
        ), 400

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify(
            success=False,
            message="Please enter email and password."
        ), 400

    with get_db() as db:
        user = db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email,)
        ).fetchone()

    if not user or not check_password_hash(user["password"], password):
        return jsonify(
            success=False,
            message="Incorrect email or password."
        ), 401

    if user["account_status"] != "Active":
        return jsonify(success=False, message="This account is inactive. Please contact an administrator."), 403

    return jsonify(
        success=True,
        message="Login successful!",
        user=user_info(user)
    )


@app.route("/api/profile", methods=["GET", "PUT"])
def profile():

    if request.method == "GET":
        email = request.args.get("email")

        if not email:
            return jsonify(
                success=False,
                message="Email is required."
            ), 400

        with get_db() as db:
            user = db.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if not user:
            return jsonify(
                success=False,
                message="User not found."
            ), 404

        return jsonify(
            success=True,
            user=user_info(user)
        )

    data = request.get_json()

    required = [
        "email", "firstName", "lastName", "dateOfBirth",
        "phone", "address", "gender"
    ]

    if not data or not all(data.get(field) for field in required):
        return jsonify(
            success=False,
            message="Please complete all profile fields."
        ), 400

    email = data["email"]

    with get_db() as db:
        result = db.execute("""
            UPDATE users SET
            first_name = ?,
            last_name = ?,
            date_of_birth = ?,
            phone = ?,
            address = ?,
            gender = ?
            WHERE email = ?
        """, (
            data["firstName"],
            data["lastName"],
            data["dateOfBirth"],
            data["phone"],
            data["address"],
            data["gender"],
            email
        ))

    if result.rowcount == 0:
        return jsonify(
            success=False,
            message="User not found."
        ), 404

    return jsonify(
        success=True,
        message="Profile updated successfully!"
    )


def is_admin(email):
    if not email:
        return False
    with get_db() as db:
        user = db.execute(
            "SELECT role, account_status FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    if not user:
        return False
    row = dict(user) if isinstance(user, sqlite3.Row) else (user or {})
    status = row.get("account_status") or "Active"
    return bool((row.get("role") or "").lower() == "admin" and status == "Active")


def is_school_user(email):
    if not email:
        return False
    with get_db() as db:
        user = db.execute(
            "SELECT id, account_status FROM users WHERE email = ?",
            (email,)
        ).fetchone()
    if not user:
        return False
    row = dict(user) if isinstance(user, sqlite3.Row) else (user or {})
    status = row.get("account_status") or "Active"
    return bool(status == "Active")


@app.route("/api/subjects", methods=["GET"])
def subjects():
    if not is_school_user(request.args.get("email")):
        return jsonify(success=False, message="Please log in first."), 403
    with get_db() as db:
        rows = db.execute("SELECT * FROM subjects ORDER BY day_of_week, start_time, name").fetchall()
    return jsonify(success=True, subjects=[{
        "id": row["id"], "name": row["name"], "dayOfWeek": row["day_of_week"], "startTime": row["start_time"]
    } for row in rows])


@app.route("/api/admin/subjects", methods=["POST", "PUT", "DELETE"])
def admin_subjects():
    data = request.get_json() or {}
    if not is_admin(data.get("adminEmail")):
        return jsonify(success=False, message="Administrator access is required."), 403

    if request.method == "DELETE":
        with get_db() as db:
            result = db.execute("DELETE FROM subjects WHERE id = ?", (data.get("id"),))
        if result.rowcount == 0:
            return jsonify(success=False, message="Subject not found."), 404
        return jsonify(success=True, message="Subject deleted.")

    name = (data.get("name") or "").strip()
    day = data.get("dayOfWeek")
    start_time = (data.get("startTime") or "").strip()
    if not name or not isinstance(day, int) or day < 1 or day > 5 or not start_time:
        return jsonify(success=False, message="Complete the subject name, weekday, and time."), 400
    try:
        with get_db() as db:
            if request.method == "POST":
                db.execute("INSERT INTO subjects (name, day_of_week, start_time) VALUES (?, ?, ?)", (name, day, start_time))
                message = "Subject added successfully!"
            else:
                result = db.execute("UPDATE subjects SET name = ?, day_of_week = ?, start_time = ? WHERE id = ?", (name, day, start_time, data.get("id")))
                if result.rowcount == 0:
                    return jsonify(success=False, message="Subject not found."), 404
                message = "Subject updated successfully!"
        return jsonify(success=True, message=message)
    except sqlite3.IntegrityError:
        return jsonify(success=False, message="That subject name already exists."), 400


@app.route("/api/admin/subject-attendance", methods=["GET", "PUT"])
def admin_subject_attendance():
    if request.method == "GET":
        admin_email = request.args.get("adminEmail")
    else:
        admin_email = (request.get_json() or {}).get("adminEmail")
    if not is_admin(admin_email):
        return jsonify(success=False, message="Administrator access is required."), 403

    if request.method == "GET":
        with get_db() as db:
            rows = db.execute("""
                SELECT subject_attendance.email, subject_attendance.subject, subject_attendance.status,
                       users.first_name, users.last_name
                FROM subject_attendance JOIN users ON users.email = subject_attendance.email
                WHERE subject_attendance.attendance_date = ?
                ORDER BY users.last_name, users.first_name, subject_attendance.subject
            """, (date.today().isoformat(),)).fetchall()
        return jsonify(success=True, records=[dict(row) for row in rows])

    data = request.get_json() or {}
    email, subject, status = data.get("email"), (data.get("subject") or "").strip(), data.get("status")
    if not email or not subject or status not in ("Present", "Late", "Absent"):
        return jsonify(success=False, message="Invalid attendance details."), 400
    with get_db() as db:
        result = db.execute("""
            UPDATE subject_attendance SET status = ?
            WHERE email = ? AND subject = ? AND attendance_date = ?
        """, (status, email, subject, date.today().isoformat()))
    if result.rowcount == 0:
        return jsonify(success=False, message="Attendance record not found."), 404
    return jsonify(success=True, message="Attendance updated successfully!")


@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    if not is_admin(request.args.get("adminEmail")):
        return jsonify(success=False, message="Administrator access is required."), 403

    with get_db() as db:
        users = db.execute("""
            SELECT users.*, (
                SELECT COUNT(*) FROM subject_attendance
                WHERE subject_attendance.email = users.email
                    AND subject_attendance.attendance_date = ?
            ) AS today_attendance
            FROM users WHERE role IN ('student', 'staff')
            ORDER BY role, last_name, first_name
        """, (date.today().isoformat(),)).fetchall()
    response_users = []
    for person in users:
        details = user_info(person)
        details["todayAttendance"] = person["today_attendance"]
        response_users.append(details)
    return jsonify(success=True, users=response_users)


@app.route("/api/admin/users/<path:email>", methods=["PUT"])
def update_user_by_admin(email):
    data = request.get_json() or {}
    if not is_admin(data.get("adminEmail")):
        return jsonify(success=False, message="Administrator access is required."), 403

    required = ["firstName", "lastName", "dateOfBirth", "phone", "address", "gender"]
    if not all(data.get(field) for field in required):
        return jsonify(success=False, message="Please complete all profile fields."), 400

    picture = data.get("profilePicture", "").strip() or "gela.jpeg"
    account_status = data.get("accountStatus", "Active")
    if account_status not in ("Active", "Inactive"):
        return jsonify(success=False, message="Choose a valid account status."), 400
    with get_db() as db:
        result = db.execute("""
            UPDATE users SET first_name = ?, last_name = ?, date_of_birth = ?,
                phone = ?, address = ?, gender = ?, profile_picture = ?, account_status = ?
            WHERE email = ? AND role IN ('student', 'staff')
        """, (data["firstName"], data["lastName"], data["dateOfBirth"],
              data["phone"], data["address"], data["gender"], picture, account_status, email))

    if result.rowcount == 0:
        return jsonify(success=False, message="Student or staff member not found."), 404
    return jsonify(success=True, message="User profile updated successfully!")


@app.route("/api/admin/users/<path:email>/status", methods=["PUT"])
def update_user_status_by_admin(email):
    data = request.get_json() or {}
    if not is_admin(data.get("adminEmail")):
        return jsonify(success=False, message="Administrator access is required."), 403

    account_status = data.get("accountStatus")
    if account_status not in ("Active", "Inactive"):
        return jsonify(success=False, message="Choose a valid account status."), 400

    with get_db() as db:
        result = db.execute(
            "UPDATE users SET account_status = ? WHERE email = ? AND role IN ('student', 'staff')",
            (account_status, email)
        )

    if result.rowcount == 0:
        return jsonify(success=False, message="Student or staff member not found."), 404
    return jsonify(
        success=True,
        message=f"Account {account_status.lower()} successfully!",
        accountStatus=account_status
    )


@app.route("/api/admin/users/<path:email>/picture", methods=["POST"])
def update_user_picture_by_admin(email):

    if not is_admin(request.form.get("adminEmail")):
        return jsonify(success=False, message="Administrator access is required."), 403

    picture = request.files.get("picture")
    if not picture or not picture.filename:
        return jsonify(success=False, message="Please choose an image file."), 400
    if not allowed_image(picture.filename):
        return jsonify(success=False, message="Use a PNG, JPG, JPEG, GIF, or WEBP image."), 400

    with get_db() as db:
        target = db.execute(
            "SELECT id FROM users WHERE email = ? AND role IN ('student', 'staff')",
            (email,)
        ).fetchone()
    if not target:
        return jsonify(success=False, message="Student or staff member not found."), 404

    extension = secure_filename(picture.filename).rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{extension}"
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    picture.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    picture_path = f"uploads/{filename}"

    with get_db() as db:
        db.execute(
            "UPDATE users SET profile_picture = ? WHERE email = ? AND role IN ('student', 'staff')",
            (picture_path, email)
        )
    return jsonify(success=True, message="Profile picture updated successfully!", profilePicture=picture_path)


@app.route("/api/attendance", methods=["GET", "PUT"])
def attendance():
    if request.method == "GET":
        email = request.args.get("email")
        if not email:
            return jsonify(success=False, message="Email is required."), 400

        with get_db() as db:
            record = db.execute(
                "SELECT status FROM attendance WHERE email = ? AND attendance_date = ?",
                (email, date.today().isoformat())
            ).fetchone()
        return jsonify(success=True, status=record["status"] if record else None)

    data = request.get_json() or {}
    email = data.get("email")
    status = data.get("status")
    if status not in ("Present", "Late", "Absent"):
        return jsonify(success=False, message="Choose Present, Late, or Absent."), 400

    with get_db() as db:
        student = db.execute(
            "SELECT id FROM users WHERE email = ? AND role = 'student'", (email,)
        ).fetchone()
        if not student:
            return jsonify(success=False, message="Student account not found."), 404

        existing = db.execute(
            "SELECT id FROM attendance WHERE email = ? AND attendance_date = ?",
            (email, date.today().isoformat())
        ).fetchone()
        if existing:
            db.execute("UPDATE attendance SET status = ? WHERE id = ?", (status, existing["id"]))
        else:
            db.execute(
                "INSERT INTO attendance (email, attendance_date, status) VALUES (?, ?, ?)",
                (email, date.today().isoformat(), status)
            )

    return jsonify(success=True, message="Attendance updated successfully!", status=status)


@app.route("/api/subject-attendance", methods=["GET", "PUT"])
def subject_attendance():
    if request.method == "GET":
        email = request.args.get("email")
        if not email:
            return jsonify(success=False, message="Email is required."), 400

        with get_db() as db:
            records = db.execute("""
                SELECT subject, status FROM subject_attendance
                WHERE email = ? AND attendance_date = ?
            """, (email, date.today().isoformat())).fetchall()
        return jsonify(success=True, records=[dict(record) for record in records])

    data = request.get_json() or {}
    email = data.get("email")
    subject = (data.get("subject") or "").strip()
    status = data.get("status")
    if not subject or status not in ("Present", "Late", "Absent"):
        return jsonify(success=False, message="Choose a subject and a valid attendance status."), 400

    with get_db() as db:
        student = db.execute(
            "SELECT id FROM users WHERE email = ? AND role = 'student'", (email,)
        ).fetchone()
        if not student:
            return jsonify(success=False, message="Student account not found."), 404

        existing = db.execute("""
            SELECT id FROM subject_attendance
            WHERE email = ? AND attendance_date = ? AND subject = ?
        """, (email, date.today().isoformat(), subject)).fetchone()
        if existing:
            db.execute("UPDATE subject_attendance SET status = ? WHERE id = ?", (status, existing["id"]))
        else:
            db.execute("""
                INSERT INTO subject_attendance (email, attendance_date, subject, status)
                VALUES (?, ?, ?, ?)
            """, (email, date.today().isoformat(), subject, status))

    return jsonify(success=True, message="Subject attendance updated!", subject=subject, status=status)


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
