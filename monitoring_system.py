
"""
Employee Personal Account Monitoring & Security Control System
Prototype Application
Language: Python
GUI: Tkinter
Database: SQLite

Run:
    python monitoring_system.py

Test login:
    username: admin
    password: admin123
"""

import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime


DB_NAME = "monitoring_system.db"


class Database:
    def __init__(self, db_name=DB_NAME):
        self.conn = sqlite3.connect(db_name)
        self.create_tables()
        self.insert_sample_data()
        self.update_demo_dates()

    def create_tables(self):
        cur = self.conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS administrators (
                admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS employees (
                employee_id INTEGER PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                department TEXT NOT NULL,
                job_title TEXT NOT NULL,
                work_email TEXT NOT NULL,
                employee_status TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_id INTEGER PRIMARY KEY,
                employee_id INTEGER NOT NULL,
                device_name TEXT NOT NULL,
                device_type TEXT NOT NULL,
                operating_system TEXT NOT NULL,
                device_status TEXT NOT NULL,
                last_check_in TEXT,
                FOREIGN KEY(employee_id) REFERENCES employees(employee_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS detection_rules (
                rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_name TEXT NOT NULL,
                rule_category TEXT NOT NULL,
                match_pattern TEXT NOT NULL,
                risk_weight INTEGER NOT NULL,
                rule_status TEXT NOT NULL
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS activity_logs (
                activity_log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                employee_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                rule_id INTEGER,
                activity_type TEXT NOT NULL,
                account_category TEXT,
                domain_accessed TEXT,
                event_time TEXT NOT NULL,
                violation_flag INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(employee_id) REFERENCES employees(employee_id),
                FOREIGN KEY(device_id) REFERENCES devices(device_id),
                FOREIGN KEY(rule_id) REFERENCES detection_rules(rule_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
                activity_log_id INTEGER NOT NULL,
                admin_id INTEGER,
                alert_type TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                alert_status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                resolved_at TEXT,
                review_notes TEXT,
                FOREIGN KEY(activity_log_id) REFERENCES activity_logs(activity_log_id),
                FOREIGN KEY(admin_id) REFERENCES administrators(admin_id)
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                admin_id INTEGER NOT NULL,
                report_name TEXT NOT NULL,
                report_type TEXT NOT NULL,
                date_generated TEXT NOT NULL,
                report_summary TEXT,
                FOREIGN KEY(admin_id) REFERENCES administrators(admin_id)
            )
        """)

        self.conn.commit()

    def insert_sample_data(self):
        cur = self.conn.cursor()
        cur.execute("SELECT COUNT(*) FROM administrators")
        if cur.fetchone()[0] > 0:
            return

        cur.execute("""
            INSERT INTO administrators (username, password, first_name, last_name, role)
            VALUES ('admin', 'admin123', 'System', 'Administrator', 'Security Analyst')
        """)

        employees = [
            (1001, "John", "Smith", "Finance", "Accountant", "jsmith@company.com", "Active"),
            (1002, "Maria", "Lee", "HR", "HR Specialist", "mlee@company.com", "Active"),
            (1003, "David", "Brown", "IT", "Support Analyst", "dbrown@company.com", "Active"),
        ]
        cur.executemany("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?, ?)", employees)

        devices = [
            (2001, 1001, "FIN-LAP-01", "Laptop", "Windows 11", "Active", "2026-05-02 09:00"),
            (2002, 1002, "HR-LAP-04", "Laptop", "Windows 11", "Active", "2026-05-01 09:20"),
            (2003, 1003, "IT-DESK-02", "Desktop", "Windows 10", "Active", "2026-04-30 10:00"),
        ]
        cur.executemany("INSERT INTO devices VALUES (?, ?, ?, ?, ?, ?, ?)", devices)

        rules = [
            ("Personal Gmail Access", "Email", "gmail.com", 10, "Active"),
            ("Cloud Storage Access", "Cloud Storage", "dropbox.com", 5, "Active"),
            ("Social Media Login", "Social Media", "facebook.com", 3, "Active"),
        ]
        cur.executemany("""
            INSERT INTO detection_rules (rule_name, rule_category, match_pattern, risk_weight, rule_status)
            VALUES (?, ?, ?, ?, ?)
        """, rules)

        logs = [
            (1001, 2001, 1, "Browser", "Email", "gmail.com", "2026-04-28 09:15", 1),
            (1002, 2002, 2, "Browser", "Cloud Storage", "dropbox.com", "2026-04-29 10:30", 1),
            (1003, 2003, None, "Login", "Company System", "companyportal.com", "2026-04-30 11:05", 0),
            (1001, 2001, 3, "Account Access", "Social Media", "facebook.com", "2026-05-01 11:40", 1),
            (1002, 2002, 1, "Browser", "Email", "gmail.com", "2026-05-02 08:50", 1),
            (1003, 2003, 2, "Browser", "Cloud Storage", "dropbox.com", "2026-05-02 13:20", 1),
        ]
        cur.executemany("""
            INSERT INTO activity_logs 
            (employee_id, device_id, rule_id, activity_type, account_category, domain_accessed, event_time, violation_flag)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, logs)

        alerts = [
            (1, 1, "Personal Account Usage", "High", "Open", "2026-04-28 09:16", None, ""),
            (2, 1, "Cloud Storage Access", "Medium", "In Review", "2026-04-29 10:31", None, ""),
            (4, None, "Social Media Login", "Low", "Open", "2026-05-01 11:41", None, ""),
            (5, 1, "Personal Account Usage", "High", "Resolved", "2026-05-02 08:51", "2026-05-02 09:10", "Reviewed and resolved."),
            (6, 1, "Cloud Storage Access", "Medium", "Open", "2026-05-02 13:21", None, ""),
        ]
        cur.executemany("""
            INSERT INTO alerts 
            (activity_log_id, admin_id, alert_type, risk_level, alert_status, created_at, resolved_at, review_notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, alerts)

        self.conn.commit()

    def update_demo_dates(self):
        """Keep demo records useful for testing report date ranges.

        The application uses a persistent SQLite file. If the database was
        already created by an older version, the seed data will not be inserted
        again, so this method updates the built-in demo records and adds a few
        missing sample records when needed.
        """
        cur = self.conn.cursor()

        # Device check-ins across multiple dates.
        demo_device_dates = {
            2001: "2026-05-02 09:00",
            2002: "2026-05-01 09:20",
            2003: "2026-04-30 10:00",
        }
        for device_id, new_date in demo_device_dates.items():
            cur.execute(
                "UPDATE devices SET last_check_in=? WHERE device_id=?",
                (new_date, device_id)
            )

        # Activity log event times across several days for report filtering tests.
        demo_logs = {
            1: (1001, 2001, 1, "Browser", "Email", "gmail.com", "2026-04-28 09:15", 1),
            2: (1002, 2002, 2, "Browser", "Cloud Storage", "dropbox.com", "2026-04-29 10:30", 1),
            3: (1003, 2003, None, "Login", "Company System", "companyportal.com", "2026-04-30 11:05", 0),
            4: (1001, 2001, 3, "Account Access", "Social Media", "facebook.com", "2026-05-01 11:40", 1),
            5: (1002, 2002, 1, "Browser", "Email", "gmail.com", "2026-05-02 08:50", 1),
            6: (1003, 2003, 2, "Browser", "Cloud Storage", "dropbox.com", "2026-05-02 13:20", 1),
        }
        for log_id, values in demo_logs.items():
            cur.execute("SELECT COUNT(*) FROM activity_logs WHERE activity_log_id=?", (log_id,))
            exists = cur.fetchone()[0] > 0
            if exists:
                cur.execute("""
                    UPDATE activity_logs
                    SET employee_id=?, device_id=?, rule_id=?, activity_type=?, account_category=?,
                        domain_accessed=?, event_time=?, violation_flag=?
                    WHERE activity_log_id=?
                """, (*values, log_id))
            else:
                cur.execute("""
                    INSERT INTO activity_logs
                    (activity_log_id, employee_id, device_id, rule_id, activity_type, account_category,
                     domain_accessed, event_time, violation_flag)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (log_id, *values))

        # Alerts across multiple dates and statuses for report summary testing.
        demo_alerts = {
            1: (1, 1, "Personal Account Usage", "High", "Open", "2026-04-28 09:16", None, ""),
            2: (2, 1, "Cloud Storage Access", "Medium", "In Review", "2026-04-29 10:31", None, ""),
            3: (4, None, "Social Media Login", "Low", "Open", "2026-05-01 11:41", None, ""),
            4: (5, 1, "Personal Account Usage", "High", "Resolved", "2026-05-02 08:51", "2026-05-02 09:10", "Reviewed and resolved."),
            5: (6, 1, "Cloud Storage Access", "Medium", "Open", "2026-05-02 13:21", None, ""),
        }
        for alert_id, values in demo_alerts.items():
            cur.execute("SELECT COUNT(*) FROM alerts WHERE alert_id=?", (alert_id,))
            exists = cur.fetchone()[0] > 0
            if exists:
                cur.execute("""
                    UPDATE alerts
                    SET activity_log_id=?, admin_id=?, alert_type=?, risk_level=?, alert_status=?,
                        created_at=?, resolved_at=?, review_notes=?
                    WHERE alert_id=?
                """, (*values, alert_id))
            else:
                cur.execute("""
                    INSERT INTO alerts
                    (alert_id, activity_log_id, admin_id, alert_type, risk_level, alert_status,
                     created_at, resolved_at, review_notes)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (alert_id, *values))



        # Reset saved demo reports so old placeholder report periods do not remain
        # in the persistent SQLite database during testing.
        cur.execute("DELETE FROM reports")
        cur.execute("DELETE FROM sqlite_sequence WHERE name='reports'")

        # Fresh sample saved reports using the same demo activity/alert dates.
        sample_report_summaries = {
            1: (
                1,
                "Activity Summary Report",
                "Activity Summary",
                "2026-04-30 12:10 PM",
                "Activity Summary\n"
                "Reporting Period: 2026-04-28 to 2026-04-30\n"
                "Risk Level: All Risk Levels\n"
                "Total Activity Logs: 3\n"
                "Flagged Activity Logs: 2\n"
                "Total Alerts: 2\n"
                "High Risk Alerts: 1\n"
                "Medium Risk Alerts: 1\n"
                "Low Risk Alerts: 0\n"
                "Resolved Alerts: 0\n\n"
                "Recommendation: Review open high-risk alerts first and update detection rules when needed."
            ),
            2: (
                1,
                "High Risk Activity Report",
                "Risk Summary",
                "2026-05-01 12:30 PM",
                "Risk Summary\n"
                "Reporting Period: 2026-05-01 to 2026-05-02\n"
                "Risk Level: High\n"
                "Total Activity Logs: 3\n"
                "Flagged Activity Logs: 3\n"
                "Total Alerts: 3\n"
                "High Risk Alerts: 1\n"
                "Medium Risk Alerts: 0\n"
                "Low Risk Alerts: 0\n"
                "Resolved Alerts: 1\n\n"
                "Recommendation: Review open high-risk alerts first and update detection rules when needed."
            ),
            3: (
                1,
                "Full Period Compliance Report",
                "Compliance Report",
                "2026-05-02 12:45 PM",
                "Compliance Report\n"
                "Reporting Period: 2026-04-28 to 2026-05-02\n"
                "Risk Level: All Risk Levels\n"
                "Total Activity Logs: 6\n"
                "Flagged Activity Logs: 5\n"
                "Total Alerts: 5\n"
                "High Risk Alerts: 2\n"
                "Medium Risk Alerts: 2\n"
                "Low Risk Alerts: 1\n"
                "Resolved Alerts: 1\n\n"
                "Recommendation: Review open high-risk alerts first and update detection rules when needed."
            ),
        }
        for report_id, values in sample_report_summaries.items():
            cur.execute("SELECT COUNT(*) FROM reports WHERE report_id=?", (report_id,))
            exists = cur.fetchone()[0] > 0
            if exists:
                cur.execute("""
                    UPDATE reports
                    SET admin_id=?, report_name=?, report_type=?, date_generated=?, report_summary=?
                    WHERE report_id=?
                """, (*values, report_id))
            else:
                cur.execute("""
                    INSERT INTO reports
                    (report_id, admin_id, report_name, report_type, date_generated, report_summary)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (report_id, *values))

        self.conn.commit()

    def query(self, sql, params=()):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur.fetchall()

    def execute(self, sql, params=()):
        cur = self.conn.cursor()
        cur.execute(sql, params)
        self.conn.commit()
        return cur.lastrowid


class MonitoringApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Employee Personal Account Monitoring & Security Control System")
        self.root.geometry("1080x720")
        self.root.configure(bg="#eef3f7")
        self.db = Database()
        self.current_admin_id = None
        self.current_admin_name = None
        self.setup_style()
        self.show_login()

    def setup_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        style.configure("Treeview", rowheight=26)

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def create_header(self, subtitle):
        header = tk.Frame(self.root, bg="#0f5f78", height=75)
        header.pack(fill="x")
        tk.Label(
            header,
            text="Employee Personal Account Monitoring & Security Control System",
            bg="#0f5f78",
            fg="white",
            font=("Arial", 18, "bold")
        ).pack(pady=(12, 2))
        tk.Label(header, text=subtitle, bg="#0f5f78", fg="white", font=("Arial", 11)).pack()

    def create_main_frame(self):
        frame = tk.Frame(self.root, bg="white", padx=25, pady=25)
        frame.pack(fill="both", expand=True, padx=30, pady=25)
        return frame

    def create_tree(self, parent, columns, height=8):
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=height)
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=130, anchor="center")

        # Color coding improves readability for administrators.
        # Only the text is colored: Red = higher concern, Orange = medium concern, Green = normal/resolved.
        tree.tag_configure("high_risk", foreground="#c00000")
        tree.tag_configure("medium_risk", foreground="#c66a00")
        tree.tag_configure("low_risk", foreground="#1f7a4d")

        tree.tag_configure("violation_yes", foreground="#c00000")
        tree.tag_configure("violation_no", foreground="#1f7a4d")

        tree.tag_configure("status_open", foreground="#c00000")
        tree.tag_configure("status_review", foreground="#c66a00")
        tree.tag_configure("status_resolved", foreground="#1f7a4d")
        tree.tag_configure("status_active", foreground="#1f7a4d")
        tree.tag_configure("status_inactive", foreground="#666666")

        tree.pack(fill="both", expand=True)
        return tree

    def get_risk_tag(self, risk_level):
        """Return the row color tag based on risk level."""
        risk = str(risk_level).strip().lower()
        if risk == "high":
            return "high_risk"
        if risk == "medium":
            return "medium_risk"
        if risk == "low":
            return "low_risk"
        return ""

    def get_violation_tag(self, violation):
        """Return the row color tag based on violation status."""
        value = str(violation).strip().lower()
        if value == "yes":
            return "violation_yes"
        if value == "no":
            return "violation_no"
        return ""

    def get_status_tag(self, status):
        """Return the row color tag based on alert/rule status."""
        value = str(status).strip().lower()
        if value == "open":
            return "status_open"
        if value == "in review":
            return "status_review"
        if value == "resolved":
            return "status_resolved"
        if value == "active":
            return "status_active"
        if value == "inactive":
            return "status_inactive"
        return ""

    def get_weight_tag(self, weight):
        """Return the row color tag based on numeric risk weight."""
        try:
            value = int(weight)
            if value >= 8:
                return "high_risk"
            if value >= 4:
                return "medium_risk"
            return "low_risk"
        except (TypeError, ValueError):
            return ""

    def format_risk_level(self, risk_level):
        """Show risk color only in the Risk Level field."""
        risk = str(risk_level).strip()
        risk_lower = risk.lower()
        if risk_lower == "high":
            return f"🔴 {risk}"
        if risk_lower == "medium":
            return f"🟠 {risk}"
        if risk_lower == "low":
            return f"🟢 {risk}"
        return risk

    def format_violation(self, violation):
        """Show violation color only in the Violation field."""
        value = str(violation).strip()
        value_lower = value.lower()
        if value_lower == "yes":
            return f"🔴 {value}"
        if value_lower == "no":
            return f"🟢 {value}"
        return value

    def format_risk_weight(self, weight):
        """Show risk color only in the Risk Weight field."""
        try:
            value = int(str(weight).replace("🔴", "").replace("🟠", "").replace("🟢", "").strip())
            if value >= 8:
                return f"🔴 {value}"
            if value >= 4:
                return f"🟠 {value}"
            return f"🟢 {value}"
        except (TypeError, ValueError):
            return str(weight)

    def plain_value(self, value):
        """Remove display-only icons before saving values back to the database."""
        return str(value).replace("🔴", "").replace("🟠", "").replace("🟢", "").strip()

    def back_button(self, frame):
        tk.Button(
            frame,
            text="Back to Dashboard",
            bg="#f7fbfd",
            fg="#0f5f78",
            font=("Arial", 10, "bold"),
            command=self.show_dashboard
        ).pack(anchor="e", pady=(0, 15))

    def show_login(self):
        self.clear_window()
        self.create_header("Administrator Login")
        frame = self.create_main_frame()

        tk.Label(frame, text="Sign In", bg="white", font=("Arial", 20, "bold")).pack(pady=(20, 10))
        tk.Label(
            frame,
            text="Only authorized administrators can access the monitoring system.",
            bg="white",
            font=("Arial", 11)
        ).pack(pady=(0, 20))

        form = tk.Frame(frame, bg="white")
        form.pack(pady=10)

        tk.Label(form, text="Username", bg="white", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=6)
        username = tk.Entry(form, width=35)
        username.grid(row=1, column=0, pady=6)

        tk.Label(form, text="Password", bg="white", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", pady=6)
        password = tk.Entry(form, width=35, show="*")
        password.grid(row=3, column=0, pady=6)

        tk.Label(
            frame,
            text="Test login: username = admin, password = admin123",
            bg="white",
            fg="#52616b",
            font=("Arial", 9)
        ).pack(pady=8)

        def login():
            user = username.get().strip()
            pwd = password.get().strip()
            result = self.db.query(
                "SELECT admin_id, first_name, last_name FROM administrators WHERE username=? AND password=?",
                (user, pwd)
            )
            if result:
                self.current_admin_id = result[0][0]
                self.current_admin_name = f"{result[0][1]} {result[0][2]}"
                messagebox.showinfo("Login Successful", "Access granted. Opening dashboard.")
                self.show_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid username or password.")

        tk.Button(
            frame,
            text="Login",
            bg="#0f5f78",
            fg="#0f5f78",
            font=("Arial", 11, "bold"),
            width=25,
            command=login
        ).pack(pady=15)

    def show_dashboard(self):
        self.clear_window()
        self.create_header("Administrator Dashboard")
        frame = self.create_main_frame()

        tk.Label(frame, text=f"Welcome, {self.current_admin_name}", bg="white", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(frame, text="Select a system function below.", bg="white", fg="#52616b").pack(anchor="w", pady=(5, 20))

        nav = tk.Frame(frame, bg="white")
        nav.pack(fill="x", pady=10)

        buttons = [
            ("View Activity Logs", self.show_activity_logs),
            ("Manage Detection Rules", self.show_detection_rules),
            ("Review Alerts", self.show_alerts),
            ("Generate Reports", self.show_reports),
            ("Logout", self.show_login),
        ]

        for i, (text, command) in enumerate(buttons):
            tk.Button(
                nav,
                text=text,
                width=22,
                bg="#e8f4f8",
                fg="#0f5f78",
                font=("Arial", 10, "bold"),
                command=command
            ).grid(row=0, column=i, padx=6, pady=8)

        summary = tk.Frame(frame, bg="white")
        summary.pack(fill="x", pady=25)

        total_logs = self.db.query("SELECT COUNT(*) FROM activity_logs")[0][0]
        open_alerts = self.db.query("SELECT COUNT(*) FROM alerts WHERE alert_status='Open'")[0][0]
        active_rules = self.db.query("SELECT COUNT(*) FROM detection_rules WHERE rule_status='Active'")[0][0]
        high_risk = self.db.query("SELECT COUNT(*) FROM alerts WHERE risk_level='High'")[0][0]

        self.summary_card(summary, "Total Activity Logs", total_logs, 0)
        self.summary_card(summary, "Open Alerts", open_alerts, 1)
        self.summary_card(summary, "Active Detection Rules", active_rules, 2)
        self.summary_card(summary, "High Risk Alerts", high_risk, 3)

        tk.Label(frame, text="Recent Alerts", bg="white", font=("Arial", 15, "bold")).pack(anchor="w", pady=(20, 10))
        columns = ("Alert ID", "Employee ID", "Risk Level", "Status", "Created At")
        tree = self.create_tree(frame, columns)

        rows = self.db.query("""
            SELECT alerts.alert_id, activity_logs.employee_id, alerts.risk_level, alerts.alert_status, alerts.created_at
            FROM alerts
            JOIN activity_logs ON alerts.activity_log_id = activity_logs.activity_log_id
            ORDER BY alerts.alert_id DESC
        """)

        for row in rows:
            display_row = list(row)
            display_row[2] = self.format_risk_level(display_row[2])
            tree.insert("", "end", values=display_row)

    def summary_card(self, parent, title, value, col):
        card = tk.Frame(parent, bg="#f7fbfd", bd=1, relief="solid", padx=18, pady=18)
        card.grid(row=0, column=col, padx=8, sticky="nsew")
        parent.grid_columnconfigure(col, weight=1)
        tk.Label(card, text=title, bg="#f7fbfd", fg="#52616b", font=("Arial", 10, "bold")).pack()
        tk.Label(card, text=str(value), bg="#f7fbfd", fg="#0f5f78", font=("Arial", 22, "bold")).pack(pady=6)

    def show_activity_logs(self):
        self.clear_window()
        self.create_header("Activity Logs")
        frame = self.create_main_frame()
        self.back_button(frame)

        tk.Label(frame, text="Activity Logs", bg="white", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(frame, text="Search and review employee activity records.", bg="white", fg="#52616b").pack(anchor="w", pady=(5, 15))

        filter_frame = tk.Frame(frame, bg="#f7fbfd", padx=15, pady=15)
        filter_frame.pack(fill="x", pady=10)

        tk.Label(filter_frame, text="Employee ID:", bg="#f7fbfd").grid(row=0, column=0, padx=5)
        emp_entry = tk.Entry(filter_frame, width=15)
        emp_entry.grid(row=0, column=1, padx=5)

        tk.Label(filter_frame, text="Activity Type:", bg="#f7fbfd").grid(row=0, column=2, padx=5)
        type_box = ttk.Combobox(filter_frame, values=["All", "Login", "Browser", "Account Access"], width=18)
        type_box.set("All")
        type_box.grid(row=0, column=3, padx=5)

        columns = ("Log ID", "Employee ID", "Device ID", "Activity Type", "Category", "Domain", "Event Time", "Violation")
        tree = self.create_tree(frame, columns, height=12)

        def load_logs():
            for item in tree.get_children():
                tree.delete(item)

            emp_id = emp_entry.get().strip()
            act_type = type_box.get()
            sql = """
                SELECT activity_log_id, employee_id, device_id, activity_type, account_category,
                       domain_accessed, event_time,
                       CASE violation_flag WHEN 1 THEN 'Yes' ELSE 'No' END
                FROM activity_logs
                WHERE 1=1
            """
            params = []

            if emp_id:
                sql += " AND employee_id=?"
                params.append(emp_id)

            if act_type != "All":
                sql += " AND activity_type=?"
                params.append(act_type)

            rows = self.db.query(sql, params)
            for row in rows:
                display_row = list(row)
                display_row[7] = self.format_violation(display_row[7])
                tree.insert("", "end", values=display_row)

        tk.Button(filter_frame, text="Search Logs", bg="#0f5f78", fg="#0f5f78", command=load_logs).grid(row=0, column=4, padx=10)
        load_logs()

    def show_detection_rules(self):
        self.clear_window()
        self.create_header("Detection Rules Management")
        frame = self.create_main_frame()
        self.back_button(frame)

        tk.Label(frame, text="Detection Rules Management", bg="white", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(frame, text="Add, select, and update rules used to detect personal account usage.", bg="white", fg="#52616b").pack(anchor="w", pady=(5, 15))

        form = tk.Frame(frame, bg="#f7fbfd", padx=15, pady=15)
        form.pack(fill="x", pady=10)

        selected_rule_id = tk.StringVar(value="")
        fields = {}
        labels = ["Rule Name", "Category", "Match Pattern", "Risk Weight", "Status"]
        values = {
            "Category": ["Email", "Cloud Storage", "Social Media", "Login Pattern"],
            "Risk Weight": ["1", "3", "5", "10"],
            "Status": ["Active", "Inactive"]
        }

        for i, label in enumerate(labels):
            tk.Label(form, text=label, bg="#f7fbfd").grid(row=0, column=i, padx=5, sticky="w")
            if label in values:
                widget = ttk.Combobox(form, values=values[label], width=18)
                if label == "Risk Weight":
                    widget.set("10")
                else:
                    widget.set(values[label][0])
            else:
                widget = tk.Entry(form, width=20)
            widget.grid(row=1, column=i, padx=5, pady=5)
            fields[label] = widget

        columns = ("Rule ID", "Rule Name", "Category", "Match Pattern", "Risk Weight", "Status")
        tree = self.create_tree(frame, columns, height=10)

        def clear_form():
            """Clear the form so the next save creates a new rule."""
            selected_rule_id.set("")
            fields["Rule Name"].delete(0, tk.END)
            fields["Match Pattern"].delete(0, tk.END)
            fields["Category"].set(values["Category"][0])
            fields["Risk Weight"].set("10")
            fields["Status"].set(values["Status"][0])
            save_button.config(text="Save Rule")
            tree.selection_remove(tree.selection())

        def load_rules():
            for item in tree.get_children():
                tree.delete(item)
            rows = self.db.query("""
                SELECT rule_id, rule_name, rule_category, match_pattern, risk_weight, rule_status
                FROM detection_rules
                ORDER BY rule_id
            """)
            for row in rows:
                display_row = list(row)
                display_row[4] = self.format_risk_weight(display_row[4])
                tree.insert("", "end", values=display_row)

        def select_rule(_event=None):
            """Load the selected rule into the form for editing."""
            selected = tree.selection()
            if not selected:
                return

            row = tree.item(selected[0], "values")
            selected_rule_id.set(row[0])

            fields["Rule Name"].delete(0, tk.END)
            fields["Rule Name"].insert(0, row[1])
            fields["Category"].set(self.plain_value(row[2]))
            fields["Match Pattern"].delete(0, tk.END)
            fields["Match Pattern"].insert(0, self.plain_value(row[3]))
            fields["Risk Weight"].set(self.plain_value(row[4]))
            fields["Status"].set(self.plain_value(row[5]))
            save_button.config(text="Update Rule")

        def save_rule():
            rule_name = fields["Rule Name"].get().strip()
            category = fields["Category"].get()
            match_pattern = fields["Match Pattern"].get().strip()
            risk_weight = int(fields["Risk Weight"].get())
            status = fields["Status"].get()
            rule_id = selected_rule_id.get().strip()

            if not rule_name or not match_pattern:
                messagebox.showwarning("Missing Information", "Rule Name and Match Pattern are required.")
                return

            if rule_id:
                self.db.execute("""
                    UPDATE detection_rules
                    SET rule_name=?, rule_category=?, match_pattern=?, risk_weight=?, rule_status=?
                    WHERE rule_id=?
                """, (rule_name, category, match_pattern, risk_weight, status, rule_id))
                messagebox.showinfo("Rule Updated", "Detection rule was updated successfully.")
            else:
                duplicate = self.db.query("""
                    SELECT rule_id
                    FROM detection_rules
                    WHERE LOWER(rule_name)=LOWER(?) AND LOWER(match_pattern)=LOWER(?)
                    LIMIT 1
                """, (rule_name, match_pattern))

                if duplicate:
                    messagebox.showwarning(
                        "Duplicate Rule",
                        "A rule with this name and match pattern already exists. Select the existing rule to update it."
                    )
                    return

                self.db.execute("""
                    INSERT INTO detection_rules (rule_name, rule_category, match_pattern, risk_weight, rule_status)
                    VALUES (?, ?, ?, ?, ?)
                """, (rule_name, category, match_pattern, risk_weight, status))
                messagebox.showinfo("Rule Saved", "Detection rule was saved successfully.")

            load_rules()
            clear_form()

        tree.bind("<<TreeviewSelect>>", select_rule)

        button_frame = tk.Frame(form, bg="#f7fbfd")
        button_frame.grid(row=1, column=5, padx=8)

        save_button = tk.Button(button_frame, text="Save Rule", bg="#0f5f78", fg="#0f5f78", command=save_rule)
        save_button.pack(side="left", padx=(0, 6))

        def delete_rule():
            rule_id = selected_rule_id.get().strip()
            if not rule_id:
                messagebox.showwarning("No Rule Selected", "Please select a detection rule to remove.")
                return

            rule_name = fields["Rule Name"].get().strip() or f"Rule ID {rule_id}"
            confirm = messagebox.askyesno(
                "Remove Rule",
                f"Remove the selected detection rule?\n\n{rule_name}\n\nExisting activity logs will be kept, but their rule reference will be cleared."
            )
            if not confirm:
                return

            self.db.execute("UPDATE activity_logs SET rule_id=NULL WHERE rule_id=?", (rule_id,))
            self.db.execute("DELETE FROM detection_rules WHERE rule_id=?", (rule_id,))
            messagebox.showinfo("Rule Removed", "Detection rule was removed successfully.")
            load_rules()
            clear_form()

        def add_new_rule():
            """Insert the current form values as a new detection rule."""
            # Make sure this action always creates a new rule, even if an existing
            # row was previously selected for editing.
            selected_rule_id.set("")
            tree.selection_remove(tree.selection())

            rule_name = fields["Rule Name"].get().strip()
            category = fields["Category"].get()
            match_pattern = fields["Match Pattern"].get().strip()
            status = fields["Status"].get()

            if not rule_name or not match_pattern:
                messagebox.showwarning("Missing Information", "Rule Name and Match Pattern are required.")
                return

            try:
                risk_weight = int(fields["Risk Weight"].get())
            except ValueError:
                messagebox.showwarning("Invalid Risk Weight", "Risk Weight must be a number.")
                return

            duplicate = self.db.query("""
                SELECT rule_id
                FROM detection_rules
                WHERE LOWER(rule_name)=LOWER(?) AND LOWER(match_pattern)=LOWER(?)
                LIMIT 1
            """, (rule_name, match_pattern))

            if duplicate:
                messagebox.showwarning(
                    "Duplicate Rule",
                    "A rule with this name and match pattern already exists. Select the existing rule to update it."
                )
                return

            self.db.execute("""
                INSERT INTO detection_rules (rule_name, rule_category, match_pattern, risk_weight, rule_status)
                VALUES (?, ?, ?, ?, ?)
            """, (rule_name, category, match_pattern, risk_weight, status))

            messagebox.showinfo("Rule Added", "New detection rule was added successfully.")
            load_rules()
            clear_form()

        tk.Button(button_frame, text="Add New Rule", bg="#f7fbfd", fg="#0f5f78", command=add_new_rule).pack(side="left", padx=(0, 6))

        load_rules()

    def show_alerts(self):
        self.clear_window()
        self.create_header("Alert Management")
        frame = self.create_main_frame()
        self.back_button(frame)

        tk.Label(frame, text="Alert Management", bg="white", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(frame, text="Review alerts and update alert status.", bg="white", fg="#52616b").pack(anchor="w", pady=(5, 15))

        columns = ("Alert ID", "Employee ID", "Log ID", "Alert Type", "Risk Level", "Status", "Created At")
        tree = self.create_tree(frame, columns, height=10)

        def load_alerts():
            for item in tree.get_children():
                tree.delete(item)

            rows = self.db.query("""
                SELECT alerts.alert_id, activity_logs.employee_id, alerts.activity_log_id, alerts.alert_type,
                       alerts.risk_level, alerts.alert_status, alerts.created_at
                FROM alerts
                JOIN activity_logs ON alerts.activity_log_id = activity_logs.activity_log_id
                ORDER BY alerts.alert_id DESC
            """)

            for row in rows:
                display_row = list(row)
                display_row[4] = self.format_risk_level(display_row[4])
                tree.insert("", "end", values=display_row)

        update_frame = tk.Frame(frame, bg="#f7fbfd", padx=15, pady=15)
        update_frame.pack(fill="x", pady=15)

        tk.Label(update_frame, text="Selected Alert ID:", bg="#f7fbfd").grid(row=0, column=0, padx=5)
        alert_id_entry = tk.Entry(update_frame, width=10)
        alert_id_entry.grid(row=0, column=1, padx=5)

        tk.Label(update_frame, text="New Status:", bg="#f7fbfd").grid(row=0, column=2, padx=5)
        status_box = ttk.Combobox(update_frame, values=["Open", "In Review", "Resolved"], width=15)
        status_box.set("In Review")
        status_box.grid(row=0, column=3, padx=5)

        tk.Label(update_frame, text="Review Notes:", bg="#f7fbfd").grid(row=1, column=0, padx=5, pady=8)
        notes_entry = tk.Entry(update_frame, width=70)
        notes_entry.grid(row=1, column=1, columnspan=3, padx=5, pady=8)

        def select_alert(_event=None):
            selected = tree.selection()
            if selected:
                values = tree.item(selected[0], "values")
                alert_id_entry.delete(0, tk.END)
                alert_id_entry.insert(0, values[0])

        def update_alert():
            alert_id = alert_id_entry.get().strip()
            if not alert_id:
                messagebox.showwarning("Missing Alert ID", "Please select or enter an Alert ID.")
                return

            resolved_at = datetime.now().strftime("%Y-%m-%d %H:%M") if status_box.get() == "Resolved" else None

            self.db.execute("""
                UPDATE alerts
                SET alert_status=?, admin_id=?, resolved_at=?, review_notes=?
                WHERE alert_id=?
            """, (status_box.get(), self.current_admin_id, resolved_at, notes_entry.get().strip(), alert_id))

            messagebox.showinfo("Alert Updated", "Alert status was updated successfully.")
            load_alerts()

        tree.bind("<<TreeviewSelect>>", select_alert)
        tk.Button(update_frame, text="Save Review", bg="#0f5f78", fg="#0f5f78", command=update_alert).grid(row=0, column=4, padx=10)

        load_alerts()

    def show_reports(self):
        self.clear_window()
        self.create_header("Reports")
        frame = self.create_main_frame()

        # Top title row: page title on the left, navigation button on the right.
        title_row = tk.Frame(frame, bg="white")
        title_row.pack(fill="x")
        left_title = tk.Frame(title_row, bg="white")
        left_title.pack(side="left", anchor="w")

        tk.Label(left_title, text="Reports", bg="white", fg="#202b36", font=("Arial", 18, "bold")).pack(anchor="w")
        tk.Label(
            left_title,
            text="Generate and review reports based on activity logs, alerts, and risk levels.",
            bg="white",
            fg="#52616b",
            font=("Arial", 10)
        ).pack(anchor="w", pady=(3, 0))

        tk.Button(
            title_row,
            text="Back to Dashboard",
            bg="#f7fbfd",
            fg="#0f5f78",
            activebackground="#e8f4f8",
            activeforeground="#0f5f78",
            font=("Arial", 9, "bold"),
            relief="solid",
            bd=1,
            padx=18,
            pady=8,
            command=self.show_dashboard
        ).pack(side="right", anchor="ne")

        # Informational banner.
        info = tk.Frame(frame, bg="#e5f2f7", height=38)
        info.pack(fill="x", pady=(20, 18))
        info.pack_propagate(False)
        tk.Frame(info, bg="#0f6b83", width=4).pack(side="left", fill="y")
        tk.Label(
            info,
            text="Select report options below to generate a monitoring report for administrator review.",
            bg="#e5f2f7",
            fg="#344b5a",
            font=("Arial", 10)
        ).pack(side="left", padx=14)

        # Report controls card.
        form_card = tk.Frame(frame, bg="#f7fbfd", bd=1, relief="solid", padx=20, pady=18)
        form_card.pack(fill="x")

        tk.Label(
            form_card,
            text="Generate Report",
            bg="#f7fbfd",
            fg="#0f5f78",
            font=("Arial", 14, "bold")
        ).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 12))

        def labeled_field(parent, label, widget, column):
            tk.Label(parent, text=label, bg="#f7fbfd", fg="#344b5a", font=("Arial", 9, "bold")).grid(
                row=1, column=column, sticky="w", padx=(0, 12)
            )
            widget.grid(row=2, column=column, sticky="ew", padx=(0, 12), pady=(4, 12))
            parent.grid_columnconfigure(column, weight=1)

        report_type = ttk.Combobox(
            form_card,
            values=["Alert Summary", "Risk Summary", "Compliance Report", "Activity Summary"],
            width=24,
            state="readonly"
        )
        report_type.set("Alert Summary")
        labeled_field(form_card, "Report Type", report_type, 0)

        risk_level = ttk.Combobox(
            form_card,
            values=["All Risk Levels", "High", "Medium", "Low"],
            width=24,
            state="readonly"
        )
        risk_level.set("All Risk Levels")
        labeled_field(form_card, "Risk Level", risk_level, 1)

        start_date = tk.Entry(form_card, width=24)
        start_date.insert(0, "04/28/2026")
        labeled_field(form_card, "Start Date", start_date, 2)

        end_date = tk.Entry(form_card, width=24)
        end_date.insert(0, "05/02/2026")
        labeled_field(form_card, "End Date", end_date, 3)

        # Summary section.
        tk.Label(frame, text="Report Summary", bg="white", fg="#202b36", font=("Arial", 16, "bold")).pack(
            anchor="w", pady=(20, 6)
        )
        tk.Frame(frame, bg="#0f6b83", height=2).pack(fill="x", pady=(0, 12))

        summary_row = tk.Frame(frame, bg="white")
        summary_row.pack(fill="x")

        summary_labels = {}

        def metric_card(parent, title, column):
            card = tk.Frame(parent, bg="white", bd=1, relief="solid", padx=18, pady=16)
            card.grid(row=0, column=column, sticky="nsew", padx=(0 if column == 0 else 8, 0))
            parent.grid_columnconfigure(column, weight=1)
            tk.Label(card, text=title, bg="white", fg="#52616b", font=("Arial", 10, "bold")).pack()
            value_label = tk.Label(card, text="0", bg="white", fg="#0f5f78", font=("Arial", 22, "bold"))
            value_label.pack(pady=(5, 0))
            return value_label

        summary_labels["total"] = metric_card(summary_row, "Total Alerts", 0)
        summary_labels["high"] = metric_card(summary_row, "High Risk Alerts", 1)
        summary_labels["resolved"] = metric_card(summary_row, "Resolved Alerts", 2)

        # Saved reports table.
        tk.Label(frame, text="Saved Reports", bg="white", fg="#202b36", font=("Arial", 16, "bold")).pack(
            anchor="w", pady=(20, 6)
        )
        tk.Frame(frame, bg="#0f6b83", height=2).pack(fill="x", pady=(0, 12))

        columns = ("Report ID", "Report Name", "Report Type", "Generated By", "Date Generated", "Status", "Action")
        saved_tree = self.create_tree(frame, columns, height=5)

        column_widths = {
            "Report ID": 90,
            "Report Name": 210,
            "Report Type": 150,
            "Generated By": 120,
            "Date Generated": 170,
            "Status": 105,
            "Action": 150
        }
        for col, width in column_widths.items():
            saved_tree.column(col, width=width, anchor="w")
            saved_tree.heading(col, text=col)

        saved_tree.tag_configure("ready", foreground="#1f7a4d")
        saved_tree.tag_configure("processing", foreground="#c66a00")

        footer = tk.Frame(self.root, bg="#eef3f7", height=38)
        footer.pack(fill="x", side="bottom")
        tk.Label(
            footer,
            text="Reports support monitoring review, security decisions, and policy compliance tracking.",
            bg="#eef3f7",
            fg="#52616b",
            font=("Arial", 9)
        ).pack(pady=11)

        def normalize_date(value):
            value = value.strip()
            for fmt in ("%m/%d/%Y", "%Y-%m-%d"):
                try:
                    return datetime.strptime(value, fmt).strftime("%Y-%m-%d")
                except ValueError:
                    pass
            raise ValueError

        def get_selected_report_values():
            selected = saved_tree.selection()
            if not selected:
                messagebox.showwarning("No Report Selected", "Please select a report first.")
                return None
            return saved_tree.item(selected[0], "values")

        def build_sample_report(report_id, report_name, report_type, generated_by, date_generated, status):
            sample_summaries = {
                "RP501": (
                    "Reporting Period: 2026-04-28 to 2026-04-30\n"
                    "Risk Level: All Risk Levels\n"
                    "Total Activity Logs: 3\n"
                    "Flagged Activity Logs: 2\n"
                    "Total Alerts: 2\n"
                    "High Risk Alerts: 1\n"
                    "Medium Risk Alerts: 1\n"
                    "Low Risk Alerts: 0\n"
                    "Resolved Alerts: 0"
                ),
                "RP502": (
                    "Reporting Period: 2026-05-01 to 2026-05-02\n"
                    "Risk Level: High\n"
                    "Total Activity Logs: 3\n"
                    "Flagged Activity Logs: 3\n"
                    "Total Alerts: 1\n"
                    "High Risk Alerts: 1\n"
                    "Medium Risk Alerts: 0\n"
                    "Low Risk Alerts: 0\n"
                    "Resolved Alerts: 1"
                ),
                "RP503": (
                    "Reporting Period: 2026-04-28 to 2026-05-02\n"
                    "Risk Level: All Risk Levels\n"
                    "Total Activity Logs: 6\n"
                    "Flagged Activity Logs: 5\n"
                    "Total Alerts: 5\n"
                    "High Risk Alerts: 2\n"
                    "Medium Risk Alerts: 2\n"
                    "Low Risk Alerts: 1\n"
                    "Resolved Alerts: 1"
                ),
            }
            summary = sample_summaries.get(report_id, sample_summaries["RP501"])
            return (
                f"{report_name}\n"
                f"Report ID: {report_id}\n"
                f"Report Type: {report_type}\n"
                f"Generated By: {generated_by}\n"
                f"Date Generated: {date_generated}\n"
                f"Status: {status}\n\n"
                f"{report_type}\n"
                f"{summary}\n\n"
                "Recommendation: Review open high-risk alerts first and update detection rules when needed."
            )

        def get_report_text(report_values):
            report_id, report_name, report_type_value, generated_by, date_generated, status, _action = report_values

            if status == "Processing":
                return (
                    f"{report_name}\n"
                    f"Report ID: {report_id}\n"
                    f"Status: Processing\n\n"
                    "This report is still processing and is not ready to download yet."
                )

            # Reports created inside the application are stored as RP001, RP002, etc.
            try:
                numeric_id = int(str(report_id).replace("RP", ""))
                rows = self.db.query(
                    """
                    SELECT reports.report_name, reports.report_type, administrators.username,
                           reports.date_generated, reports.report_summary
                    FROM reports
                    JOIN administrators ON reports.admin_id = administrators.admin_id
                    WHERE reports.report_id=?
                    """,
                    (numeric_id,)
                )
                if rows:
                    db_report_name, db_report_type, db_generated_by, db_date_generated, db_summary = rows[0]
                    return (
                        f"{db_report_name}\n"
                        f"Report ID: {report_id}\n"
                        f"Report Type: {db_report_type}\n"
                        f"Generated By: {db_generated_by}\n"
                        f"Date Generated: {db_date_generated}\n"
                        f"Status: Ready\n\n"
                        f"{db_summary}"
                    )
            except ValueError:
                pass

            return build_sample_report(report_id, report_name, report_type_value, generated_by, date_generated, status)

        def view_report(report_values=None):
            if report_values is None:
                report_values = get_selected_report_values()
            if not report_values:
                return

            report_text = get_report_text(report_values)
            report_window = tk.Toplevel(self.root)
            report_window.title(f"View Report - {report_values[0]}")
            report_window.geometry("760x520")
            report_window.configure(bg="white")

            tk.Label(
                report_window,
                text=f"{report_values[1]}",
                bg="white",
                fg="#202b36",
                font=("Arial", 16, "bold")
            ).pack(anchor="w", padx=18, pady=(18, 6))

            text_area = tk.Text(report_window, wrap="word", font=("Arial", 10), padx=12, pady=12)
            text_area.pack(fill="both", expand=True, padx=18, pady=(0, 18))
            text_area.insert("1.0", report_text)
            text_area.config(state="disabled")

        def download_report(report_values=None):
            if report_values is None:
                report_values = get_selected_report_values()
            if not report_values:
                return

            if report_values[5] == "Processing":
                messagebox.showinfo("Report Not Ready", "This report is still processing and cannot be downloaded yet.")
                return

            report_text = get_report_text(report_values)
            safe_name = "".join(ch if ch.isalnum() or ch in (" ", "-", "_") else "_" for ch in report_values[1]).strip()
            default_name = f"{report_values[0]}_{safe_name}.txt"
            file_path = filedialog.asksaveasfilename(
                title="Download Report",
                defaultextension=".txt",
                initialfile=default_name,
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
            )
            if not file_path:
                return

            with open(file_path, "w", encoding="utf-8") as report_file:
                report_file.write(report_text)

            messagebox.showinfo("Download Complete", f"Report downloaded successfully:\n{file_path}")

        def handle_report_action(event):
            row_id = saved_tree.identify_row(event.y)
            column_id = saved_tree.identify_column(event.x)
            if not row_id or column_id != "#7":
                return

            saved_tree.selection_set(row_id)
            values = saved_tree.item(row_id, "values")
            if not values:
                return

            if values[5] == "Processing":
                view_report(values)
                return

            bbox = saved_tree.bbox(row_id, column_id)
            if bbox:
                relative_x = event.x - bbox[0]
                if relative_x < bbox[2] / 2:
                    view_report(values)
                else:
                    download_report(values)

        saved_tree.bind("<Button-1>", handle_report_action)

        def load_summary():
            try:
                start_value = normalize_date(start_date.get()) + " 00:00"
                end_value = normalize_date(end_date.get()) + " 23:59"
            except ValueError:
                return

            selected_risk = risk_level.get()

            base_sql = """
                FROM alerts
                JOIN activity_logs ON alerts.activity_log_id = activity_logs.activity_log_id
                WHERE activity_logs.event_time BETWEEN ? AND ?
            """
            params = [start_value, end_value]

            if selected_risk != "All Risk Levels":
                base_sql += " AND alerts.risk_level=?"
                params.append(selected_risk)

            total_alerts = self.db.query("SELECT COUNT(*) " + base_sql, params)[0][0]
            high_alerts = self.db.query("SELECT COUNT(*) " + base_sql + " AND alerts.risk_level='High'", params)[0][0]
            resolved_alerts = self.db.query("SELECT COUNT(*) " + base_sql + " AND alerts.alert_status='Resolved'", params)[0][0]

            summary_labels["total"].config(text=str(total_alerts))
            summary_labels["high"].config(text=str(high_alerts))
            summary_labels["resolved"].config(text=str(resolved_alerts))

        def extract_report_period(report_summary):
            """Return the reporting-period start and end dates stored in a report summary."""
            for line in str(report_summary).splitlines():
                line = line.strip()
                if line.startswith("Reporting Period:") and " to " in line:
                    period_text = line.split(":", 1)[1].strip()
                    start_text, end_text = period_text.split(" to ", 1)
                    return normalize_date(start_text), normalize_date(end_text)
            return None, None

        def report_matches_selected_filters(report_type_value, report_summary):
            """Only show saved reports whose saved report period fits inside the selected date range."""
            try:
                selected_start = normalize_date(start_date.get())
                selected_end = normalize_date(end_date.get())
                report_start, report_end = extract_report_period(report_summary)
            except ValueError:
                return False

            if not report_start or not report_end:
                return False

            if report_start < selected_start or report_end > selected_end:
                return False

            if report_type.get() and report_type_value != report_type.get():
                return False

            selected_risk = risk_level.get()
            if selected_risk != "All Risk Levels":
                expected_line = f"Risk Level: {selected_risk}"
                if expected_line not in str(report_summary):
                    return False

            return True

        def load_saved_reports():
            for item in saved_tree.get_children():
                saved_tree.delete(item)

            rows = self.db.query("""
                SELECT reports.report_id, reports.report_name, reports.report_type,
                       administrators.username, reports.date_generated, reports.report_summary
                FROM reports
                JOIN administrators ON reports.admin_id = administrators.admin_id
                ORDER BY reports.report_id DESC
            """)

            display_rows = []
            if not rows:
                sample_rows = [
                    ("RP501", "Weekly Alert Summary", "Alert Summary", "Admin01", "2026-04-29 12:10 PM", "Ready", "View   Download"),
                    ("RP502", "High Risk Activity Report", "Risk Summary", "Admin01", "2026-05-01 12:30 PM", "Ready", "View   Download"),
                    ("RP503", "Monthly Compliance Report", "Compliance Report", "Admin02", "2026-05-02 12:45 PM", "Processing", "View Status"),
                ]
                for sample_row in sample_rows:
                    sample_text = build_sample_report(*sample_row[:6])
                    if report_matches_selected_filters(sample_row[2], sample_text):
                        display_rows.append(sample_row)
            else:
                for row in rows:
                    if report_matches_selected_filters(row[2], row[5]):
                        display_rows.append((
                            f"RP{row[0]:03}", row[1], row[2], row[3], row[4],
                            "Ready", "View   Download"
                        ))

            for row in display_rows:
                saved_tree.insert("", "end", values=row)

        def validate_dates():
            try:
                normalize_date(start_date.get())
                normalize_date(end_date.get())
                return True
            except ValueError:
                messagebox.showwarning("Invalid Date", "Please enter dates as MM/DD/YYYY or YYYY-MM-DD.")
                return False

        def generate_report():
            if not validate_dates():
                return

            start_value = normalize_date(start_date.get()) + " 00:00"
            end_value = normalize_date(end_date.get()) + " 23:59"
            selected_risk = risk_level.get()

            base_sql = """
                FROM alerts
                JOIN activity_logs ON alerts.activity_log_id = activity_logs.activity_log_id
                WHERE activity_logs.event_time BETWEEN ? AND ?
            """
            params = [start_value, end_value]

            if selected_risk != "All Risk Levels":
                base_sql += " AND alerts.risk_level=?"
                params.append(selected_risk)

            total_alerts = self.db.query("SELECT COUNT(*) " + base_sql, params)[0][0]
            high_alerts = self.db.query("SELECT COUNT(*) " + base_sql + " AND alerts.risk_level='High'", params)[0][0]
            resolved_alerts = self.db.query("SELECT COUNT(*) " + base_sql + " AND alerts.alert_status='Resolved'", params)[0][0]

            report_summary = (
                f"{report_type.get()}\n"
                f"Reporting Period: {normalize_date(start_date.get())} to {normalize_date(end_date.get())}\n"
                f"Risk Level: {selected_risk}\n"
                f"Total Alerts: {total_alerts}\n"
                f"High Risk Alerts: {high_alerts}\n"
                f"Resolved Alerts: {resolved_alerts}"
            )

            self.db.execute("""
                INSERT INTO reports (admin_id, report_name, report_type, date_generated, report_summary)
                VALUES (?, ?, ?, ?, ?)
            """, (
                self.current_admin_id,
                f"{report_type.get()} Report",
                report_type.get(),
                datetime.now().strftime("%Y-%m-%d %H:%M"),
                report_summary
            ))

            load_summary()
            load_saved_reports()
            messagebox.showinfo("Report Generated", "Report was generated and saved successfully.")

        def clear_options():
            report_type.set("Alert Summary")
            risk_level.set("All Risk Levels")
            start_date.delete(0, tk.END)
            start_date.insert(0, "04/28/2026")
            end_date.delete(0, tk.END)
            end_date.insert(0, "05/02/2026")
            load_summary()
            load_saved_reports()

        tk.Button(
            form_card,
            text="Generate Report",
            bg="#f7fbfd",
            fg="#0f5f78",
            activebackground="#e8f4f8",
            activeforeground="#0f5f78",
            font=("Arial", 10, "bold"),
            relief="solid",
            bd=1,
            padx=18,
            pady=8,
            command=generate_report
        ).grid(row=3, column=0, sticky="w", pady=(2, 0))

        tk.Button(
            form_card,
            text="Clear Options",
            bg="white",
            fg="#0f5f78",
            activebackground="#e8f4f8",
            activeforeground="#0f5f78",
            font=("Arial", 10, "bold"),
            relief="solid",
            bd=1,
            padx=18,
            pady=8,
            command=clear_options
        ).grid(row=3, column=0, sticky="w", padx=(150, 0), pady=(2, 0))

        action_button_row = tk.Frame(frame, bg="white")
        action_button_row.pack(anchor="e", pady=(8, 0))
        tk.Button(
            action_button_row,
            text="View Selected Report",
            bg="#f7fbfd",
            fg="#0f5f78",
            activebackground="#e8f4f8",
            activeforeground="#0f5f78",
            font=("Arial", 9, "bold"),
            relief="solid",
            bd=1,
            padx=12,
            pady=6,
            command=view_report
        ).pack(side="left", padx=(0, 8))
        tk.Button(
            action_button_row,
            text="Download Selected Report",
            bg="#0f6b83",
            fg="white",
            activebackground="#0b5265",
            activeforeground="white",
            font=("Arial", 9, "bold"),
            relief="flat",
            padx=12,
            pady=7,
            command=download_report
        ).pack(side="left")

        load_summary()
        load_saved_reports()


def main():
    root = tk.Tk()
    MonitoringApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
