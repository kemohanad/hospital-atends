import sys
import logging
import bcrypt
import shutil
from datetime import datetime
from threading import Thread
from cryptography.fernet import Fernet

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QTabWidget, QTableWidget, QTableWidgetItem,
                            QPushButton, QLabel, QLineEdit, QMessageBox, QMenuBar, QMenu, QAction)
from PyQt6.QtCore import Qt, pyqtSignal, QObject
from sqlalchemy import create_engine, Column, String, DateTime, Integer, BLOB
from sqlalchemy.orm import declarative_base, sessionmaker
from pyfingerprint.pyfingerprint import PyFingerprint

# -------------------------------
# 1. تكوين قاعدة البيانات
# -------------------------------
Base = declarative_base()
KEY = Fernet.generate_key()  # مفتاح التشفير

class Employee(Base):
    __tablename__ = 'employees'
    id = Column(String, primary_key=True)
    name = Column(String)
    department = Column(String)
    hashed_password = Column(String)
    encrypted_biometric = Column(BLOB)  # بيانات البصمة المشفرة

class AttendanceRecord(Base):
    __tablename__ = 'attendance'
    id = Column(Integer, primary_key=True)
    employee_id = Column(String)
    timestamp = Column(DateTime)
    status = Column(String)

engine = create_engine('sqlite:///hospital.db')
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

# -------------------------------
# 2. واجهة تسجيل الدخول
# -------------------------------
class LoginWindow(QWidget):
    login_success = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.setWindowTitle("تسجيل الدخول")
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        self.username = QLineEdit()
        self.username.setPlaceholderText("اسم المستخدم")
        self.password = QLineEdit()
        self.password.setPlaceholderText("كلمة المرور")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        
        login_btn = QPushButton("دخول")
        login_btn.clicked.connect(self.authenticate)
        
        layout.addWidget(self.username)
        layout.addWidget(self.password)
        layout.addWidget(login_btn)
        
        self.setLayout(layout)

    def authenticate(self):
        with Session() as session:
            emp = session.query(Employee).filter_by(id=self.username.text()).first()
            if emp and bcrypt.checkpw(self.password.text().encode(), emp.hashed_password.encode()):
                self.login_success.emit()
            else:
                QMessageBox.warning(self, "خطأ", "بيانات الدخول غير صحيحة!")

# -------------------------------
# 3. نظام النسخ الاحتياطي
# -------------------------------
class BackupManager:
    @staticmethod
    def create_backup():
        timestamp = datetime.now().strftime("%Y%m%d_%H%M")
        shutil.copyfile('hospital.db', f'backups/backup_{timestamp}.db')
        logging.info("تم إنشاء نسخة احتياطية")

# -------------------------------
# 4. واجهة إدارة الرواتب
# -------------------------------
class PayrollTab(QWidget):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        self.export_btn = QPushButton("تصدير بيانات الرواتب")
        self.export_btn.clicked.connect(self.export_payroll)
        layout.addWidget(self.export_btn)
        self.setLayout(layout)

    def export_payroll(self):
        with Session() as session:
            records = session.query(AttendanceRecord).all()
            # تصدير إلى CSV (مثال مبسط)
            with open('payroll_export.csv', 'w') as f:
                f.write("Employee ID,Date,Status\n")
                for record in records:
                    f.write(f"{record.employee_id},{record.timestamp},{record.status}\n")
            QMessageBox.information(self, "تم التصدير", "تم تصدير بيانات الرواتب بنجاح")

# -------------------------------
# 5. الواجهة الرئيسية مع القائمة
# -------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("نظام إدارة الحضور المتكامل")
        self.setGeometry(100, 100, 1200, 800)
        self.setup_menu()
        self.setup_ui()

    def setup_menu(self):
        menu_bar = QMenuBar()
        file_menu = QMenu("الملف", self)
        
        backup_action = QAction("إنشاء نسخة احتياطية", self)
        backup_action.triggered.connect(BackupManager.create_backup)
        
        file_menu.addAction(backup_action)
        menu_bar.addMenu(file_menu)
        
        self.setMenuBar(menu_bar)

    def setup_ui(self):
        tabs = QTabWidget()
        
        # تبويب الحضور
        attendance_tab = QWidget()
        attendance_layout = QVBoxLayout()
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["الاسم", "القسم", "الوقت"])
        attendance_layout.addWidget(self.table)
        attendance_tab.setLayout(attendance_layout)
        
        # تبويب الرواتب
        payroll_tab = PayrollTab()
        
        tabs.addTab(attendance_tab, "سجلات الحضور")
        tabs.addTab(payroll_tab, "إدارة الرواتب")
        
        self.setCentralWidget(tabs)
        self.update_table()

    def update_table(self):
        self.table.setRowCount(0)
        with Session() as session:
            records = session.query(AttendanceRecord).order_by(AttendanceRecord.timestamp.desc()).limit(50)
            for row, record in enumerate(records):
                employee = session.query(Employee).filter_by(id=record.employee_id).first()
                self.table.insertRow(row)
                self.table.setItem(row, 0, QTableWidgetItem(employee.name))
                self.table.setItem(row, 1, QTableWidgetItem(employee.department))
                self.table.setItem(row, 2, QTableWidgetItem(str(record.timestamp)))

# -------------------------------
# 6. نظام البصمة مع التشفير
# -------------------------------
class BiometricManager(QObject):
    fingerprint_detected = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.device = PyFingerprint('/dev/ttyUSB0', 57600)
        self.cipher = Fernet(KEY)
        self.running = True

    def enroll_fingerprint(self, employee_id, fingerprint_data):
        encrypted_data = self.cipher.encrypt(fingerprint_data)
        with Session() as session:
            emp = session.query(Employee).filter_by(id=employee_id).first()
            emp.encrypted_biometric = encrypted_data
            session.commit()

    def start_scan(self):
        while self.running:
            try:
                if self.device.readImage():
                    self.device.convertImage(0x01)
                    template = self.device.downloadCharacteristics()
                    self._match_template(template)
            except Exception as e:
                logging.error(f"Biometric Error: {e}")

    def _match_template(self, template):
        with Session() as session:
            employees = session.query(Employee).all()
            for emp in employees:
                if emp.encrypted_biometric:
                    decrypted = self.cipher.decrypt(emp.encrypted_biometric)
                    if decrypted == bytes(str(template), 'utf-8'):
                        self.fingerprint_detected.emit(emp.id)
                        return

# -------------------------------
# 7. النظام الرئيسي
# -------------------------------
class HospitalSystem(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        
        self.login_window = LoginWindow()
        self.main_window = None
        self.biometric_manager = BiometricManager()
        
        self.login_window.login_success.connect(self.show_main)
        self.login_window.show()
        
        self.scan_thread = Thread(target=self.biometric_manager.start_scan)
        self.scan_thread.start()

    def show_main(self):
        self.login_window.close()
        self.main_window = MainWindow()
        self.biometric_manager.fingerprint_detected.connect(self.handle_attendance)
        self.main_window.show()

    def handle_attendance(self, employee_id):
        with Session() as session:
            new_record = AttendanceRecord(
                employee_id=employee_id,
                timestamp=datetime.now(),
                status="Present"
            )
            session.add(new_record)
            session.commit()
            self.main_window.update_table()

# -------------------------------
# 8. التشغيل والتهيئة
# -------------------------------
if __name__ == "__main__":
    # تهيئة بيانات تجريبية
    with Session() as session:
        if not session.query(Employee).first():
            emp = Employee(
                id="admin",
                name="مدير النظام",
                department="الإدارة",
                hashed_password=bcrypt.hashpw("admin123".encode(), bcrypt.gensalt()).decode(),
                encrypted_biometric=None
            )
            session.add(emp)
            session.commit()

    # تشغيل التطبيق
    app = HospitalSystem(sys.argv)
    sys.exit(app.exec())