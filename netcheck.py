import sys
import json
import asyncio
import aiohttp
import platform
import logging
import ssl
import socket
import struct
import time
import pyqrcode
import io
import re
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any, Union
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QPushButton, QListWidget,
    QWidget, QLabel, QLineEdit, QComboBox, QMessageBox, QTextEdit, QListWidgetItem,
    QTabWidget, QGroupBox, QFormLayout, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QToolBar, QStatusBar, QDialog, QFileDialog, QStyleFactory,
    QGraphicsDropShadowEffect, QProgressBar, QCheckBox, QSizePolicy, QScrollArea,
    QStyle, QMenu, QSystemTrayIcon
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QObject, QPropertyAnimation, QEasingCurve, QRectF,
    QRegularExpression, QRegularExpressionMatchIterator, QUrl, QTimer, QSettings,
    QPoint, QSize, QMimeData, QTranslator, QLocale, QLibraryInfo
)
from PyQt6.QtGui import (
    QColor, QPalette, QIcon, QAction, QFont, QTextCharFormat, QSyntaxHighlighter,
    QPainter, QBrush, QPen, QPainterPath, QDesktopServices, QTextCursor, QPixmap,
    QClipboard
)
from PyQt6.QtCharts import (
    QChart, QChartView, QPieSeries, QPieSlice, QBarSet, QBarSeries,
    QBarCategoryAxis, QValueAxis, QStackedBarSeries, QLineSeries, QCategoryAxis
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWebEngineCore import QWebEngineUrlRequestInterceptor
import qasync
from urllib.parse import urlparse

COLORS = {
    "black": "#000000",
    "baby_powder": "#fffffc",
    "khaki": "#beb7a4",
    "orange": "#ff7f11",
    "red": "#ff1b1c",
    "dark_bg": "#121212",
    "medium_bg": "#1e1e1e",
    "light_bg": "#2a2a2a",
    "text_primary": "#fffffc",
    "text_secondary": "#beb7a4",
    "accent": "#ff7f11",
    "success": "#4CAF50",
    "warning": "#FFC107",
    "danger": "#ff1b1c"
}

APP_VERSION = "1.0.5"
APP_NAME = "NetCheck by Etherhaus"
DEFAULT_TIMEOUT = 10
DEFAULT_DNS_SERVER = "8.8.8.8"
TELEGRAM_CHANNEL = "https://t.me/etherhaus"
YOUTUBE_CHANNEL = "https://www.youtube.com/etherhaus"
DONATION_LINK = "https://www.donatty.com/etherhaus"
SUPPORT_EMAIL = "info@etherhaus.ru"
SETTINGS_FILE = "settings.ini"
CUSTOM_SERVICES_FILE = "custom_services.json"
LOG_FILE = "network_checker.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class ModernRoundedWidget(QWidget):
    def __init__(self, parent=None, radius=12, shadow=True, background_color=None):
        super().__init__(parent)
        self.radius = radius
        self.shadow = shadow
        self.background_color = background_color or QColor(COLORS["medium_bg"])
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        if shadow:
            self.shadow_effect = QGraphicsDropShadowEffect(self)
            self.shadow_effect.setBlurRadius(20)
            self.shadow_effect.setXOffset(0)
            self.shadow_effect.setYOffset(3)
            self.shadow_effect.setColor(QColor(0, 0, 0, 80))
            self.setGraphicsEffect(self.shadow_effect)

    def paintEvent(self, event):
        path = QPainterPath()
        rect = QRectF(self.rect())
        path.addRoundedRect(rect, self.radius, self.radius)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setClipPath(path)
        painter.fillPath(path, QBrush(self.background_color))
        pen = QPen(QColor(0, 0, 0, 30), 1)
        painter.setPen(pen)
        painter.drawPath(path)

class ModernJSONHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = [
            (r'".*?"', QColor(COLORS["khaki"])),
            (r'\b\d+\b', QColor(COLORS["orange"])),
            (r'\b(true|false|null)\b', QColor("#9C27B0")),
            (r'\b[A-Za-z0-9_]+(?=\s*:)', QColor("#4DA6FF")),
            (r'\{|\}|\[|\]|,|:', QColor(COLORS["text_secondary"])),
        ]

    def highlightBlock(self, text):
        for pattern, color in self.rules:
            expression = QRegularExpression(pattern)
            iterator = QRegularExpressionMatchIterator(expression.globalMatch(text))
            while iterator.hasNext():
                match = iterator.next()
                format = QTextCharFormat()
                format.setForeground(color)
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class ServiceChecker(QObject):
    progress = pyqtSignal(str, str, str, dict)
    log = pyqtSignal(str)
    update_stats = pyqtSignal(int, int, int)
    update_chart = pyqtSignal(dict)
    finished = pyqtSignal()

    def __init__(self, services: Dict, timeout: int, dns_server: str):
        super().__init__()
        self.services = services
        self.timeout = timeout
        self.dns_server = dns_server
        self.stats = {"total": 0, "available": 0, "blocked": 0, "errors": 0}
        self._canceled = False
        self.chart_data = {}
        self.start_time = None
        self.end_time = None
        self.ssl_context = ssl.create_default_context()

    async def check_tcp_connection(self, host: str, port: int) -> Tuple[bool, str, float]:
        try:
            start_time = datetime.now()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=self.ssl_context if port == 443 else None),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            return True, f"TCP connection successful ({elapsed:.2f} ms)", elapsed
        except asyncio.TimeoutError:
            return False, f"TCP connection timed out after {self.timeout} seconds", 0
        except Exception as e:
            return False, f"TCP connection failed: {str(e)}", 0

    async def check_udp_connection(self, host: str, port: int) -> Tuple[bool, str, float]:
        try:
            start_time = datetime.now()
            loop = asyncio.get_running_loop()
            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    lambda: asyncio.DatagramProtocol(),
                    remote_addr=(host, port)
                ),
                timeout=self.timeout
            )
            transport.sendto(b'ping')
            transport.close()
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            return True, f"UDP connection successful ({elapsed:.2f} ms)", elapsed
        except asyncio.TimeoutError:
            return False, f"UDP connection timed out after {self.timeout} seconds", 0
        except Exception as e:
            return False, f"UDP connection failed: {str(e)}", 0

    async def check_http_request(self, url: str) -> Tuple[bool, str, float]:
        try:
            start_time = datetime.now()
            connector = aiohttp.TCPConnector(ssl=self.ssl_context)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(url, timeout=self.timeout) as response:
                    text = await response.text()
                    elapsed = (datetime.now() - start_time).total_seconds() * 1000
                    status = response.status
                    if status == 200:
                        return True, f"HTTP {status} OK ({elapsed:.2f} ms, {len(text)} bytes)", elapsed
                    else:
                        return False, f"HTTP {status} ({elapsed:.2f} ms)", elapsed
        except asyncio.TimeoutError:
            return False, f"HTTP request timed out after {self.timeout} seconds", 0
        except aiohttp.ClientConnectorError as e:
            return False, f"Connection error: {str(e)}", 0
        except Exception as e:
            return False, f"HTTP request failed: {str(e)}", 0

    async def check_dns(self, host: str) -> Tuple[bool, str, float]:
        try:
            start_time = datetime.now()
            resolver = aiohttp.resolver.AsyncResolver()
            await asyncio.wait_for(resolver.resolve(host, self.dns_server), timeout=self.timeout)
            elapsed = (datetime.now() - start_time).total_seconds() * 1000
            return True, f"DNS resolution successful ({elapsed:.2f} ms)", elapsed
        except asyncio.TimeoutError:
            return False, f"DNS resolution timed out after {self.timeout} seconds", 0
        except Exception as e:
            return False, f"DNS resolution failed: {str(e)}", 0

    async def check_ping(self, host: str) -> Tuple[bool, str, float]:
        try:
            start_time = datetime.now()
            if platform.system().lower() == "windows":
                command = ["ping", "-n", "1", "-w", str(self.timeout * 1000), host]
            else:
                command = ["ping", "-c", "1", "-W", str(self.timeout), host]
            proc = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self.timeout)
            if proc.returncode == 0:
                output = stdout.decode().strip()
                if "time=" in output:
                    time_pos = output.find("time=") + 5
                    time_end = output.find("ms", time_pos)
                    ping_time = output[time_pos:time_end].strip()
                    return True, f"Ping successful ({ping_time} ms)", float(ping_time)
                return True, "Ping successful", 0
            else:
                return False, f"Ping failed: {stderr.decode().strip()}", 0
        except Exception as e:
            return False, f"Ping check failed: {str(e)}", 0

    async def check_service(self, name: str, service: Dict) -> bool:
        if self._canceled:
            return False
        self.stats["total"] += 1
        result = {
            "name": name,
            "status": "unknown",
            "message": "",
            "response_time": 0,
            "details": {},
            "category": service.get("category", "Other"),
            "timestamp": datetime.now().isoformat()
        }
        category = service.get("category", "Other")
        if category not in self.chart_data:
            self.chart_data[category] = {"total": 0, "available": 0, "blocked": 0, "errors": 0}
        self.chart_data[category]["total"] += 1
        try:
            if service["type"] == "tcp":
                success, message, response_time = await self.check_tcp_connection(service["host"], service["port"])
                result["details"] = {
                    "type": "tcp",
                    "host": service["host"],
                    "port": service["port"]
                }
            elif service["type"] == "udp":
                success, message, response_time = await self.check_udp_connection(service["host"], service["port"])
                result["details"] = {
                    "type": "udp",
                    "host": service["host"],
                    "port": service["port"]
                }
            elif service["type"] in ["https", "http"]:
                success, message, response_time = await self.check_http_request(service["url"])
                result["details"] = {
                    "type": "http",
                    "url": service["url"]
                }
                if success:
                    host = urlparse(service["url"]).hostname
                    if host:
                        dns_success, dns_message, _ = await self.check_dns(host)
                        result["details"]["dns"] = {
                            "status": "success" if dns_success else "failed",
                            "message": dns_message
                        }
                        if host != "localhost":
                            ping_success, ping_message, ping_time = await self.check_ping(host)
                            result["details"]["ping"] = {
                                "status": "success" if ping_success else "failed",
                                "message": ping_message,
                                "time": ping_time
                            }
            elif service["type"] == "dns":
                success, message, response_time = await self.check_dns(service["host"])
                result["details"] = {
                    "type": "dns",
                    "host": service["host"]
                }
            else:
                success = False
                message = "Unknown service type"
                response_time = 0
            if success:
                self.stats["available"] += 1
                self.chart_data[category]["available"] += 1
                result["status"] = "available"
            else:
                self.stats["blocked"] += 1
                self.chart_data[category]["blocked"] += 1
                result["status"] = "blocked"
            result["message"] = message
            result["response_time"] = response_time
            self.progress.emit(name, result["status"], message, result)
            self.update_stats.emit(
                self.stats["total"],
                self.stats["available"],
                self.stats["blocked"]
            )
            log_message = f"{datetime.now().isoformat()} - {name}: {result['status']} - {message}"
            if response_time > 0:
                log_message += f" (Response time: {response_time:.2f} ms)"
            self.log.emit(log_message)
            logger.info(log_message)
            return success
        except Exception as e:
            self.stats["blocked"] += 1
            self.stats["errors"] += 1
            self.chart_data[category]["blocked"] += 1
            self.chart_data[category]["errors"] += 1
            result["status"] = "error"
            result["message"] = f"Unexpected error: {str(e)}"
            self.progress.emit(name, "error", result["message"], result)
            self.log.emit(f"{datetime.now().isoformat()} - {name}: error - {result['message']}")
            logger.error(f"Error checking service {name}: {str(e)}", exc_info=True)
            return False

    async def run_checks(self):
        self.start_time = datetime.now()
        self.log.emit(f"Started service checks at {self.start_time.isoformat()}")
        logger.info(f"Started service checks at {self.start_time.isoformat()}")
        try:
            tasks = []
            for name, service in self.services.items():
                if self._canceled:
                    break
                task = asyncio.create_task(self.check_service(name, service))
                tasks.append(task)
            await asyncio.gather(*tasks)
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds()
            self.log.emit(f"Completed service checks in {duration:.2f} seconds")
            logger.info(f"Completed service checks in {duration:.2f} seconds")
            self.update_chart.emit(self.chart_data)
        except Exception as e:
            self.log.emit(f"Error in run_checks: {str(e)}")
            logger.error(f"Error in run_checks: {str(e)}", exc_info=True)
        finally:
            self.finished.emit()

    def cancel_checks(self):
        self._canceled = True
        self.log.emit(f"{datetime.now().isoformat()} - Checks canceled by user")
        logger.info("Checks canceled by user")

class WorkerWrapper(QObject):
    finished = pyqtSignal()
    progress = pyqtSignal(str, str, str, dict)
    log = pyqtSignal(str)
    update_stats = pyqtSignal(int, int, int)
    update_chart = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.checker = None
        self.thread = None

    def run_checks(self, services: Dict, timeout: int, dns_server: str):
        self.thread = QThread()
        self.checker = ServiceChecker(services, timeout, dns_server)
        self.checker.moveToThread(self.thread)
        self.checker.progress.connect(self.progress)
        self.checker.log.connect(self.log)
        self.checker.update_stats.connect(self.update_stats)
        self.checker.update_chart.connect(self.update_chart)
        self.checker.finished.connect(self.on_finished)
        self.checker.finished.connect(self.thread.quit)
        self.checker.finished.connect(self.checker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.start()
        asyncio.run_coroutine_threadsafe(self.checker.run_checks(), asyncio.get_event_loop())

    def on_finished(self):
        self.finished.emit()

    def cancel(self):
        if self.checker:
            self.checker.cancel_checks()

class ModernAnimatedButton(QPushButton):
    def __init__(self, text: str, parent=None, icon: str = None):
        super().__init__(text, parent)
        self.setStyleSheet(f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: none;
                border-radius: 8px;
                padding: 10px 20px;
                font-size: 14px;
                font-weight: 500;
                font-family: 'Segoe UI';
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
            QPushButton:pressed {{
                background-color: {COLORS["orange"]};
            }}
            QPushButton:disabled {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["text_secondary"]};
            }}
        """)
        if icon:
            self.setIcon(QIcon(icon))
        self.animation = QPropertyAnimation(self, b"geometry")
        self.animation.setDuration(200)
        self.animation.setEasingCurve(QEasingCurve.Type.OutQuad)
        self.shadow_effect = QGraphicsDropShadowEffect(self)
        self.shadow_effect.setBlurRadius(15)
        self.shadow_effect.setXOffset(0)
        self.shadow_effect.setYOffset(2)
        self.shadow_effect.setColor(QColor(0, 0, 0, 100))
        self.setGraphicsEffect(self.shadow_effect)

    def enterEvent(self, event):
        self.animation.setStartValue(self.geometry())
        self.animation.setEndValue(self.geometry().adjusted(0, 0, 2, 2))
        self.animation.start()
        super().enterEvent(event)

    def leaveEvent(self, event):
        self.animation.setStartValue(self.geometry())
        self.animation.setEndValue(self.geometry().adjusted(0, 0, -2, -2))
        self.animation.start()
        super().leaveEvent(event)

class LinkDialog(QDialog):
    def __init__(self, url: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Link Information")
        self.setMinimumSize(400, 300)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["baby_powder"]};
                font-family: 'Segoe UI';
            }}
        """)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        self.url_label = QLabel(f"<h3>URL:</h3><p>{url}</p>")
        self.url_label.setWordWrap(True)
        self.url_label.setStyleSheet(f"font-size: 14px; color: {COLORS['text_secondary']};")
        main_layout.addWidget(self.url_label)
        self.copy_btn = ModernAnimatedButton("Copy to Clipboard")
        self.copy_btn.setStyleSheet(self.copy_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["khaki"]};
                margin-top: 10px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS["orange"]};
            }}
        """)
        self.copy_btn.clicked.connect(lambda: self.copy_to_clipboard(url))
        main_layout.addWidget(self.copy_btn)
        qr_label = QLabel("QR Code:")
        qr_label.setStyleSheet(f"font-size: 16px; font-weight: 600; color: {COLORS['orange']};")
        main_layout.addWidget(qr_label)
        qr = pyqrcode.create(url)
        buffer = io.BytesIO()
        qr.svg(buffer, scale=5)
        svg_data = buffer.getvalue()
        self.qr_label = QLabel()
        self.qr_label.setPixmap(self.svg_to_pixmap(svg_data))
        self.qr_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.qr_label)
        close_btn = ModernAnimatedButton("Close")
        close_btn.setStyleSheet(close_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                padding: 8px 16px;
                font-size: 14px;
                margin-top: 15px;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        close_btn.clicked.connect(self.accept)
        main_layout.addWidget(close_btn)

    def svg_to_pixmap(self, svg_data):
        from PyQt6.QtSvg import QSvgRenderer
        svg_renderer = QSvgRenderer()
        svg_renderer.load(svg_data.encode('utf-8'))
        pixmap = QPixmap(200, 200)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        svg_renderer.render(painter)
        painter.end()
        return pixmap

    def copy_to_clipboard(self, text):
        clipboard = QApplication.clipboard()
        clipboard.setText(text)
        QMessageBox.information(self, "Copied", "URL copied to clipboard!")

class ServiceDetailsDialog(QDialog):
    def __init__(self, service_name: str, result: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Details for {service_name}")
        self.setMinimumSize(600, 500)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["baby_powder"]};
                font-family: 'Segoe UI';
            }}
        """)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        header = QLabel(f"<h2 style='color:{COLORS['orange']}'>{service_name}</h2>")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.setStyleSheet(f"font-size: 20px; font-weight: 600; margin-bottom: 10px; color: {COLORS['orange']}")
        main_layout.addWidget(header)
        basic_group = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
        basic_layout = QVBoxLayout(basic_group)
        basic_layout.setContentsMargins(15, 15, 15, 15)
        basic_layout.setSpacing(10)
        status_color = COLORS["success"] if result['status'] == "available" else COLORS["danger"] if result['status'] == "blocked" else COLORS["warning"]
        status_label = QLabel(f"Status: {result['status'].capitalize()}")
        status_label.setStyleSheet(f"""
            color: {status_color};
            font-size: 16px;
            font-weight: 600;
            padding: 8px;
            background-color: rgba(255, 255, 255, 0.05);
            border-radius: 6px;
            border-left: 3px solid {status_color};
        """)
        basic_layout.addWidget(status_label)
        message_label = QLabel(f"Message: {result['message']}")
        message_label.setStyleSheet(f"font-size: 14px; color: {COLORS['text_secondary']}; padding: 5px;")
        basic_layout.addWidget(message_label)
        if result['response_time'] > 0:
            time_label = QLabel(f"Response Time: {result['response_time']:.2f} ms")
            time_label.setStyleSheet(f"font-size: 14px; color: {COLORS['text_secondary']}; padding: 5px;")
            basic_layout.addWidget(time_label)
        timestamp_label = QLabel(f"Checked at: {result.get('timestamp', 'N/A')}")
        timestamp_label.setStyleSheet(f"font-size: 13px; color: {COLORS['text_secondary']}; opacity: 0.8; padding: 5px;")
        basic_layout.addWidget(timestamp_label)
        main_layout.addWidget(basic_group)
        if result['details']:
            details_group = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
            details_layout = QVBoxLayout(details_group)
            details_layout.setContentsMargins(15, 15, 15, 15)
            details_layout.setSpacing(10)
            details_title = QLabel("Technical Details")
            details_title.setStyleSheet(f"""
                font-size: 16px;
                font-weight: 600;
                color: {COLORS['orange']};
                margin-bottom: 10px;
            """)
            details_layout.addWidget(details_title)
            details_text = QTextEdit()
            details_text.setReadOnly(True)
            details_text.setFont(QFont("Consolas", 11))
            details_text.setStyleSheet(f"""
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: none;
                border-radius: 6px;
                padding: 12px;
            """)
            url = None
            if 'url' in result['details']:
                url = result['details']['url']
            elif 'host' in result['details']:
                url = f"http://{result['details']['host']}"
                if 'port' in result['details']:
                    url += f":{result['details']['port']}"
            if url:
                link_btn = ModernAnimatedButton("Show Link Info")
                link_btn.setStyleSheet(link_btn.styleSheet() + f"""
                    QPushButton {{
                        background-color: {COLORS["khaki"]};
                        margin-bottom: 10px;
                        font-weight: 600;
                    }}
                    QPushButton:hover {{
                        background-color: {COLORS["orange"]};
                    }}
                """)
                link_btn.clicked.connect(lambda: self.show_link_dialog(url))
                details_layout.addWidget(link_btn)
            details_str = json.dumps(result['details'], indent=2)
            details_text.setPlainText(details_str)
            details_layout.addWidget(details_text)
            main_layout.addWidget(details_group)
        close_btn = ModernAnimatedButton("Close")
        close_btn.setStyleSheet(close_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                padding: 8px 16px;
                font-size: 14px;
                margin-top: 15px;
                border-radius: 8px;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        close_btn.clicked.connect(self.accept)
        main_layout.addWidget(close_btn)

    def show_link_dialog(self, url):
        dialog = LinkDialog(url, self)
        dialog.exec()

class AddCustomServiceDialog(QDialog):
    def __init__(self, parent=None, service_name=None, service_data=None):
        super().__init__(parent)
        self.original_service_name = service_name
        self.service_data = service_data or {}
        self.setWindowTitle("Add Custom Service" if not service_name else "Edit Custom Service")
        self.setMinimumSize(500, 450)
        self.setStyleSheet(f"""
            QDialog {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["baby_powder"]};
                font-family: 'Segoe UI';
            }}
        """)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(15)
        form_group = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
        form_layout = QFormLayout(form_group)
        form_layout.setContentsMargins(15, 15, 15, 15)
        form_layout.setSpacing(12)
        form_layout.setVerticalSpacing(15)
        self.service_name_edit = QLineEdit()
        if service_name:
            self.service_name_edit.setText(service_name)
        self.service_name_edit.setPlaceholderText("Service Name")
        self.service_name_edit.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QLineEdit:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
        """)
        self.service_url_edit = QLineEdit()
        if 'host' in self.service_data:
            self.service_url_edit.setText(self.service_data['host'])
        elif 'url' in self.service_data:
            self.service_url_edit.setText(self.service_data['url'])
        self.service_url_edit.setPlaceholderText("URL/Host:")
        self.service_url_edit.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QLineEdit:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
        """)
        self.service_type_combo = QComboBox()
        self.service_type_combo.addItems(["HTTP/HTTPS", "TCP", "UDP", "DNS"])
        if 'type' in self.service_data:
            if self.service_data['type'] == 'https':
                self.service_type_combo.setCurrentText("HTTP/HTTPS")
            else:
                self.service_type_combo.setCurrentText(self.service_data['type'].upper())
        self.service_type_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                selection-background-color: {COLORS["khaki"]};
                font-family: 'Segoe UI';
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                selection-background-color: {COLORS["khaki"]};
                border: none;
                outline: none;
            }}
            QComboBox:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
        """)
        self.service_category_combo = QComboBox()
        self.service_category_combo.addItems([
            "VPN", "Social", "Messaging", "Streaming",
            "Gaming", "Email", "DNS", "AI", "Cloud", "Other"
        ])
        if 'category' in self.service_data:
            self.service_category_combo.setCurrentText(self.service_data['category'])
        self.service_category_combo.setStyleSheet(f"""
            QComboBox {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                selection-background-color: {COLORS["khaki"]};
                font-family: 'Segoe UI';
            }}
            QComboBox QAbstractItemView {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                selection-background-color: {COLORS["khaki"]};
                border: none;
                outline: none;
            }}
            QComboBox:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
            QComboBox::drop-down {{
                border: none;
            }}
        """)
        self.port_group = QWidget()
        self.port_layout = QFormLayout(self.port_group)
        self.port_layout.setContentsMargins(0, 0, 0, 0)
        self.port_layout.setSpacing(8)
        self.service_port_spin = QSpinBox()
        self.service_port_spin.setRange(1, 65535)
        if 'port' in self.service_data:
            self.service_port_spin.setValue(self.service_data['port'])
        else:
            self.service_port_spin.setValue(80)
        self.service_port_spin.setStyleSheet(f"""
            QSpinBox {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QSpinBox:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                width: 20px;
                background-color: {COLORS["khaki"]};
                border: none;
            }}
        """)
        self.port_layout.addRow("Port:", self.service_port_spin)
        self.port_group.hide()
        self.service_type_combo.currentTextChanged.connect(
            lambda text: self.port_group.setVisible(text in ["TCP", "UDP"]))
        form_layout.addRow("Name:", self.service_name_edit)
        form_layout.addRow("URL/Host:", self.service_url_edit)
        form_layout.addRow("Type:", self.service_type_combo)
        form_layout.addRow("Category:", self.service_category_combo)
        form_layout.addRow(self.port_group)
        main_layout.addWidget(form_group)
        buttons_layout = QHBoxLayout()
        buttons_layout.setContentsMargins(0, 0, 0, 0)
        buttons_layout.setSpacing(15)
        self.add_btn = ModernAnimatedButton("Add" if not service_name else "Save")
        self.add_btn.setStyleSheet(self.add_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["success"]};
                margin-top: 15px;
                flex: 1;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: #5fb85f;
            }}
        """)
        cancel_btn = ModernAnimatedButton("Cancel")
        cancel_btn.setStyleSheet(cancel_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                margin-top: 15px;
                flex: 1;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        buttons_layout.addWidget(self.add_btn)
        buttons_layout.addWidget(cancel_btn)
        main_layout.addLayout(buttons_layout)
        cancel_btn.clicked.connect(self.reject)

    def tr(self, text):
        return text

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(1100, 750)
        self.setWindowIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.set_dark_palette()
        self.translator = QTranslator()
        self.current_language = "en"
        self.settings = QSettings(SETTINGS_FILE, QSettings.Format.IniFormat)
        self.load_settings()
        self.services = self._initialize_services()
        self.custom_services = self.load_custom_services()
        self.services_to_check = {}
        self.worker_wrapper = WorkerWrapper()
        self.worker_wrapper.progress.connect(self.update_results)
        self.worker_wrapper.log.connect(self.update_log)
        self.worker_wrapper.update_stats.connect(self.update_summary)
        self.worker_wrapper.update_chart.connect(self.update_chart)
        self.worker_wrapper.finished.connect(self.on_check_finished)
        self.init_ui()
        self.init_status_bar()
        self.auto_save_timer = QTimer(self)
        self.auto_save_timer.timeout.connect(self.save_custom_services)
        self.auto_save_timer.start(30000)
        self.create_tray_icon()

    def set_dark_palette(self):
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(COLORS["dark_bg"]))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(COLORS["baby_powder"]))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(COLORS["medium_bg"]))
        dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor(COLORS["light_bg"]))
        dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(COLORS["light_bg"]))
        dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor(COLORS["baby_powder"]))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(COLORS["baby_powder"]))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(COLORS["baby_powder"]))
        dark_palette.setColor(QPalette.ColorRole.BrightText, QColor(COLORS["orange"]))
        dark_palette.setColor(QPalette.ColorRole.Link, QColor(COLORS["orange"]))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(COLORS["khaki"]))
        dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor(COLORS["black"]))
        dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(COLORS["text_secondary"]))
        dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(COLORS["text_secondary"]))
        dark_palette.setColor(QPalette.ColorRole.Light, QColor(COLORS["khaki"]))
        dark_palette.setColor(QPalette.ColorRole.Midlight, QColor(COLORS["khaki"]))
        dark_palette.setColor(QPalette.ColorRole.Dark, QColor(COLORS["dark_bg"]))
        dark_palette.setColor(QPalette.ColorRole.Mid, QColor(COLORS["medium_bg"]))
        dark_palette.setColor(QPalette.ColorRole.Shadow, QColor(0, 0, 0))
        self.setPalette(dark_palette)

    def create_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.windowIcon())
        tray_menu = QMenu()
        tray_menu.setStyleSheet(f"""
            QMenu {{
                background-color: {COLORS["medium_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["light_bg"]};
                font-family: 'Segoe UI';
                padding: 5px;
            }}
            QMenu::item {{
                padding: 8px 20px;
                margin: 2px;
                border-radius: 4px;
            }}
            QMenu::item:selected {{
                background-color: {COLORS["khaki"]};
                color: {COLORS["black"]};
            }}
            QMenu::item:disabled {{
                color: {COLORS["text_secondary"]};
            }}
        """)
        show_action = QAction("Show", self)
        show_action.triggered.connect(self.show)
        check_all_action = QAction("Check All Services", self)
        check_all_action.triggered.connect(self.check_all_services)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        tray_menu.addAction(show_action)
        tray_menu.addAction(check_all_action)
        tray_menu.addSeparator()
        tray_menu.addAction(exit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.setToolTip(APP_NAME)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.tray_icon_activated)

    def tray_icon_activated(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.DoubleClick:
            self.show()
            self.raise_()
            self.activateWindow()

    def load_settings(self):
        self.timeout = self.settings.value("timeout", DEFAULT_TIMEOUT, type=int)
        self.dns_server = self.settings.value("dns_server", DEFAULT_DNS_SERVER, type=str)
        self.current_language = self.settings.value("language", "en", type=str)

    def save_settings(self):
        self.settings.setValue("timeout", self.timeout)
        self.settings.setValue("dns_server", self.dns_server)
        self.settings.setValue("language", self.current_language)
        self.settings.sync()

    def load_custom_services(self) -> Dict:
        try:
            with open(CUSTOM_SERVICES_FILE, "r", encoding='utf-8') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_custom_services(self):
        try:
            with open(CUSTOM_SERVICES_FILE, "w", encoding='utf-8') as f:
                json.dump(self.custom_services, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Failed to save custom services: {str(e)}")

    def _initialize_services(self) -> Dict:
        return {
            "VPN Protocols": {
                "Shadowsocks (TCP)": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 8388,
                    "description": "Shadowsocks TCP protocol check",
                    "category": "VPN"
                },
                "Shadowsocks (UDP)": {
                    "type": "udp",
                    "host": "1.1.1.1",
                    "port": 8388,
                    "description": "Shadowsocks UDP protocol check",
                    "category": "VPN"
                },
                "V2Ray VMess": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 443,
                    "description": "V2Ray VMess protocol check",
                    "category": "VPN"
                },
                "V2Ray VLESS": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 443,
                    "description": "V2Ray VLESS protocol check",
                    "category": "VPN"
                },
                "Trojan": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 443,
                    "description": "Trojan protocol check",
                    "category": "VPN"
                },
                "WireGuard": {
                    "type": "udp",
                    "host": "1.1.1.1",
                    "port": 51820,
                    "description": "WireGuard UDP protocol check",
                    "category": "VPN"
                },
                "OpenVPN (TCP)": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 1194,
                    "description": "OpenVPN TCP protocol check",
                    "category": "VPN"
                },
                "OpenVPN (UDP)": {
                    "type": "udp",
                    "host": "1.1.1.1",
                    "port": 1194,
                    "description": "OpenVPN UDP protocol check",
                    "category": "VPN"
                },
                "SoftEther": {
                    "type": "tcp",
                    "host": "1.1.1.1",
                    "port": 443,
                    "description": "SoftEther protocol check",
                    "category": "VPN"
                },
            },
            "DNS Services": {
                "Google DNS": {
                    "type": "dns",
                    "host": "8.8.8.8",
                    "description": "Google DNS availability check",
                    "category": "DNS"
                },
                "Cloudflare DNS": {
                    "type": "dns",
                    "host": "1.1.1.1",
                    "description": "Cloudflare DNS availability check",
                    "category": "DNS"
                },
                "Yandex DNS": {
                    "type": "dns",
                    "host": "77.88.8.8",
                    "description": "Yandex DNS availability check",
                    "category": "DNS"
                },
                "AdGuard DNS": {
                    "type": "dns",
                    "host": "94.140.14.14",
                    "description": "AdGuard DNS availability check",
                    "category": "DNS"
                },
            },
            "Social Media": {
                "YouTube": {
                    "url": "https://www.youtube.com",
                    "type": "https",
                    "description": "YouTube availability check",
                    "category": "Social"
                },
                "Twitter (X)": {
                    "url": "https://twitter.com",
                    "type": "https",
                    "description": "Twitter (X) availability check",
                    "category": "Social"
                },
                "Instagram": {
                    "url": "https://www.instagram.com",
                    "type": "https",
                    "description": "Instagram availability check",
                    "category": "Social"
                },
                "Facebook": {
                    "url": "https://www.facebook.com",
                    "type": "https",
                    "description": "Facebook availability check",
                    "category": "Social"
                },
                "TikTok": {
                    "url": "https://www.tiktok.com",
                    "type": "https",
                    "description": "TikTok availability check",
                    "category": "Social"
                },
                "VK": {
                    "url": "https://vk.com",
                    "type": "https",
                    "description": "VK availability check",
                    "category": "Social"
                },
                "VK Video": {
                    "url": "https://vk.com/video",
                    "type": "https",
                    "description": "VK Video availability check",
                    "category": "Social"
                },
            },
            "Messaging": {
                "Discord Main": {
                    "url": "https://discord.com",
                    "type": "https",
                    "description": "Discord main page availability check",
                    "category": "Messaging"
                },
                "Discord DMs": {
                    "url": "https://discord.com/channels/@me",
                    "type": "https",
                    "description": "Discord direct messages availability check",
                    "category": "Messaging"
                },
                "Telegram Web": {
                    "url": "https://web.telegram.org",
                    "type": "https",
                    "description": "Telegram web availability check",
                    "category": "Messaging"
                },
                "WhatsApp Web": {
                    "url": "https://web.whatsapp.com",
                    "type": "https",
                    "description": "WhatsApp Web availability check",
                    "category": "Messaging"
                },
            },
            "Streaming": {
                "Twitch": {
                    "url": "https://www.twitch.tv",
                    "type": "https",
                    "description": "Twitch availability check",
                    "category": "Streaming"
                },
                "Netflix": {
                    "url": "https://www.netflix.com",
                    "type": "https",
                    "description": "Netflix availability check",
                    "category": "Streaming"
                },
                "Spotify": {
                    "url": "https://www.spotify.com",
                    "type": "https",
                    "description": "Spotify availability check",
                    "category": "Streaming"
                },
                "Rutube": {
                    "url": "https://rutube.ru",
                    "type": "https",
                    "description": "Rutube availability check",
                    "category": "Streaming"
                },
            },
            "Email Services": {
                "Gmail": {
                    "url": "https://mail.google.com",
                    "type": "https",
                    "description": "Gmail availability check",
                    "category": "Email"
                },
                "Yandex Mail": {
                    "url": "https://mail.yandex.com",
                    "type": "https",
                    "description": "Yandex Mail availability check",
                    "category": "Email"
                },
                "ProtonMail": {
                    "url": "https://mail.proton.me",
                    "type": "https",
                    "description": "ProtonMail availability check",
                    "category": "Email"
                },
                "Outlook": {
                    "url": "https://outlook.live.com",
                    "type": "https",
                    "description": "Outlook availability check",
                    "category": "Email"
                },
            },
            "Gaming Platforms": {
                "Steam": {
                    "url": "https://store.steampowered.com",
                    "type": "https",
                    "description": "Steam availability check",
                    "category": "Gaming"
                },
                "Epic Games Store": {
                    "url": "https://store.epicgames.com",
                    "type": "https",
                    "description": "Epic Games Store availability check",
                    "category": "Gaming"
                },
                "Battle.net": {
                    "url": "https://eu.battle.net",
                    "type": "https",
                    "description": "Battle.net availability check",
                    "category": "Gaming"
                },
                "GOG": {
                    "url": "https://www.gog.com",
                    "type": "https",
                    "description": "GOG availability check",
                    "category": "Gaming"
                },
            },
            "AI Services": {
                "OpenAI": {
                    "url": "https://www.openai.com",
                    "type": "https",
                    "description": "OpenAI website availability check",
                    "category": "AI"
                },
                "ChatGPT": {
                    "url": "https://chat.openai.com",
                    "type": "https",
                    "description": "ChatGPT availability check",
                    "category": "AI"
                },
            },
            "Other Services": {
                "GitHub": {
                    "url": "https://github.com",
                    "type": "https",
                    "description": "GitHub availability check",
                    "category": "Other"
                },
                "Reddit": {
                    "url": "https://www.reddit.com",
                    "type": "https",
                    "description": "Reddit availability check",
                    "category": "Other"
                },
                "Zoom": {
                    "url": "https://zoom.us",
                    "type": "https",
                    "description": "Zoom availability check",
                    "category": "Other"
                },
                "Dzen": {
                    "url": "https://dzen.ru",
                    "type": "https",
                    "description": "Dzen availability check",
                    "category": "Other"
                },
            }
        }

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        self.splitter.setHandleWidth(8)
        self.splitter.setStyleSheet(f"""
            QSplitter::handle {{
                background-color: {COLORS["khaki"]};
                width: 8px;
            }}
        """)
        self.main_layout.addWidget(self.splitter)
        self.left_panel = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
        self.left_layout = QVBoxLayout(self.left_panel)
        self.left_layout.setContentsMargins(15, 15, 15, 15)
        self.left_layout.setSpacing(15)
        title_label = QLabel("Service Selection")
        title_label.setStyleSheet(f"""
            color: {COLORS["baby_powder"]};
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 10px;
            font-family: 'Segoe UI';
        """)
        self.left_layout.addWidget(title_label)
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search services...")
        self.search_box.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 8px;
                padding: 12px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QLineEdit:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
        """)
        self.search_box.textChanged.connect(self.filter_services)
        self.left_layout.addWidget(self.search_box)
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet(f"""
            QTabWidget {{
                background-color: {COLORS["medium_bg"]};
                border: none;
                font-family: 'Segoe UI';
            }}
            QTabWidget::pane {{
                border: none;
            }}
            QTabWidget::tab-bar {{
                alignment: left;
            }}
            QTabBar::tab {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["text_secondary"]};
                padding: 10px 15px;
                border: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 14px;
                min-width: 120px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border-bottom: 2px solid {COLORS["orange"]};
            }}
            QTabBar::tab:hover {{
                background-color: {COLORS["khaki"]};
                color: {COLORS["baby_powder"]};
            }}
        """)
        self.category_tabs = {}
        self.category_lists = {}
        for category in self.services.keys():
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            tab_layout.setContentsMargins(10, 10, 10, 10)
            tab_layout.setSpacing(10)
            list_widget = QListWidget()
            list_widget.setStyleSheet(f"""
                QListWidget {{
                    background-color: {COLORS["light_bg"]};
                    color: {COLORS["baby_powder"]};
                    border: none;
                    border-radius: 8px;
                    padding: 8px;
                    font-size: 14px;
                    font-family: 'Segoe UI';
                }}
                QListWidget::item {{
                    padding: 12px;
                    border-radius: 6px;
                    margin-bottom: 4px;
                }}
                QListWidget::item:selected {{
                    background-color: {COLORS["khaki"]};
                    color: {COLORS["black"]};
                }}
            """)
            list_widget.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
            list_widget.itemSelectionChanged.connect(self.update_selection)
            tab_layout.addWidget(list_widget)
            tab_layout.addStretch()
            self.category_tabs[category] = tab
            self.category_lists[category] = list_widget
            self.tab_widget.addTab(tab, category)
        self.custom_tab = QWidget()
        self.custom_layout = QVBoxLayout(self.custom_tab)
        self.custom_layout.setContentsMargins(10, 10, 10, 10)
        self.custom_layout.setSpacing(10)
        self.custom_list = QListWidget()
        self.custom_list.setStyleSheet(f"""
            QListWidget {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: none;
                border-radius: 8px;
                padding: 8px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QListWidget::item {{
                padding: 12px;
                border-radius: 6px;
                margin-bottom: 4px;
            }}
            QListWidget::item:selected {{
                background-color: {COLORS["khaki"]};
                color: {COLORS["black"]};
            }}
        """)
        self.custom_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.custom_list.itemSelectionChanged.connect(self.update_selection)
        custom_button_layout = QHBoxLayout()
        custom_button_layout.setSpacing(10)
        self.add_custom_service_btn = ModernAnimatedButton("Add Service")
        self.add_custom_service_btn.setStyleSheet(self.add_custom_service_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["khaki"]};
                margin-top: 10px;
                flex: 1;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS["orange"]};
            }}
        """)
        self.add_custom_service_btn.clicked.connect(self.show_add_custom_service_dialog)
        self.edit_custom_service_btn = ModernAnimatedButton("Edit Service")
        self.edit_custom_service_btn.setStyleSheet(self.edit_custom_service_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["orange"]};
                margin-top: 10px;
                flex: 1;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        self.edit_custom_service_btn.clicked.connect(self.edit_selected_custom_service)
        self.remove_custom_service_btn = ModernAnimatedButton("Remove Service")
        self.remove_custom_service_btn.setStyleSheet(self.remove_custom_service_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["danger"]};
                margin-top: 10px;
                flex: 1;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: #ff4444;
            }}
        """)
        self.remove_custom_service_btn.clicked.connect(self.remove_selected_custom_service)
        custom_button_layout.addWidget(self.add_custom_service_btn)
        custom_button_layout.addWidget(self.edit_custom_service_btn)
        custom_button_layout.addWidget(self.remove_custom_service_btn)
        self.custom_layout.addWidget(self.custom_list)
        self.custom_layout.addLayout(custom_button_layout)
        self.custom_layout.addStretch()
        self.tab_widget.addTab(self.custom_tab, "Custom Services")
        self.left_layout.addWidget(self.tab_widget)
        self.check_selected_btn = ModernAnimatedButton("Check Selected")
        self.check_selected_btn.setStyleSheet(self.check_selected_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["orange"]};
                margin-top: 10px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        self.check_selected_btn.clicked.connect(self.check_selected_services)
        self.left_layout.addWidget(self.check_selected_btn)
        self.right_panel = QTabWidget()
        self.right_panel.setStyleSheet(f"""
            QTabWidget::pane {{
                border: none;
            }}
            QTabBar::tab {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["text_secondary"]};
                padding: 12px 15px;
                border: none;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 14px;
                min-width: 120px;
            }}
            QTabBar::tab:selected {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border-bottom: 3px solid {COLORS["orange"]};
            }}
            QTabBar::tab:hover {{
                background-color: {COLORS["khaki"]};
                color: {COLORS["baby_powder"]};
            }}
        """)
        self.results_tab = QWidget()
        self.results_layout = QVBoxLayout(self.results_tab)
        self.results_layout.setContentsMargins(15, 15, 15, 15)
        self.results_layout.setSpacing(15)
        results_title = QLabel("Check Results")
        results_title.setStyleSheet(f"color: {COLORS['baby_powder']}; font-size: 18px; font-weight: 600; font-family: 'Segoe UI';")
        self.results_layout.addWidget(results_title)
        self.summary_group = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
        self.summary_layout = QVBoxLayout(self.summary_group)
        self.summary_layout.setContentsMargins(15, 15, 15, 15)
        self.summary_layout.setSpacing(10)
        self.chart_view = QChartView()
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.chart_view.setMinimumHeight(250)
        self.summary_layout.addWidget(self.chart_view)
        stats_container = QWidget()
        stats_layout = QHBoxLayout(stats_container)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_layout.setSpacing(15)
        total_group = QWidget()
        total_layout = QVBoxLayout(total_group)
        total_layout.setContentsMargins(0, 0, 0, 0)
        total_layout.setSpacing(4)
        total_label = QLabel("Total")
        total_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; font-family: 'Segoe UI';")
        self.total_value = QLabel("0")
        self.total_value.setStyleSheet(f"color: {COLORS['baby_powder']}; font-size: 20px; font-weight: 600; font-family: 'Segoe UI';")
        total_layout.addWidget(total_label)
        total_layout.addWidget(self.total_value)
        available_group = QWidget()
        available_layout = QVBoxLayout(available_group)
        available_layout.setContentsMargins(0, 0, 0, 0)
        available_layout.setSpacing(4)
        available_label = QLabel("Available")
        available_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; font-family: 'Segoe UI';")
        self.available_value = QLabel("0")
        self.available_value.setStyleSheet(f"color: {COLORS['success']}; font-size: 20px; font-weight: 600; font-family: 'Segoe UI';")
        available_layout.addWidget(available_label)
        available_layout.addWidget(self.available_value)
        blocked_group = QWidget()
        blocked_layout = QVBoxLayout(blocked_group)
        blocked_layout.setContentsMargins(0, 0, 0, 0)
        blocked_layout.setSpacing(4)
        blocked_label = QLabel("Blocked")
        blocked_label.setStyleSheet(f"color: {COLORS['text_secondary']}; font-size: 14px; font-family: 'Segoe UI';")
        self.blocked_value = QLabel("0")
        self.blocked_value.setStyleSheet(f"color: {COLORS['danger']}; font-size: 20px; font-weight: 600; font-family: 'Segoe UI';")
        blocked_layout.addWidget(blocked_label)
        blocked_layout.addWidget(self.blocked_value)
        stats_layout.addWidget(total_group)
        stats_layout.addWidget(available_group)
        stats_layout.addWidget(blocked_group)
        self.summary_layout.addWidget(stats_container)
        self.results_layout.addWidget(self.summary_group)
        self.results_table = QTableWidget()
        self.results_table.setStyleSheet(f"""
            QTableWidget {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: none;
                gridline-color: {COLORS["khaki"]};
                selection-background-color: {COLORS["khaki"]};
                font-size: 14px;
                font-family: 'Segoe UI';
                border-radius: 8px;
            }}
            QHeaderView::section {{
                background-color: {COLORS["medium_bg"]};
                color: {COLORS["baby_powder"]};
                padding: 12px;
                border: none;
                font-size: 14px;
                font-weight: 600;
                font-family: 'Segoe UI';
            }}
            QTableWidget::item {{
                padding: 10px;
            }}
        """)
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels([
            "Service",
            "Category",
            "Status",
            "Response Time",
            "Details"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.results_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.results_layout.addWidget(self.results_table)
        self.logs_tab = QWidget()
        self.logs_layout = QVBoxLayout(self.logs_tab)
        self.logs_layout.setContentsMargins(15, 15, 15, 15)
        self.logs_layout.setSpacing(15)
        logs_title = QLabel("Activity Log")
        logs_title.setStyleSheet(f"color: {COLORS['baby_powder']}; font-size: 18px; font-weight: 600; font-family: 'Segoe UI';")
        self.logs_layout.addWidget(logs_title)
        self.logs_text = QTextEdit()
        self.logs_text.setStyleSheet(f"""
            QTextEdit {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-family: 'Consolas';
                font-size: 13px;
            }}
        """)
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Consolas", 11))
        self.json_highlighter = ModernJSONHighlighter(self.logs_text.document())
        log_buttons = QWidget()
        log_buttons_layout = QHBoxLayout(log_buttons)
        log_buttons_layout.setContentsMargins(0, 0, 0, 0)
        log_buttons_layout.setSpacing(10)
        self.clear_logs_btn = ModernAnimatedButton("Clear Logs")
        self.clear_logs_btn.setStyleSheet(self.clear_logs_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                margin-top: 10px;
                flex: 1;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        self.clear_logs_btn.clicked.connect(self.clear_logs)
        self.export_logs_btn = ModernAnimatedButton("Export Logs")
        self.export_logs_btn.setStyleSheet(self.export_logs_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                margin-top: 10px;
                flex: 1;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        self.export_logs_btn.clicked.connect(self.export_logs)
        log_buttons_layout.addWidget(self.clear_logs_btn)
        log_buttons_layout.addWidget(self.export_logs_btn)
        self.logs_layout.addWidget(self.logs_text)
        self.logs_layout.addWidget(log_buttons)
        self.dashboard_tab = QWidget()
        self.dashboard_layout = QVBoxLayout(self.dashboard_tab)
        self.dashboard_layout.setContentsMargins(15, 15, 15, 15)
        self.dashboard_layout.setSpacing(15)
        self.web_view = QWebEngineView()
        self.load_dashboard()
        self.dashboard_layout.addWidget(self.web_view)
        self.settings_tab = QWidget()
        self.settings_layout = QVBoxLayout(self.settings_tab)
        self.settings_layout.setContentsMargins(15, 15, 15, 15)
        self.settings_layout.setSpacing(15)
        settings_title = QLabel("Settings")
        settings_title.setStyleSheet(f"color: {COLORS['baby_powder']}; font-size: 18px; font-weight: 600; font-family: 'Segoe UI';")
        self.settings_layout.addWidget(settings_title)
        self.settings_group = ModernRoundedWidget(self, radius=10, background_color=QColor(COLORS["medium_bg"]))
        self.settings_form = QFormLayout(self.settings_group)
        self.settings_form.setContentsMargins(15, 15, 15, 15)
        self.settings_form.setSpacing(15)
        self.settings_form.setVerticalSpacing(15)
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 60)
        self.timeout_spin.setValue(self.timeout)
        self.timeout_spin.setSuffix(" seconds")
        self.timeout_spin.setStyleSheet(f"""
            QSpinBox {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QSpinBox:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
            QSpinBox::up-button, QSpinBox::down-button {{
                width: 20px;
                background-color: {COLORS["khaki"]};
                border: none;
            }}
        """)
        self.dns_server_edit = QLineEdit(self.dns_server)
        self.dns_server_edit.setPlaceholderText("DNS Server:")
        self.dns_server_edit.setStyleSheet(f"""
            QLineEdit {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 6px;
                padding: 10px;
                font-size: 14px;
                font-family: 'Segoe UI';
            }}
            QLineEdit:focus {{
                border: 1px solid {COLORS["orange"]};
            }}
        """)
        self.settings_form.addRow("Timeout:", self.timeout_spin)
        self.settings_form.addRow("DNS Server:", self.dns_server_edit)
        self.apply_settings_btn = ModernAnimatedButton("Apply Settings")
        self.apply_settings_btn.setStyleSheet(self.apply_settings_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["success"]};
                margin-top: 15px;
                font-weight: 600;
            }}
            QPushButton:hover {{
                background-color: #5fb85f;
            }}
        """)
        self.apply_settings_btn.clicked.connect(self.apply_settings)
        self.settings_layout.addWidget(self.settings_group)
        self.settings_layout.addWidget(self.apply_settings_btn)
        self.settings_layout.addStretch()
        self.right_panel.addTab(self.results_tab, "Check Results")
        self.right_panel.addTab(self.logs_tab, "Activity Log")
        self.right_panel.addTab(self.dashboard_tab, "Dashboard")
        self.right_panel.addTab(self.settings_tab, "Settings")
        self.splitter.addWidget(self.left_panel)
        self.splitter.addWidget(self.right_panel)
        self.splitter.setSizes([350, 750])
        self.create_toolbar()
        self.populate_service_lists()
        self.populate_custom_list()

    def create_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setStyleSheet(f"""
            QToolBar {{
                background-color: {COLORS["dark_bg"]};
                spacing: 6px;
                padding: 6px;
                border: none;
            }}
        """)
        self.addToolBar(toolbar)
        check_all_action = QAction(QIcon.fromTheme("view-refresh"), "Check All", self)
        check_all_action.triggered.connect(self.check_all_services)
        check_selected_action = QAction(QIcon.fromTheme("view-refresh"), "Check Selected", self)
        check_selected_action.triggered.connect(self.check_selected_services)
        clear_results_action = QAction(QIcon.fromTheme("edit-clear"), "Clear Results", self)
        clear_results_action.triggered.connect(self.clear_results)
        cancel_action = QAction(QIcon.fromTheme("process-stop"), "Cancel", self)
        cancel_action.triggered.connect(self.cancel_checks)
        settings_action = QAction(QIcon.fromTheme("preferences-system"), "Settings", self)
        settings_action.triggered.connect(lambda: self.right_panel.setCurrentIndex(3))
        toolbar.addAction(check_all_action)
        toolbar.addAction(check_selected_action)
        toolbar.addAction(clear_results_action)
        toolbar.addAction(cancel_action)
        toolbar.addSeparator()
        toolbar.addAction(settings_action)

    def init_status_bar(self):
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet(f"""
            QStatusBar {{
                background-color: {COLORS["dark_bg"]};
                color: {COLORS["baby_powder"]};
                font-size: 13px;
                padding: 6px;
                font-family: 'Segoe UI';
            }}
        """)
        self.setStatusBar(self.status_bar)
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet(f"font-size: 13px; color: {COLORS['text_secondary']};")
        self.status_bar.addPermanentWidget(self.status_label, 1)
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {COLORS["light_bg"]};
                color: {COLORS["baby_powder"]};
                border: 1px solid {COLORS["khaki"]};
                border-radius: 4px;
                text-align: center;
                height: 16px;
                font-family: 'Segoe UI';
            }}
            QProgressBar::chunk {{
                background-color: {COLORS["orange"]};
                width: 10px;
                margin: 0.5px;
            }}
        """)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        self.status_bar.showMessage("Ready")

    def populate_service_lists(self):
        for category, services in self.services.items():
            self.category_lists[category].clear()
            for name, service in services.items():
                item = QListWidgetItem(name)
                item.setData(Qt.ItemDataRole.UserRole, service)
                item.setData(Qt.ItemDataRole.UserRole + 1, category)
                item.setFont(QFont("Segoe UI", 13))
                self.category_lists[category].addItem(item)

    def populate_custom_list(self):
        self.custom_list.clear()
        for name, service in self.custom_services.items():
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, service)
            item.setData(Qt.ItemDataRole.UserRole + 1, "Custom Services")
            item.setFont(QFont("Segoe UI", 13))
            self.custom_list.addItem(item)

    def filter_services(self, text: str):
        for category, list_widget in self.category_lists.items():
            for i in range(list_widget.count()):
                item = list_widget.item(i)
                item.setHidden(text.lower() not in item.text().lower())

    def check_all_services(self):
        all_services = {
            **{k: v for category in self.services.values() for k, v in category.items()},
            **self.custom_services
        }
        self.services_to_check = all_services
        self.start_checks(all_services)

    def check_selected_services(self):
        selected_services = {}
        for category, list_widget in self.category_lists.items():
            for item in list_widget.selectedItems():
                name = item.text()
                service = item.data(Qt.ItemDataRole.UserRole)
                selected_services[name] = service
        for item in self.custom_list.selectedItems():
            name = item.text()
            service = item.data(Qt.ItemDataRole.UserRole)
            selected_services[name] = service
        if not selected_services:
            QMessageBox.information(self, "Info", "No services selected for checking!")
            return
        self.services_to_check = selected_services
        self.start_checks(selected_services)

    def start_checks(self, services_to_check: Dict):
        self.services_to_check = services_to_check
        self.clear_results()
        timeout = self.timeout_spin.value()
        dns_server = self.dns_server_edit.text()
        if not self.validate_ip(dns_server):
            QMessageBox.warning(self, "Invalid DNS Server", "Please enter a valid IP address for the DNS server!")
            return
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_bar.showMessage("Checking services...")
        self.status_label.setText("Checking services...")
        self.worker_wrapper.run_checks(services_to_check, timeout, dns_server)
        self.right_panel.setCurrentIndex(0)

    def validate_ip(self, ip: str) -> bool:
        pattern = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(pattern, ip) is not None

    def cancel_checks(self):
        if self.worker_wrapper:
            self.worker_wrapper.cancel()
            self.status_bar.showMessage("Checks canceled")
            self.status_label.setText("Checks canceled")
            self.progress_bar.setVisible(False)

    def update_results(self, name: str, status: str, message: str, result: dict):
        row_position = self.results_table.rowCount()
        self.results_table.insertRow(row_position)
        service_item = QTableWidgetItem(name)
        service_item.setData(Qt.ItemDataRole.UserRole, result)
        service_item.setFont(QFont("Segoe UI", 13))
        category_item = QTableWidgetItem(result.get("category", "Other"))
        category_item.setFont(QFont("Segoe UI", 13))
        status_item = QTableWidgetItem(status.capitalize())
        status_item.setFont(QFont("Segoe UI", 13, QFont.Weight.Bold))
        if status == "available":
            status_item.setBackground(QColor(COLORS["success"]))
            status_item.setForeground(QColor(COLORS["black"]))
        elif status == "blocked":
            status_item.setBackground(QColor(COLORS["danger"]))
            status_item.setForeground(QColor(COLORS["baby_powder"]))
        else:
            status_item.setBackground(QColor(COLORS["warning"]))
            status_item.setForeground(QColor(COLORS["black"]))
        response_item = QTableWidgetItem(
            f"{result['response_time']:.2f} ms" if result['response_time'] > 0 else "N/A"
        )
        response_item.setFont(QFont("Segoe UI", 13))
        details_btn = ModernAnimatedButton("Details")
        details_btn.setStyleSheet(details_btn.styleSheet() + f"""
            QPushButton {{
                background-color: {COLORS["light_bg"]};
                padding: 6px 12px;
                font-size: 12px;
                font-weight: 500;
            }}
            QPushButton:hover {{
                background-color: {COLORS["khaki"]};
            }}
        """)
        details_btn.setProperty("row", row_position)
        details_btn.clicked.connect(self.show_details_dialog)
        self.results_table.setItem(row_position, 0, service_item)
        self.results_table.setItem(row_position, 1, category_item)
        self.results_table.setItem(row_position, 2, status_item)
        self.results_table.setItem(row_position, 3, response_item)
        self.results_table.setCellWidget(row_position, 4, details_btn)
        total = self.results_table.rowCount()
        if hasattr(self, 'services_to_check') and self.services_to_check:
            self.progress_bar.setValue(int((total / len(self.services_to_check)) * 100))
        current_total = int(self.total_value.text())
        current_available = int(self.available_value.text())
        current_blocked = int(self.blocked_value.text())
        self.update_dashboard_stats(
            current_total + 1,
            current_available + (1 if status == "available" else 0),
            current_blocked + (1 if status == "blocked" else 0)
        )

    def update_selection(self):
        self.selected_services = {}
        for category, list_widget in self.category_lists.items():
            for item in list_widget.selectedItems():
                name = item.text()
                service = item.data(Qt.ItemDataRole.UserRole)
                self.selected_services[name] = service
        for item in self.custom_list.selectedItems():
            name = item.text()
            service = item.data(Qt.ItemDataRole.UserRole)
            self.selected_services[name] = service

    def update_log(self, message: str):
        self.logs_text.append(message)
        self.logs_text.verticalScrollBar().setValue(
            self.logs_text.verticalScrollBar().maximum()
        )

    def update_summary(self, total: int, available: int, blocked: int):
        logger.info(f"Updating summary: total={total}, available={available}, blocked={blocked}")
        self.total_value.setText(str(total))
        self.available_value.setText(str(available))
        self.blocked_value.setText(str(blocked))
        self.update_dashboard_stats(total, available, blocked)

    def update_chart(self, chart_data: dict):
        series = QPieSeries()
        series.setHoleSize(0.35)
        total_available = 0
        total_blocked = 0
        for category, data in chart_data.items():
            if data['total'] == 0:
                continue
            total_available += data['available']
            total_blocked += data['blocked']
            slice = QPieSlice(
                f"{category} ({data['available']}/{data['total']})",
                data['available']
            )
            slice.setLabelVisible(True)
            slice.setLabelPosition(QPieSlice.LabelPosition.LabelOutside)
            if category == "VPN":
                slice.setColor(QColor(COLORS["success"]))
            elif category == "Social":
                slice.setColor(QColor("#9C27B0"))
            elif category == "Messaging":
                slice.setColor(QColor("#4DA6FF"))
            elif category == "Streaming":
                slice.setColor(QColor("#FF9800"))
            elif category == "Gaming":
                slice.setColor(QColor("#E91E63"))
            elif category == "Email":
                slice.setColor(QColor("#00BCD4"))
            elif category == "DNS":
                slice.setColor(QColor("#607D8B"))
            elif category == "AI":
                slice.setColor(QColor("#795548"))
            elif category == "Cloud":
                slice.setColor(QColor("#9E9E9E"))
            else:
                slice.setColor(QColor(COLORS["khaki"]))
            series.append(slice)
        if total_available + total_blocked > 0:
            summary_slice = QPieSlice(
                f"Summary ({total_available}/{total_available + total_blocked})",
                total_available
            )
            summary_slice.setLabelVisible(True)
            summary_slice.setLabelPosition(QPieSlice.LabelPosition.LabelOutside)
            summary_slice.setColor(QColor(COLORS["orange"]))
            series.append(summary_slice)
        chart = QChart()
        chart.addSeries(series)
        chart.setTitle("Service Availability")
        chart.setAnimationOptions(QChart.AnimationOption.SeriesAnimations)
        chart.legend().setVisible(True)
        chart.legend().setAlignment(Qt.AlignmentFlag.AlignRight)
        chart.setBackgroundVisible(False)
        chart.setTitleBrush(QBrush(QColor(COLORS["baby_powder"])))
        self.chart_view.setChart(chart)
        self.chart_view.setRenderHint(QPainter.RenderHint.Antialiasing)

    def update_dashboard_stats(self, total: int, available: int, blocked: int):
        self.total_value.setText(str(total))
        self.available_value.setText(str(available))
        self.blocked_value.setText(str(blocked))
        js_code = f"""
            document.getElementById('total-checks').textContent = '{total}';
            document.getElementById('available-services').textContent = '{available}';
            document.getElementById('blocked-services').textContent = '{blocked}';
            const statusElement = document.querySelector('.status');
            if (statusElement) {{
                if ({available} > 0 && {blocked} === 0) {{
                    statusElement.textContent = 'All services available';
                    statusElement.className = 'status status-available';
                }} else if ({blocked} > 0 && {available} === 0) {{
                    statusElement.textContent = 'All services blocked';
                    statusElement.className = 'status status-blocked';
                }} else if ({available} > 0 && {blocked} > 0) {{
                    statusElement.textContent = 'Some services blocked';
                    statusElement.className = 'status status-unknown';
                }} else {{
                    statusElement.textContent = 'Beta version';
                    statusElement.className = 'status status-unknown';
                }}
            }}
        """
        self.web_view.page().runJavaScript(js_code)

    def on_check_finished(self):
        self.status_bar.showMessage("Check completed")
        self.status_label.setText("Check completed")
        self.progress_bar.setVisible(False)
        total = int(self.total_value.text())
        available = int(self.available_value.text())
        if total > 0:
            percentage = (available / total) * 100
            QMessageBox.information(
                self,
                "Check Completed",
                f"Service check completed!\n\n"
                f"Total services checked: {total}\n"
                f"Available services: {available} ({percentage:.1f}%)\n"
                f"Blocked services: {int(self.blocked_value.text())}"
            )

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.total_value.setText("0")
        self.available_value.setText("0")
        self.blocked_value.setText("0")
        self.progress_bar.setValue(0)
        chart = QChart()
        chart.setTitle("Service Availability")
        chart.setBackgroundVisible(False)
        chart.setTitleBrush(QBrush(QColor(COLORS["baby_powder"])))
        self.chart_view.setChart(chart)
        self.update_dashboard_stats(0, 0, 0)

    def clear_logs(self):
        self.logs_text.clear()

    def export_logs(self):
        log_text = self.logs_text.toPlainText()
        if not log_text:
            QMessageBox.warning(self, "Warning", "No log data to export!")
            return
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Save Log File",
            "",
            "Text Files (*.txt);;JSON Files (*.json);;HTML Files (*.html)"
        )
        if filename:
            try:
                if filename.endswith('.json'):
                    json_data = []
                    for line in log_text.split('\n'):
                        if line:
                            parts = line.split(' - ')
                            if len(parts) >= 3:
                                json_data.append({
                                    "timestamp": parts[0],
                                    "service": parts[1],
                                    "status": parts[2],
                                    "message": ' - '.join(parts[3:]) if len(parts) > 3 else ""
                                })
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(json_data, f, indent=2, ensure_ascii=False)
                elif filename.endswith('.html'):
                    html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>Service Check Logs</title>
                        <style>
                            body {{
                                font-family: 'Segoe UI', Arial, sans-serif;
                                line-height: 1.6;
                                margin: 20px;
                                background-color: {COLORS["dark_bg"]};
                                color: {COLORS["baby_powder"]};
                            }}
                            h1 {{
                                color: {COLORS["orange"]};
                                font-family: 'Segoe UI';
                            }}
                            .log-entry {{
                                margin-bottom: 12px;
                                padding: 12px;
                                border-radius: 6px;
                                background-color: {COLORS["light_bg"]};
                                font-family: 'Consolas';
                            }}
                            .available {{
                                border-left: 4px solid {COLORS["success"]};
                            }}
                            .blocked {{
                                border-left: 4px solid {COLORS["danger"]};
                            }}
                            .error {{
                                border-left: 4px solid {COLORS["warning"]};
                            }}
                            .timestamp {{
                                color: {COLORS["text_secondary"]};
                                font-size: 13px;
                                margin-bottom: 4px;
                            }}
                            .service {{
                                font-weight: 600;
                                color: {COLORS["orange"]};
                                font-size: 15px;
                                margin-bottom: 4px;
                            }}
                            .message {{
                                color: {COLORS["baby_powder"]};
                                font-size: 14px;
                            }}
                        </style>
                    </head>
                    <body>
                        <h1>Service Check Logs</h1>
                        <div class="logs">
                    """
                    for line in log_text.split('\n'):
                        if line:
                            parts = line.split(' - ')
                            if len(parts) >= 3:
                                timestamp = parts[0]
                                service = parts[1]
                                status = parts[2].lower()
                                message = ' - '.join(parts[3:]) if len(parts) > 3 else ""
                                status_class = status
                                html += f"""
                                <div class="log-entry {status_class}">
                                    <div class="timestamp">{timestamp}</div>
                                    <div class="service">{service}</div>
                                    <div class="message">{message}</div>
                                </div>
                                """
                    html += """
                        </div>
                    </body>
                    </html>
                    """
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(html)
                else:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(log_text)
                QMessageBox.information(self, "Info", f"Logs exported to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")

    def show_details_dialog(self):
        button = self.sender()
        if button:
            row = button.property("row")
            if 0 <= row < self.results_table.rowCount():
                item = self.results_table.item(row, 0)
                if item:
                    result = item.data(Qt.ItemDataRole.UserRole)
                    if result:
                        dialog = ServiceDetailsDialog(item.text(), result, self)
                        dialog.exec()

    def show_add_custom_service_dialog(self):
        dialog = AddCustomServiceDialog(self)
        def add_service():
            name = dialog.service_name_edit.text().strip()
            url_host = dialog.service_url_edit.text().strip()
            service_type = dialog.service_type_combo.currentText()
            category = dialog.service_category_combo.currentText()
            if not name:
                QMessageBox.warning(dialog, "Warning", "Please enter a service name!")
                return
            if not url_host:
                QMessageBox.warning(dialog, "Warning", "Please enter a URL or host!")
                return
            if service_type in ["HTTP/HTTPS"]:
                if not self.validate_url(url_host):
                    QMessageBox.warning(dialog, "Warning", "Please enter a valid URL!")
                    return
            else:
                if not self.validate_host(url_host):
                    QMessageBox.warning(dialog, "Warning", "Please enter a valid host or IP address!")
                    return
            service = {"category": category}
            if service_type == "HTTP/HTTPS":
                if not url_host.startswith(("http://", "https://")):
                    url_host = "https://" + url_host
                service.update({
                    "url": url_host,
                    "type": "https",
                    "description": f"Custom service: {name}"
                })
            elif service_type == "DNS":
                service.update({
                    "type": "dns",
                    "host": url_host,
                    "description": f"Custom DNS service: {name}"
                })
            else:
                try:
                    port = dialog.service_port_spin.value()
                    service.update({
                        "type": service_type.lower(),
                        "host": url_host.split(':')[0],
                        "port": port,
                        "description": f"Custom {service_type} service: {name}"
                    })
                except Exception as e:
                    QMessageBox.warning(dialog, "Warning", f"Invalid host address! {str(e)}")
                    return
            self.custom_services[name] = service
            self.populate_custom_list()
            self.save_custom_services()
            dialog.accept()
            QMessageBox.information(self, "Info", f"Service '{name}' added successfully!")
        dialog.add_btn.clicked.connect(add_service)
        dialog.exec()

    def edit_selected_custom_service(self):
        selected_items = self.custom_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "No service selected!")
            return
        if len(selected_items) > 1:
            QMessageBox.warning(self, "Warning", "Please select only one service to edit!")
            return
        item = selected_items[0]
        name = item.text()
        service_data = item.data(Qt.ItemDataRole.UserRole)
        dialog = AddCustomServiceDialog(self, name, service_data)
        def save_service():
            new_name = dialog.service_name_edit.text().strip()
            url_host = dialog.service_url_edit.text().strip()
            service_type = dialog.service_type_combo.currentText()
            category = dialog.service_category_combo.currentText()
            if not new_name:
                QMessageBox.warning(dialog, "Warning", "Please enter a service name!")
                return
            if not url_host:
                QMessageBox.warning(dialog, "Warning", "Please enter a URL or host!")
                return
            if service_type in ["HTTP/HTTPS"]:
                if not self.validate_url(url_host):
                    QMessageBox.warning(dialog, "Warning", "Please enter a valid URL!")
                    return
            else:
                if not self.validate_host(url_host):
                    QMessageBox.warning(dialog, "Warning", "Please enter a valid host or IP address!")
                    return
            service = {"category": category}
            if service_type == "HTTP/HTTPS":
                if not url_host.startswith(("http://", "https://")):
                    url_host = "https://" + url_host
                service.update({
                    "url": url_host,
                    "type": "https",
                    "description": f"Custom service: {new_name}"
                })
            elif service_type == "DNS":
                service.update({
                    "type": "dns",
                    "host": url_host,
                    "description": f"Custom DNS service: {new_name}"
                })
            else:
                try:
                    port = dialog.service_port_spin.value()
                    service.update({
                        "type": service_type.lower(),
                        "host": url_host.split(':')[0],
                        "port": port,
                        "description": f"Custom {service_type} service: {new_name}"
                    })
                except Exception as e:
                    QMessageBox.warning(dialog, "Warning", f"Invalid host address! {str(e)}")
                    return
            if new_name != name:
                del self.custom_services[name]
            self.custom_services[new_name] = service
            self.populate_custom_list()
            self.save_custom_services()
            dialog.accept()
            QMessageBox.information(self, "Info", f"Service '{new_name}' updated successfully!")
        dialog.add_btn.clicked.connect(save_service)
        dialog.exec()

    def remove_selected_custom_service(self):
        selected_items = self.custom_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "No service selected!")
            return
        names = [item.text() for item in selected_items]
        confirm = QMessageBox.question(
            self,
            "Confirm Removal",
            f"Are you sure you want to remove {len(names)} service(s)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm == QMessageBox.StandardButton.Yes:
            for name in names:
                if name in self.custom_services:
                    del self.custom_services[name]
            self.populate_custom_list()
            self.save_custom_services()
            QMessageBox.information(self, "Info", "Selected services removed successfully!")

    def validate_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def validate_host(self, host: str) -> bool:
        if self.validate_ip(host):
            return True
        if len(host) > 253:
            return False
        pattern = r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
        return re.match(pattern, host) is not None

    def load_dashboard(self):
        dashboard_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Checker Dashboard</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: {COLORS["dark_bg"]};
                    color: {COLORS["baby_powder"]};
                }}
                .dashboard-container {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                    gap: 20px;
                    max-width: 1400px;
                    margin: 0 auto;
                }}
                .card {{
                    background-color: {COLORS["medium_bg"]};
                    border-radius: 10px;
                    padding: 20px;
                    border-left: 4px solid {COLORS["orange"]};
                }}
                .card h2 {{
                    margin-top: 0;
                    color: {COLORS["orange"]};
                    font-size: 1.4rem;
                    font-family: 'Segoe UI';
                    font-weight: 600;
                }}
                .card p {{
                    margin-bottom: 10px;
                    color: {COLORS["text_secondary"]};
                    font-family: 'Segoe UI';
                }}
                .status {{
                    display: inline-block;
                    padding: 6px 12px;
                    border-radius: 6px;
                    font-weight: 500;
                    margin-top: 10px;
                    font-size: 0.95rem;
                    font-family: 'Segoe UI';
                }}
                .status-available {{
                    background-color: rgba(76, 175, 80, 0.2);
                    color: {COLORS["success"]};
                    border: 1px solid {COLORS["success"]};
                }}
                .status-blocked {{
                    background-color: rgba(255, 27, 28, 0.2);
                    color: {COLORS["danger"]};
                    border: 1px solid {COLORS["danger"]};
                }}
                .status-unknown {{
                    background-color: rgba(255, 193, 7, 0.2);
                    color: {COLORS["warning"]};
                    border: 1px solid {COLORS["warning"]};
                }}
                .stats {{
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 15px;
                    margin-top: 20px;
                }}
                .stat-item {{
                    background-color: {COLORS["light_bg"]};
                    padding: 15px;
                    border-radius: 8px;
                    text-align: center;
                }}
                .stat-item h3 {{
                    margin-top: 0;
                    color: {COLORS["text_secondary"]};
                    font-size: 1rem;
                    font-family: 'Segoe UI';
                }}
                .stat-item p {{
                    font-size: 1.4rem;
                    font-weight: 600;
                    margin-bottom: 0;
                    font-family: 'Segoe UI';
                }}
                .stat-available p {{
                    color: {COLORS["success"]};
                }}
                .stat-blocked p {{
                    color: {COLORS["danger"]};
                }}
                .how-it-works {{
                    background-color: {COLORS["light_bg"]};
                    border-radius: 10px;
                    padding: 20px;
                    margin-top: 20px;
                    border-left: 4px solid {COLORS["orange"]};
                }}
                .how-it-works h2 {{
                    color: {COLORS["orange"]};
                    margin-top: 0;
                    font-size: 1.4rem;
                    font-family: 'Segoe UI';
                    font-weight: 600;
                }}
                .how-it-works p {{
                    color: {COLORS["text_secondary"]};
                    margin-bottom: 12px;
                    font-family: 'Segoe UI';
                }}
                .warning {{
                    background-color: rgba(255, 193, 7, 0.1);
                    border-left: 4px solid {COLORS["warning"]};
                    padding: 15px;
                    margin-top: 15px;
                    color: {COLORS["warning"]};
                    border-radius: 6px;
                    font-family: 'Segoe UI';
                }}
                .warning h3 {{
                    margin-top: 0;
                    color: {COLORS["warning"]};
                    font-size: 1.1rem;
                    font-family: 'Segoe UI';
                    font-weight: 600;
                }}
                .warning p {{
                    margin-bottom: 5px;
                    font-family: 'Segoe UI';
                }}
                .contact-info {{
                    margin-top: 10px;
                    font-family: 'Segoe UI';
                }}
                .contact-item {{
                    margin-bottom: 8px;
                    color: {COLORS["text_secondary"]};
                }}
                .contact-link {{
                    color: {COLORS["orange"]};
                    text-decoration: none;
                    cursor: pointer;
                }}
                .contact-link:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="dashboard-container">
                <div class="card">
                    <h2>System Information</h2>
                    <p><strong>OS:</strong> {platform.system()} {platform.release()}</p>
                    <p><strong>Version:</strong> {APP_VERSION}</p>
                    <p><strong>Release Date:</strong> 12.07.2025</p>
                    <div class="status status-unknown">Beta version</div>
                </div>
                <div class="card">
                    <h2>Quick Actions</h2>
                    <p>Use the buttons in the toolbar to perform quick actions:</p>
                    <ul style="color: {COLORS["text_secondary"]}; padding-left: 20px; font-family: 'Segoe UI';">
                        <li>Check All Services</li>
                        <li>Check Selected Services</li>
                        <li>Clear Results</li>
                        <li>View Settings</li>
                    </ul>
                </div>
                <div class="card stats">
                    <div class="stat-item">
                        <h3>Total Checks</h3>
                        <p id="total-checks">0</p>
                    </div>
                    <div class="stat-item stat-available">
                        <h3>Available</h3>
                        <p id="available-services">0</p>
                    </div>
                    <div class="stat-item stat-blocked">
                        <h3>Blocked</h3>
                        <p id="blocked-services">0</p>
                    </div>
                </div>
                <div class="card how-it-works">
                    <h2>How This Software Works</h2>
                    <p>This application checks the availability of various network services by attempting to establish connections using different protocols (HTTP, TCP, UDP, DNS).</p>
                    <p>For each service, it measures response times and determines whether the service is available or blocked based on the connection success.</p>
                    <p>The application performs the following types of checks:</p>
                    <ul style="color: {COLORS["text_secondary"]}; padding-left: 20px; font-family: 'Segoe UI';">
                        <li><strong>HTTP/HTTPS checks:</strong> Verifies if web services are accessible</li>
                        <li><strong>TCP checks:</strong> Tests if specific TCP ports are open</li>
                        <li><strong>UDP checks:</strong> Tests if specific UDP ports are responsive</li>
                        <li><strong>DNS checks:</strong> Verifies if DNS resolution works for specific hosts</li>
                    </ul>
                    <div class="warning">
                        <h3>Important Note:</h3>
                        <p>The results provided by this software are based on network connectivity tests and may not be 100% accurate.</p>
                        <p>There might be false positives or false negatives due to various factors including network fluctuations, temporary service outages, or firewall configurations.</p>
                        <p>The application provides its best effort to determine service availability, but results should be interpreted with this limitation in mind.</p>
                    </div>
                </div>
                <div class="card">
                    <h2>Help & Support</h2>
                    <div class="contact-info">
                        <div class="contact-item">Telegram: <a class="contact-link" href="{TELEGRAM_CHANNEL}" target="_blank">{TELEGRAM_CHANNEL}</a></div>
                        <div class="contact-item">YouTube: <a class="contact-link" href="{YOUTUBE_CHANNEL}" target="_blank">{YOUTUBE_CHANNEL}</a></div>
                        <div class="contact-item">Email: <a class="contact-link" href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a></div>
                        <div class="contact-item">Support: <a class="contact-link" href="{DONATION_LINK}" target="_blank">{DONATION_LINK}</a></div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        """
        self.web_view.setHtml(dashboard_html)
        class UrlInterceptor(QWebEngineUrlRequestInterceptor):
            def interceptRequest(self, info):
                url = info.requestUrl().toString()
                if url.startswith("http") or url.startswith("mailto"):
                    QDesktopServices.openUrl(QUrl(url))
                    return True
                return False
        interceptor = UrlInterceptor()
        self.web_view.page().profile().setUrlRequestInterceptor(interceptor)

    def apply_settings(self):
        dns_server = self.dns_server_edit.text()
        if not self.validate_ip(dns_server):
            QMessageBox.warning(self, "Invalid DNS Server", "Please enter a valid IP address for the DNS server!")
            return
        self.timeout = self.timeout_spin.value()
        self.dns_server = dns_server
        self.save_settings()
        QMessageBox.information(
            self,
            "Info",
            f"Settings applied successfully!\n\n"
            f"Timeout: {self.timeout} seconds\n"
            f"DNS Server: {self.dns_server}"
        )

    def closeEvent(self, event):
        self.save_custom_services()
        self.save_settings()
        event.accept()

def main():
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create("Fusion"))
    font = QFont("Segoe UI", 11)
    app.setFont(font)
    if platform.system() == "Windows":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main_window = MainWindow()
    main_window.show()
    loop = qasync.QEventLoop(app)
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Program interrupted by user")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}", exc_info=True)
    finally:
        logger.info("Application shutting down")

if __name__ == "__main__":
    main()
