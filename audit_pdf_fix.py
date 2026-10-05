from pathlib import Path

from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import ListFlowable, ListItem, Paragraph, SimpleDocTemplate, Spacer


OUT_DIR = Path(r"C:\Users\jdaya\AppData\Local\Temp\server_audit_simple")
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "server_audit_home_jday_in_ua_2026-06-02_simple.pdf"

FONT_REG = Path(r"C:\Windows\Fonts\DejaVuSans.ttf")
FONT_BOLD = Path(r"C:\Windows\Fonts\DejaVuSans-Bold.ttf")

pdfmetrics.registerFont(TTFont("DejaVuSans", str(FONT_REG)))
pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", str(FONT_BOLD)))

doc = SimpleDocTemplate(
    str(OUT_FILE),
    pagesize=A4,
    leftMargin=18 * mm,
    rightMargin=18 * mm,
    topMargin=16 * mm,
    bottomMargin=16 * mm,
    title="Аудит сервера home.jday.in.ua",
    author="Codex",
)

styles = getSampleStyleSheet()
styles.add(
    ParagraphStyle(
        name="UA_Title",
        fontName="DejaVuSans-Bold",
        fontSize=18,
        leading=22,
        spaceAfter=8,
        alignment=TA_LEFT,
    )
)
styles.add(
    ParagraphStyle(
        name="UA_Subtitle",
        fontName="DejaVuSans",
        fontSize=10.5,
        leading=14,
        spaceAfter=10,
    )
)
styles.add(
    ParagraphStyle(
        name="UA_Section",
        fontName="DejaVuSans-Bold",
        fontSize=13,
        leading=16,
        spaceBefore=8,
        spaceAfter=5,
    )
)
styles.add(
    ParagraphStyle(
        name="UA_Body",
        fontName="DejaVuSans",
        fontSize=10.5,
        leading=14,
        spaceAfter=4,
    )
)
styles.add(
    ParagraphStyle(
        name="UA_Small",
        fontName="DejaVuSans",
        fontSize=9.2,
        leading=12,
        spaceAfter=3,
    )
)


def bullets(items):
    return ListFlowable(
        [ListItem(Paragraph(item, styles["UA_Body"])) for item in items],
        bulletType="bullet",
        start="circle",
        leftIndent=14,
    )


story = []
story.append(Paragraph("Аудит сервера home.jday.in.ua", styles["UA_Title"]))
story.append(
    Paragraph(
        "Дата звіту: 2026-06-02. Формат: простий текстовий PDF без складного оформлення.",
        styles["UA_Subtitle"],
    )
)

story.append(Paragraph("Коротко", styles["UA_Section"]))
story.append(
    Paragraph(
        "Сервер працює як багатофункціональна машина для веб-хостингу, NOC-панелі, DHCP, Samba, PostgreSQL, Redis, Fail2ban та інших внутрішніх сервісів. "
        "Основні ризики раніше були пов’язані з великими логами, масовим веб-трафіком і надмірним навантаженням на обробники.",
        styles["UA_Body"],
    )
)

story.append(Paragraph("Інвентаризація", styles["UA_Section"]))
story.append(
    bullets(
        [
            "Хост: home.jday.in.ua",
            "ОС: CentOS Stream 9",
            "Ядро: 5.14.0-605.el9.x86_64",
            "CPU: Intel Celeron J4125, 4 ядра",
            "RAM: 7.3 GiB",
            "Swap: 8 GiB",
            "Root disk: Samsung SSD 870 EVO 1TB",
            "Стан розділу /: 924G, використано приблизно 51%",
            "Публічна IP: 93.126.70.50",
            "Внутрішня IP: 10.1.1.1",
            "Аптайм: близько 138 днів",
        ]
    )
)

story.append(Paragraph("Активні ролі та сервіси", styles["UA_Section"]))
story.append(
    bullets(
        [
            "Nginx на 80/443",
            "Apache на 8080",
            "NOC service на 1983",
            "PHP-FPM на 9000 (localhost)",
            "DHCP server на 67/UDP",
            "Samba / NetBIOS: 137-138, 139, 445",
            "PostgreSQL на 5432",
            "Redis на 6379 (localhost)",
            "SSH на 2283",
            "Fail2ban, hostapd, chronyd, rsyslog, crond, smartd, auditd",
        ]
    )
)

story.append(Paragraph("Безпека та стабілізація", styles["UA_Section"]))
story.append(
    bullets(
        [
            "Увімкнено fail2ban і окремі jail-и для concerts50.app.jday.in.ua.",
            "Є rate limit-и на важкі URL і швидкі бани для повторних 499.",
            "Логи Nginx переведені на ротацію 10M / 20, щоб не роздувалися до десятків гігабайт.",
            "Налаштовано maintenance mode для зовнішніх клієнтів при сплеску трафіку, але внутрішня мережа 10.1.1.* лишається доступною.",
            "Масові скраперські або ботові потоки вже частково обмежені на рівні Nginx і fail2ban.",
        ]
    )
)

story.append(Paragraph("Ризики", styles["UA_Section"]))
story.append(
    bullets(
        [
            "Високий і нерівномірний веб-трафік може створювати шум у логах та навантаження на процеси.",
            "За наявності нових IP-адрес один fail2ban не завжди зменшує перший запит у логах.",
            "Потрібно стежити за ростом access.json та access.log, щоб уникнути повторного розростання.",
            "Локальні сервіси на кшталт DHCP, Samba, PostgreSQL і NOC потребують регулярного контролю доступності.",
        ]
    )
)

story.append(Paragraph("Рекомендації", styles["UA_Section"]))
story.append(
    bullets(
        [
            "Тримати logrotate для access.json / access.log / error.log у режимі 10M / 20.",
            "Продовжувати моніторинг 429 / 499 / 403 і підсилювати обмеження на найважчих URL.",
            "Регулярно перевіряти стан fail2ban і iptables-банів.",
            "Стежити за пам’яттю, CPU та swap під час піків трафіку.",
            "За потреби винести окремі звіти по веб-атаках, DHCP, firewall і flows.",
        ]
    )
)

story.append(Spacer(1, 6))
story.append(
    Paragraph(
        "Звіт підготовлено у максимально простому текстовому форматі UTF-8 для зручного відкриття на Windows.",
        styles["UA_Small"],
    )
)

doc.build(story)
print(OUT_FILE)
