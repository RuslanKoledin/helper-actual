import os
import threading
from typing import Any
from markupsafe import escape as m_escape
from telebot.types import InlineKeyboardMarkup, InlineKeyboardButton
from flask import Flask, render_template, request, session, redirect, url_for, flash, abort, jsonify
from dotenv import load_dotenv
import telebot
import werkzeug.routing
import traceback
import re
from html import escape as html_escape
from functools import wraps
from time import time
from collections import defaultdict

# Загружаем переменные окружения ПЕРЕД импортом admin_manager
load_dotenv()

from flask_wtf.csrf import CSRFProtect
from admin_manager import admin_manager, AdminAuth, admins_manager, ROLE_SUPER_ADMIN, ROLE_EDITOR, ROLE_NAMES
from topics_manager import TopicsManager
from stats_manager import StatsManager

# ============================================
# RATE LIMITING
# ============================================

class RateLimiter:
    """Simple in-memory rate limiter"""
    def __init__(self):
        self.requests = defaultdict(list)
        self.login_attempts = defaultdict(list)

    def is_allowed(self, key: str, max_requests: int = 60, window: int = 60) -> bool:
        """Check if request is allowed within rate limit"""
        now = time()
        # Clean old requests
        self.requests[key] = [req_time for req_time in self.requests[key]
                             if now - req_time < window]
        # Check limit
        if len(self.requests[key]) >= max_requests:
            return False
        self.requests[key].append(now)
        return True

    def check_login_attempt(self, ip: str, max_attempts: int = 5, window: int = 300) -> bool:
        """Check login attempts (stricter limit)"""
        now = time()
        self.login_attempts[ip] = [req_time for req_time in self.login_attempts[ip]
                                   if now - req_time < window]
        if len(self.login_attempts[ip]) >= max_attempts:
            return False
        self.login_attempts[ip].append(now)
        return True

rate_limiter = RateLimiter()

def rate_limit(max_requests: int = 60, window: int = 60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Security Fix: Get client IP safely (validate trusted proxy)
            # Only trust X-Forwarded-For if request comes from trusted proxy
            trusted_proxies = set()
            if TRUSTED_PROXY_IP:
                trusted_proxies = {ip.strip() for ip in TRUSTED_PROXY_IP.split(',') if ip.strip()}

            if request.remote_addr in trusted_proxies and request.headers.get('X-Forwarded-For'):
                ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
            else:
                ip = request.remote_addr

            key = f"{ip}:{f.__name__}"
            if not rate_limiter.is_allowed(key, max_requests, window):
                return jsonify({
                    'success': False,
                    'error': 'Слишком много запросов. Пожалуйста, подождите.'
                }), 429

            return f(*args, **kwargs)
        return decorated_function
    return decorator

app = Flask(__name__)

# Secret key must be set in environment variables
FLASK_SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
if not FLASK_SECRET_KEY:
    print("CRITICAL ERROR: FLASK_SECRET_KEY not found in environment variables!")
    print("Please set FLASK_SECRET_KEY in your .env file")
    exit(1)
app.secret_key = FLASK_SECRET_KEY

# CSRF Configuration
app.config['WTF_CSRF_ENABLED'] = True
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for CSRF tokens
csrf = CSRFProtect(app)

# Security configurations for production
# Security Fix: Always use secure cookies in production
IS_DEVELOPMENT = os.getenv('FLASK_ENV', 'production') == 'development'
app.config['SESSION_COOKIE_SECURE'] = False  # Disabled for HTTP (enable in production with HTTPS)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Lax for better compatibility
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session timeout
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max request size (DoS protection)

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'  # Changed from SAMEORIGIN to DENY for better security
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Security Fix: Add HSTS header for HTTPS enforcement
    if request.is_secure or not IS_DEVELOPMENT:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

    # Security Fix: Improved CSP - consider removing unsafe-inline in future iterations
    # TODO: Remove unsafe-inline by using nonces or hashes for inline scripts/styles
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' https://api.telegram.org data:; "
        "media-src 'self' https://api.telegram.org; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "  # Changed from 'self' to 'none'
        "base-uri 'self'; "  # Added base-uri restriction
        "form-action 'self';"  # Added form-action restriction
    )

    # Security Fix: Add additional security headers
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    return response

BOT_TOKEN = os.getenv('BOT_TOKEN')

TRUSTED_PROXY_IP = os.getenv("TRUSTED_PROXY_IP")

# Security Fix: Safe integer conversion with validation
try:
    TECH_SUPPORT_CHAT_ID = int(os.getenv('TECH_SUPPORT_CHAT_ID', '0'))
    NEW_TICKETS_THREAD_ID = int(os.getenv('NEW_TICKETS_THREAD_ID', '0'))
    IN_PROGRESS_THREAD_ID = int(os.getenv('IN_PROGRESS_THREAD_ID', '0'))
    SOLVED_TICKETS_THREAD_ID = int(os.getenv('SOLVED_TICKETS_THREAD_ID', '0'))

    if not all([TECH_SUPPORT_CHAT_ID, NEW_TICKETS_THREAD_ID, IN_PROGRESS_THREAD_ID, SOLVED_TICKETS_THREAD_ID]):
        print("ПРЕДУПРЕЖДЕНИЕ: Не все ID чатов/топиков Telegram установлены!")
except (ValueError, TypeError) as e:
    print(f"ОШИБКА: Некорректные значения ID в переменных окружения: {e}")
    exit(1)

# Список ID пользователей техподдержки (загружается из env)
SUPPORT_STAFF_IDS_STR = os.getenv('SUPPORT_STAFF_IDS', '')
SUPPORT_STAFF_IDS = [int(x.strip()) for x in SUPPORT_STAFF_IDS_STR.split(',') if x.strip().isdigit()]

if not BOT_TOKEN:
    print("Ошибка: BOT_TOKEN не найден в переменных окружения. Пожалуйста, проверьте ваш .env файл.")
    exit()

bot = telebot.TeleBot(BOT_TOKEN)

# Инициализация TopicsManager
tm = TopicsManager("topics.db")

# TODO: СТАТИСТИКА В РАЗРАБОТКЕ
# Инициализация StatsManager для сбора аналитики
# ВНИМАНИЕ: Модуль статистики находится в стадии разработки и тестирования
# Используется PostgreSQL для хранения данных аналитики
# В production окружении убедитесь, что база данных настроена корректно
# ОТКЛЮЧЕНО: Раскомментируйте когда настроите PostgreSQL
# sm = StatsManager()
sm = None

# Константы результатов обращения (используются даже когда StatsManager отключен)
RESULT_VIDEO_HELPED = "video_helped"
RESULT_VIDEO_NOT_HELPED = "video_not_helped"
RESULT_SOLVED_BY_HELPER = "solved_by_helper"
RESULT_TICKET_CREATED = "ticket_created"
RESULT_TICKET_DONE = "ticket_done"
RESULT_TICKET_NOT_RELEVANT = "ticket_not_relevant"

# Импорт тематик при первом запуске (если база пустая)
stats = tm.get_statistics()
if stats['total_topics'] == 0:
    try:
        # Сначала пробуем загрузить полную базу
        import os
        if os.path.exists("topics_full.csv"):
            print("📊 База данных тематик пустая, импортирую topics_full.csv...")
            result = tm.import_from_csv("topics_full.csv", encoding="utf-8")
        else:
            print("📊 База данных тематик пустая, импортирую example_topics.csv...")
            result = tm.import_from_csv("example_topics.csv", encoding="utf-8")

        if result['success']:
            print(f"✅ Импортировано тематик: {result['imported']}")
        else:
            print(f"⚠️ Ошибка импорта: {result.get('error', 'Неизвестная ошибка')}")
    except Exception as e:
        print(f"⚠️ Не удалось импортировать данные: {e}")

def deep_escape(obj: Any) -> Any:
    """Рекурсивно экранирует все строковые поля (dict, list, tuple, str)."""
    if isinstance(obj, str):
        return m_escape(obj)
    if isinstance(obj, dict):
        return {k: deep_escape(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [deep_escape(v) for v in obj]
    if isinstance(obj, tuple):
        return tuple(deep_escape(v) for v in obj)
    return obj

# Загружаем мануалы из JSON файла через admin_manager
def load_manuals():
    """Загружает мануалы из JSON файла при каждом запросе"""
    return admin_manager.load_manuals()

def create_ticket_buttons():
    """Создает кнопки для заявки: Готово и Не актуально"""
    markup = InlineKeyboardMarkup(row_width=2)
    button_done = InlineKeyboardButton("Готово ✅", callback_data="ticket_done")
    button_not_relevant = InlineKeyboardButton("Не актуально ❌", callback_data="ticket_not_relevant")
    markup.add(button_done, button_not_relevant)
    return markup

# Функция для получения URL изображения
# Note: This function returns Telegram API URLs that contain the bot token.
# These URLs are safe to use in server-side rendering but should not be exposed
# in client-side JavaScript or cached publicly. Telegram file URLs expire after ~1 hour.
def get_file_url(file_id):
    try:
        if not file_id:
            return None
        # Validate file_id format to prevent injection
        if not isinstance(file_id, str) or len(file_id) > 200:
            return None

        # Check if it's a local video file (stored in static/videos/)
        if file_id.endswith('.MOV') or file_id.endswith('.mov') or file_id.endswith('.mp4'):
            # Return URL for static file
            return url_for('static', filename=f'videos/{file_id}')

        # Otherwise, it's a Telegram file_id - get it from Telegram API
        file_info = bot.get_file(file_id)
        return f"https://api.telegram.org/file/bot{BOT_TOKEN}/{file_info.file_path}"
    except telebot.apihelper.ApiTelegramException as e:
        # Don't log file_id in production - could be user input
        print(f"Telegram API error getting file URL")
        return None
    except Exception as e:
        print(f"Error getting file URL")
        return None

def send_ticket(problem, screenshots=None, topic_info=None):
    user_info = session.get('user_info', {})
    department = user_info.get('department', 'Неизвестно')
    name = user_info.get('name', 'Неизвестно')
    workplace = user_info.get('workplace', 'Неизвестно')

    support_message = (
        f"🚨 **НОВАЯ ЗАЯВКА** 🚨\n"
        f"Отдел: {department}\n"
        f"Имя: {name}\n"
        f"Рабочее место: {workplace}\n"
        f"Проблема: {problem}\n"
    )

    # Тематика НЕ отправляется в Telegram - только для маркировки в CRM
    # topic_info используется только на стороне веб-приложения

    try:
        print(f"[send_ticket] Отправка новой заявки в чат {TECH_SUPPORT_CHAT_ID}")
        msg = bot.send_message(
            TECH_SUPPORT_CHAT_ID,
            support_message,
            message_thread_id=NEW_TICKETS_THREAD_ID,
            parse_mode='Markdown',
            reply_markup=create_ticket_buttons()  # <- добавляем кнопки
        )
        print(f"[send_ticket] OK, message_id={getattr(msg, 'message_id', 'unknown')}")

        # Отправляем скриншоты, если они есть
        if screenshots:
            for i, screenshot in enumerate(screenshots, 1):
                try:
                    bot.send_photo(
                        TECH_SUPPORT_CHAT_ID,
                        screenshot,
                        caption=f"Скриншот {i}",
                        message_thread_id=NEW_TICKETS_THREAD_ID
                    )
                    print(f"[send_ticket] Отправлен скриншот {i}")
                except Exception as e:
                    print(f"[send_ticket] Ошибка при отправке скриншота {i}: {e}")

        # Логируем в PostgreSQL для статистики
        topic_id = None
        topic_name = None
        if topic_info:
            topic_name = topic_info.get('topic')
            # Можно попробовать извлечь topic_id из session или topic_info
            try:
                from flask import request
                if request.method == 'POST':
                    topic_id = request.form.get('selected_topic_id')
                    if topic_id:
                        topic_id = int(topic_id)
            except:
                pass

        if sm:
            sm.log_request(
                result_type=RESULT_TICKET_CREATED,
                problem_description=problem,
                department=department,
                name=name,
                workplace=workplace,
                problem_id=session.get('problem_id'),
                subproblem_id=session.get('current_subproblem_id'),
                topic_id=topic_id,
                topic_name=topic_name
            )

        return msg
    except Exception as e:
        print("[send_ticket] Ошибка при отправке заявки:", e)
        traceback.print_exc()
        return None
# обработчик кнопки
# обработчик кнопки "Готово"
@bot.callback_query_handler(func=lambda call: call.data == "ticket_done")
def handle_ticket_done(call):
    print(f"🔔 Получен callback от кнопки 'Готово'! User: {call.from_user.id}, Chat: {call.message.chat.id}")
    try:
        # Пересылаем оригинальное сообщение в IN_PROGRESS_THREAD_ID
        bot.copy_message(
            chat_id=TECH_SUPPORT_CHAT_ID,
            from_chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            message_thread_id=IN_PROGRESS_THREAD_ID
        )

        # Добавляем комментарий с информацией о сотруднике
        bot.send_message(
            TECH_SUPPORT_CHAT_ID,
            f"💬 Заявка готова ✅\n\n"
            f"Отмечена сотрудником: {call.from_user.first_name}",
            message_thread_id=IN_PROGRESS_THREAD_ID
        )

        # Убираем кнопку с оригинального сообщения
        bot.edit_message_reply_markup(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=None
        )

        print("✅ Кнопка 'Готово' успешно обработана!")

    except Exception as e:
        print(f"❌ Ошибка при обработке кнопки 'Готово': {e}")
        traceback.print_exc()

# обработчик кнопки "Не актуально"
@bot.callback_query_handler(func=lambda call: call.data == "ticket_not_relevant")
def handle_ticket_not_relevant(call):
    print(f"🔔 Получен callback от кнопки 'Не актуально'! User: {call.from_user.id}, Chat: {call.message.chat.id}")
    try:
        # Убираем кнопки с оригинального сообщения
        bot.edit_message_reply_markup(
            chat_id=call.message.chat.id,
            message_id=call.message.message_id,
            reply_markup=None
        )

        # Отправляем отдельное сообщение о том, что заявка не актуальна
        bot.send_message(
            TECH_SUPPORT_CHAT_ID,
            f"❌ ЗАЯВКА НЕ АКТУАЛЬНА ❌\n\n"
            f"Заявка отмечена сотрудником {call.from_user.first_name} как не актуальная.\n"
            f"Решение не требуется.",
            message_thread_id=NEW_TICKETS_THREAD_ID,
            parse_mode='Markdown',
            reply_to_message_id=call.message.message_id
        )

        print("✅ Кнопка 'Не актуально' успешно обработана!")

    except Exception as e:
        print(f"❌ Ошибка при обработке кнопки 'Не актуально': {e}")
        traceback.print_exc()

def send_solved_ticket(problem):
    user_info = session.get('user_info')
    if user_info:
        department = user_info.get('department', 'Неизвестно')
        name = user_info.get('name', 'Неизвестно')
        workplace = user_info.get('workplace', 'Неизвестно')

        support_message = (
            f"✅ **ПРОБЛЕМА РЕШЕНА Помощником** ✅\n"
            f"Отдел: {department}\n"
            f"Имя: {name}\n"
            f"Рабочее место: {workplace}\n"
            f"Проблема: {problem}"
        )
        try:
            bot.send_message(
                TECH_SUPPORT_CHAT_ID,
                support_message,
                message_thread_id=SOLVED_TICKETS_THREAD_ID,
                parse_mode='Markdown'
            )

            # Логируем в PostgreSQL для статистики
            if sm:
                sm.log_request(
                    result_type=RESULT_SOLVED_BY_HELPER,
                    problem_description=problem,
                    department=department,
                    name=name,
                    workplace=workplace,
                    problem_id=session.get('problem_id'),
                    subproblem_id=session.get('current_subproblem_id')
                )
        except Exception as e:
            print(f"Ошибка при отправке решённой заявки: {e}")
            traceback.print_exc()

def send_video_feedback(problem, helped):
    """Отправляет уведомление в ТГ о том, помогло ли видео-мануал"""
    user_info = session.get('user_info')
    if user_info:
        department = user_info.get('department', 'Неизвестно')
        name = user_info.get('name', 'Неизвестно')
        workplace = user_info.get('workplace', 'Неизвестно')

        if helped:
            support_message = (
                f"📹 **ВИДЕО-МАНУАЛ ПОМОГ** ✅\n"
                f"Отдел: {department}\n"
                f"Имя: {name}\n"
                f"Рабочее место: {workplace}\n"
                f"Проблема: {problem}"
            )
            thread_id = SOLVED_TICKETS_THREAD_ID
            result_type = RESULT_VIDEO_HELPED
        else:
            support_message = (
                f"📹 **ВИДЕО-МАНУАЛ НЕ ПОМОГ** ❌\n"
                f"Отдел: {department}\n"
                f"Имя: {name}\n"
                f"Рабочее место: {workplace}\n"
                f"Проблема: {problem}\n"
                f"Пользователь перешел к пошаговой инструкции"
            )
            thread_id = SOLVED_TICKETS_THREAD_ID
            result_type = RESULT_VIDEO_NOT_HELPED

        try:
            bot.send_message(
                TECH_SUPPORT_CHAT_ID,
                support_message,
                message_thread_id=thread_id,
                parse_mode='Markdown'
            )

            # Логируем в PostgreSQL для статистики
            if sm:
                sm.log_request(
                    result_type=result_type,
                    problem_description=problem,
                    department=department,
                    name=name,
                    workplace=workplace,
                    problem_id=session.get('problem_id'),
                    subproblem_id=session.get('current_subproblem_id')
                )
        except Exception as e:
            print(f"Ошибка при отправке фидбека по видео: {e}")
            traceback.print_exc()

@app.route('/video_feedback/<string:result>')
def video_feedback(result):
    """Обработка фидбека по видео-мануалу"""
    if 'user_info' not in session:
        return redirect(url_for('index'))

    problem_description = session.get('problem_title', 'Неизвестная проблема')

    if result == 'helped':
        # Видео помогло - отправляем уведомление и завершаем
        send_video_feedback(problem_description, helped=True)
        return render_template('success.html')
    elif result == 'not_helped':
        # Видео не помогло - отправляем уведомление и показываем страницу с инструкцией
        send_video_feedback(problem_description, helped=False)
        session['video_not_helped'] = True
        return redirect(url_for('show_manual_steps'))
    else:
        return redirect(url_for('show_problems'))

@app.route('/manual_steps')
def show_manual_steps():
    """Показывает только пошаговую инструкцию (без видео) после того как видео не помогло"""
    if 'user_info' not in session:
        return redirect(url_for('index'))

    problem_id = session.get('problem_id')
    subproblem_id = session.get('current_subproblem_id')

    if not problem_id:
        return redirect(url_for('show_problems'))

    manuals = load_manuals()
    problem_data = manuals.get(problem_id, {})

    # Получаем данные подпроблемы или основной проблемы
    if subproblem_id:
        subproblems = problem_data.get('subproblems', {})
        data = subproblems.get(subproblem_id, {})
    else:
        data = problem_data

    manual_title = session.get('problem_title', 'Инструкция')

    # Получаем фото
    photo_urls_with_captions = []
    for photo in data.get('photos', []):
        url = get_file_url(photo.get('id'))
        if not url:
            continue
        caption = photo.get('caption', '')
        safe_caption = m_escape(str(caption).strip()[:300])
        photo_urls_with_captions.append({'url': url, 'caption': safe_caption})

    safe_manual_data = deep_escape(data)
    safe_photos = deep_escape(photo_urls_with_captions)

    return render_template(
        'manual.html',
        manual=safe_manual_data,
        manual_title=manual_title,
        photo_urls_with_captions=safe_photos,
        video_data=None,  # Не показываем видео
        skip_video_feedback=True  # Флаг чтобы не показывать опрос по видео
    )

@app.route('/')
def index():
    session.clear()
    departments = [
        "Отдел по работе с социальными сетями",
        "Отдел аналитики, отчетности и мониторинга показателей",
        "Отдел обучения",
        "Отдел сопровождения обслуживания (ГОПЗ)",
        "Отдел по работе с обратной связью",
        "Отдел обслуживания юридических лиц",
        "Группа по развитию клиентов",
        "Отдел онлайн обращений",
        "Отдел входящей линии",
        "Группа по предотвращению мошенничества (Антифрод)",
        "Отдел клиентским опытом",
        "Отдел поддержки обслуживания",
        "Отдел обслуживания специальных проектов",
        "Управление клиентского опыта, инцидент-менеджмента и пользовательского тестирования",
    ]
    departments.sort()
    return render_template('index.html', departments=departments)

@app.route('/submit_user_info', methods=['POST'])
def submit_user_info():
    try:
        department = request.form.get('department', '').strip()
        name = request.form.get('name', '').strip()
        workplace = request.form.get('workplace', '').strip()

        # ✅ Проверка имени: только буквы и пробелы, макс. 20 символов
        if not re.fullmatch(r"[A-Za-zА-Яа-яЁё\s]{1,20}", name):
            flash("Имя должно содержать только буквы (макс. 20 символов)")
            return redirect(url_for("index"))

        # ✅ Проверка рабочего места: только цифры, макс. 4 символа
        if not re.fullmatch(r"\d{1,4}", workplace):
            flash("Рабочее место должно содержать только цифры (макс. 4)")
            return redirect(url_for("index"))

        # Если всё ок — сохраняем в сессию
        session['user_info'] = {
            'department': department,
            'name': name,
            'workplace': workplace
        }

        return redirect(url_for('choose_help_type'))

    except werkzeug.routing.exceptions.BuildError as e:
        print(f"Ошибка построения URL: {e}")
        return "Произошла ошибка. Пожалуйста, попробуйте еще раз."

@app.route('/choose_help_type')
def choose_help_type():
    """Страница выбора типа помощи после регистрации"""
    if 'user_info' not in session:
        return redirect(url_for('index'))
    return render_template('choose_help_type.html', user_info=session['user_info'])

@app.route('/search_topics')
def search_topics():
    """Страница поиска тематик обращений"""
    if 'user_info' not in session:
        return redirect(url_for('index'))

    # Получаем список каналов из БД
    channels = tm.get_all_channels()
    return render_template('search_topics.html', channels=channels)

@app.route('/submit_selected_topic', methods=['POST'])
def submit_selected_topic():
    """Обработка выбранной тематики и отправка в Telegram"""
    if 'user_info' not in session:
        return redirect(url_for('index'))

    try:
        selected_topic_id = request.form.get('selected_topic_id')
        selected_topic_name = request.form.get('selected_topic_name')
        selected_topic_similarity = request.form.get('selected_topic_similarity')

        if not selected_topic_id or not selected_topic_name:
            flash('Не выбрана тематика')
            return redirect(url_for('search_topics'))

        # Формируем topic_info для отправки
        topic_info = {
            'topic': selected_topic_name,
            'similarity': selected_topic_similarity
        }

        # Отправляем заявку с выбранной тематикой
        send_ticket(f"Запрос по тематике: {selected_topic_name}", None, topic_info)

        # Очищаем сессию и показываем страницу успеха
        session.clear()
        return render_template('ticket_sent.html')

    except Exception as e:
        print(f"[submit_selected_topic] Ошибка: {e}")
        traceback.print_exc()
        flash('Произошла ошибка при отправке заявки')
        return redirect(url_for('search_topics'))

@app.route('/problems')
def show_problems():
    if 'user_info' not in session:
        return redirect(url_for('index'))
    # Загружаем актуальные мануалы из JSON
    return render_template('problems.html', manuals=load_manuals())

@app.route('/select_problem/<string:problem_id>')
def select_problem(problem_id):
    # Проверяем авторизацию по сессии
    if 'user_info' not in session:
        print("[select_problem] No user_info in session, redirecting to index")
        return redirect(url_for('index'))

    # --- Проверяем корректность problem_id ---
    if not re.match(r'^\d+$', problem_id):
        print(f"[select_problem] Invalid problem_id format: {problem_id}")
        abort(404)

    try:
        problem_id_int = int(problem_id)
        if problem_id_int < 1 or problem_id_int > 7:
            print(f"[select_problem] problem_id out of range: {problem_id}")
            abort(404)
    except ValueError:
        print(f"[select_problem] Invalid problem_id (not an integer): {problem_id}")
        abort(404)

    # --- Белый список проблем ---
    # Загружаем актуальные мануалы из JSON
    manuals = load_manuals()
    if problem_id not in manuals:
        print(f"[select_problem] problem_id not in manuals: {problem_id}")
        flash('Выбрана несуществующая проблема.')
        return redirect(url_for('show_problems'))

    problem_data = manuals.get(problem_id, {})

    # --- Есть подпроблемы ---
    if 'subproblems' in problem_data and isinstance(problem_data['subproblems'], dict):
        session['problem_id'] = problem_id
        safe_problem_id = m_escape(problem_id)

        sanitized_subproblems = {}
        for sid, sub in problem_data['subproblems'].items():
            safe_sid = str(sid)
            title = sub.get('title', '')
            safe_title = m_escape(str(title).strip()[:200])
            sanitized_subproblems[safe_sid] = {'title': safe_title}

        # Получаем и экранируем подсказки по версиям, если они есть
        version_hints = None
        if 'version_hints' in problem_data:
            hints_data = problem_data['version_hints']
            version_hints = {
                'title': m_escape(str(hints_data.get('title', '')).strip()[:200]),
                'hints': []
            }
            for hint in hints_data.get('hints', []):
                hint_item = {
                    'version': m_escape(str(hint.get('version', '')).strip()[:100]),
                    'description': m_escape(str(hint.get('description', '')).strip()[:500])
                }
                # Добавляем фото если есть
                if 'photo' in hint:
                    photo_data = hint['photo']
                    photo_id = photo_data.get('id')
                    photo_url = get_file_url(photo_id) if photo_id else None
                    hint_item['photo'] = {
                        'url': photo_url,
                        'caption': m_escape(str(photo_data.get('caption', '')).strip()[:300])
                    }
                version_hints['hints'].append(hint_item)

        print(f"[select_problem] Rendering subproblems.html for problem_id: {problem_id}")
        return render_template(
            'subproblems.html',
            subproblems=sanitized_subproblems,
            problem_id=safe_problem_id,
            version_hints=version_hints
        )

    # --- Нет подпроблем — показываем мануал ---
    else:
        raw_manual_title = problem_data.get('title', 'Проблема')
        manual_title = m_escape(str(raw_manual_title).strip()[:200])
        session['problem_title'] = manual_title

        # Если выбрана "Другая проблема" или "CISCO" — редиректим
        if 'Другая проблема' in str(raw_manual_title) or 'CISCO' in str(raw_manual_title):
            print(f"[select_problem] Redirecting to other_problem for problem_id: {problem_id}")
            return redirect(url_for('other_problem'))

        # --- Обрабатываем фото ---
        photo_urls_with_captions = []
        for photo in problem_data.get('photos', []):
            url = get_file_url(photo.get('id'))
            if not url:
                continue
            caption = photo.get('caption', '')
            safe_caption = m_escape(str(caption).strip()[:300])
            photo_urls_with_captions.append({'url': url, 'caption': safe_caption})

        # --- Экранируем и передаём безопасные данные ---
        safe_manual_data = deep_escape(problem_data)
        safe_photos = deep_escape(photo_urls_with_captions)

        print(f"[select_problem] Rendering manual.html for problem_id: {problem_id}")
        return render_template(
            'manual.html',
            manual=safe_manual_data,
            manual_title=manual_title,
            photo_urls_with_captions=safe_photos
        )

@app.route('/show_manual/<string:subproblem_id>')
def show_manual(subproblem_id):
    if 'user_info' not in session or 'problem_id' not in session:
        return redirect(url_for('index'))

    problem_id = session.get('problem_id')

    # --- Проверка формата subproblem_id (только цифра.цифра, например "1.2") ---
    if not re.match(r'^\d\.\d$', subproblem_id):
        flash('Неверный идентификатор подпроблемы.')
        return redirect(url_for('show_problems'))

    # Получаем данные основной проблемы - загружаем актуальные мануалы из JSON
    manuals = load_manuals()
    problem_data = manuals.get(problem_id, {})

    # Проверяем, существует ли указанная подпроблема
    subproblems = problem_data.get('subproblems', {})
    if subproblem_id not in subproblems:
        flash('Выбрана несуществующая подпроблема.')
        return redirect(url_for('show_problems'))

    # Получаем данные подпроблемы
    subproblem_data = subproblems.get(subproblem_id, {})

    # --- Экранируем и валидируем заголовок ---
    raw_manual_title = subproblem_data.get('title', 'Инструкция')
    # Обрезаем лишние символы и экранируем HTML
    manual_title = m_escape(str(raw_manual_title).strip()[:200])  # ограничим длину, защита от XSS
    session['problem_title'] = manual_title
    session['current_subproblem_id'] = subproblem_id  # Сохраняем для возврата после опроса по видео

    # Проверяем, нужна ли форма для добавления скриншотов
    can_add_screenshots = subproblem_data.get('can_add_screenshots', False)

    # Если это подпроблема с возможностью добавления скриншотов и нет фотографий
    if can_add_screenshots and not subproblem_data.get('photos'):
        return render_template('other_problem.html')

    photo_urls_with_captions = []
    for photo in subproblem_data.get('photos', []):
        photo_id = photo.get('id')
        url = get_file_url(photo_id) if photo_id else None
        caption = photo.get('caption', '')
        safe_caption = m_escape(str(caption).strip()[:300])
        # Добавляем ВСЕ шаги, даже если фото удалено (url = None)
        photo_urls_with_captions.append({'url': url, 'caption': safe_caption})

    # Получаем видео если есть
    video_data = None
    if 'video' in subproblem_data:
        video_id = subproblem_data['video'].get('id')
        if video_id:
            video_url = get_file_url(video_id)
            if video_url:
                video_data = {
                    'url': video_url,
                    'caption': m_escape(str(subproblem_data['video'].get('caption', 'Видео-инструкция')).strip()[:300])
                }

    safe_manual_data = deep_escape(subproblem_data)
    safe_photos = deep_escape(photo_urls_with_captions)
    safe_video = deep_escape(video_data) if video_data else None

    return render_template(
        'manual.html',
        manual=safe_manual_data,
        manual_title=manual_title,
        photo_urls_with_captions=safe_photos,
        video_data=safe_video
    )


@app.route('/other_problem', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window=60)  # Security Fix: Add rate limiting to prevent DoS via file uploads
def other_problem():
    if 'user_info' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        problem_description = request.form.get('problem')

        # Получаем выбранную тематику (если есть)
        topic_info = None
        selected_topic_id = request.form.get('selected_topic_id')
        if selected_topic_id:
            try:
                # Получаем полную информацию о тематике из БД
                topic_data = tm.get_topic_by_id(int(selected_topic_id))
                if topic_data:
                    topic_info = {
                        'topic': topic_data.get('full_topic', 'Неизвестно'),
                        'similarity': request.form.get('selected_topic_similarity', '0')
                    }
            except Exception as e:
                print(f"[other_problem] Ошибка получения тематики: {e}")

        # Security Fix: File upload vulnerability - check size before loading into memory
        screenshots = []
        max_file_size = 10 * 1024 * 1024  # 10 МБ
        allowed_image_types = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}

        for i in range(1, 4):  # screenshot1, screenshot2, screenshot3
            file_key = f'screenshot{i}'
            if file_key in request.files:
                file = request.files[file_key]
                if file and file.filename:
                    # Security Fix: Validate content type before reading
                    if not file.content_type or file.content_type not in allowed_image_types:
                        flash(f'Файл {file.filename} имеет недопустимый тип. Разрешены: JPEG, PNG, GIF, WebP')
                        continue

                    # Security Fix: Check content-length header first (before loading into memory)
                    content_length = request.content_length
                    if content_length and content_length > max_file_size:
                        flash(f'Файл {file.filename} слишком большой. Максимальный размер: 10 МБ')
                        continue

                    # Read file with size limit
                    file.seek(0, os.SEEK_END)
                    file_size = file.tell()
                    file.seek(0)

                    if file_size > max_file_size:
                        flash(f'Файл {file.filename} слишком большой. Максимальный размер: 10 МБ')
                        continue

                    screenshots.append(file)

        send_ticket(problem_description, screenshots, topic_info)
        session.clear()
        return render_template('ticket_sent.html')
    return render_template('other_problem.html')

@app.route('/send_final_ticket')
def send_final_ticket():
    try:
        problem_description = session.get('problem_title', 'Неизвестная проблема')
        send_ticket(problem_description)

        return render_template('ticket_sent.html')
    except Exception as e:
        print(f"Ошибка при отправке заявки: {e}")
        return "Произошла ошибка при отправке заявки. Пожалуйста, попробуйте еще раз."

# --- Кнопка «На главную» после решения проблемы ---
@app.route('/finish_solved')
def finish_solved():
    try:
        problem_description = session.get('problem_title', 'Неизвестная проблема')
        send_solved_ticket(problem_description)

        # вместо очистки сессии показываем страницу успеха
        return render_template('success.html')  # там будет кнопка "На главную"

    except Exception as e:
        print(f"Ошибка при отправке сообщения: {e}")
        return "Произошла ошибка, но сессия сохранена."


# --- Обновлённый маршрут finish_unsolved с логированием ---
@app.route('/finish_unsolved')
def finish_unsolved():
    # Security: require user_info in session
    if 'user_info' not in session:
        return redirect(url_for('index'))

    try:
        # Security: only use session data, not query params (prevent injection)
        problem_description = session.get('problem_title', 'Неизвестная проблема')
        # Sanitize before sending
        problem_description = m_escape(str(problem_description)[:500])
        send_ticket(problem_description)
        return render_template('ticket_sent.html')
    except Exception as e:
        print("[finish_unsolved] Error sending ticket")
        traceback.print_exc()
        return render_template('ticket_sent.html')

@app.route('/go_home')
def go_home():
    # Security: don't log session content
    if 'user_info' in session:
        return redirect(url_for('show_problems'))
    else:
        return redirect(url_for('index'))

# ============================================
# API ДЛЯ ПОИСКА ТЕМАТИК
# ============================================

@app.route('/api/get_all_topics', methods=['GET'])
@csrf.exempt  # Exempted but protected by rate limiting
@rate_limit(max_requests=30, window=60)  # Security Fix: Add rate limiting
def get_all_topics_api():
    """API для получения всех тематик (ограничено 100 записями)"""
    try:
        # Получаем все тематики с ограничением
        topics = tm.get_all_topics(limit=100)

        formatted_results = []
        for topic in topics:
            formatted_results.append({
                'id': topic['id'],
                'topic': topic['full_topic'],
                'channel': topic['channel'],
                'similarity': 100,  # Для всех тематик = 100%
                'sr1': topic.get('sr1', ''),
                'sr2': topic.get('sr2', ''),
                'sr3': topic.get('sr3', ''),
                'sr4': topic.get('sr4', '')
            })

        return jsonify({
            'success': True,
            'count': len(formatted_results),
            'results': formatted_results
        })

    except Exception as e:
        print(f"[get_all_topics_api] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Внутренняя ошибка сервера'
        })

@app.route('/api/search_topic', methods=['POST'])
@csrf.exempt  # Exempt from CSRF for API endpoint
@rate_limit(max_requests=30, window=60)  # Security Fix: Add rate limiting
def search_topic_api():
    """API для поиска тематики по описанию проблемы"""
    try:
        # Security Fix: Validate Content-Type header
        if request.content_type != 'application/json':
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400

        data = request.json
        query = data.get('query', '').strip()
        channel = data.get('channel', '').strip()  # Получаем выбранный канал

        # Security Fix: Validate maximum query length
        if len(query) > 500:
            return jsonify({
                'success': False,
                'error': 'Запрос слишком длинный (максимум 500 символов)'
            }), 400
        if len(channel) > 200:
            return jsonify({
                'success': False,
                'error': 'Название канала слишком длинное'
            }), 400

        # Если query пустой, но канал выбран - возвращаем все тематики канала
        if not query and channel:
            topics = tm.get_topics_by_channel(channel, limit=100)
            formatted_results = []
            for r in topics:
                formatted_results.append({
                    'id': r['id'],
                    'topic': r['full_topic'],
                    'channel': r['channel'],
                    'similarity': 100,  # Все тематики канала = 100%
                    'sr1': r.get('sr1', ''),
                    'sr2': r.get('sr2', ''),
                    'sr3': r.get('sr3', ''),
                    'sr4': r.get('sr4', '')
                })
            return jsonify({
                'success': True,
                'query': '',
                'channel': channel,
                'count': len(formatted_results),
                'results': formatted_results
            })

        if not query or len(query) < 3:
            return jsonify({
                'success': False,
                'error': 'Запрос слишком короткий (минимум 3 символа)'
            })

        # Поиск тематик
        results = tm.search(
            query=query,
            limit=50,  # Увеличено до 50 для отображения большего количества результатов
            threshold=0.2,  # Низкий порог для большего кол-ва результатов
            use_cache=True
        )

        # Фильтруем результаты по каналу если он выбран
        if channel:
            # Умная фильтрация: ищем по словам, а не по полной строке
            filtered_results = []
            channel_words = set(channel.lower().split())

            for r in results:
                r_channel_words = set(r['channel'].lower().split())
                # Проверяем, есть ли общие слова
                if channel_words & r_channel_words:  # пересечение множеств
                    filtered_results.append(r)

            results = filtered_results

        # Форматируем результаты
        formatted_results = []
        for r in results:
            formatted_results.append({
                'id': r['id'],
                'topic': r['full_topic'],
                'channel': r['channel'],
                'similarity': round(r['similarity'] * 100, 1),  # В процентах
                'sr1': r.get('sr1', ''),
                'sr2': r.get('sr2', ''),
                'sr3': r.get('sr3', ''),
                'sr4': r.get('sr4', '')
            })

        return jsonify({
            'success': True,
            'query': query,
            'channel': channel,
            'count': len(formatted_results),
            'results': formatted_results
        })

    except Exception as e:
        print(f"[search_topic_api] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Внутренняя ошибка сервера'
        })

# Обработчик для получения photo file_id (для админов)
@bot.message_handler(content_types=['photo'])
def handle_photo_upload(message):
    """Получает photo file_id для добавления в мануалы"""
    try:
        # Берем самую большую версию фото
        photo_id = message.photo[-1].file_id
        file_size_mb = message.photo[-1].file_size / (1024 * 1024) if message.photo[-1].file_size else 0

        response_text = (
            f"📷 <b>Photo File ID получен!</b>\n\n"
            f"<code>{photo_id}</code>\n\n"
            f"📊 Размер: {file_size_mb:.2f} MB\n\n"
            f"Скопируйте file_id выше и добавьте в manuals_data.json"
        )

        bot.reply_to(message, response_text, parse_mode='HTML')
        print(f"✅ Photo file_id: {photo_id} (Size: {file_size_mb:.2f}MB)")

    except Exception as e:
        print(f"❌ Ошибка при обработке фото: {e}")
        traceback.print_exc()
        bot.reply_to(message, "❌ Ошибка при получении file_id фото")

# Обработчик для получения video file_id (для админов)
@bot.message_handler(content_types=['video'])
def handle_video_upload(message):
    """Получает video file_id для добавления в мануалы"""
    try:
        video_id = message.video.file_id
        file_size_mb = message.video.file_size / (1024 * 1024) if message.video.file_size else 0
        duration = message.video.duration if message.video.duration else 0

        response_text = (
            f"📹 <b>Video File ID получен!</b>\n\n"
            f"<code>{video_id}</code>\n\n"
            f"📊 Размер: {file_size_mb:.2f} MB\n"
            f"⏱ Длительность: {duration} сек\n\n"
            f"Скопируйте file_id выше и добавьте в manuals_data.json"
        )

        bot.reply_to(message, response_text, parse_mode='HTML')
        print(f"✅ Video file_id: {video_id} (Size: {file_size_mb:.2f}MB, Duration: {duration}s)")

    except Exception as e:
        print(f"❌ Ошибка при обработке видео: {e}")
        traceback.print_exc()
        bot.reply_to(message, "❌ Ошибка при получении file_id видео")

@bot.message_handler(func=lambda message: message.chat.type in ['group', 'supergroup'])
def handle_channel_messages(message):
    try:
        print(f"Получено сообщение: {message.text} от {message.from_user.id}")
        if message.reply_to_message:
            print(f"Это ответ на сообщение ID {message.reply_to_message.message_id}")
        else:
            print("❌ Сообщение не является ответом")

        if message.reply_to_message and message.from_user.id in SUPPORT_STAFF_IDS:
            text = message.text.lower()
            original_message_id = message.reply_to_message.message_id

            if "в работе" in text or "в процессе" in text or "решена" in text or "готово" in text:
                print("➡ Пересылаем в IN_PROGRESS_THREAD")
                bot.copy_message(
                    chat_id=TECH_SUPPORT_CHAT_ID,
                    from_chat_id=message.chat.id,
                    message_id=original_message_id,
                    message_thread_id=IN_PROGRESS_THREAD_ID
                )
                # Security Fix: Limit text length and sanitize
                safe_text = html_escape(message.text[:1000])  # Limit to 1000 chars
                bot.send_message(
                    TECH_SUPPORT_CHAT_ID,
                    f"💬 Статус по заявки на помощь: {safe_text}",
                    message_thread_id=IN_PROGRESS_THREAD_ID,
                    parse_mode='HTML'
                )
        else:
            print("❌ Не прошли проверки (нет reply_to_message или ID не в SUPPORT_STAFF_IDS)")
    except Exception as e:
        print(f"Ошибка при обработке сообщения в канале: {e}")

# ============================================
# АДМИН-ПАНЕЛЬ
# ============================================

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Страница авторизации администратора"""
    if request.method == 'POST':
        # Security Fix: Stricter rate limiting for login attempts to prevent brute force
        ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0].strip()
        if not rate_limiter.check_login_attempt(ip, max_attempts=5, window=900):  # 5 attempts per 15 minutes
            flash('Слишком много попыток входа. Попробуйте через 15 минут.')
            return redirect(url_for('admin_login')), 429

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        # Валидация длины
        if len(username) > 50 or len(password) > 100:
            flash('Некорректные учётные данные')
            return redirect(url_for('admin_login'))

        admin_data = AdminAuth.verify_admin(username, password)
        if admin_data:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            session['admin_role'] = admin_data.get('role', ROLE_EDITOR)
            session['admin_token'] = AdminAuth.generate_session_token()
            session.permanent = True  # Use permanent session with timeout
            flash(f'Успешная авторизация. Роль: {ROLE_NAMES.get(admin_data.get("role"), "Редактор")}')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Неверный логин или пароль')

    return render_template('admin_login.html')


@app.route('/admin/logout')
def admin_logout():
    """Выход из админ-панели"""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_role', None)
    session.pop('admin_token', None)
    flash('Вы вышли из системы')
    return redirect(url_for('admin_login'))


@app.route('/admin/dashboard')
@AdminAuth.login_required
def admin_dashboard():
    """Главная страница админ-панели"""
    manuals = admin_manager.load_manuals()
    return render_template('admin_dashboard.html', manuals=manuals)


@app.route('/admin/manual/<string:manual_id>/edit')
@AdminAuth.login_required
def admin_edit_manual(manual_id):
    """Страница редактирования мануала - теперь показывает список подпроблем"""
    # Валидация ID
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    manual = admin_manager.get_manual(manual_id)
    if not manual:
        flash('Мануал не найден')
        return redirect(url_for('admin_dashboard'))

    # Если есть подпроблемы - показываем список подпроблем
    if 'subproblems' in manual and manual['subproblems']:
        return render_template('admin_manual_subproblems.html', manual_id=manual_id, manual=manual)

    # Если нет подпроблем - редактируем сам мануал (старая логика для обратной совместимости)
    return render_template('admin_edit_manual.html', manual_id=manual_id, manual=manual, photo_urls={}, video_urls={})


@app.route('/admin/manual/<string:manual_id>/subproblem/<string:subproblem_id>/edit')
@AdminAuth.login_required
def admin_edit_subproblem(manual_id, subproblem_id):
    """Страница редактирования отдельной подпроблемы"""
    # Валидация ID
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    manual = admin_manager.get_manual(manual_id)
    if not manual:
        flash('Мануал не найден')
        return redirect(url_for('admin_dashboard'))

    # Проверяем существование подпроблемы
    if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
        flash('Подпроблема не найдена')
        return redirect(url_for('admin_edit_manual', manual_id=manual_id))

    subproblem = manual['subproblems'][subproblem_id]

    # Получаем URLs для фотографий чтобы показать preview
    photo_urls = []
    if 'photos' in subproblem:
        for photo in subproblem['photos']:
            url = get_file_url(photo.get('id'))
            photo_urls.append(url)

    # Получаем URL для видео если есть
    video_url = None
    if 'video' in subproblem:
        video_id = subproblem['video'].get('id')
        if video_id:
            video_url = get_file_url(video_id)

    return render_template('admin_edit_subproblem.html',
                         manual_id=manual_id,
                         manual_title=manual.get('title', ''),
                         subproblem_id=subproblem_id,
                         subproblem=subproblem,
                         photo_urls=photo_urls,
                         video_url=video_url)


@app.route('/admin/manual/<string:manual_id>/update', methods=['POST'])
@AdminAuth.login_required
def admin_update_manual(manual_id):
    """Обновление мануала (только заголовок, подпроблемы редактируются отдельно)"""
    # Валидация ID
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    title = request.form.get('title', '').strip()

    # Валидация заголовка
    title = admin_manager.sanitize_text(title, max_length=200)
    if not title:
        flash('Заголовок не может быть пустым')
        return redirect(url_for('admin_edit_manual', manual_id=manual_id))

    manual = admin_manager.get_manual(manual_id)
    if not manual:
        flash('Мануал не найден')
        return redirect(url_for('admin_dashboard'))

    # Обновляем только заголовок
    manual['title'] = title

    # Сохраняем изменения
    if admin_manager.update_manual(manual_id, title, manual):
        flash('Заголовок мануала успешно обновлён')
    else:
        flash('Ошибка при сохранении изменений')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


@app.route('/admin/manual/<string:manual_id>/subproblem/<string:subproblem_id>/update', methods=['POST'])
@AdminAuth.login_required
def admin_update_subproblem(manual_id, subproblem_id):
    """Обновление отдельной подпроблемы"""
    # Валидация ID
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    manual = admin_manager.get_manual(manual_id)
    if not manual:
        flash('Мануал не найден')
        return redirect(url_for('admin_dashboard'))

    # Проверяем существование подпроблемы
    if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
        flash('Подпроблема не найдена')
        return redirect(url_for('admin_edit_manual', manual_id=manual_id))

    subproblem = manual['subproblems'][subproblem_id]

    # Обновляем подписи к фото
    if 'photos' in subproblem:
        for photo_index, photo in enumerate(subproblem['photos']):
            caption_field = f'caption_{photo_index}'
            if caption_field in request.form:
                new_caption = request.form.get(caption_field, '').strip()
                new_caption = admin_manager.sanitize_text(new_caption, max_length=300)
                photo['caption'] = new_caption

    # Обновляем подпись к видео если есть
    if 'video' in subproblem:
        video_caption_field = 'video_caption'
        if video_caption_field in request.form:
            new_video_caption = request.form.get(video_caption_field, '').strip()
            new_video_caption = admin_manager.sanitize_text(new_video_caption, max_length=300)
            subproblem['video']['caption'] = new_video_caption

    # Сохраняем изменения
    if admin_manager.update_manual(manual_id, manual.get('title', ''), manual):
        flash('Подпроблема успешно обновлена')
    else:
        flash('Ошибка при сохранении изменений')

    return redirect(url_for('admin_edit_subproblem', manual_id=manual_id, subproblem_id=subproblem_id))


@app.route('/admin/delete-photo', methods=['POST'])
@AdminAuth.login_required
def admin_delete_photo():
    """Удаление фото из мануала"""
    manual_id = request.form.get('manual_id', '')
    subproblem_id = request.form.get('subproblem_id', '')
    photo_index_str = request.form.get('photo_index', '0')

    # Валидация
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    try:
        photo_index = int(photo_index_str)
        if photo_index < 0:
            raise ValueError
    except (ValueError, TypeError):
        flash('Некорректный индекс фото')
        return redirect(url_for('admin_dashboard'))

    # Удаляем фото
    if admin_manager.delete_photo(manual_id, subproblem_id, photo_index):
        flash('Фото успешно удалено')
    else:
        flash('Ошибка при удалении фото')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


@app.route('/admin/delete-video', methods=['POST'])
@AdminAuth.login_required
def admin_delete_video():
    """Удаление видео из подпроблемы"""
    manual_id = request.form.get('manual_id', '')
    subproblem_id = request.form.get('subproblem_id', '')

    # Валидация
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    # Удаляем видео
    if admin_manager.delete_video(manual_id, subproblem_id):
        flash('Видео успешно удалено')
    else:
        flash('Ошибка при удалении видео')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


@app.route('/admin/upload-photo', methods=['GET', 'POST'])
@AdminAuth.login_required
def admin_upload_photo():
    """Загрузка нового скриншота"""
    if request.method == 'GET':
        manual_id = request.args.get('manual_id', '')
        subproblem_id = request.args.get('subproblem_id', '')
        photo_index = request.args.get('photo_index', '0')

        # Валидация параметров
        if not admin_manager.validate_manual_id(manual_id):
            flash('Некорректный ID мануала')
            return redirect(url_for('admin_dashboard'))

        if not admin_manager.validate_subproblem_id(subproblem_id):
            flash('Некорректный ID подпроблемы')
            return redirect(url_for('admin_dashboard'))

        try:
            photo_index = int(photo_index)
            if photo_index < 0:
                raise ValueError
        except (ValueError, TypeError):
            flash('Некорректный индекс фото')
            return redirect(url_for('admin_dashboard'))

        return render_template('admin_upload_photo.html',
                             manual_id=manual_id,
                             subproblem_id=subproblem_id,
                             photo_index=photo_index)

    # POST - обработка загрузки
    manual_id = request.form.get('manual_id', '')
    subproblem_id = request.form.get('subproblem_id', '')
    photo_index_str = request.form.get('photo_index', '0')

    # Валидация
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    try:
        photo_index = int(photo_index_str)
        if photo_index < 0:
            raise ValueError
    except (ValueError, TypeError):
        flash('Некорректный индекс фото')
        return redirect(url_for('admin_dashboard'))

    # Security Fix: Improved file upload validation
    allowed_image_types = {'image/jpeg', 'image/png', 'image/gif', 'image/webp'}
    max_file_size = 10 * 1024 * 1024  # 10 MB

    if 'photo' not in request.files:
        flash('Файл не был загружен')
        return redirect(request.url)

    file = request.files['photo']
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(request.url)

    # Security Fix: Strict content type validation
    if not file.content_type or file.content_type not in allowed_image_types:
        flash('Можно загружать только изображения (JPEG, PNG, GIF, WebP)')
        return redirect(request.url)

    # Security Fix: Check content-length header first
    if request.content_length and request.content_length > max_file_size:
        flash('Файл слишком большой (максимум 10 МБ)')
        return redirect(request.url)

    # Проверка размера (максимум 10MB)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > max_file_size:
        flash('Файл слишком большой (максимум 10 МБ)')
        return redirect(request.url)

    try:
        # Отправляем фото в Telegram чтобы получить file_id
        msg = bot.send_photo(TECH_SUPPORT_CHAT_ID, file)

        # Получаем file_id самой большой версии фото
        if msg.photo:
            new_photo_id = msg.photo[-1].file_id

            # Получаем текущую подпись
            manual = admin_manager.get_manual(manual_id)
            if not manual:
                flash('Мануал не найден')
                return redirect(url_for('admin_dashboard'))

            current_caption = ""
            if 'subproblems' in manual and subproblem_id in manual['subproblems']:
                subproblem = manual['subproblems'][subproblem_id]
                if 'photos' in subproblem and photo_index < len(subproblem['photos']):
                    current_caption = subproblem['photos'][photo_index].get('caption', '')

            # Обновляем фото
            if admin_manager.update_photo(manual_id, subproblem_id, photo_index, new_photo_id, current_caption):
                flash(f'Скриншот успешно обновлён! File ID: {new_photo_id}')
            else:
                flash('Ошибка при сохранении изменений')
        else:
            flash('Не удалось получить file_id от Telegram')

    except Exception as e:
        print(f"Ошибка при загрузке фото: {e}")
        traceback.print_exc()
        flash('Ошибка при загрузке файла')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


@app.route('/admin/add-new-step', methods=['POST'])
@AdminAuth.login_required
def admin_add_new_step():
    """Добавление нового шага в подпроблему"""
    manual_id = request.form.get('manual_id', '')
    subproblem_id = request.form.get('subproblem_id', '')
    caption = request.form.get('caption', '').strip()
    after_index_str = request.form.get('after_index', '-1')

    # Валидация
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    caption = admin_manager.sanitize_text(caption, max_length=300)
    if not caption:
        flash('Описание шага не может быть пустым')
        return redirect(url_for('admin_edit_manual', manual_id=manual_id))

    # Парсим индекс
    try:
        after_index = int(after_index_str)
    except (ValueError, TypeError):
        after_index = -1

    # Добавляем новый шаг
    if admin_manager.add_new_step(manual_id, subproblem_id, caption, after_index):
        if after_index == -1:
            flash('Новый шаг успешно добавлен в конец')
        else:
            flash(f'Новый шаг успешно добавлен после шага {after_index + 1}')
    else:
        flash('Ошибка при добавлении шага')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


@app.route('/admin/upload-video', methods=['GET', 'POST'])
@AdminAuth.login_required
def admin_upload_video():
    """Загрузка видео-мануала"""
    if request.method == 'GET':
        manual_id = request.args.get('manual_id', '')
        subproblem_id = request.args.get('subproblem_id', '')

        # Валидация параметров
        if not admin_manager.validate_manual_id(manual_id):
            flash('Некорректный ID мануала')
            return redirect(url_for('admin_dashboard'))

        if not admin_manager.validate_subproblem_id(subproblem_id):
            flash('Некорректный ID подпроблемы')
            return redirect(url_for('admin_dashboard'))

        return render_template('admin_upload_video.html',
                             manual_id=manual_id,
                             subproblem_id=subproblem_id)

    # POST - обработка загрузки
    manual_id = request.form.get('manual_id', '')
    subproblem_id = request.form.get('subproblem_id', '')
    caption = request.form.get('caption', '').strip()

    # Валидация
    if not admin_manager.validate_manual_id(manual_id):
        flash('Некорректный ID мануала')
        return redirect(url_for('admin_dashboard'))

    if not admin_manager.validate_subproblem_id(subproblem_id):
        flash('Некорректный ID подпроблемы')
        return redirect(url_for('admin_dashboard'))

    # Security Fix: Improved video upload validation
    allowed_video_types = {'video/mp4', 'video/mpeg', 'video/quicktime', 'video/x-msvideo', 'video/webm'}
    max_file_size = 50 * 1024 * 1024  # 50 MB

    if 'video' not in request.files:
        flash('Файл не был загружен')
        return redirect(request.url)

    file = request.files['video']
    if file.filename == '':
        flash('Файл не выбран')
        return redirect(request.url)

    # Security Fix: Strict content type validation
    if not file.content_type or file.content_type not in allowed_video_types:
        flash('Можно загружать только видео (MP4, MPEG, MOV, AVI, WebM)')
        return redirect(request.url)

    # Security Fix: Check content-length header first
    if request.content_length and request.content_length > max_file_size:
        flash('Файл слишком большой (максимум 50 МБ)')
        return redirect(request.url)

    # Проверка размера (максимум 50MB)
    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)

    if file_size > max_file_size:
        flash('Файл слишком большой (максимум 50 МБ)')
        return redirect(request.url)

    try:
        # Отправляем видео в Telegram чтобы получить file_id
        msg = bot.send_video(TECH_SUPPORT_CHAT_ID, file)

        # Получаем file_id видео
        if msg.video:
            video_file_id = msg.video.file_id

            # Sanitize caption
            caption = admin_manager.sanitize_text(caption, max_length=300) if caption else 'Видео-инструкция'

            # Добавляем видео в подпроблему
            if admin_manager.add_video_to_subproblem(manual_id, subproblem_id, video_file_id, caption):
                flash(f'Видео успешно загружено! File ID: {video_file_id}')
            else:
                flash('Ошибка при сохранении изменений')
        else:
            flash('Не удалось получить file_id от Telegram')

    except Exception as e:
        print(f"Ошибка при загрузке видео: {e}")
        traceback.print_exc()
        flash('Ошибка при загрузке файла')

    return redirect(url_for('admin_edit_manual', manual_id=manual_id))


# ============================================
# УПРАВЛЕНИЕ ТЕМАТИКАМИ
# ============================================

@app.route('/admin/topics')
@AdminAuth.login_required
def admin_topics():
    """Страница управления тематиками"""
    stats = tm.get_statistics()
    channels = tm.get_all_channels()
    return render_template('admin_topics.html', stats=stats, channels=channels)


@app.route('/admin/topics/add', methods=['POST'])
@AdminAuth.login_required
def admin_add_topic():
    """Добавление новой тематики"""
    try:
        channel = request.form.get('channel', '').strip()
        sr1 = request.form.get('sr1', '').strip() or None
        sr2 = request.form.get('sr2', '').strip() or None
        sr3 = request.form.get('sr3', '').strip() or None
        sr4 = request.form.get('sr4', '').strip() or None
        full_topic = request.form.get('full_topic', '').strip() or None

        # Валидация
        if not channel:
            flash('Канал обязателен для заполнения')
            return redirect(url_for('admin_topics'))

        # Ограничение длины полей
        if len(channel) > 100:
            flash('Канал слишком длинный (макс. 100 символов)')
            return redirect(url_for('admin_topics'))

        for field, value in [('SR1', sr1), ('SR2', sr2), ('SR3', sr3), ('SR4', sr4)]:
            if value and len(value) > 200:
                flash(f'{field} слишком длинный (макс. 200 символов)')
                return redirect(url_for('admin_topics'))

        if full_topic and len(full_topic) > 500:
            flash('Полная тематика слишком длинная (макс. 500 символов)')
            return redirect(url_for('admin_topics'))

        # Добавляем тематику
        result = tm.add_topic(
            channel=channel,
            sr1=sr1,
            sr2=sr2,
            sr3=sr3,
            sr4=sr4,
            full_topic=full_topic
        )

        if result['success']:
            flash(f'Тематика успешно добавлена (ID: {result["id"]})')
        else:
            flash(f'Ошибка при добавлении тематики: {result.get("error", "Неизвестная ошибка")}')

    except Exception as e:
        print(f"[admin_add_topic] Ошибка: {e}")
        traceback.print_exc()
        flash('Произошла ошибка при добавлении тематики')

    return redirect(url_for('admin_topics'))


@app.route('/admin/topics/delete/<int:topic_id>', methods=['POST'])
@AdminAuth.login_required
def admin_delete_topic(topic_id):
    """Удаление тематики"""
    try:
        result = tm.delete_topic(topic_id)

        if result['success']:
            flash(f'Тематика успешно удалена')
        else:
            flash(f'Ошибка при удалении тематики: {result.get("error", "Неизвестная ошибка")}')

    except Exception as e:
        print(f"[admin_delete_topic] Ошибка: {e}")
        traceback.print_exc()
        flash('Произошла ошибка при удалении тематики')

    return redirect(url_for('admin_topics'))


@app.route('/admin/topics/list')
@AdminAuth.login_required
def admin_list_topics():
    """Список всех тематик"""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    channel = request.form.get('channel', '').strip()

    if channel:
        topics = tm.get_topics_by_channel(channel, limit=1000)
    else:
        topics = tm.get_all_topics(limit=1000)

    # Простая пагинация
    total = len(topics)
    start = (page - 1) * per_page
    end = start + per_page
    topics_page = topics[start:end]

    return render_template('admin_topics_list.html',
                         topics=topics_page,
                         page=page,
                         total=total,
                         per_page=per_page)


@app.route('/admin/topics/import', methods=['GET'])
@AdminAuth.login_required
def admin_import_topics():
    """Страница импорта тематик из Excel"""
    stats = tm.get_statistics()
    return render_template('admin_import_topics.html', stats=stats)


@app.route('/admin/topics/import', methods=['POST'])
@AdminAuth.login_required
@rate_limit(max_requests=5, window=60)
def admin_import_topics_upload():
    """Обработка загрузки Excel файла с тематиками"""
    try:
        # Проверяем наличие файла
        if 'file' not in request.files:
            flash('Файл не выбран', 'error')
            return redirect(url_for('admin_import_topics'))

        file = request.files['file']
        if file.filename == '':
            flash('Файл не выбран', 'error')
            return redirect(url_for('admin_import_topics'))

        # Проверяем расширение файла
        if not (file.filename.lower().endswith('.xlsx') or file.filename.lower().endswith('.xls')):
            flash('Неверный формат файла. Поддерживаются только .xlsx и .xls', 'error')
            return redirect(url_for('admin_import_topics'))

        # Получаем параметры
        sheet_name = request.form.get('sheet_name', 'subject_category').strip()
        clear_existing = request.form.get('clear_existing') == 'on'

        # Сохраняем файл временно
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
            file.save(tmp_file.name)
            tmp_path = tmp_file.name

        try:
            # Удаляем все существующие тематики если требуется
            if clear_existing:
                cursor = tm.conn.cursor()
                cursor.execute("DELETE FROM topics")
                tm.conn.commit()
                print(f"[admin_import_topics_upload] Все существующие тематики удалены")

            # Импортируем из Excel
            result = tm.import_from_excel(tmp_path, sheet_name=sheet_name)

            if result['success']:
                flash(f'✅ Успешно импортировано тематик: {result["imported"]}', 'success')
                print(f"[admin_import_topics_upload] Импортировано: {result['imported']} тематик")
                if result.get('errors'):
                    flash(f'⚠️ Ошибки при импорте: {len(result["errors"])} строк', 'warning')
                    print(f"[admin_import_topics_upload] Ошибок: {len(result['errors'])}")
            else:
                flash(f'❌ Ошибка импорта: {result.get("error", "Неизвестная ошибка")}', 'error')
                print(f"[admin_import_topics_upload] Ошибка: {result.get('error')}")

        finally:
            # Удаляем временный файл
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    except Exception as e:
        print(f"[admin_import_topics_upload] Ошибка: {e}")
        traceback.print_exc()
        flash(f'Произошла ошибка при импорте: {str(e)}', 'error')

    return redirect(url_for('admin_import_topics'))


@app.route('/admin/topics/export')
@AdminAuth.login_required
def admin_export_topics():
    """Экспорт всех тематик в Excel"""
    try:
        import tempfile
        import os
        from flask import send_file
        from datetime import datetime

        # Создаем временный файл
        tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx')
        tmp_path = tmp_file.name
        tmp_file.close()

        # Экспортируем в Excel
        result = tm.export_to_excel(tmp_path)

        if result['success']:
            print(f"[admin_export_topics] Экспортировано: {result['exported']} тематик")
            # Отправляем файл пользователю
            return send_file(
                tmp_path,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'topics_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
            )
        else:
            flash(f'Ошибка экспорта: {result.get("error", "Неизвестная ошибка")}', 'error')
            return redirect(url_for('admin_topics'))

    except Exception as e:
        print(f"[admin_export_topics] Ошибка: {e}")
        traceback.print_exc()
        flash(f'Произошла ошибка при экспорте: {str(e)}', 'error')
        return redirect(url_for('admin_topics'))


# ============================================
# СТАТИСТИКА И АНАЛИТИКА
# ============================================
# TODO: МОДУЛЬ В РАЗРАБОТКЕ
# Данный функционал находится в стадии разработки и тестирования
# Требуется настройка PostgreSQL базы данных (см. переменные POSTGRES_* в .env)
# В production окружении убедитесь в корректной настройке БД перед использованием

@app.route('/admin/stats')
@AdminAuth.login_required
def admin_stats_dashboard():
    """Страница статистики с dashboard"""
    return render_template('admin_stats_dashboard.html')


@app.route('/api/stats/summary')
@AdminAuth.login_required
def api_stats_summary():
    """API для получения общей статистики"""
    if not sm:
        return jsonify({
            'success': False,
            'error': 'Модуль статистики отключен. Настройте PostgreSQL.'
        }), 503
    try:
        days = request.args.get('days', 30, type=int)
        # Ограничиваем период от 1 до 365 дней
        days = max(1, min(days, 365))

        stats = sm.get_statistics(days=days)
        return jsonify({
            'success': True,
            'data': stats
        })
    except Exception as e:
        print(f"[api_stats_summary] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Ошибка получения статистики'
        }), 500


@app.route('/api/stats/top_problems')
@AdminAuth.login_required
def api_stats_top_problems():
    """API для получения топ проблем"""
    if not sm:
        return jsonify({
            'success': False,
            'error': 'Модуль статистики отключен. Настройте PostgreSQL.'
        }), 503
    try:
        limit = request.args.get('limit', 10, type=int)
        days = request.args.get('days', 30, type=int)

        # Ограничиваем параметры
        limit = max(1, min(limit, 50))
        days = max(1, min(days, 365))

        problems = sm.get_top_problems(limit=limit, days=days)
        return jsonify({
            'success': True,
            'data': problems
        })
    except Exception as e:
        print(f"[api_stats_top_problems] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Ошибка получения топ проблем'
        }), 500


@app.route('/api/stats/departments')
@AdminAuth.login_required
def api_stats_departments():
    """API для получения статистики по отделам"""
    if not sm:
        return jsonify({
            'success': False,
            'error': 'Модуль статистики отключен. Настройте PostgreSQL.'
        }), 503
    try:
        days = request.args.get('days', 30, type=int)
        days = max(1, min(days, 365))

        departments = sm.get_department_stats(days=days)
        return jsonify({
            'success': True,
            'data': departments
        })
    except Exception as e:
        print(f"[api_stats_departments] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Ошибка получения статистики по отделам'
        }), 500


@app.route('/api/stats/timeline')
@AdminAuth.login_required
def api_stats_timeline():
    """API для получения статистики по дням (для графика)"""
    if not sm:
        return jsonify({
            'success': False,
            'error': 'Модуль статистики отключен. Настройте PostgreSQL.'
        }), 503
    try:
        days = request.args.get('days', 30, type=int)
        days = max(1, min(days, 365))

        timeline = sm.get_timeline_stats(days=days)
        return jsonify({
            'success': True,
            'data': timeline
        })
    except Exception as e:
        print(f"[api_stats_timeline] Ошибка: {e}")
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': 'Ошибка получения timeline'
        }), 500


# ============================================
# УПРАВЛЕНИЕ УЧЕТНЫМИ ЗАПИСЯМИ АДМИНИСТРАТОРОВ
# ============================================

@app.route('/admin/users')
@AdminAuth.super_admin_required
def admin_users():
    """Список всех администраторов (только для супер-админа)"""
    admins = admins_manager.load_admins()
    return render_template('admin_users.html', admins=admins, role_names=ROLE_NAMES)


@app.route('/admin/users/add', methods=['GET', 'POST'])
@AdminAuth.super_admin_required
def admin_add_user():
    """Добавление нового администратора"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        role = request.form.get('role', ROLE_EDITOR)

        # Валидация
        if not username or not password:
            flash('Логин и пароль обязательны для заполнения')
            return redirect(url_for('admin_add_user'))

        if password != password_confirm:
            flash('Пароли не совпадают')
            return redirect(url_for('admin_add_user'))

        # Создаем администратора
        created_by = session.get('admin_username', 'system')
        result = admins_manager.create_admin(username, password, role, created_by)

        if result['success']:
            flash(f'Администратор {username} успешно создан')
            return redirect(url_for('admin_users'))
        else:
            flash(f'Ошибка: {result.get("error", "Неизвестная ошибка")}')

    return render_template('admin_add_user.html', roles={'super_admin': ROLE_SUPER_ADMIN, 'editor': ROLE_EDITOR}, role_names=ROLE_NAMES)


@app.route('/admin/users/<string:username>/change_password', methods=['GET', 'POST'])
@AdminAuth.super_admin_required
def admin_change_user_password(username):
    """Изменение пароля администратора"""
    admin = admins_manager.get_admin_by_username(username)
    if not admin:
        flash('Администратор не найден')
        return redirect(url_for('admin_users'))

    if request.method == 'POST':
        new_password = request.form.get('new_password', '')
        password_confirm = request.form.get('password_confirm', '')

        if not new_password:
            flash('Новый пароль обязателен для заполнения')
            return redirect(url_for('admin_change_user_password', username=username))

        if new_password != password_confirm:
            flash('Пароли не совпадают')
            return redirect(url_for('admin_change_user_password', username=username))

        result = admins_manager.update_admin_password(username, new_password)

        if result['success']:
            flash(f'Пароль для {username} успешно изменен')
            return redirect(url_for('admin_users'))
        else:
            flash(f'Ошибка: {result.get("error", "Неизвестная ошибка")}')

    return render_template('admin_change_password.html', admin=admin)


@app.route('/admin/users/<string:username>/change_role', methods=['POST'])
@AdminAuth.super_admin_required
def admin_change_user_role(username):
    """Изменение роли администратора"""
    new_role = request.form.get('role', '')

    if not new_role:
        flash('Роль обязательна для заполнения')
        return redirect(url_for('admin_users'))

    result = admins_manager.change_admin_role(username, new_role)

    if result['success']:
        flash(f'Роль для {username} успешно изменена на {ROLE_NAMES.get(new_role, new_role)}')
    else:
        flash(f'Ошибка: {result.get("error", "Неизвестная ошибка")}')

    return redirect(url_for('admin_users'))


@app.route('/admin/users/<string:username>/delete', methods=['POST'])
@AdminAuth.super_admin_required
def admin_delete_user(username):
    """Удаление администратора"""
    # Защита от удаления самого себя
    current_username = session.get('admin_username')
    if username == current_username:
        flash('Нельзя удалить самого себя')
        return redirect(url_for('admin_users'))

    result = admins_manager.delete_admin(username)

    if result['success']:
        flash(f'Администратор {username} успешно удален')
    else:
        flash(f'Ошибка: {result.get("error", "Неизвестная ошибка")}')

    return redirect(url_for('admin_users'))


# --- Запуск ---
def run_flask():
    # Security: debug=False in production, host binding from env
    flask_host = os.getenv('FLASK_HOST', '0.0.0.0')
    flask_port = int(os.getenv('FLASK_PORT', '5003'))
    flask_debug = IS_DEVELOPMENT  # Debug mode enabled in development
    # use_reloader=False because Flask runs in a thread and reloader doesn't work in threads
    app.run(host=flask_host, port=flask_port, debug=flask_debug, use_reloader=False)

def run_bot():
    print("🤖 Telegram бот запущен и слушает обновления...")
    print("🔍 Ожидание callback запросов от кнопок...")
    try:
        bot.infinity_polling(timeout=10, long_polling_timeout=5)
    except Exception as e:
        print(f"❌ Ошибка в bot polling: {e}")
        traceback.print_exc()

if __name__ == '__main__':
    print("=" * 60)
    print("Запуск приложения Helper Bot")
    print("=" * 60)
    # Security Fix: Do not log any information about tokens
    print("Bot Token: ***REDACTED***")
    print(f"Tech Support Chat ID: {TECH_SUPPORT_CHAT_ID}")
    print(f"Flask будет доступен на: http://0.0.0.0:5003")
    print(f"Telegram bot handlers: {len(bot.message_handlers)} message handlers")
    print(f"Callback handlers: {len(bot.callback_query_handlers)} callback handlers")
    print("=" * 60)

    flask_thread = threading.Thread(target=run_flask)
    bot_thread = threading.Thread(target=run_bot)
    flask_thread.start()
    bot_thread.start()