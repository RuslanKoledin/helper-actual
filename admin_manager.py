"""
Безопасный модуль для управления мануалами
Соответствует требованиям безопасности DerScanner
"""
import json
import os
import hashlib
import secrets
import re
from typing import Dict, Any, Optional, List
from functools import wraps
from flask import session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash


class AdminManager:
    """Безопасное управление мануалами"""

    def __init__(self, data_file: str = 'manuals_data.json'):
        self.data_file = data_file
        self._ensure_file_exists()

    def _ensure_file_exists(self) -> None:
        """Создаёт файл данных если его нет"""
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump({"manuals": {}}, f, ensure_ascii=False, indent=2)

    def load_manuals(self) -> Dict[str, Any]:
        """Загружает мануалы из файла"""
        try:
            with open(self.data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return data.get('manuals', {})
        except (json.JSONDecodeError, IOError) as e:
            print(f"Ошибка загрузки мануалов: {e}")
            return {}

    def save_manuals(self, manuals: Dict[str, Any]) -> bool:
        """Сохраняет мануалы в файл"""
        try:
            # Валидация перед сохранением
            if not isinstance(manuals, dict):
                raise ValueError("Manuals must be a dictionary")

            with open(self.data_file, 'w', encoding='utf-8') as f:
                json.dump({"manuals": manuals}, f, ensure_ascii=False, indent=2)
            return True
        except (IOError, ValueError) as e:
            print(f"Ошибка сохранения мануалов: {e}")
            return False

    @staticmethod
    def validate_manual_id(manual_id: str) -> bool:
        """Валидация ID мануала (только цифры)"""
        return bool(re.match(r'^\d+$', manual_id))

    @staticmethod
    def validate_subproblem_id(subproblem_id: str) -> bool:
        """Валидация ID подпроблемы (формат: цифра.цифра)"""
        return bool(re.match(r'^\d\.\d+$', subproblem_id))

    @staticmethod
    def sanitize_text(text: str, max_length: int = 500) -> str:
        """Очистка текста от потенциально опасных символов"""
        if not isinstance(text, str):
            return ""
        # Удаляем HTML теги
        text = re.sub(r'<[^>]+>', '', text)
        # Ограничиваем длину
        text = text[:max_length]
        return text.strip()

    @staticmethod
    def validate_photo_id(photo_id: str) -> bool:
        """Валидация Telegram file_id"""
        # Telegram file_id может содержать различные символы
        if not isinstance(photo_id, str):
            return False
        if len(photo_id) == 0 or len(photo_id) > 300:
            return False
        # Проверяем что это printable ASCII символы
        return all(32 <= ord(c) <= 126 for c in photo_id)

    @staticmethod
    def validate_video_id(video_id: str) -> bool:
        """Валидация Telegram video file_id (аналогично photo_id)"""
        if not isinstance(video_id, str):
            return False
        if len(video_id) == 0 or len(video_id) > 300:
            return False
        # Проверяем что это printable ASCII символы
        return all(32 <= ord(c) <= 126 for c in video_id)

    def get_manual(self, manual_id: str) -> Optional[Dict[str, Any]]:
        """Получить конкретный мануал"""
        if not self.validate_manual_id(manual_id):
            return None
        manuals = self.load_manuals()
        return manuals.get(manual_id)

    def update_manual(self, manual_id: str, title: str, data: Dict[str, Any]) -> bool:
        """Обновить мануал"""
        if not self.validate_manual_id(manual_id):
            return False

        # Валидация заголовка
        title = self.sanitize_text(title, max_length=200)
        if not title:
            return False

        manuals = self.load_manuals()

        # Безопасное обновление
        if manual_id not in manuals:
            manuals[manual_id] = {}

        manuals[manual_id]['title'] = title

        # Обновляем остальные данные с валидацией
        if 'subproblems' in data and isinstance(data['subproblems'], dict):
            manuals[manual_id]['subproblems'] = data['subproblems']

        if 'version_hints' in data and isinstance(data['version_hints'], dict):
            manuals[manual_id]['version_hints'] = data['version_hints']

        return self.save_manuals(manuals)

    def delete_manual(self, manual_id: str) -> bool:
        """Удалить мануал"""
        if not self.validate_manual_id(manual_id):
            return False

        manuals = self.load_manuals()
        if manual_id in manuals:
            del manuals[manual_id]
            return self.save_manuals(manuals)
        return False

    def update_photo(self, manual_id: str, subproblem_id: str,
                     photo_index: int, new_photo_id: str, caption: str) -> bool:
        """Обновить фото в мануале"""
        if not self.validate_manual_id(manual_id):
            return False
        if not self.validate_subproblem_id(subproblem_id):
            return False
        if not self.validate_photo_id(new_photo_id):
            return False

        caption = self.sanitize_text(caption, max_length=300)

        manuals = self.load_manuals()

        if manual_id not in manuals:
            return False

        manual = manuals[manual_id]

        if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
            return False

        subproblem = manual['subproblems'][subproblem_id]

        if 'photos' not in subproblem or not isinstance(subproblem['photos'], list):
            subproblem['photos'] = []

        # Проверка индекса
        if photo_index < 0 or photo_index >= len(subproblem['photos']):
            return False

        # Обновляем фото
        subproblem['photos'][photo_index] = {
            'id': new_photo_id,
            'caption': caption
        }

        return self.save_manuals(manuals)

    def delete_photo(self, manual_id: str, subproblem_id: str, photo_index: int) -> bool:
        """Удалить фото из мануала (оставляет текст, удаляет только фото)"""
        if not self.validate_manual_id(manual_id):
            return False
        if not self.validate_subproblem_id(subproblem_id):
            return False

        manuals = self.load_manuals()

        if manual_id not in manuals:
            return False

        manual = manuals[manual_id]

        if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
            return False

        subproblem = manual['subproblems'][subproblem_id]

        if 'photos' not in subproblem or not isinstance(subproblem['photos'], list):
            return False

        # Проверка индекса
        if photo_index < 0 or photo_index >= len(subproblem['photos']):
            return False

        # Удаляем только id фото, оставляя caption (текст шага)
        subproblem['photos'][photo_index]['id'] = None

        return self.save_manuals(manuals)

    def add_video_to_subproblem(self, manual_id: str, subproblem_id: str,
                                video_file_id: str, caption: str) -> bool:
        """Добавить Telegram видео в подпроблему"""
        if not self.validate_manual_id(manual_id):
            return False
        if not self.validate_subproblem_id(subproblem_id):
            return False
        if not self.validate_video_id(video_file_id):
            return False

        caption = self.sanitize_text(caption, max_length=300)

        manuals = self.load_manuals()

        if manual_id not in manuals:
            return False

        manual = manuals[manual_id]

        if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
            return False

        subproblem = manual['subproblems'][subproblem_id]

        # Добавляем video_id в подпроблему (только один видео-мануал на подпроблему)
        subproblem['video'] = {
            'id': video_file_id,
            'caption': caption
        }

        return self.save_manuals(manuals)

    def delete_video(self, manual_id: str, subproblem_id: str) -> bool:
        """Удалить видео из подпроблемы"""
        if not self.validate_manual_id(manual_id):
            return False
        if not self.validate_subproblem_id(subproblem_id):
            return False

        manuals = self.load_manuals()

        if manual_id not in manuals:
            return False

        manual = manuals[manual_id]

        if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
            return False

        subproblem = manual['subproblems'][subproblem_id]

        # Удаляем видео если оно есть
        if 'video' in subproblem:
            del subproblem['video']
            return self.save_manuals(manuals)

        return False

    def add_new_step(self, manual_id: str, subproblem_id: str, caption: str, after_index: int = -1) -> bool:
        """Добавить новый пустой шаг в подпроблему

        Args:
            manual_id: ID мануала
            subproblem_id: ID подпроблемы
            caption: Описание шага
            after_index: Индекс, после которого вставить шаг.
                        -1 = в конец
                        -2 = в начало (перед первым шагом)
        """
        if not self.validate_manual_id(manual_id):
            return False
        if not self.validate_subproblem_id(subproblem_id):
            return False

        caption = self.sanitize_text(caption, max_length=300)
        if not caption:
            return False

        manuals = self.load_manuals()

        if manual_id not in manuals:
            return False

        manual = manuals[manual_id]

        if 'subproblems' not in manual or subproblem_id not in manual['subproblems']:
            return False

        subproblem = manual['subproblems'][subproblem_id]

        if 'photos' not in subproblem or not isinstance(subproblem['photos'], list):
            subproblem['photos'] = []

        # Создаем новый шаг
        new_step = {
            'id': None,
            'caption': caption
        }

        # Вставляем на нужную позицию
        if after_index == -2:
            # Вставляем в начало (перед первым шагом)
            subproblem['photos'].insert(0, new_step)
        elif after_index == -1 or after_index >= len(subproblem['photos']) - 1:
            # Добавляем в конец
            subproblem['photos'].append(new_step)
        else:
            # Вставляем после указанного индекса
            subproblem['photos'].insert(after_index + 1, new_step)

        return self.save_manuals(manuals)


class AdminAuth:
    """Безопасная авторизация администраторов"""

    @staticmethod
    def _get_admin_credentials() -> Dict[str, str]:
        """Получает учетные данные администраторов из переменных окружения"""
        admin_username = os.getenv('ADMIN_USERNAME', '')
        admin_password_hash = os.getenv('ADMIN_PASSWORD_HASH', '')

        if admin_username and admin_password_hash:
            return {admin_username: admin_password_hash}
        return {}

    @staticmethod
    def verify_admin(username: str, password: str) -> bool:
        """Проверка учётных данных администратора"""
        if not isinstance(username, str) or not isinstance(password, str):
            return False

        # Ограничение длины для предотвращения DoS
        if len(username) > 50 or len(password) > 128:
            return False

        credentials = AdminAuth._get_admin_credentials()
        if username not in credentials:
            return False

        hashed = credentials[username]
        return check_password_hash(hashed, password)

    @staticmethod
    def login_required(f):
        """Декоратор для защиты admin маршрутов"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('admin_logged_in'):
                flash('Требуется авторизация')
                return redirect(url_for('admin_login'))
            return f(*args, **kwargs)
        return decorated_function

    @staticmethod
    def generate_session_token() -> str:
        """Генерация безопасного токена сессии"""
        return secrets.token_urlsafe(32)


# Глобальный экземпляр
admin_manager = AdminManager()
