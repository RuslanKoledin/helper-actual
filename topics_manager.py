"""
Модуль для управления тематиками обращений
Поддерживает импорт из CSV/Excel, быстрый поиск с учетом ошибок и падежей
"""

import sqlite3
import pandas as pd
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from difflib import SequenceMatcher
import re
import json


# Маппинг клавиш для транслитерации (русская ↔ английская раскладка)
KEYBOARD_LAYOUT_MAP = {
    # Русская → Английская
    'й': 'q', 'ц': 'w', 'у': 'e', 'к': 'r', 'е': 't', 'н': 'y', 'г': 'u', 'ш': 'i', 'щ': 'o', 'з': 'p',
    'х': '[', 'ъ': ']', 'ф': 'a', 'ы': 's', 'в': 'd', 'а': 'f', 'п': 'g', 'р': 'h', 'о': 'j', 'л': 'k',
    'д': 'l', 'ж': ';', 'э': "'", 'я': 'z', 'ч': 'x', 'с': 'c', 'м': 'v', 'и': 'b', 'т': 'n', 'ь': 'm',
    'б': ',', 'ю': '.', 'ё': '`',
    # Английская → Русская
    'q': 'й', 'w': 'ц', 'e': 'у', 'r': 'к', 't': 'е', 'y': 'н', 'u': 'г', 'i': 'ш', 'o': 'щ', 'p': 'з',
    '[': 'х', ']': 'ъ', 'a': 'ф', 's': 'ы', 'd': 'в', 'f': 'а', 'g': 'п', 'h': 'р', 'j': 'о', 'k': 'л',
    'l': 'д', ';': 'ж', "'": 'э', 'z': 'я', 'x': 'ч', 'c': 'с', 'v': 'м', 'b': 'и', 'n': 'т', 'm': 'ь',
    ',': 'б', '.': 'ю', '`': 'ё',
}

# Словарь синонимов для банковской тематики
SYNONYMS_DICT = {
    # Карты
    "карта": ["карточка", "картка", "карт", "картой", "карте", "карты", "кредитка", "дебетовая"],
    "карточка": ["карта", "картка", "карт", "картой", "карте", "карты"],
    "кредитка": ["карта", "кредитная карта", "кредитная"],

    # Платежи
    "платеж": ["оплата", "транзакция", "перевод", "платежа", "платежом", "платежи", "payment"],
    "оплата": ["платеж", "транзакция", "перевод", "платежи"],
    "перевод": ["платеж", "транзакция", "оплата", "переводы", "перевода"],
    "транзакция": ["платеж", "оплата", "перевод", "операция"],

    # Блокировка
    "блокировка": ["блок", "заблокировать", "заблокирована", "блокирован", "блокировали", "freeze"],
    "заблокировать": ["блокировка", "блок", "заблокирована", "блокирован"],
    "разблокировать": ["разблокировка", "разблок", "разблокирована", "разблокирован"],

    # Счет/аккаунт
    "счет": ["счёт", "аккаунт", "счета", "счету", "счетом", "account"],
    "аккаунт": ["счет", "счёт", "учетная запись", "профиль"],

    # Пароль/ПИН
    "пароль": ["пасс", "код", "password", "пароля", "паролем"],
    "пин": ["пин-код", "pin", "пинкод"],

    # Не работает
    "неработает": ["не работает", "сломалось", "отказ", "ошибка", "проблема", "баг"],
    "ошибка": ["error", "проблема", "сбой", "неисправность", "отказ"],
    "проблема": ["ошибка", "сбой", "неисправность", "не работает"],

    # Банкомат/терминал
    "банкомат": ["atm", "банкомата", "банкоматом", "банкоматы", "терминал"],
    "терминал": ["банкомат", "pos", "pos-терминал", "платежный терминал"],

    # Кредит
    "кредит": ["займ", "ссуда", "loan", "кредита", "кредитом", "кредиты"],
    "займ": ["кредит", "ссуда", "микрозайм"],

    # Депозит/вклад
    "вклад": ["депозит", "deposit", "вклада", "вкладом", "вклады"],
    "депозит": ["вклад", "deposit", "депозита"],

    # Мобильный банк
    "мобильныйбанк": ["мобильный банк", "mobile bank", "приложение", "мобильное приложение", "моб банк"],
    "приложение": ["app", "мобильное приложение", "мобильный банк"],

    # ДБО
    "дбо": ["интернет-банк", "онлайн банк", "web банк", "дистанционное обслуживание"],
    "интернет-банк": ["дбо", "онлайн банк", "web банк", "internet banking"],

    # Баланс
    "баланс": ["остаток", "balance", "баланса", "балансом"],
    "остаток": ["баланс", "balance", "остатка"],

    # Комиссия
    "комиссия": ["fee", "commission", "комиссии", "комиссией", "процент"],

    # Активация
    "активация": ["активировать", "активирована", "активирован", "включить"],
    "активировать": ["активация", "включить", "подключить"],

    # SMS
    "смс": ["sms", "сообщение", "уведомление"],
    "сообщение": ["смс", "sms", "message", "уведомление"],

    # Регистрация
    "регистрация": ["регистрация", "зарегистрировать", "создать аккаунт", "signup"],
    "авторизация": ["вход", "логин", "login", "войти"],

    # Клиент
    "клиент": ["пользователь", "юзер", "customer", "клиента"],
    "пользователь": ["клиент", "юзер", "user"],
}


class TopicsManager:
    """Управление тематиками с быстрым поиском"""
    
    def __init__(self, db_path: str = "topics.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()
        
    def _init_db(self):
        """Инициализация базы данных"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        cursor = self.conn.cursor()
        
        # Основная таблица тематик
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS topics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                sr1 TEXT,
                sr2 TEXT,
                sr3 TEXT,
                sr4 TEXT,
                full_topic TEXT NOT NULL,
                keywords TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Индексы для быстрого поиска
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_channel ON topics(channel)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_keywords ON topics(keywords)
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_full_topic ON topics(full_topic)
        """)
        
        # Таблица для кэша поисковых запросов
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS search_cache (
                query TEXT PRIMARY KEY,
                results TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        self.conn.commit()
    
    def _normalize_text(self, text: str) -> str:
        """Нормализация текста для поиска (приведение к нижнему регистру, удаление лишних пробелов)"""
        if not text:
            return ""
        # Приводим к нижнему регистру
        text = text.lower()
        # Удаляем лишние пробелы
        text = re.sub(r'\s+', ' ', text).strip()
        return text
    
    def _extract_keywords(self, *texts) -> str:
        """Извлечение ключевых слов из текстов для быстрого поиска"""
        keywords = []
        for text in texts:
            if text:
                # Извлекаем слова длиной > 2 символов
                words = re.findall(r'\b\w{3,}\b', self._normalize_text(text))
                keywords.extend(words)
        return ' '.join(set(keywords))
    
    def _similarity(self, a: str, b: str) -> float:
        """Вычисление схожести двух строк (0.0 - 1.0)"""
        return SequenceMatcher(None,
                             self._normalize_text(a),
                             self._normalize_text(b)).ratio()

    def _transliterate(self, text: str) -> str:
        """
        Конвертирует текст из одной раскладки клавиатуры в другую
        Например: "gkfnt;b" → "платежи"

        Args:
            text: исходный текст

        Returns:
            транслитерированный текст
        """
        result = []
        for char in text.lower():
            result.append(KEYBOARD_LAYOUT_MAP.get(char, char))
        return ''.join(result)

    def _expand_query_with_synonyms(self, query: str) -> set:
        """
        Расширяет поисковый запрос синонимами и транслитерацией

        Args:
            query: исходный поисковый запрос

        Returns:
            множество ключевых слов с учетом синонимов и транслитерации
        """
        query_normalized = self._normalize_text(query)
        words = set(re.findall(r'\b\w{2,}\b', query_normalized))

        # Добавляем транслитерацию всего запроса
        transliterated_query = self._transliterate(query_normalized)
        transliterated_words = set(re.findall(r'\b\w{2,}\b', transliterated_query))

        # Начинаем с оригинальных слов + транслитерированных
        expanded_words = set(words)
        expanded_words.update(transliterated_words)

        # Добавляем синонимы для каждого слова (включая транслитерированные)
        all_words = set(words) | transliterated_words

        for word in all_words:
            # Убираем пробелы из слова для поиска в словаре
            word_clean = word.replace(" ", "")

            # Ищем прямые совпадения в словаре синонимов
            if word_clean in SYNONYMS_DICT:
                for synonym in SYNONYMS_DICT[word_clean]:
                    # Добавляем каждое слово из синонима
                    synonym_words = re.findall(r'\b\w{2,}\b', self._normalize_text(synonym))
                    expanded_words.update(synonym_words)

            # Ищем частичные совпадения (если слово является частью ключа в словаре)
            for key in SYNONYMS_DICT:
                if word_clean in key or key in word_clean:
                    for synonym in SYNONYMS_DICT[key]:
                        synonym_words = re.findall(r'\b\w{2,}\b', self._normalize_text(synonym))
                        expanded_words.update(synonym_words)

        return expanded_words

    def import_from_csv(self, file_path: str, encoding: str = 'utf-8') -> Dict:
        """
        Импорт тематик из CSV файла
        
        Ожидаемые колонки: Канал, SR1, SR2, SR3, SR4, SR (или аналогичные)
        """
        try:
            df = pd.read_csv(file_path, encoding=encoding)
            return self._import_dataframe(df)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def import_from_excel(self, file_path: str, sheet_name: int = 0) -> Dict:
        """
        Импорт тематик из Excel файла
        
        Args:
            file_path: путь к файлу
            sheet_name: номер листа (0 - первый лист)
        """
        try:
            df = pd.read_excel(file_path, sheet_name=sheet_name)
            return self._import_dataframe(df)
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def _import_dataframe(self, df: pd.DataFrame) -> Dict:
        """Внутренний метод импорта из DataFrame"""
        cursor = self.conn.cursor()
        imported = 0
        errors = []
        
        # Определяем маппинг колонок (гибко)
        column_mapping = {}
        for col in df.columns:
            col_lower = col.lower().strip()
            if 'канал' in col_lower or 'channel' in col_lower:
                column_mapping['channel'] = col
            elif col_lower in ['sr1', 'sr 1', 'уровень 1', 'level 1']:
                column_mapping['sr1'] = col
            elif col_lower in ['sr2', 'sr 2', 'уровень 2', 'level 2']:
                column_mapping['sr2'] = col
            elif col_lower in ['sr3', 'sr 3', 'уровень 3', 'level 3']:
                column_mapping['sr3'] = col
            elif col_lower in ['sr4', 'sr 4', 'уровень 4', 'level 4']:
                column_mapping['sr4'] = col
            elif col_lower in ['sr', 'тематика', 'topic', 'полная тематика']:
                column_mapping['full_topic'] = col
        
        if 'channel' not in column_mapping:
            return {"success": False, "error": "Не найдена колонка 'Канал' или 'Channel'"}
        
        # Импортируем данные
        for idx, row in df.iterrows():
            try:
                channel = str(row[column_mapping['channel']]) if pd.notna(row[column_mapping['channel']]) else None
                sr1 = str(row[column_mapping['sr1']]) if 'sr1' in column_mapping and pd.notna(row[column_mapping['sr1']]) else None
                sr2 = str(row[column_mapping['sr2']]) if 'sr2' in column_mapping and pd.notna(row[column_mapping['sr2']]) else None
                sr3 = str(row[column_mapping['sr3']]) if 'sr3' in column_mapping and pd.notna(row[column_mapping['sr3']]) else None
                sr4 = str(row[column_mapping['sr4']]) if 'sr4' in column_mapping and pd.notna(row[column_mapping['sr4']]) else None
                
                # Формируем полную тематику
                if 'full_topic' in column_mapping and pd.notna(row[column_mapping['full_topic']]):
                    full_topic = str(row[column_mapping['full_topic']])
                else:
                    # Собираем из SR1-SR4
                    parts = [p for p in [sr1, sr2, sr3, sr4] if p and p != 'None']
                    full_topic = '/'.join(parts) if parts else channel
                
                if not channel or not full_topic:
                    continue
                
                # Генерируем ключевые слова
                keywords = self._extract_keywords(channel, sr1, sr2, sr3, sr4, full_topic)
                
                cursor.execute("""
                    INSERT INTO topics (channel, sr1, sr2, sr3, sr4, full_topic, keywords)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (channel, sr1, sr2, sr3, sr4, full_topic, keywords))
                
                imported += 1
                
            except Exception as e:
                errors.append(f"Строка {idx + 2}: {str(e)}")
        
        self.conn.commit()
        
        # Очищаем кэш после импорта
        cursor.execute("DELETE FROM search_cache")
        self.conn.commit()
        
        return {
            "success": True,
            "imported": imported,
            "errors": errors if errors else None
        }
    
    def add_topic(self, channel: str, sr1: str = None, sr2: str = None, 
                  sr3: str = None, sr4: str = None, full_topic: str = None) -> Dict:
        """Добавление одной тематики"""
        try:
            if not full_topic:
                parts = [p for p in [sr1, sr2, sr3, sr4] if p]
                full_topic = '/'.join(parts) if parts else channel
            
            keywords = self._extract_keywords(channel, sr1, sr2, sr3, sr4, full_topic)
            
            cursor = self.conn.cursor()
            cursor.execute("""
                INSERT INTO topics (channel, sr1, sr2, sr3, sr4, full_topic, keywords)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (channel, sr1, sr2, sr3, sr4, full_topic, keywords))
            
            self.conn.commit()
            
            # Очищаем кэш
            cursor.execute("DELETE FROM search_cache")
            self.conn.commit()
            
            return {"success": True, "id": cursor.lastrowid}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def delete_topic(self, topic_id: int) -> Dict:
        """Удаление тематики по ID"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("DELETE FROM topics WHERE id = ?", (topic_id,))
            self.conn.commit()
            
            # Очищаем кэш
            cursor.execute("DELETE FROM search_cache")
            self.conn.commit()
            
            return {"success": True, "deleted": cursor.rowcount}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def update_topic(self, topic_id: int, **kwargs) -> Dict:
        """Обновление тематики"""
        try:
            allowed_fields = ['channel', 'sr1', 'sr2', 'sr3', 'sr4', 'full_topic']
            updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
            
            if not updates:
                return {"success": False, "error": "Нет полей для обновления"}
            
            # Получаем текущие данные
            cursor = self.conn.cursor()
            cursor.execute("SELECT * FROM topics WHERE id = ?", (topic_id,))
            current = dict(cursor.fetchone())
            
            # Обновляем поля
            for key, value in updates.items():
                current[key] = value
            
            # Пересчитываем ключевые слова
            current['keywords'] = self._extract_keywords(
                current['channel'], current['sr1'], current['sr2'], 
                current['sr3'], current['sr4'], current['full_topic']
            )
            
            # Сохраняем
            set_clause = ', '.join([f"{k} = ?" for k in updates.keys()] + ['keywords = ?', 'updated_at = CURRENT_TIMESTAMP'])
            values = list(updates.values()) + [current['keywords'], topic_id]
            
            cursor.execute(f"UPDATE topics SET {set_clause} WHERE id = ?", values)
            self.conn.commit()
            
            # Очищаем кэш
            cursor.execute("DELETE FROM search_cache")
            self.conn.commit()
            
            return {"success": True}
            
        except Exception as e:
            return {"success": False, "error": str(e)}
    
    def search(self, query: str, limit: int = 10, threshold: float = 0.3,
               use_cache: bool = True) -> List[Dict]:
        """
        Умный поиск тематик с учетом ошибок и падежей

        Args:
            query: поисковый запрос
            limit: максимальное количество результатов
            threshold: минимальный порог схожести (0.0 - 1.0)
            use_cache: использовать кэш

        Returns:
            список найденных тематик с рейтингом схожести
        """
        if not query:
            return []

        query_normalized = self._normalize_text(query)

        # Проверяем кэш
        if use_cache:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT results FROM search_cache WHERE query = ? AND datetime(timestamp, '+1 hour') > datetime('now')",
                (query_normalized,)
            )
            cached = cursor.fetchone()
            if cached:
                return json.loads(cached['results'])

        # Извлекаем ключевые слова из запроса с учетом синонимов
        query_keywords = self._expand_query_with_synonyms(query)

        # Быстрый поиск по ключевым словам
        cursor = self.conn.cursor()

        # Ищем по full_topic напрямую (более точный поиск)
        candidates = []

        # 1. Сначала точный поиск по полной тематике
        if query_keywords:
            keyword_conditions = ' OR '.join(['full_topic LIKE ?' for _ in query_keywords])
            keyword_params = [f'%{kw}%' for kw in query_keywords]

            cursor.execute(f"""
                SELECT * FROM topics
                WHERE {keyword_conditions}
            """, keyword_params)

            candidates.extend([dict(row) for row in cursor.fetchall()])

        # 2. Дополнительный поиск по keywords для расширения результатов
        if len(candidates) < 100 and query_keywords:
            keyword_conditions = ' OR '.join(['keywords LIKE ?' for _ in query_keywords])
            keyword_params = [f'%{kw}%' for kw in query_keywords]

            cursor.execute(f"""
                SELECT * FROM topics
                WHERE {keyword_conditions}
            """, keyword_params)

            for row in cursor.fetchall():
                row_dict = dict(row)
                # Добавляем только уникальные записи
                if not any(c['id'] == row_dict['id'] for c in candidates):
                    candidates.append(row_dict)

        # Если все еще мало результатов, берем больше кандидатов
        if len(candidates) < 50:
            cursor.execute("SELECT * FROM topics LIMIT 500")
            for row in cursor.fetchall():
                row_dict = dict(row)
                if not any(c['id'] == row_dict['id'] for c in candidates):
                    candidates.append(row_dict)

        # Вычисляем схожесть для каждого кандидата
        results = []
        for topic in candidates:
            # Вычисляем схожесть по всем полям
            scores = []

            # Проверяем полную тематику с повышенным весом
            if topic['full_topic']:
                full_topic_score = self._similarity(query, topic['full_topic'])
                scores.append(full_topic_score * 1.5)  # Увеличиваем вес для полной тематики

            # Проверяем каждое поле SR
            for field in ['sr1', 'sr2', 'sr3', 'sr4']:
                if topic[field]:
                    score = self._similarity(query, topic[field])
                    scores.append(score)

            # Проверяем канал и ключевые слова с меньшим весом
            if topic['channel']:
                scores.append(self._similarity(query, topic['channel']) * 0.8)
            if topic['keywords']:
                scores.append(self._similarity(query, topic['keywords']) * 0.7)

            # Берем максимальную схожесть
            max_score = max(scores) if scores else 0

            # Дополнительный бонус за частичное совпадение подстрок
            if query_normalized in self._normalize_text(topic['full_topic']):
                max_score = min(max_score + 0.2, 1.0)

            if max_score >= threshold:
                results.append({
                    **topic,
                    'similarity': round(max_score, 3)
                })

        # Сортируем по схожести
        results.sort(key=lambda x: x['similarity'], reverse=True)
        results = results[:limit]

        # Кэшируем результаты
        if use_cache and results:
            cursor.execute(
                "INSERT OR REPLACE INTO search_cache (query, results) VALUES (?, ?)",
                (query_normalized, json.dumps(results))
            )
            self.conn.commit()

        return results
    
    def get_all_topics(self, limit: int = None) -> List[Dict]:
        """Получить все тематики"""
        cursor = self.conn.cursor()
        query = "SELECT * FROM topics ORDER BY channel, sr1, sr2, sr3, sr4"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query)
        return [dict(row) for row in cursor.fetchall()]

    def get_topics_by_channel(self, channel: str, limit: int = None) -> List[Dict]:
        """Получить все тематики для конкретного канала"""
        cursor = self.conn.cursor()
        query = "SELECT * FROM topics WHERE channel = ? ORDER BY sr1, sr2, sr3, sr4"
        if limit:
            query += f" LIMIT {limit}"

        cursor.execute(query, (channel,))
        return [dict(row) for row in cursor.fetchall()]

    def get_all_channels(self) -> List[str]:
        """Получить список всех уникальных каналов"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT DISTINCT channel FROM topics ORDER BY channel")
        return [row['channel'] for row in cursor.fetchall()]
    
    def get_topic_by_id(self, topic_id: int) -> Optional[Dict]:
        """Получить тематику по ID"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM topics WHERE id = ?", (topic_id,))
        row = cursor.fetchone()
        return dict(row) if row else None
    
    def get_statistics(self) -> Dict:
        """Получить статистику по тематикам"""
        cursor = self.conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as total FROM topics")
        total = cursor.fetchone()['total']
        
        cursor.execute("SELECT COUNT(DISTINCT channel) as channels FROM topics")
        channels = cursor.fetchone()['channels']
        
        cursor.execute("SELECT COUNT(*) as cache_size FROM search_cache")
        cache_size = cursor.fetchone()['cache_size']
        
        return {
            "total_topics": total,
            "unique_channels": channels,
            "cache_entries": cache_size
        }
    
    def clear_cache(self):
        """Очистка кэша поиска"""
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM search_cache")
        self.conn.commit()
    
    def export_to_csv(self, file_path: str):
        """Экспорт всех тематик в CSV"""
        topics = self.get_all_topics()
        df = pd.DataFrame(topics)
        df = df.drop(columns=['keywords'], errors='ignore')
        df.to_csv(file_path, index=False, encoding='utf-8-sig')
        return {"success": True, "exported": len(topics)}
    
    def export_to_excel(self, file_path: str):
        """Экспорт всех тематик в Excel"""
        topics = self.get_all_topics()
        df = pd.DataFrame(topics)
        df = df.drop(columns=['keywords'], errors='ignore')
        df.to_excel(file_path, index=False, engine='openpyxl')
        return {"success": True, "exported": len(topics)}
    
    def close(self):
        """Закрытие соединения с БД"""
        if self.conn:
            self.conn.close()


# Пример использования
if __name__ == "__main__":
    # Инициализация
    tm = TopicsManager("topics.db")
    
    # Импорт из CSV
    result = tm.import_from_csv("topics.csv")
    print(f"Импортировано: {result}")
    
    # Поиск
    results = tm.search("платеж карта", limit=5)
    print("\nРезультаты поиска:")
    for r in results:
        print(f"  {r['full_topic']} (схожесть: {r['similarity']})")
    
    # Статистика
    stats = tm.get_statistics()
    print(f"\nСтатистика: {stats}")
    
    tm.close()
