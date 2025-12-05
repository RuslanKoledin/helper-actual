"""
Модуль для управления статистикой обращений
Отслеживает все обращения пользователей и их результаты
Использует PostgreSQL для надежного хранения аналитических данных
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import json
import os
from dotenv import load_dotenv

load_dotenv()


class StatsManager:
    """Управление статистикой обращений"""

    # Типы результатов обращения
    RESULT_VIDEO_HELPED = "video_helped"  # Видео помогло
    RESULT_VIDEO_NOT_HELPED = "video_not_helped"  # Видео не помогло
    RESULT_SOLVED_BY_HELPER = "solved_by_helper"  # Решено через помощника
    RESULT_TICKET_CREATED = "ticket_created"  # Создана заявка в техподдержку
    RESULT_TICKET_DONE = "ticket_done"  # Заявка выполнена
    RESULT_TICKET_NOT_RELEVANT = "ticket_not_relevant"  # Заявка не актуальна

    def __init__(self):
        self.conn = None
        self._init_db()

    def _get_connection(self):
        """Получить подключение к PostgreSQL"""
        if not self.conn or self.conn.closed:
            self.conn = psycopg2.connect(
                host=os.getenv('POSTGRES_HOST', 'localhost'),
                port=os.getenv('POSTGRES_PORT', '5432'),
                database=os.getenv('POSTGRES_DB', 'helper_analytics'),
                user=os.getenv('POSTGRES_USER', 'ruslan'),
                password=os.getenv('POSTGRES_PASSWORD', ''),
                cursor_factory=RealDictCursor
            )
        return self.conn

    def _init_db(self):
        """Инициализация базы данных"""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            # Таблица обращений
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS user_requests (
                    id SERIAL PRIMARY KEY,
                    department VARCHAR(200),
                    name VARCHAR(100),
                    workplace VARCHAR(50),
                    problem_description TEXT NOT NULL,
                    problem_id VARCHAR(50),
                    subproblem_id VARCHAR(50),
                    result_type VARCHAR(50) NOT NULL,
                    topic_id INTEGER,
                    topic_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Индексы для быстрых запросов
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_result_type
                ON user_requests(result_type)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_created_at
                ON user_requests(created_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_department
                ON user_requests(department)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_problem_description
                ON user_requests USING gin(to_tsvector('russian', problem_description))
            """)

            conn.commit()
            print("[StatsManager] PostgreSQL таблицы созданы успешно")

        except Exception as e:
            print(f"[StatsManager] Ошибка инициализации БД: {e}")
            if self.conn:
                self.conn.rollback()

    def log_request(self, result_type: str, problem_description: str,
                   department: str = None, name: str = None, workplace: str = None,
                   problem_id: str = None, subproblem_id: str = None,
                   topic_id: int = None, topic_name: str = None) -> int:
        """
        Логирование обращения

        Args:
            result_type: тип результата (RESULT_*)
            problem_description: описание проблемы
            department: отдел сотрудника
            name: имя сотрудника
            workplace: рабочее место
            problem_id: ID проблемы из мануала
            subproblem_id: ID подпроблемы
            topic_id: ID тематики из базы тематик
            topic_name: название тематики

        Returns:
            ID созданной записи
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO user_requests
                (department, name, workplace, problem_description, problem_id,
                 subproblem_id, result_type, topic_id, topic_name)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (department, name, workplace, problem_description, problem_id,
                  subproblem_id, result_type, topic_id, topic_name))

            result = cursor.fetchone()
            conn.commit()
            return result['id'] if result else -1

        except Exception as e:
            print(f"[StatsManager] Ошибка логирования: {e}")
            if self.conn:
                self.conn.rollback()
            return -1

    def get_statistics(self, days: int = 30) -> Dict:
        """
        Получить общую статистику за указанный период

        Args:
            days: количество дней для анализа

        Returns:
            словарь со статистикой
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            date_from = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d 00:00:00')

            # Общее количество обращений
            cursor.execute("""
                SELECT COUNT(*) as total
                FROM user_requests
                WHERE created_at >= %s
            """, (date_from,))
            total = cursor.fetchone()['total']

            # Статистика по типам результатов
            cursor.execute("""
                SELECT result_type, COUNT(*) as count
                FROM user_requests
                WHERE created_at >= %s
                GROUP BY result_type
            """, (date_from,))

            results_stats = {}
            for row in cursor.fetchall():
                results_stats[row['result_type']] = row['count']

            # Вычисляем агрегированные метрики
            helped_count = (
                results_stats.get(self.RESULT_VIDEO_HELPED, 0) +
                results_stats.get(self.RESULT_SOLVED_BY_HELPER, 0)
            )

            not_helped_count = (
                results_stats.get(self.RESULT_VIDEO_NOT_HELPED, 0) +
                results_stats.get(self.RESULT_TICKET_CREATED, 0)
            )

            # Самостоятельно решенные (видео помогло + решено через помощника)
            self_solved_count = helped_count

            return {
                'total': total,
                'helped': helped_count,
                'not_helped': not_helped_count,
                'self_solved': self_solved_count,
                'results_breakdown': results_stats,
                'period_days': days
            }

        except Exception as e:
            print(f"[StatsManager] Ошибка получения статистики: {e}")
            return {
                'total': 0,
                'helped': 0,
                'not_helped': 0,
                'self_solved': 0,
                'results_breakdown': {},
                'period_days': days
            }

    def get_top_problems(self, limit: int = 10, days: int = 30) -> List[Dict]:
        """
        Получить топ самых частых проблем

        Args:
            limit: количество проблем для вывода
            days: период анализа в днях

        Returns:
            список проблем с количеством обращений
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            date_from = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d 00:00:00')

            cursor.execute("""
                SELECT
                    problem_description,
                    COUNT(*) as count,
                    COUNT(CASE WHEN result_type IN (%s, %s) THEN 1 END) as helped_count,
                    COUNT(CASE WHEN result_type NOT IN (%s, %s) THEN 1 END) as not_helped_count
                FROM user_requests
                WHERE created_at >= %s
                GROUP BY problem_description
                ORDER BY count DESC
                LIMIT %s
            """, (self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  date_from, limit))

            problems = []
            for row in cursor.fetchall():
                problems.append({
                    'problem': row['problem_description'],
                    'count': row['count'],
                    'helped': row['helped_count'],
                    'not_helped': row['not_helped_count']
                })

            return problems

        except Exception as e:
            print(f"[StatsManager] Ошибка получения топ проблем: {e}")
            return []

    def get_department_stats(self, days: int = 30) -> List[Dict]:
        """
        Получить статистику по отделам

        Args:
            days: период анализа в днях

        Returns:
            список статистики по отделам
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            date_from = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d 00:00:00')

            cursor.execute("""
                SELECT
                    department,
                    COUNT(*) as total,
                    COUNT(CASE WHEN result_type IN (%s, %s) THEN 1 END) as helped,
                    COUNT(CASE WHEN result_type NOT IN (%s, %s) THEN 1 END) as not_helped
                FROM user_requests
                WHERE created_at >= %s AND department IS NOT NULL
                GROUP BY department
                ORDER BY total DESC
            """, (self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  date_from))

            departments = []
            for row in cursor.fetchall():
                departments.append({
                    'department': row['department'],
                    'total': row['total'],
                    'helped': row['helped'],
                    'not_helped': row['not_helped']
                })

            return departments

        except Exception as e:
            print(f"[StatsManager] Ошибка получения статистики по отделам: {e}")
            return []

    def get_timeline_stats(self, days: int = 30) -> List[Dict]:
        """
        Получить статистику по дням (для графика)

        Args:
            days: период анализа в днях

        Returns:
            список статистики по дням
        """
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            date_from = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d 00:00:00')

            cursor.execute("""
                SELECT
                    DATE(created_at) as date,
                    COUNT(*) as total,
                    COUNT(CASE WHEN result_type IN (%s, %s) THEN 1 END) as helped,
                    COUNT(CASE WHEN result_type NOT IN (%s, %s) THEN 1 END) as not_helped
                FROM user_requests
                WHERE created_at >= %s
                GROUP BY DATE(created_at)
                ORDER BY date ASC
            """, (self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  self.RESULT_VIDEO_HELPED, self.RESULT_SOLVED_BY_HELPER,
                  date_from))

            timeline = []
            for row in cursor.fetchall():
                timeline.append({
                    'date': str(row['date']),
                    'total': row['total'],
                    'helped': row['helped'],
                    'not_helped': row['not_helped']
                })

            return timeline

        except Exception as e:
            print(f"[StatsManager] Ошибка получения timeline: {e}")
            return []

    def close(self):
        """Закрытие соединения с БД"""
        if self.conn and not self.conn.closed:
            self.conn.close()


# Тестирование
if __name__ == "__main__":
    sm = StatsManager()

    # Тестовые данные
    print("Добавляем тестовые данные...")

    sm.log_request(
        result_type=sm.RESULT_VIDEO_HELPED,
        problem_description="Не работает ДБО",
        department="Отдел обучения",
        name="Иван",
        workplace="101"
    )

    sm.log_request(
        result_type=sm.RESULT_TICKET_CREATED,
        problem_description="Проблема с картой",
        department="Отдел онлайн обращений",
        name="Мария",
        workplace="202"
    )

    # Получаем статистику
    print("\n=== Общая статистика ===")
    stats = sm.get_statistics(days=30)
    print(json.dumps(stats, indent=2, ensure_ascii=False))

    print("\n=== Топ проблем ===")
    top_problems = sm.get_top_problems(limit=5)
    print(json.dumps(top_problems, indent=2, ensure_ascii=False))

    print("\n=== Статистика по отделам ===")
    dept_stats = sm.get_department_stats()
    print(json.dumps(dept_stats, indent=2, ensure_ascii=False))

    sm.close()
