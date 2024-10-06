# advanced_query_optimizer.py

import sqlparse
from sqlparse.sql import IdentifierList, Identifier, Function
from sqlparse.tokens import Keyword, DML
from collections import defaultdict
import re
from .database import db

class AdvancedQueryOptimizer:
    def __init__(self, db):
        self.db = db

    def optimize_query(self, sql_query):
        # Parse the SQL query
        parsed = sqlparse.parse(sql_query)[0]
        
        # Analyze and optimize the query
        optimized = self._optimize_statement(parsed)
        
        # Convert back to SQL string
        return str(optimized)

    def _optimize_statement(self, statement):
        if statement.get_type() == 'SELECT':
            return self._optimize_select(statement)
        # Add optimizations for other types of statements (INSERT, UPDATE, DELETE) if needed
        return statement

    def _optimize_select(self, select_stmt):
        # Extract main components of the SELECT statement
        select_tokens = []
        from_token = None
        where_token = None
        group_by_token = None
        having_token = None
        order_by_token = None
        limit_token = None

        for token in select_stmt.tokens:
            if token.ttype is DML and token.value.upper() == 'SELECT':
                select_tokens = list(token.parent.get_identifiers())
            elif token.ttype is Keyword and token.value.upper() == 'FROM':
                from_token = token
            elif token.ttype is Keyword and token.value.upper() == 'WHERE':
                where_token = token
            elif token.ttype is Keyword and token.value.upper() == 'GROUP BY':
                group_by_token = token
            elif token.ttype is Keyword and token.value.upper() == 'HAVING':
                having_token = token
            elif token.ttype is Keyword and token.value.upper() == 'ORDER BY':
                order_by_token = token
            elif token.ttype is Keyword and token.value.upper() == 'LIMIT':
                limit_token = token

        # Apply optimizations
        select_tokens = self._optimize_projections(select_tokens)
        from_token = self._optimize_joins(from_token)
        where_token = self._optimize_where_clause(where_token)
        group_by_token = self._optimize_group_by(group_by_token)
        having_token = self._optimize_having(having_token)
        order_by_token = self._optimize_order_by(order_by_token)

        # Reconstruct the optimized query
        optimized_tokens = [
            sqlparse.sql.Token(DML, 'SELECT'),
            sqlparse.sql.TokenList(select_tokens)
        ]
        if from_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'FROM'), from_token])
        if where_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'WHERE'), where_token])
        if group_by_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'GROUP BY'), group_by_token])
        if having_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'HAVING'), having_token])
        if order_by_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'ORDER BY'), order_by_token])
        if limit_token:
            optimized_tokens.extend([sqlparse.sql.Token(Keyword, 'LIMIT'), limit_token])

        return sqlparse.sql.Statement(optimized_tokens)

    def _optimize_projections(self, select_tokens):
        # Remove unnecessary columns, optimize function calls
        optimized_tokens = []
        for token in select_tokens:
            if isinstance(token, Function):
                optimized_tokens.append(self._optimize_function(token))
            else:
                optimized_tokens.append(token)
        return optimized_tokens

    def _optimize_function(self, func_token):
        # Optimize function calls (e.g., replace COUNT(*) with COUNT(1))
        if func_token.get_name().upper() == 'COUNT' and str(func_token.get_parameters()) == '(*)':
            return Function(f"COUNT(1)")
        return func_token

    def _optimize_joins(self, from_token):
        if not from_token:
            return None
        
        # Parse the FROM clause
        from_clause = from_token.parent
        tables = []
        join_conditions = []
        
        for token in from_clause.tokens:
            if isinstance(token, Identifier):
                tables.append(token)
            elif isinstance(token, IdentifierList):
                tables.extend(list(token.get_identifiers()))
            elif isinstance(token, Function) and token.get_name().upper() in ('INNER JOIN', 'LEFT JOIN', 'RIGHT JOIN', 'FULL JOIN'):
                join_type = token.get_name().upper()
                join_table = list(token.get_parameters())[0]
                on_clause = next((t for t in token.tokens if isinstance(t, Where) and t.value.upper().startswith('ON')), None)
                if on_clause:
                    join_conditions.append((join_type, join_table, on_clause))
        
        # Reorder joins based on estimated table sizes and join conditions
        optimized_joins = self._reorder_joins(tables, join_conditions)
        
        # Reconstruct the optimized FROM clause
        optimized_from = sqlparse.sql.TokenList([tables[0]])
        for join_type, table, condition in optimized_joins:
            optimized_from.append(sqlparse.sql.Token(Keyword, join_type))
            optimized_from.append(table)
            optimized_from.append(sqlparse.sql.Token(Keyword, 'ON'))
            optimized_from.append(condition)
        
        return optimized_from

    def _reorder_joins(self, tables, join_conditions):
        # Implement join reordering logic here
        # This is a complex topic that often involves cost-based optimization
        # For simplicity, we'll use a rule-based approach
        
        # Start with the table that has the most selective join condition
        table_scores = defaultdict(int)
        for _, table, condition in join_conditions:
            table_scores[str(table)] += self._estimate_condition_selectivity(condition)
        
        ordered_tables = sorted(tables, key=lambda t: table_scores[str(t)], reverse=True)
        
        # Reorder joins based on the table order
        optimized_joins = []
        for i, table in enumerate(ordered_tables[1:], 1):
            join_type, _, condition = next((jc for jc in join_conditions if str(jc[1]) == str(table)), ('INNER JOIN', table, None))
            optimized_joins.append((join_type, table, condition))
        
        return optimized_joins

    def _estimate_condition_selectivity(self, condition):
        # Implement condition selectivity estimation
        # This is a simplified version; in practice, you'd use statistics and more complex heuristics
        condition_str = str(condition)
        if '=' in condition_str:
            return 10
        elif 'LIKE' in condition_str:
            return 5
        elif 'IN' in condition_str:
            return 7
        else:
            return 1

    def _optimize_where_clause(self, where_token):
        if not where_token:
            return None
        
        where_clause = where_token.parent
        conditions = self._split_conditions(where_clause)
        
        # Reorder conditions based on estimated selectivity
        optimized_conditions = sorted(conditions, key=self._estimate_condition_selectivity, reverse=True)
        
        # Reconstruct the optimized WHERE clause
        optimized_where = sqlparse.sql.TokenList([sqlparse.sql.Token(Keyword, 'WHERE')])
        optimized_where.extend(optimized_conditions)
        
        return optimized_where

    def _split_conditions(self, where_clause):
        conditions = []
        current_condition = []
        for token in where_clause.tokens:
            if token.value.upper() in ('AND', 'OR'):
                if current_condition:
                    conditions.append(sqlparse.sql.TokenList(current_condition))
                    current_condition = []
                conditions.append(token)
            else:
                current_condition.append(token)
        if current_condition:
            conditions.append(sqlparse.sql.TokenList(current_condition))
        return conditions

    def _optimize_group_by(self, group_by_token):
        # Optimize GROUP BY clause (e.g., remove unnecessary columns)
        return group_by_token

    def _optimize_having(self, having_token):
        # Optimize HAVING clause (e.g., move conditions to WHERE if possible)
        return having_token

    def _optimize_order_by(self, order_by_token):
        # Optimize ORDER BY clause (e.g., remove if unnecessary due to unique constraint)
        return order_by_token

    def analyze_query_performance(self, sql_query):
        # Execute EXPLAIN ANALYZE
        explain_query = f"EXPLAIN ANALYZE {sql_query}"
        result = self.db.session.execute(explain_query)
        plan = result.fetchall()
        
        # Parse the execution plan
        total_cost = 0
        total_time = 0
        table_scans = []
        index_scans = []
        
        for row in plan:
            plan_line = row[0]
            if 'Total Cost:' in plan_line:
                total_cost = float(re.search(r'Total Cost: (\d+\.\d+)', plan_line).group(1))
            elif 'Execution Time:' in plan_line:
                total_time = float(re.search(r'Execution Time: (\d+\.\d+)', plan_line).group(1))
            elif 'Seq Scan' in plan_line:
                table_scans.append(re.search(r'Seq Scan on (\w+)', plan_line).group(1))
            elif 'Index Scan' in plan_line:
                index_scans.append(re.search(r'Index Scan using (\w+)', plan_line).group(1))
        
        return {
            'total_cost': total_cost,
            'total_time': total_time,
            'table_scans': table_scans,
            'index_scans': index_scans,
            'full_plan': plan
        }

    def suggest_optimizations(self, query_analysis):
        suggestions = []
        
        if query_analysis['table_scans']:
            suggestions.append(f"Consider adding indexes for tables: {', '.join(query_analysis['table_scans'])}")
        
        if query_analysis['total_time'] > 1000:  # If query takes more than 1 second
            suggestions.append("Query is slow. Consider optimizing or caching frequently accessed data.")
        
        if len(query_analysis['index_scans']) == 0 and query_analysis['total_cost'] > 1000:
            suggestions.append("No indexes were used. Review your table design and add appropriate indexes.")
        
        return suggestions

from flask import current_app
from sqlalchemy import text
from functools import wraps
from cachetools import TTLCache
import time
import logging

class QueryOptimizer:
    def __init__(self, db):
        self.db = db
        self.cache = TTLCache(maxsize=1000, ttl=300)  # Cache for 5 minutes
        self.logger = logging.getLogger(__name__)

    def explain_analyze(self, query):
        try:
            result = self.db.session.execute(text(f"EXPLAIN ANALYZE {query}"))
            return result.fetchall()
        except Exception as e:
            self.logger.error(f"Error in explain_analyze: {str(e)}")
            return None

    def optimize_join(self, query):
        # This is a simplified example. In reality, you'd need to parse the query
        # and make intelligent decisions about join types and order.
        optimized_query = query.replace("JOIN", "INNER JOIN")
        return optimized_query

    def cache_query(self, func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            if key in self.cache:
                return self.cache[key]
            result = func(*args, **kwargs)
            self.cache[key] = result
            return result
        return wrapper

    def paginate_query(self, query, page, per_page):
        return query.paginate(page=page, per_page=per_page, error_out=False)

    def create_materialized_view(self, name, query):
        try:
            self.db.session.execute(text(f"CREATE MATERIALIZED VIEW IF NOT EXISTS {name} AS {query}"))
            self.db.session.commit()
        except Exception as e:
            self.logger.error(f"Error creating materialized view {name}: {str(e)}")
            self.db.session.rollback()

    def refresh_materialized_view(self, name):
        try:
            self.db.session.execute(text(f"REFRESH MATERIALIZED VIEW CONCURRENTLY {name}"))
            self.db.session.commit()
        except Exception as e:
            self.logger.error(f"Error refreshing materialized view {name}: {str(e)}")
            self.db.session.rollback()

    def optimize_query(self, query):
        # This is a placeholder for more advanced query optimization logic
        # You could implement query rewriting, index recommendations, etc.
        return query

    def monitor_query_performance(self, query_func):
        @wraps(query_func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = query_func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            if execution_time > 1.0:  # Log slow queries (taking more than 1 second)
                self.logger.warning(f"Slow query detected: {query_func.__name__} took {execution_time:.2f} seconds")
            return result
        return wrapper

    def create_index_recommendation(self, table_name, column_name):
        # This is a simplified example. In a real-world scenario, you'd analyze query patterns
        # and make more intelligent recommendations.
        return f"CREATE INDEX idx_{table_name}_{column_name} ON {table_name} ({column_name});"

    def analyze_table(self, table_name):
        try:
            self.db.session.execute(text(f"ANALYZE {table_name};"))
            self.db.session.commit()
        except Exception as e:
            self.logger.error(f"Error analyzing table {table_name}: {str(e)}")
            self.db.session.rollback()

query_optimizer = QueryOptimizer(db)