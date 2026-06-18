"""Data-access layer.

CRUD helpers isolate SQLAlchemy queries from the API routes. Every query is
expressed with the SQLAlchemy 2.0 ``select()`` construct and bound parameters
— never string interpolation — which is the structural fix for the SQL
injection that riddled the original PHP backend.
"""
