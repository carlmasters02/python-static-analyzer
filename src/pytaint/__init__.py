"""pytaint — a taint-based static analyzer for Python.

Detects SQL injection and command injection by parsing source into an AST
and tracking data flow from user-controlled *sources* to dangerous *sinks*.
"""

__version__ = "0.1.0"
