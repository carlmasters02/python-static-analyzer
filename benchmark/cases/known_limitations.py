"""Labeled benchmark cases that exercise our KNOWN blind spots.

These exist so the precision/recall numbers are honest instead of
flattering. Each is annotated with which limitation it triggers. We fully
expect the current engine to get these "wrong" — that's the point.

Markers (hash-at-VULN should flag / hash-at-SAFE should not flag).
"""

import os


# ---- Expected FALSE NEGATIVES (real bugs we currently MISS) ---------------

def unknown_source_getenv():
    # LIMITATION: os.getenv() is not in our source list (we only model
    # os.environ). Taint is never introduced, so this real injection is missed.
    cmd = os.getenv("USER_CMD")
    os.system(cmd)  #@ VULN


def taint_through_return():
    # LIMITATION: no interprocedural analysis. We don't follow taint out of
    # get_input()'s return value, so we don't know os.system's arg is tainted.
    def get_input():
        return input()

    os.system(get_input())  #@ VULN


def taint_through_container():
    # LIMITATION: we don't track taint through list/dict elements.
    items = []
    items.append(input())
    os.system(items[0])  #@ VULN


# ---- Expected FALSE POSITIVE (safe, but we flag it anyway) -----------------

def reassigned_clean():
    # LIMITATION: flow-insensitive within a scope. 'x' is tainted, then
    # reassigned to a constant BEFORE the sink, so this is actually SAFE —
    # but we don't model statement order, so we flag it. A real false alarm.
    x = input()
    x = "safe_constant_value"
    os.system(x)  #@ SAFE
