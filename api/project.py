import os
import sys
from orm import *
from connexion import request


def dump_full(p):
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
    }


def get_projects():
    db = Database()
    q = db.session.query(Project)
    q_cnt = q.count()
    for p in q:
        print(dump_full(p))
    print(q_cnt)

get_projects()