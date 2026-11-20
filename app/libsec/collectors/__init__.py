"""Коллекторы: у каждого NAME, INTERVAL (сек), SILENT_H (часов без новых записей до алерта, 0 — не следить) и run(c, state) -> число новых/изменённых записей.

state — dict курсора источника (sources.cursor), коллектор меняет его на месте.
"""
from . import cvelist, osv, kev, epss, cveapi, nginx

ALL = [cvelist, osv, kev, cveapi, epss, nginx]
BY_NAME = {m.NAME: m for m in ALL}
