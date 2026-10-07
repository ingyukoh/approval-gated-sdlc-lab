"""Lightweight shared rejection type; public page loading needs no model SDK."""
class Rejected(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)
