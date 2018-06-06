"""AUCR yara plugin."""
# coding=utf-8
from app.plugins.yara.routes import yara_page


def load(app):
    """AUCR Yara plugin flask app blueprint registration."""
    app.register_blueprint(yara_page, url_prefix='/yara')
