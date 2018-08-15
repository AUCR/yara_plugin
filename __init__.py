"""AUCR yara plugin."""
# coding=utf-8
from app.plugins.yara.routes import yara_page
from app.plugins.yara.api.rules import rules_api_page


def load(app):
    """AUCR Yara plugin flask app blueprint registration."""
    app.register_blueprint(yara_page, url_prefix='/yara')
    app.register_blueprint(rules_api_page, url_prefix='/yara_rules')
