"""AUCR yara plugin."""
# coding=utf-8
from aucr_app.plugins.yara.routes import yara_page
from aucr_app.plugins.yara.api.rules import rules_api_page
from aucr_app.plugins.yara import models


def load(app):
    """AUCR Yara plugin flask app blueprint registration."""
    app.register_blueprint(yara_page, url_prefix='/yara')
    app.register_blueprint(rules_api_page, url_prefix='/yara_rules')
