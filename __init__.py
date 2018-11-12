"""AUCR yara plugin."""
# coding=utf-8
import os
from multiprocessing import Process
from aucr_app.plugins.tasks.mq import get_a_task_mq
from aucr_app.plugins.yara.yara_processing import call_back
from aucr_app.plugins.yara.routes import yara_page
from aucr_app.plugins.yara.api.rules import rules_api_page
from aucr_app.plugins.yara import models


def load(app):
    """AUCR Yara plugin flask app blueprint registration."""
    app.register_blueprint(yara_page, url_prefix='/yara')
    app.register_blueprint(rules_api_page, url_prefix='/yara_rules')
    yara_processor = os.environ.get('YARA_PROCESSOR')
    tasks = "yararesults"
    rabbitmq_server = os.environ.get('RABBITMQ_SERVER')
    rabbitmq_username = os.environ.get('RABBITMQ_USERNAME')
    rabbitmq_password = os.environ.get('RABBITMQ_PASSWORD')
    if yara_processor:
        p = Process(target=get_a_task_mq, args=(tasks, call_back, rabbitmq_server, rabbitmq_username,
                                                rabbitmq_password))
        p.start()
