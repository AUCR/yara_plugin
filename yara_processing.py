"""AUCR Yara plugin function library."""
# coding=utf-8
import os
import udatetime
import logging
import yara
from flask import current_app
from aucr_app.plugins.unum.models import UNUM, Classification
from aucr_app import db, create_app
from aucr_app.plugins.yara_plugin.models import YaraRules, YaraRuleResults
from aucr_app.plugins.auth.models import Message


def check_dir(file_dir, name):
    if file_dir:
        if not os.path.exists(file_dir):
            raise RuntimeError("The {} dir '{}' must exist but it doesn't!".format(name, file_dir))


def scan(scanner, file_dir, findings):
    for file in os.scandir(file_dir):
        if file.is_file():
            try:
                if scanner.match(file.path):
                    findings.append(str(file.name))
            except Exception as e:
                print("Yara issue; " + str(e))


def test_yara(yara_rule_file):
    yara_matches = []
    try:
        scanner = yara.compile(source=yara_rule_file["fileobj"])
        file_dir = os.environ.get('FILE_FOLDER')
        scan(scanner, file_dir, yara_matches)
        return yara_matches
    except Exception as e:
        logging.warning("Not a valid Yara File" + str(e))
        return [], []


def call_back(ch, method, properties, report_id):
    """Yara Processing call back function."""
    app = create_app()
    db.init_app(app)
    with app.app_context():
        yara_report = YaraRules.query.filter_by(id=report_id.decode('utf-8')).first()
        yara_rule_file = current_app.mongo.db.aucr.find_one({"filename": yara_report.yara_list_name})
        yara_matches = test_yara(yara_rule_file)
        for item in yara_matches:
            match_known_item = UNUM.query.filter_by(md5_hash=item).first()
            match_known_classification = Classification.query.filter_by(id=match_known_item.classification).first()
            if match_known_item:
                new_yara_result = YaraRuleResults(yara_list_id=yara_report.id, matches=match_known_item.md5_hash,
                                                  file_matches=match_known_item.id,
                                                  file_classification=match_known_classification.classification,
                                                  run_time=udatetime.utcnow())
                db.session.add(new_yara_result)
                db.session.commit()
                yara_notification = \
                    Message(sender_id=1, recipient_id=match_known_item.created_by, body=str(new_yara_result.to_dict()))
                db.session.add(yara_notification)
                db.session.commit()
