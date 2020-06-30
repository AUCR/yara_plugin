"""AUCR Yara plugin function library."""
# coding=utf-8
import os
import udatetime
import logging
import yara
import ujson
from flask import current_app
from aucr_app.plugins.auth.models import Group
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
                    data = scanner.match(file.path)
                    findings[str(file.name)] = {}
                    findings[str(file.name)]["strings"] = str(data[0].strings)

            except Exception as e:
                if scanner.match(file.path):
                    data = scanner.match(file.path)
                    findings[str(file.name)] = {}
                    findings[str(file.name)]["strings"] = str(data["main"][0]["strings"])


def test_yara(yara_report):
    yara_matches = {}
    try:
        scanner = yara.compile(source=yara_report.yara_rules)
        file_dir = os.environ.get('FILE_FOLDER')
        scan(scanner, file_dir, yara_matches)
        return yara_matches
    except Exception as e:
        logging.warning("Not a valid Yara File" + str(e))
        app = create_app()
        db.init_app(app)
        with app.app_context():
            group_ids = Group.query.filter_by(groups_id=yara_report.group_access).all()
            for player in group_ids:
                yara_notification = \
                    Message(sender_id=1,
                            recipient_id=player.username_id,
                            body=("Not a valid Yara File ID:" + str(yara_report.id) + " Error:" + str(e)))
                db.session.add(yara_notification)
                db.session.commit()
        return [], []


def call_back(ch, method, properties, report_id):
    """Yara Processing call back function."""
    app = create_app()
    db.init_app(app)
    with app.app_context():
        yara_report = YaraRules.query.filter_by(id=report_id.decode('utf-8')).first()
        yara_rule_file = yara_report.yara_rules
        yara_matches = test_yara(yara_report)
        for item in yara_matches:
            match_known_item = UNUM.query.filter_by(md5_hash=item).first()
            if match_known_item:
                match_known_classification = Classification.query.filter_by(id=match_known_item.classification).first()
                new_yara_result = YaraRuleResults(yara_list_id=yara_report.id,
                                                  matches=match_known_item.md5_hash,
                                                  file_matches=match_known_item.id,
                                                  file_string_matches=yara_matches[item]["strings"],
                                                  file_classification=match_known_classification.classification,
                                                  run_time=udatetime.utcnow())
                db.session.add(new_yara_result)
                db.session.commit()
                message_data = ujson.dumps(new_yara_result.to_dict(), indent=2, sort_keys=True)
                yara_notification = \
                    Message(sender_id=1, recipient_id=yara_report.created_by, body=message_data)
                db.session.add(yara_notification)
                db.session.commit()
