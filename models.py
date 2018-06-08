"""Yara AUCR plugin default database tables."""
# coding=utf-8
import udatetime as datetime
from app import db
from yaml_info.yamlinfo import YamlInfo
import yara
import os
from sqlalchemy import event


class YaraRules(db.Model):
    """Yara data default table for aucr."""

    __tablename__ = 'yara_rules'
    id = db.Column(db.Integer, primary_key=True)
    yara_list_name = db.Column(db.String(32), index=True)
    created_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modify_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    yara_rules = db.Column(db.String(4912))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_access = db.Column(db.Integer, db.ForeignKey('groups.id'))

    def __repr__(self):
        return '<Yara {}>'.format(self.yara_name)

    def test_yara(self, provided_key):
        results = []
        try:
            rules = yara.compile(source=provided_key)
            malz_path = os.listdir('CTFd/plugins/CTFd-yarachallenge/assets/malware')
            for file_names in malz_path:
                test_file = ('CTFd/plugins/CTFd-yarachallenge/assets/malware/' + file_names)
                matches = rules.match(test_file)
                if matches:
                    match_name = str(file_names)
                    results.append(match_name)
        except Exception as e:
            # logging.warning("Not a valid Answer" + str(e))
            return results


@event.listens_for(db.session, 'before_flush')
def receive_before_flush(session, flush_context, instances):
    for t in (x for x in session.new.union(session.dirty) if isinstance(x, YaraRules)):
        t.test_yara()
