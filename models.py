"""Yara AUCR plugin default database tables."""
import os

# coding=utf-8
import udatetime as datetime
import yara
from sqlalchemy import event

from app import db


def check_dir(dir, name):
    if not os.path.exists(dir):
        raise RuntimeError("The {} dir '{}' must exist but it doesn't!".format(name, dir))


class YaraRules(db.Model):
    """Yara data default table for aucr."""

    __mal_dir = '/upload/malware'
    __fp_dir = '/upload/fp'

    check_dir(__mal_dir, 'malware')
    check_dir(__fp_dir, 'fp')

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

    @staticmethod
    def __scan(scanner, d, findings):
        for file in os.scandir(d):
            if file.is_file():
                try:
                    if scanner.match(file.path):
                        findings.append(str(file.name))
                except Exception as e:
                    print("Yara issue; " + str(e))

    def test_yara(self):
        good_matches = []
        bad_matches = []

        try:
            scanner = yara.compile(source=self.yara_rules)
            YaraRules.__scan(scanner, YaraRules.__mal_dir, good_matches)
            YaraRules.__scan(scanner, YaraRules.__fp_dir, bad_matches)
            return good_matches, bad_matches
        except Exception as e:
            # logging.warning("Not a valid Answer" + str(e))
            print("Something broke " + str(e))
            return [], []


@event.listens_for(db.session, 'before_flush')
def receive_before_flush(session, flush_context, instances):
    for t in (x for x in session.new.union(session.dirty) if (isinstance(x, YaraRules) and
                                                              x.yara_rules is not None and len(x.yara_rules) > 0)):
        good, bad = t.test_yara()
        print('GOOD Yara: ' + ' -- '.join(good))
        print('BAD Yara:  ' + ' -- '.join(bad))
        ()
