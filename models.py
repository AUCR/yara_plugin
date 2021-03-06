# coding=utf-8
"""Yara AUCR plugin default database tables."""
import udatetime as datetime
from aucr_app import db
from aucr_app.plugins.auth.models import SearchableMixin, PaginatedAPIMixin


class YaraRuleResults(db.Model):
    """Yara Result database table."""

    __tablename__ = 'yara_rule_results'
    id = db.Column(db.Integer, primary_key=True)
    yara_list_id = db.Column(db.Integer, db.ForeignKey('yara_rules.id'))
    matches = db.Column(db.String(3072))
    file_string_matches = db.Column(db.String(4912000))
    file_matches = db.Column(db.Integer, db.ForeignKey('uploaded_file_table.id'))
    file_classification = db.Column(db.String(3072))
    run_time = db.Column(db.DateTime)

    def __repr__(self):
        return '<Yara Results {}>'.format(self.yara_name)

    def to_dict(self):
        """Return dictionary object type for API calls."""
        data = {
            'id': self.id,
            'yara_list_id': self.yara_list_id,
            'matches': self.matches,
            'run_time': self.run_time.isoformat() + 'Z',
            'file_matches': self.file_matches,
            'file_string_matches': self.file_string_matches,
            'file_classification': self.file_classification
        }
        return data


class YaraRules(SearchableMixin, PaginatedAPIMixin, db.Model):
    """Yara data default table for aucr."""

    __searchable__ = ['id', 'yara_list_name', 'modify_time_stamp', 'created_by', 'yara_rules']
    __tablename__ = 'yara_rules'
    id = db.Column(db.Integer, primary_key=True)
    yara_list_name = db.Column(db.String(32), index=True, unique=True)
    created_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    modify_time_stamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    group_access = db.Column(db.Integer, db.ForeignKey('groups.id'))
    last_updated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    yara_rules = db.Column(db.String(4912000))

    def __repr__(self):
        return '<Yara {}>'.format(self.yara_list_name)

    def to_dict(self):
        """Return dictionary object type for API calls."""
        data = {
            'id': self.id,
            'yara_list_name': self.yara_list_name,
            'last_seen': self.created_time_stamp.isoformat() + 'Z',
            'modify_time_stamp': self.modify_time_stamp.isoformat() + 'Z',
            'created_by': self.created_by,
            'group_access': self.group_access,
            'yara_rules': self.yara_rules,
            'last_updated_by': self.last_updated_by
        }
        return data

    def from_dict(self, data):
        """Process from dictionary object type for API Yara Rule Post."""
        for field in ['yara_list_name', 'group_access', 'created_by']:
            if field in data:
                setattr(self, field, data[field])
