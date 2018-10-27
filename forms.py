"""AUCR yara plugin default page forms."""
# coding=utf-8
from flask_wtf import FlaskForm
from wtforms import SubmitField, TextAreaField, SelectMultipleField, IntegerField
from wtforms.validators import Length
from flask_babel import lazy_gettext as _l
from aucr_app.plugins.Horatio.globals import AVAILABLE_CHOICES


class CreateYara(FlaskForm):
    """Yara Rule Creation Form."""

    yara_rules = TextAreaField(_l('Yara Rules'), validators=[Length(min=0, max=4912)])
    yara_list_name = TextAreaField(_l('List Name'), validators=[Length(min=0, max=32)])
    group_access = SelectMultipleField(_l('Group Access'), choices=AVAILABLE_CHOICES)
    submit = SubmitField(_l('Create'))


class EditYara(FlaskForm):
    """Edit user profile settings."""

    yara_id = IntegerField(_l('Yara ID'), validators=[Length(min=0, max=12)])
    yara_list_name = TextAreaField(_l('List Name'), validators=[Length(min=0, max=32)])
    yara_rules = TextAreaField(_l('Yara Rules'), validators=[Length(min=0, max=4912000)])
    submit = SubmitField(_l('Save'))

    def __init__(self, yara, *args, **kwargs):
        """Edit yara rule init function."""
        super(EditYara, self).__init__(*args, **kwargs)
        try:
            self.yara_id = yara.id
            self.yara_rules = yara.yara_rules
            self.yara_list_name = yara.yara_list_name
        except:
            self.yara_rules = yara["yara_rules"]
            self.yara_list_name = yara["yara_list_name"]
