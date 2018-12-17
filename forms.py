"""AUCR yara plugin default page forms."""
# coding=utf-8
from flask import request
from flask_wtf import FlaskForm
from flask_babel import lazy_gettext as _l
from wtforms.validators import DataRequired
from wtforms import SubmitField, TextAreaField, SelectMultipleField, IntegerField, StringField
from wtforms.validators import Length
from aucr_app.plugins.Horatio.globals import AVAILABLE_CHOICES


class SearchForm(FlaskForm):
    """SearchForm wtf search form builder."""
    q = StringField(_l('yara.yara_search'), validators=[DataRequired()])

    def __init__(self, *args, **kwargs):
        if 'formdata' not in kwargs:
            kwargs['formdata'] = request.args
        if 'csrf_enabled' not in kwargs:
            kwargs['csrf_enabled'] = False
        super(SearchForm, self).__init__(*args, **kwargs)


class Yara(FlaskForm):
    """Upload New File Form."""

    createnewyara = SubmitField(_l("Create"))


class CreateYara(FlaskForm):
    """Yara Rule Creation Form."""

    yara_rules = TextAreaField(_l('Yara Rules'), validators=[Length(min=0, max=4912000)])
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
            self.yara_list_name = yara.yara_list_name
        except:
            self.yara_list_name = yara["yara_list_name"]
