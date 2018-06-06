"""AUCR yara plugin route page handler."""
# coding=utf-8
import udatetime
from app import db
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.plugins.auth.models import Groups, Group
from app.plugins.yara.forms import CreateYara, EditYara
from app.plugins.yara.models import YaraRules
from sqlalchemy import or_

yara_page = Blueprint('yara', __name__, template_folder='templates')


@yara_page.route('/yara')
@login_required
def yara_route():
    """Yara Plugin default rule view."""

    yara_list_name = YaraRules.query.all()
    yara_dict = {}
    for item in yara_list_name:
        item_dict = {"id": item.id, "yara_list_name": item.yara_list_name}
        yara_dict[str(item.id)] = item_dict
    return render_template('yara.html', table_dict=yara_dict)


@yara_page.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create yara default view."""
    group_info = Groups.query.all()
    if request.method == 'POST':
        form = CreateYara(request.form)
        if form.validate():
            new_yara = YaraRules(created_by=current_user.id, group_access=form.group_access.data,
                                 created_time_stamp=udatetime.utcnow(), modify_time_stamp=udatetime.utcnow())
            db.session.add(new_yara)
            db.session.commit()
            flash("The yara rule has been created.")
            return redirect(url_for('yara.yara_route'))
    form = CreateYara(request.form)
    return render_template('create.html', title='Create Yara', form=form, groups=group_info)


@yara_page.route('/edit', methods=['GET', 'POST'])
@login_required
def edit():
    """Edit yara view."""
    group_info = Groups.query.all()
    submitted_yara_id = request.args.get("id")
    group_ids = Group.query.filter_by(username_id=current_user.id).all()
    user_groups = []
    for user_group in group_ids:
        user_groups.append(user_group.groups_id)
    yara = YaraRules.query.filter_by(id=submitted_yara_id)
    yara = yara.filter(or_(YaraRules.id==submitted_yara_id, YaraRules.group_access.in_(user_groups))).first()
    if request.method == 'POST':
        if yara:
            form = EditYara(request.form)
            if form.validate_on_submit():
                yara.yara_rules = request.form["yara_rules"]
                yara.yara_list_name = request.form["yara_list_name"]
                db.session.commit()
        return yara_route()
    if request.method == "GET":
        if yara:
            form = EditYara(yara)
            yara_dict = {"id": yara.id, "yara_rules": yara.yara_rules, "yara_list_name": yara.yara_list_name}
            return render_template('edit.html', title='Edit Yara Rule', form=form,
                                   groups=group_info, table_dict=yara_dict)
        else:
            return yara_route()
