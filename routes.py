"""AUCR yara plugin route page handler."""
# coding=utf-8
import udatetime
import logging
from aucr_app import db
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from aucr_app.plugins.tasks.mq import get_mq_yaml_configs, index_mq_aucr_report
from aucr_app.plugins.auth.models import Groups, Group, User
from aucr_app.plugins.yara.forms import CreateYara, EditYara, Yara
from aucr_app.plugins.yara.models import YaraRules, YaraRuleResults
from sqlalchemy import or_

yara_page = Blueprint('yara', __name__, template_folder='templates')


@yara_page.route('/yara',  methods=['GET', 'POST'])
@login_required
def yara_route():
    """Yara Plugin default rule view."""
    form = Yara(request.form)
    if request.method == 'POST':
        request_form = Yara(request.form)
        if request_form.createnewyara:
            return redirect("yara/create")
    page = request.args.get('page', 1, type=int) or 1
    count = page * 10
    yara_dict = {}
    total = 0
    while total < 10:
        total += 1
        id_item = count - 10 + total
        item = YaraRules.query.filter_by(id=id_item).first()
        if item:
            group_ids = Group.query.filter_by(username_id=current_user.id).all()
            for groups in group_ids:
                if item.group_access == groups.groups_id:
                    author_name = User.query.filter_by(id=item.created_by).first()
                    total_hits = len(YaraRuleResults.query.filter_by(yara_list_id=item.id).all())
                    item_dict = {"id": item.id, "yara_list_name": item.yara_list_name, "author": author_name.username,
                                 "total_hits": total_hits,  "modify_time_stamp": item.modify_time_stamp}
                    yara_dict[str(item.id)] = item_dict
    prev_url = '?page=' + str(page - 1)
    next_url = '?page=' + str(page + 1)
    return render_template('yara.html', table_dict=yara_dict, form=form, page=page,
                           prev_url=prev_url, next_url=next_url)


@yara_page.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    """Create yara default view."""
    group_info = Groups.query.all()
    if request.method == 'POST':
        form = CreateYara(request.form)
        if form.validate():
            form.yara_rules = request.form["yara_rules"]
            form.yara_list_name = request.form["yara_list_name"]
            data = {"filename": form.yara_list_name, "fileobj": form.yara_rules}
            current_app.mongo.db.aucr.insert_one(data)
            new_yara = YaraRules(created_by=current_user.id, group_access=form.group_access.data[0],
                                 yara_list_name=form.yara_list_name, created_time_stamp=udatetime.utcnow(),
                                 modify_time_stamp=udatetime.utcnow())
            db.session.add(new_yara)
            db.session.commit()
            flash("The yara rule has been created.")
            return redirect(url_for('yara.yara_route'))
    form = CreateYara(request.form)
    return render_template('create.html', title='Create A New Yara Ruleset', form=form, groups=group_info)


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
    yara = yara.filter(or_(YaraRules.id == submitted_yara_id, YaraRules.group_access.in_(user_groups))).first()
    if request.method == 'POST':
        if yara:
            form = EditYara(request.form)
            if form.validate_on_submit():
                rabbit_mq_server_ip = current_app.config['RABBITMQ_SERVER']
                yara.yara_rules = request.form["yara_rules"]
                yara.yara_list_name = request.form["yara_list_name"]
                current_app.mongo.db.aucr.delete_one({"filename": yara.yara_list_name})
                data = {"filename": request.form["yara_list_name"], "fileobj": request.form["yara_rules"]}
                current_app.mongo.db.aucr.insert_one(data)
                mq_config_dict = get_mq_yaml_configs()
                files_config_dict = mq_config_dict["reports"]
                for item in files_config_dict:
                    if "yara" in item:
                        logging.info("Adding " + str(yara.id) + " " + str(item["yara"][0]) + " to MQ")
                        index_mq_aucr_report(str(yara.id), str(rabbit_mq_server_ip), item["yara"][0])
                flash("The Yara Rule " + str(yara.yara_list_name) + " has been updated and the rule is running.")
        return redirect(url_for('yara.yara_route'))
    if request.method == "GET":
        if yara:
            form = EditYara(yara)
            yara_list_results = YaraRuleResults.query.filter_by(yara_list_id=yara.id)
            yara_results_dict = {}
            for item in yara_list_results:
                item_dict = {"id": item.file_matches, "MD5 Hash": item.matches,
                             "Classification": item.file_classification}
                yara_results_dict[str(item.file_matches)] = item_dict
            yara_rule_file = current_app.mongo.db.aucr.find_one({"filename": yara.yara_list_name})
            yara_dict = {"id": yara.id, "yara_rules": yara_rule_file["fileobj"], "yara_list_name": yara.yara_list_name}
            form.yara_rules = yara_rule_file["fileobj"]
            return render_template('edit.html', title='Edit Yara Ruleset', form=form,
                                   groups=group_info, table_dict=yara_dict, yara_results=yara_results_dict)
        else:
            return yara_route()
