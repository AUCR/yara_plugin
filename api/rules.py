"""YARA plugin api functionality."""
# coding=utf-8
import udatetime
from flask import jsonify, g, request, current_app
from aucr_app import db
from aucr_app.plugins.yara_plugin.models import YaraRules, YaraRuleResults
from aucr_app.plugins.api.auth import token_auth
from aucr_app.plugins.api.routes import api_page as rules_api_page
from aucr_app.plugins.auth.models import Group
from aucr_app.plugins.errors.api.errors import bad_request


@rules_api_page.route('/yara_rule_list/<int:_id>', methods=['GET'])
@token_auth.login_required
def yara_rule_list(_id):
    """Return yara list API call."""
    if request.method == "GET":
        yara_rule_list_id = YaraRules.query.filter_by(id=_id).first()
        api_current_user = g.current_user
        group_access_value = Group.query.filter_by(username_id=api_current_user.id,
                                                   groups_id=yara_rule_list_id.group_access).first()
        if group_access_value:
            return jsonify(YaraRules.query.get_or_404(yara_rule_list_id.id).to_dict())
        else:
            error_data = {"error": "Not authorized to view this file.", "error_code": 403}
            return jsonify(error_data)


@rules_api_page.route('/yara_rule_list/<int:_id>', methods=['POST'])
@token_auth.login_required
def update_yara_rule_list(_id):
    """API Update Yara Rule."""
    if request.method == "POST":
        yara_rule = YaraRules.query.filter_by(id=_id).first()
        data = request.form
        if 'yara_rule_list' in data and data['yara_rule_list'] != yara_rule.yara_rule_list and \
                YaraRules.query.filter_by(yara_rule_list=data['yara_rule_list']).first():
            return bad_request('Please use a different yara rule list name.')
        current_app.mongo.db.aucr.delete_one({"filename": yara_rule.yara_list_name})
        data = {"filename": data["yara_list_name"], "fileobj": data["yara_rules"]}
        current_app.mongo.db.aucr.insert_one(data)
        yara_rule.from_dict(data)
        db.session.commit()
        return jsonify(yara_rule.to_dict())


@rules_api_page.route('/yara_rule_results/<int:_id>', methods=['GET'])
@token_auth.login_required
def yara_rule_results(_id):
    """Return yara list results."""
    if request.method == "GET":
        yara_rule_list_id = YaraRules.query.filter_by(id=_id).first()
        api_current_user = g.current_user
        group_access_value = Group.query.filter_by(username_id=api_current_user.id,
                                                   groups_id=yara_rule_list_id.group_access).first()
        if group_access_value:
            yara_list_results = YaraRuleResults.query.filter_by(yara_list_id=yara_rule_list_id.id).all()
            yara_results_dict = {}
            for item in yara_list_results:
                item_dict = {"id": item.file_matches, "MD5 Hash": item.matches,
                             "Classification": item.file_classification}
                yara_results_dict[str(item.file_matches)] = item_dict
            return jsonify(yara_results_dict)
        else:
            error_data = {"error": "Not authorized to view this file.", "error_code": 403}
            return jsonify(error_data)


@rules_api_page.route('/yara_rule_create/', methods=['POST'])
@token_auth.login_required
def create_yara_rule_list():
    """API Update Yara Rule."""
    if request.method == "POST":
        data = request.form
        if 'yara_rule_list' in data and data['yara_rule_list'] != data.yara_rule_list and \
                YaraRules.query.filter_by(yara_rule_list=data['yara_rule_list']).first():
            return bad_request('Please use a different yara rule list name.')
        data_mongo = {"filename": data["yara_list_name"], "fileobj": data["yara_rules"]}
        current_app.mongo.db.aucr.insert_one(data_mongo)
        new_yara = YaraRules(created_by=int(data["created_by"]), group_access=int(data["group_access"]),
                             yara_list_name=str(data["yara_list_name"]), created_time_stamp=udatetime.utcnow(),
                             modify_time_stamp=udatetime.utcnow())
        db.session.add(new_yara)
        db.session.commit()
        return jsonify(new_yara.to_dict())
