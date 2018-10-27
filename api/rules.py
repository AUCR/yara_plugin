"""UNUM file plugin api functionality."""
# coding=utf-8
import os
from flask import jsonify, g
from aucr_app.plugins.yara.models import YaraRules
from aucr_app.plugins.api.auth import token_auth
from aucr_app.plugins.api.routes import api_page as rules_api_page
from aucr_app.plugins.auth.models import Group


@rules_api_page.route('/yara_rule_list/<int:_id>', methods=['GET'])
@token_auth.login_required
def yara_rule_list(_id):
    """Return yara list API call."""
    yara_rule_list_id = YaraRules.query.filter_by(id=_id).first()
    api_current_user = g.current_user
    group_access_value = Group.query.filter_by(username_id=api_current_user.id,
                                               groups_id=yara_rule_list_id.group_access).first()
    if group_access_value:
        return jsonify(YaraRules.query.get_or_404(yara_rule_list_id.id).to_dict())
    else:
        error_data = {"error": "Not authorized to view this file.", "error_code": 403}
        return jsonify(error_data)
