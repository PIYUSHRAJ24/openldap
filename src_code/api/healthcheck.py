from flask import Blueprint
bp = Blueprint('healthcheck', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    return {"status": "success"}, 200
