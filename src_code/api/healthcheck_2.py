from flask import Blueprint
bp = Blueprint('healthcheck_2', __name__)

@bp.route('/', methods=['GET', 'POST'])
def index():
    return {"status": "success"}
