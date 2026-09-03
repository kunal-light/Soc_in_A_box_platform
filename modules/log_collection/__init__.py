from flask import Blueprint

log_collection_bp = Blueprint(
    "log_collection",
    __name__,
    template_folder="../../templates/log_collection"
)


from . import routes