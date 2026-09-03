from flask import Blueprint

threat_detection_bp = Blueprint(
    "threat_detection",
    __name__,
    template_folder="../../templates/threat_detection"
)

from . import routes