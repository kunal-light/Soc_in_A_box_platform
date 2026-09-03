from flask import Blueprint

threat_detection = Blueprint(
    "threat_detection",
    __name__,
    template_folder="../../templates/threat_detection"
)

#from . import routes