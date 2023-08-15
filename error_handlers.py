from flask import render_template
from appli_flask import app

@app.errorhandler(400)
def bad_request(error):
    return render_template("error_400.html", title="400_Error")

@app.errorhandler(401)
def unauthorized(error):
    return render_template("error_401.html", title="401_Error")

@app.errorhandler(403)
def forbidden(error):
    return render_template("error_403.html", title="403_Error")

@app.errorhandler(404)
def not_found(error):
    return render_template("error_404.html", title="404_Error")
