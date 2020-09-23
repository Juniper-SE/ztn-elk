from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    args = request.args
    srcaddr = str(args['srcaddr'])
    srcport = str(args['srcport'])
    destaddr = str(args['destaddr'])
    destport = str(args['destport'])
    servicename = str(args['servicename'])
    srczone = str(args['srczone'])
    destzone = str(args['destzone'])

    ztn_elk.create_application(servicename, destport, srcport)
    ztn_elk.create_policy()
    return render_template("index.html")

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
