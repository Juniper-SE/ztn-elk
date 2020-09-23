from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    srcaddr = request.args.get("srcaddr")
    srcport = request.args.get("srcport")
    destaddr = request.args.get("destaddr")
    destport = request.args.get("destport")
    servicename = request.args.get("servicename")
    srczone = request.args.get("srczone")
    destzone = request.args.get("destzone")

    ztn_elk.create_application(servicename, destport, srcport)
    ztn_elk.create_policy()
    return render_template("index.html")

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
