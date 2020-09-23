from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    srcaddr = request.args.get("srcaddr")

    ztn_elk.create_application(servicename, destport, srcport)
    ztn_elk.create_policy()
    return render_template("index.html")

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
