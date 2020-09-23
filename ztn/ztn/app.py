from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    srcaddr = request.args.get("srcaddr")
    srcport = request.args.get("srcport")
    return render_template("index.html", test_addr=srcaddr)


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
