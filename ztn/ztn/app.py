from flask import Flask
from flask import render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    test_addr = "172.28.10.1"
    ztn_elk.create_address("172.28.200.1")
    return render_template("index.html", test_addr=test_addr)


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
