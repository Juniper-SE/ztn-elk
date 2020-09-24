from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/')
def index():
    args = request.args
    content = {
        "srcaddr": str(args['srcaddr']),
        "srcport": str(args['srcport']),
        "destaddr": str(args['destaddr']),
        "destport": str(args['destport']),
        "servicename": str(args['servicename']),
        "srczone": str(args['srczone']),
        "destzone": str(args['destzone'])
    }

    # c_a, addr_id = ztn_elk.create_address(srcaddr)
    # if c_a:
    #     print("Created address")
    #     print(addr_id)

    # c_app, app_id = ztn_elk.create_application(servicename, destport, srcport)
    # if c_app:
    #     print("created application")

    # c_p, policy_id = ztn_elk.create_policy()
    # if c_p:
    #     print("created policy")

    return render_template("index.html", **content)

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
