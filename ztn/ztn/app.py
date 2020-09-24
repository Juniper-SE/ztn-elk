from flask import Flask, request, render_template
import ztn_elk

app = Flask(__name__, template_folder="../templates")


@app.route('/', methods=['GET', 'POST'])
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

    if request.method == 'POST':
        c_a, addr_id = ztn_elk.create_address(srcaddr)
        if c_a:
            print("Created address")
            print(addr_id)

        c_app, service_id = ztn_elk.create_application(
            servicename, destport, srcport)
        if c_app:
            print("created application")

        c_p, policy_id = ztn_elk.create_policy()
        if c_p:
            print("created policy")

        c_tr, rule = ztn_elk.create_tradtl_rule(
            src_addr_id, dest_addr_id, service_id, policy_id)

    return render_template("index.html", **content)

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
