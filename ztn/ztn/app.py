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
        "destzone": str(args['destzone']),
        "qs": request.query_string
    }

    if request.method == 'POST':
        c_a, addr_id = ztn_elk.create_address(content['srcaddr'])
        if c_a:
            print("Created address")
            print(addr_id)

        c_app, service_id = ztn_elk.create_application(
            content['servicename'], content['destport'], content['srcport'])
        if c_app:
            print("created application")

        c_p, policy_id = ztn_elk.create_policy()
        if c_p:
            print("created policy")

        c_tr, rule = ztn_elk.create_tradtl_rule(
            content['src_addr_id'], content['dest_addr_id'], content['service_id'], content['policy_id'])

        if c_tr:
            print("created rule")

    return render_template("index.html", **content)

    # return render_template("index.html")


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
