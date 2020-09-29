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
        "application": str(args['application']),
        "username": str(args['username']),
        "protocol_id": str(args['protocol_id']),
        "qs": request.query_string.decode('utf-8')
    }

    if request.method == 'POST':
        c_a, src_addr_id = ztn_elk.create_address(content['srcaddr'])
        c_a, dest_addr_id = ztn_elk.create_address(content['srcaddr'])
        if c_a:
            print("Created address")

        c_app, service_id = ztn_elk.create_application(
            content['servicename'], content['destport'], content['srcport'], content['protocol_id'])
        if c_app:
            print("created application")

        c_p, policy_id = ztn_elk.create_policy()
        if c_p:
            print("created policy")
            print(policy_id)

        c_tr = ztn_elk.create_tradtl_rule(
            src_addr_id, dest_addr_id, service_id, policy_id, content['srczone'], content['destzone'])

        if c_tr:
            print("created rule")

    return render_template("index.html", **content)

    # return render_template("index.html")


@app.route('/enrichment', methods=['GET', 'POST'])
def enriched_data():
    args = request.args
    content = {
        "srcaddr": str(args['srcaddr']),
        "srcsubnet": str(convert_ip_to_subnet(args['srcaddr'])),
        "srcport": str(args['srcport']),
        "destaddr": str(args['destaddr']),
        "destsubnet": str(convert_ip_to_subnet(args['srcaddr'])),
        "destport": str(args['destport']),
        "servicename": str(args['servicename']),
        "srczone": str(args['srczone']),
        "destzone": str(args['destzone']),
        "application": str(args['application']),
        "username": str(args['username']),
        "protocol_id": str(args['protocol_id']),
        "qs": request.query_string.decode('utf-8')
    }

    return render_template("enrichment.html", **content)


def convert_ip_to_subnet(address):
    last_period = address.rindex(".") + 1
    subnet = address[:last_period] + "0"
    return subnet


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
