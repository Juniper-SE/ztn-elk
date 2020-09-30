from flask import Flask, request, render_template, send_from_directory
import ztn_elk
import os
import logging

app = Flask(__name__, template_folder="../templates")

# Logging configuration
logging.basicConfig(filename="ztn_elk.log",
                    format='%(asctime)s %(message)s', level=logging.DEBUG)


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
        if not ztn_elk.check_address_exists(content['srcaddr']):
            create_src_addr, src_addr_id = ztn_elk.create_address(
                content['srcaddr'])

            if create_src_addr:
                logging.info("Source address object created.")
            else:
                logging.warn("Source address object failed to be created.")
        else:
            logging.info(
                "Source address object with same IP exists, skipping creation.")

        if not ztn_elk.check_address_exists(content['destaddr']):
            create_dest_addr, dest_addr_id = ztn_elk.create_address(
                content['destaddr'])

            if create_dest_addr:
                logging.info("Destination address object created.")
            else:
                logging.warn(
                    "Destination address object failed to be created.")
        else:
            logging.info(
                "Destination address object with same IP exists, skipping creation.")

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

        return '''The form has been submitted, you can close this page.'''

    return render_template("index.html", **content)


@app.route('/enrichment', methods=['GET', 'POST'])
def enriched_data():
    args = request.args
    content = {
        "srcaddr": str(args['srcaddr']),
        "srcsubnet": str(convert_ip_to_subnet(args['srcaddr'])),
        "srcport": str(args['srcport']),
        "destaddr": str(args['destaddr']),
        "destsubnet": str(convert_ip_to_subnet(args['destaddr'])),
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


@app.route('/js/<path:filename>')
def serve_static(filename):
    root_dir = os.path.dirname(os.getcwd())
    return send_from_directory(os.path.join(root_dir, 'static', 'js'), filename)


def convert_ip_to_subnet(address):
    last_period = address.rindex(".") + 1
    subnet = address[:last_period] + "0"
    return subnet


if __name__ == "__main__":
    app.run("0.0.0.0", port=9999, debug=True)
