from flask import Flask, request, render_template, send_from_directory
import ztn_elk
import os
import logging
import json

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
        # Check if source and destination addresses already exist in SD
        src_addr_id, src_status_code = ztn_elk.check_address_exists(
            content['srcaddr'])
        dest_addr_id, dest_status_code = ztn_elk.check_address_exists(
            content['destaddr'])

        # If the source address doesn't exist in SD,
        # check the status code to see if API connection is failing
        if src_addr_id is None:
            # If API connection is fine,
            # attempt to create the address objects
            if src_status_code < 400:
                create_src_addr_status, src_addr_id = ztn_elk.create_address(
                    content['srcaddr'])

                if create_src_addr_status == 200:
                    logging.info(
                        "Source address object created for %s.", content['srcaddr'])
                else:
                    logging.warn(
                        "Source address object failed to be created with status code %d.", create_src_addr_status)

            # Failed API connection
            else:
                logging.warn(
                    "API call to Security Director failed, check your connections, URLs, and IPs. Status code: %d", src_status_code)

        # Address object with matching IP exists, skip creation
        else:
            logging.info(
                "Source address object with same IP %s exists, skipping creation.", content['srcaddr'])

        # If the source address doesn't exist in SD,
        # check the status code to see if API connection is failing
        if dest_addr_id is None:
            # If API connection is fine,
            # attempt to create the address objects
            if dest_status_code < 400:
                create_dest_addr_status, dest_addr_id = ztn_elk.create_address(
                    content['destaddr'])

                if create_dest_addr_status == 200:
                    logging.info(
                        "Destination address object created for %s.", content['destaddr'])
                else:
                    logging.warning(
                        "Destination address object failed to be created for %s with status code %d.", content['destaddr'], create_dest_addr_status)

            # Failed API connection
            else:
                logging.warn(
                    "API call to Security Director failed, check your connections, URLs, and IPs. Status code: %d", dest_status_code)

        # Address object with matching IP exists, skip creation
        else:
            logging.info(
                "Destination address object with same IP %s exists, skipping creation.", content['destaddr'])

        # Attempt to create application based off the given name, ports, and protocol id as applicable
        servicename = "any" if content['servicename'] == "None" else content['servicename']
        create_app_status, service_id = ztn_elk.create_application(
            servicename, content['destport'], content['srcport'], content['protocol_id'])

        if create_app_status < 300:
            logging.info("L4 Application (Service) %s created with id %s.",
                         servicename, service_id)
        elif create_app_status == 302:
            logging.info(
                "L4 Application (Service) matching %s found, using id %s", servicename, service_id)
        else:
            logging.warning("L4 Application (Service) %s was NOT created with status code %d.",
                            servicename, create_app_status)

        app_id = ztn_elk.find_application(content['application'])

        # Attempt to create a policy based on the addrress objects and application created previously
        create_policy_status, policy_id = ztn_elk.create_policy()
        if create_policy_status < 400:
            logging.info("Policy %s created.", policy_id)
        else:
            logging.warning(
                "Policy %s NOT created with status code %d.", policy_id, create_policy_status)

        # Attempt to create a policy firewall rule based on the policy and associated objects created previously
        create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
            src_addr_id, dest_addr_id, service_id, content['application'], app_id, policy_id, content['srczone'], content['destzone'])

        if create_tradtl_rule_status < 400:
            logging.info(
                "Traditional firewall rule created for policy id %s", policy_id)
        else:
            logging.warning("Traditional firewall rule NOT created for policy id %s with status code %d",
                            policy_id, create_tradtl_rule_status)

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


@app.route('/enrichment/submit', methods=['POST'])
def submit_enriched_form():
    form = request.form
    print(json.dumps(form))

    srcaddr = form['sourceaddr'] if 'src_cidr' not in form else form['sourceaddr'] + \
        '/' + form['src_cidr']
    print(srcaddr)
    destaddr = form['destaddr'] if 'dest_cidr' not in form else form['destaddr'] + \
        '/' + form['dest_cidr']
    print(destaddr)

    # Check if source and destination addresses already exist in SD
    src_addr_id, src_status_code = ztn_elk.check_address_exists(
        srcaddr)
    dest_addr_id, dest_status_code = ztn_elk.check_address_exists(
        destaddr)

    # If the source address doesn't exist in SD,
    # check the status code to see if API connection is failing
    if src_addr_id is None:
        # If API connection is fine,
        # attempt to create the address objects
        if src_status_code < 400:
            create_src_addr_status, src_addr_id = ztn_elk.create_address(
                srcaddr)

            if create_src_addr_status == 200:
                logging.info(
                    "Source address object created for %s.", srcaddr)
            else:
                logging.warn(
                    "Source address object failed to be created with status code %d.", create_src_addr_status)

        # Failed API connection
        else:
            logging.warn(
                "API call to Security Director failed, check your connections, URLs, and IPs. Status code: %d", src_status_code)

        # Address object with matching IP exists, skip creation
    else:
        logging.info(
            "Source address object with same IP %s exists, skipping creation.", srcaddr)

    # If the source address doesn't exist in SD,
    # check the status code to see if API connection is failing
    if dest_addr_id is None:
        # If API connection is fine,
        # attempt to create the address objects
        if dest_status_code < 400:
            create_dest_addr_status, dest_addr_id = ztn_elk.create_address(
                destaddr)

            if create_dest_addr_status == 200:
                logging.info(
                    "Destination address object created for %s.", destaddr)
            else:
                logging.warning(
                    "Destination address object failed to be created for %s with status code %d.", destaddr, create_dest_addr_status)

        # Failed API connection
        else:
            logging.warn(
                "API call to Security Director failed, check your connections, URLs, and IPs. Status code: %d", dest_status_code)

    # Address object with matching IP exists, skip creation
    else:
        logging.info(
            "Destination address object with same IP %s exists, skipping creation.", destaddr)

    # Attempt to create application based off the given name, ports, and protocol id as applicable
    servicename = "any" if form['servicename'] == "None" else form['servicename']
    create_app_status, service_id = ztn_elk.create_service(
        form['application'], servicename, form['destport'], form['sourceport'], form['protocol_id'])

    if create_app_status < 400:
        logging.info("Application %s created with id %s.",
                     form['application'], service_id)
    else:
        logging.warning("Application %s was NOT created with status code %d.",
                        form['application'], create_app_status)

    # Attempt to create a policy based on the addrress objects and application created previously
    create_policy_status, policy_id = \
        ztn_elk.create_policy() if 'policy_name' not in form else ztn_elk.create_policy(
            policyname=form['policy_name'])
    if create_policy_status < 400:
        logging.info("Policy %s created.", policy_id)
        # Attempt to create a policy firewall rule based on the policy and associated objects created previously
        if form['rule_name'] is None:
            create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
                src_addr_id, dest_addr_id, service_id, policy_id, form['srczone'], form['destzone'])
        else:
            create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
                src_addr_id, dest_addr_id, service_id, policy_id, form['srczone'], form['destzone'], rulename=form['rule_name'])

        if create_tradtl_rule_status < 400:
            logging.info(
                "Traditional firewall rule created for policy id %s", policy_id)
        else:
            logging.warning("Traditional firewall rule NOT created for policy id %s with status code %d",
                            policy_id, create_tradtl_rule_status)
    elif create_policy_status == 409:
        logging.warning(
            "Policy with the same name already exists, skipping rule creation.")
        return '''A policy with that name already exists, please go back and choose a new name.'''
    else:
        logging.warning(
            "Policy %s NOT created with status code %d.", policy_id, create_policy_status)

    return '''The form has been submitted, you can close this page.'''


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
