from flask import Flask, request, render_template, send_from_directory
from ztn_elk import ZTN_ELK_Server
from ztn_graph import ZTN_Graph
import os
import logging
import json
import time
import yaml
from werkzeug.utils import secure_filename
from elasticsearch import Elasticsearch
import pandasticsearch as pds
import pandas as pd


UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'yaml'}

app = Flask(__name__, template_folder="../templates")
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

### SECURITY DIRECTOR LOGIN ###
## Load the configuration file and login to SD API
with open("../ztn.yml", 'r') as stream:
    try:
        obj = yaml.safe_load(stream)
    except yaml.YAMLError as exc:
        print(exc)
ztn_elk = ZTN_ELK_Server(url="https://" + obj["sd.ip_addr"], user=obj["sd.user"], password=obj["sd.password"] )
ztn_elk.login()

### GRAPHISTRY LOGIN / SETUP ###
ztn_graph = ZTN_Graph(url='hub.graphistry.com', user='natzberg', password='Tastiness2-Variably-Hesitate')
ztn_graph.login()

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
        "nested_app": str(args['nested_app']),
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
        create_app_status, service_id = ztn_elk.create_service(
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

        # Attempt to create a policy based on the addrress objects and application created previously
        create_policy_status, policy_id = ztn_elk.create_policy()
        if create_policy_status < 400:
            logging.info("Policy %s created.", policy_id)
        else:
            logging.warning(
                "Policy %s NOT created with status code %d.", policy_id, create_policy_status)

        # Attempt to create a policy firewall rule based on the policy and associated objects created previously
        if content['nested_app'] != "%{{nested_app}}":
            app_id = ztn_elk.find_application(content['nested_app'])

            create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
                src_addr_id, dest_addr_id, service_id, content['nested_app'], app_id, policy_id, content['srczone'], content['destzone'])
        else:
            app_id = ztn_elk.find_application(content['application'])

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


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_enrichment_file(filename, content):
    with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'r') as stream:
        try:
            json_obj = yaml.safe_load(stream)

            content['subnets'].extend(set(json_obj['subnets'].split(',')))
            content['ad_names'].extend(set(json_obj['ad_names'].split(',')))
            content['ad_groups'].extend(set(json_obj['ad_groups'].split(',')))
            content['zones'].extend(set(json_obj['zones'].split(',')))
            content['file'] = filename
        except yaml.YAMLError as exc:
            print(exc)
            return None


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
        "nested_app": str(args['nested_app']),
        "username": str(args['username']),
        "protocol_id": str(args['protocol_id']),
        "qs": request.query_string.decode('utf-8'),
        "subnets": [],
        "ad_names": [],
        "ad_groups": [],
        "zones": [],
        "file": ""
    }

    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            print('No file part')
            return render_template("enrichment.html", **content)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            print('No selected file')
            return render_template("enrichment.html", **content)
        if file and allowed_file(file.filename):
            print("acceptable file, attempting to save")
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

            process_enrichment_file(filename, content)

            return render_template("enrichment.html", **content)

    return render_template("enrichment.html", **content)


@app.route('/enrichment/submit', methods=['POST'])
def submit_enriched_form():
    form = request.form

    srcaddr = form['sourceaddr'] if 'src_cidr' not in form else form['sourceaddr'] + \
        '/' + form['src_cidr']

    destaddr = form['destaddr'] if 'dest_cidr' not in form else form['destaddr'] + \
        '/' + form['dest_cidr']

    # Check if source and destination addresses already exist in SD
    src_addr_id, src_status_code = ztn_elk.check_address_exists(srcaddr)
    dest_addr_id, dest_status_code = ztn_elk.check_address_exists(destaddr)

    if src_status_code == 401 or dest_status_code == 401:
        logging.info("API login session timed out, attempting login again.")
        ztn_elk.login()

        src_addr_id, src_status_code = ztn_elk.check_address_exists(srcaddr)
        dest_addr_id, dest_status_code = ztn_elk.check_address_exists(destaddr)

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
            return '''"API call to Security Director failed, check your connections, URLs, and IPs. Check the logs for status code.'''

        # Address object with matching IP exists, skip creation
    else:
        logging.info(
            "Source address object with same IP %s exists, skipping creation.", srcaddr)

    # If the destination address doesn't exist in SD,
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
            return '''"API call to Security Director failed, check your connections, URLs, and IPs. Check the logs for status code.'''

    # Address object with matching IP exists, skip creation
    else:
        logging.info(
            "Destination address object with same IP %s exists, skipping creation.", destaddr)

    # Attempt to create application based off the given name, ports, and protocol id as applicable
    servicename = "any" if form['servicename'] == "None" else form['servicename']
    create_app_status, service_id = ztn_elk.create_service(
        servicename, form['destport'], form['sourceport'], form['protocol_id'])

    if create_app_status < 300:
        logging.info("L4 Application (Service) %s created with id %s.",
                     servicename, service_id)
    elif create_app_status == 302:
        logging.info(
            "L4 Application (Service) matching %s found, using id %s", servicename, service_id)
    else:
        logging.warning("L4 Application (Service) %s was NOT created with status code %d.",
                        servicename, create_app_status)

    app_id = ztn_elk.find_application(form['application'])


    # Check if a policy schedule with the given name already exists, if not create one
    if form['policy_schedule_name']:
        policy_schedule_id, policy_schedule_status_code = ztn_elk.check_scheduler_exists(form['policy_schedule_name'])

        if policy_schedule_status_code < 400:
            selected_days = []
            if form['policy_daily']:
                selected_days = ['DAILY']
            elif form['policy_custom']:
                weekdays = [ "SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY","SATURDAY" ]

                # Gets the selected days, add to an array
                for day in weekdays:
                    if form[day.lower()]:
                        selected_days.append(day)

            create_policy_schedule_status, policy_schedule_id = ztn_elk.create_scheduler(form['policy_schedule_name'], selected_days=selected_days, start_time=form['policy_time_start'],end_time=form['policy_time_end'], start_date=form['policy_date_start'], end_date=form['policy_date_end'])

            return 'break for policy schedule test'

            if create_policy_schedule_status == 200:
                logging.info(
                    "Policy schedule object created for %s.", form['policy_schedule_name'])
            else:
                logging.warning(
                    "Policy schedule object failed to be created for %s with status code %d.", form['policy_schedule_name'], create_policy_schedule_status)

        # Failed API connection
        else:
            logging.warn(
                "API call to Security Director failed, check your connections, URLs, and IPs. Status code: %d", policy_schedule_status_code)
            return '''"API call to Security Director failed, check your connections, URLs, and IPs. Check the logs for status code.'''
    else:
        create_policy_schedule_status, policy_schedule_id = ztn_elk.create_scheduler()

        if create_policy_schedule_status == 409:
            logging.warn("Policy schedule with name %s already exists, new name needs to be chosen.", form['policy_schedule_name'])
            return '''There is already a policy schedule with that name, please return to the previous page and try again.'''

        logging.info("Policy schedule with name %s created.")

    # Attempt to create a policy based on the addrress objects and application created previously
    if form['policy_name']:
        create_policy_status, policy_id = ztn_elk.create_policy(
            policyname=form['policy_name'],
            policyscheduleid=policy_schedule_id,
            policyschedulename=form['policy_schedule_name'])
    else:
        create_policy_status, policy_id = ztn_elk.create_policy()

    if create_policy_status < 400 or create_policy_status == 409:
        if create_policy_status == 409:
            # logging.info("Policy already exists with name %s.", form['policy_name'])
            # return '''Policy already exists with that name, please enter a new one.
            #         In the future, this will add the rule to the existing policy.'''
            logging.info("Policy already exists with name %s, adding rule.", form['policy_name'])
            policy_id = ztn_elk.find_existing_policy(form['policy_name'])
            # TODO check for duplicate policy and add rule once SD API properly returns all policies
        else:
            logging.info("Policy %s created.", policy_id)

        time.sleep(3)
        # Attempt to create a policy firewall rule based on the policy and associated objects created previously
        if form['rule_name']:
            create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
                src_addr_id, dest_addr_id, service_id, form['application'], app_id, policy_id, form['srczone'], form['destzone'], rulename=form['rule_name'])
        else:
            create_tradtl_rule_status = ztn_elk.create_tradtl_rule(
                src_addr_id, dest_addr_id, service_id, form['application'], app_id, policy_id, form['srczone'], form['destzone'])

        if create_tradtl_rule_status < 400:
            logging.info(
                "Traditional firewall rule created for policy id %s", policy_id)
        else:
            logging.warning("Traditional firewall rule NOT created for policy id %s with status code %d",
                            policy_id, create_tradtl_rule_status)
            return '''The firewall rule could not be created, please check the logs.'''
    else:
        logging.warning(
            "Policy %s NOT created with status code %d.", policy_id, create_policy_status)
        return '''There was an error creating the policy, please check the logs.'''

    return render_template("policy_submitted.html", sd_url=ztn_elk.root_url)

@app.route('/graph/')
def test():
    es = Elasticsearch('http://10.192.16.248:9200')
    # es_result = es.search(index="junos-syslog", query={"match_all": {}})
    results = elasticsearch.helpers.scan(es, query={"query": {"match_all": {}}}, index="junos-syslog")
    df = pd.DataFrame.from_dict([document['_source'] for document in results])

    pandas_df = pds.Select.from_dict(es_result).to_pandas()
    pandas_df.print_schema()

    return 'yeah'

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
