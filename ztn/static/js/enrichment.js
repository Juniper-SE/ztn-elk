function onChangeSrcAddr() {
    var selectBox = document.getElementById("sourceaddr")

    if (selectBox.options[selectBox.selectedIndex].id === "src_subnet") {
        document.getElementById("src_cidr").disabled = false;
    } else {
        document.getElementById("src_cidr").disabled = true;
        document.getElementById("src_cidr").value = "";
    }
}

function onChangeSrcPort() {

}

function onChangeDestAddr() {

    var selectBox = document.getElementById("destaddr")

    if (selectBox.options[selectBox.selectedIndex].id === "dest_subnet") {
        document.getElementById("dest_cidr").disabled = false;
    } else {
        document.getElementById("dest_cidr").disabled = true;
        document.getElementById("dest_cidr").value = "";
    }

}

function onChangeDestPort() {

}

function useRecommended() {
    var isChecked = document.getElementById("recommended").checked;

    if (isChecked) {
        // Set source address to subnet + /24 cidr
        document.getElementById("sourceaddr").selectedIndex = document.getElementById("src_subnet").index;
        document.getElementById("src_cidr").value = 24;
        document.getElementById("src_cidr").disabled = false;

        // Set source port to specific port
        document.getElementById("sourceport").selectedIndex = 0;

        // Set destination address to subnet + /24 cidr
        document.getElementById("destaddr").selectedIndex = document.getElementById("dest_subnet").index;
        document.getElementById("dest_cidr").value = 24;
        document.getElementById("dest_cidr").disabled = false;

        // Set dest port to specific port
        document.getElementById("destport").selectedIndex = 0;

        // Set source + dest zone to value from log
        document.getElementById("srczone").selectedIndex = document.getElementById("log_src_zone").index;
        document.getElementById("destzone").selectedIndex = document.getElementById("log_dest_zone").index;

        // Set username to one from log
        document.getElementById("username").selectedIndex = document.getElementById("log_username").index;

        // Set application to one from log
        document.getElementById("application").selectedIndex = 0;
    }
}

function submitEnriched() {

}

function timeBased() {
    var isChecked = document.getElementById("yes_policy_time").checked;

    if (isChecked) {
        document.getElementById("policy_time_start").disabled = false;
        document.getElementById("policy_time_end").disabled = false;
        document.getElementById("policy_date_start").disabled = false;
        document.getElementById("policy_date_end").disabled = false;
        document.getElementById("policy_daily").disabled = false;
        document.getElementById("policy_custom").disabled = false;
    } else {
        document.getElementById("policy_time_start").disabled = true;
        document.getElementById("policy_time_end").disabled = true;
        document.getElementById("policy_date_start").disabled = true;
        document.getElementById("policy_date_end").disabled = true;
        document.getElementById("policy_daily").disabled = true;
        document.getElementById("policy_custom").disabled = true;
        document.getElementById("policy_time_start").value = "";
        document.getElementById("policy_time_end").value = "";
    }
}

function daily() {
    if (!document.getElementById("policy_daily").checked) {
        document.getElementById("policy_schedule_name").disabled = true;
        document.getElementById("policy_schedule_name").value = "";
    } else {
        document.getElementById("policy_schedule_name").disabled = false;
    }

    document.getElementById("policy_custom").checked = false;
    document.getElementById("policy_custom_area_1").style.display = 'none';
    document.getElementById("policy_custom_area_2").style.display = 'none';
    document.getElementById("policy_custom_area_3").style.display = 'none';
    document.getElementById("sunday").checked = false;
    document.getElementById("monday").checked = false;
    document.getElementById("tuesday").checked = false;
    document.getElementById("wednesday").checked = false;
    document.getElementById("thursday").checked = false;
    document.getElementById("friday").checked = false;
    document.getElementById("saturday").checked = false;

}

function custom() {
    if (document.getElementById("policy_custom").checked) {
        document.getElementById("policy_schedule_name").disabled = false;
        document.getElementById("policy_daily").checked = false;
        document.getElementById("policy_custom_area_1").style.display = 'table-row';
        document.getElementById("policy_custom_area_2").style.display = 'table-row';
        document.getElementById("policy_custom_area_3").style.display = 'table-row';
    }
    else {
        document.getElementById("policy_schedule_name").disabled = true;
        document.getElementById("policy_custom_area_1").style.display = 'none';
        document.getElementById("policy_custom_area_2").style.display = 'none';
        document.getElementById("policy_custom_area_3").style.display = 'none';
        document.getElementById("sunday").checked = false;
        document.getElementById("monday").checked = false;
        document.getElementById("tuesday").checked = false;
        document.getElementById("wednesday").checked = false;
        document.getElementById("thursday").checked = false;
        document.getElementById("friday").checked = false;
        document.getElementById("saturday").checked = false;
    }
}