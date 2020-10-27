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
        console.log(document.getElementById("src_subnet").index);

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
