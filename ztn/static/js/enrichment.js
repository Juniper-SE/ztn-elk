function onChangeSrcAddr() {
    var selectBox = document.getElementById("sourceaddr")
    var selectedValue = selectBox.options[selectBox.selectedIndex].value;

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

}

function onChangeDestPort() {

}

function useRecommended() {
    var isChecked = document.getElementById("recommended").checked;

    if (isChecked) {
        alert("checked, yeehaw")
    } else {
        alert("not checked :(")
    }
}
