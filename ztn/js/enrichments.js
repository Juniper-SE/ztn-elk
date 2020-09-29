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
