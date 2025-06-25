<%@ Page Language="vb" AutoEventWireup="false" CodeBehind="SmartFleetApk.aspx.vb" Inherits="YTLWebApplication.SmartFleetApk" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-type" />
    <title>Smart Fleet</title>
    <style type="text/css" title="currentStyle">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
        @import "cssfiles/jquery-ui.css";
        @import "cssfiles/jquery.ui.dialog.css";
        @import "cssfiles/TableTools.css";
        @import "cssfiles/ColVis.css";

        .pk {
            padding-left: 30px;
            color: Black;
            font-weight: normal;
        }

        table.display td {
            padding: 2px 2px;
            border: 1px solid lightblue;
            nowrap: nowrap;
            white-space: nowrap;
        }

        th {
            width: auto;
            min-width: 5px;
            nowrap: nowrap;
            white-space: nowrap;
        }


        #refreshbtn {
            position: fixed;
        }

        .dataTables_filter {
            width: 300px;
        }

        input {
            margin: 0px;
            font-size: 19px;
            border: 0px solid gray;
        }

        .MyButton {
            text-align: left;
            float: left;
            width: 350px;
        }

        #ddluser {
            margin: 0px;
            position: absolute;
            top: 4px;
            text-decoration: none;
            height: 25px;
        }

        tr.odd {
            background-color: white;
        }

        tr.even {
            background-color: #f7fbff;
        }

            tr.even:hover {
                background-color: #00cccc;
            }

        tr.odd:hover {
            background-color: #00cccc;
        }

        tr.odd td.sorting_1 {
            background-color: white;
        }

        tr.even td.sorting_1 {
            background-color: #f7fbff;
        }

        tr.even:hover td.sorting_1 {
            background-color: #00cccc;
        }

        tr.odd:hover td.sorting_1 {
            background-color: #00cccc;
        }

        .g1 {
            background-image: url(images/g.png);
            background-repeat: no-repeat;
            width: 16px;
            height: 16px;
            vertical-align: middle;
            display: inline-table;
        }

        .p1 {
            background-image: url(images/p.png);
            background-repeat: no-repeat;
            width: 16px;
            height: 16px;
            vertical-align: middle;
            display: inline-table;
        }

        .r1 {
            background-image: url(images/r.png);
            background-repeat: no-repeat;
            width: 13px;
            height: 13px;
            vertical-align: middle;
            display: inline-table;
        }

        .yv {
            color: darkviolet;
        }

        .gv {
            color: green;
        }

        .ov {
            color: darkorange;
        }

        .rv {
            color: red;
        }
    </style>
    <script type="text/javascript" src="js/googana.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.js"></script>
    <link href="cssfiles/chosen.css" rel="stylesheet" type="text/css" />
    <script type="text/javascript" src="jsfiles/chosen.jquery.js"></script>
    <script src="jsfiles/jquery-ui.min.js" type="text/javascript"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.dataTables.js"></script>
    <script type="text/javascript" src="jsfiles/TableTools.min.js"></script>
    <script type="text/javascript" src="jsfiles/ColVis.js"></script>
    <script src="jsfiles/SmartFleet.js" type="text/javascript"></script>
    <script type="text/javascript" charset="utf-8">
        function getWindowWidth() { if (window.self && self.innerWidth) { return self.innerWidth; } if (document.documentElement && document.documentElement.clientWidth) { return document.documentElement.clientWidth; } return document.documentElement.offsetWidth; }
        function getWindowHeight() { if (window.self && self.innerHeight) { return self.innerHeight; } if (document.documentElement && document.documentElement.clientHeight) { return document.documentElement.clientHeight; } return document.documentElement.offsetHeight; }
        function resize() {
            table = oTable.dataTable();
            table.fnSettings().oScroll.sY = getWindowHeight() - 135 + "px";
            table.fnDraw();

        }
        function load() {
        }
        function unload() {
        }

        function blinkIt() {

            for (i = 0; i < document.getElementsByTagName("blink").length; i++) {
                s = document.getElementsByTagName("blink")[i].parentElement;
                s.style.color = (s.style.color == 'red') ? 'blue' : 'red';
            }

        }

        window.setInterval("blinkIt()", 500);

        function refreshTable() {

            table = oTable.dataTable();
            table._fnProcessingDisplay(true);
            oSettings = table.fnSettings();
            $.getJSON('GetSmartFleetAPK.aspx?u=' + $("#ddluser").val(), null, function (json) {
                table.fnClearTable(this);

                for (var i = 0; i < json.aaData.length; i++) {
                    table.oApi._fnAddData(oSettings, json.aaData[i]);
                }

                oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                table._fnProcessingDisplay(false);
                table.fnDraw();
            });
            return false;
        }
        jQuery.extend(jQuery.fn.dataTableExt.oSort, {
            "num-html-pre": function (a) {
                var x = parseFloat(a.toString().replace(/<.*?>/g, ""));
                if (isNaN(x)) {
                    if (a.toString().indexOf("fuel sensor problem") > 0) {
                        return -1;
                    }
                    else if (a.toString().indexOf("no fuel sensor") > 0) {
                        return -0.1;
                    }

                    return 0.0;
                }
                else {
                    return x;
                }
            },

            "num-html-asc": function (a, b) {
                return ((a < b) ? -1 : ((a > b) ? 1 : 0));
            },

            "num-html-desc": function (a, b) {
                return ((a < b) ? 1 : ((a > b) ? -1 : 0));
            }
        });

        var oTable;
        function SendPoll(plateno) {
            var lastXHR = $.get("InsertPoll.aspx?plateno=" + plateno, function (data) {
                if (data == "Yes") {
                    return false;
                }
                else {
                    alertbox("<b style='Color:Red;'>Sorry.Please try again..!!!</b>");
                    var x;
                    return false;
                }
            });

        }

        $(document).ready(function () {
            $('#chkrunning').change(function () {
                if (this.checked) {
                    $("#txtrecentstatus").attr("readonly", true);
                    $("#txtrecentstatus").val("");
                    $("#txtstatusremarks").val("");
                }
                else {
                    $("#txtrecentstatus").attr("readonly", false);
                    $("#txtstatusremarks").attr("readonly", false);
                }
            });

            $("#dialog-message").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                minWidth: 1000,
                minHeight: 512
            });

            $("#Div1").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                buttons: {
                    Ok: function () {
                        $(this).dialog("close");
                    }
                }
            });

            $("#dialog-form").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 500,
                minHeight: 320,
                height: 320,
                buttons: {
                    //Status: function () {
                    //    UpdateRecentStatus();
                    //    $(this).dialog("close");
                    //},
                    Update: function () {
                        UpdateData();
                        $(this).dialog("close");
                    },
                    Close: function () {
                        $(this).dialog("close");
                    }
                }
            });

            $("#dialog-formstatus").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 500,
                minHeight: 320,
                height: 320,
                buttons: {

                    Update: function () {
                        UpdateRecentStatus();
                        $(this).dialog("close");
                    },
                    Close: function () {
                        $(this).dialog("close");
                    }
                }
            });

            $("#PollDiv").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                minWidth: 1000,
                minHeight: 400,
                buttons: {
                    Refresh: function () {
                        window.parent.frames[0].frames[1].refreshPoll();
                    },
                    Poll: function () {
                        var x = window.frames[1].document.getElementById("hdnPlate").value;
                        SendPoll(x);
                        window.setInterval(window.parent.frames[0].frames[1].refreshPoll(), 6000);
                        alertbox("Please wait while we refresh the data.It may take some time.");

                    },
                    Close: function () {
                        $(this).dialog("close");
                    }
                }
            });
            $("#OssDiv").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                minWidth: 1000,
                minHeight: 400,
                buttons: {
                    Close: function () {
                        $(this).dialog("close");
                    }
                }
            });

            var h = getWindowHeight() - 135 + "px";
            var varexclu = new Array();
            varexclu.push(5);
            if (<%=puserid %> != 6896) {
                varexclu.push(9);

            }
            oTable = $('#example').dataTable({
                "bProcessing": true,
                "bJQueryUI": true,
                "bServerSide": false,
                "sPaginationType": "full_numbers",
                "sAjaxSource": "GetSmartFleetAPK.aspx?u=<%=suserid %>",
                "sScrollY": h,
                "sScrollX": "100%",
                "scrollX": true,
                "bScrollCollapse": true,
                "bLengthChange": false,
                "iDisplayLength": 2000,
                "bStateSave": true,
                "bInfo": true,
                "bAutoWidth": false,
                "aaSorting": [[7, "desc"]],
                "oLanguage": { "sProcessing": " Loading...", "sEmptyTable": "" },
                "fnDrawCallback": function (oSettings) {
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(0)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },
                "fnStateSave": function (oSettings, oData) {
                    oData.oSearch.sSearch = "";
                    localStorage.setItem('DataTables_' + $("#unname").val(), JSON.stringify(oData));
                },
                "fnStateLoad": function (oSettings) {
                    return JSON.parse(localStorage.getItem('DataTables_' + $("#unname").val()));
                },
                "aoColumnDefs": [
                    { "bVisible": true, "bSortable": false, "sWidth": "30px", "aTargets": [0] },
                    {
                        "bVisible": true, "sWidth": "30px", "fnRender": function (oData, sVal) {
                            var ppp = "";
                            var s = "";
                            // var extVolt = oData.aData[26];
                            var vehicleicon = "<img src='images/PT.png' style='height:16px;width:16px;' title='Travelling' />";

                            if (oData.aData[7] == "--") {
                                return "";
                            }
                            else {

                                if (oData.aData[9] == "OFF") {
                                    ppp = "Stop";
                                    s = "style=\"color:red;cursor:pointer;";
                                    vehicleicon = "<img src='images/PS.png' style='height:16px;width:16px;' title='Stopped' alt='Stopped' />";

                                }
                                else {
                                    if (oData.aData[10] == 0) {
                                        ppp = "Idling";
                                        s = "style=\"color:blue;cursor:pointer;";
                                        vehicleicon = "<img src='images/PI.png' style='height:16px;width:16px;' title='Idling' alt='Idling' />";
                                    }
                                    else {
                                        ppp = "Travelling";
                                        s = "style=\"color:green;cursor:pointer;";
                                        vehicleicon = "<img src='images/PT.png' style='height:16px;width:16px;' title='Travelling' alt='Travelling' />";
                                    }
                                }

                                var status = new StringBuilder();
                                status.append("");
                                if (sVal[0][1] != "--") {

                                    var statusimg = "";

                                    switch (sVal[0][1]) {
                                        case "Vehicle's Ignition Off":
                                            statusimg = "us25.png";
                                            break;
                                        case "SMS Pending":
                                            statusimg = "us22.png";
                                            break;
                                        case "Battery Taken Out":
                                            statusimg = "us24.png";
                                            break;
                                        case "Vehicle is dismentled":
                                            statusimg = "us27.png";
                                            break;
                                        case "Dismentled":
                                            statusimg = "us27.png";
                                            break;
                                        case "Not in Operation":
                                            statusimg = "us28.png";
                                            break;
                                        case "Power Cut":
                                            statusimg = "pc.png";
                                            break;
                                        case "Workshop":
                                            statusimg = "w3.gif";
                                            break;
                                        case "Immobilizer Activated":
                                            statusimg = "immobilizer.png";
                                            break;
                                        case "V Data":
                                            statusimg = "us20.png";
                                            break;
                                        case "Data Not Coming":
                                            statusimg = "us2.gif";
                                            break;
                                        case "Spare Truck":
                                            statusimg = "sparetruck.png";
                                            break;

                                        case "Other":
                                            statusimg = "us23.png";
                                            break;
                                        default:
                                            statusimg = "w3.gif";
                                    }
                                    status = "<div " + s + "\"><img src=\"images/" + statusimg + "\" width=\"16px\" height=\"16px\" style=\"color:gray;cursor:pointer;\" onclick=\"javascript:openPopup('" + sVal[0][1] + "','" + oData.aData[3] + "','" + oData.aData[23] + "','" + sVal[0][0] + "','" + sVal[0][2] + "','" + sVal[0][3] + "','" + oData.aData[35] + "');\" title=\"Date Time: " + sVal[0][0] + "\nUnit Status: " + sVal[0][1] + "\" />" + vehicleicon + "</div>";

                                    return status;
                                }
                                else {
                                    var statusimg = "us1.gif";
                                    var stst = "Running";
                                    status = "<div " + s + "\"><img src=\"images/" + statusimg + "\" width=\"16px\" height=\"16px\"  style=\"color:gray;cursor:pointer;\" onclick=\"javascript:openPopup('" + stst + "','" + oData.aData[3] + "','" + oData.aData[23] + "','--','--','--','" + oData.aData[35] + "');\" title=\"Status: " + stst + "\" />" + vehicleicon + "</div>";

                                    return status;
                                }
                            }
                        }, "aTargets": [1], "asSorting": ["desc", "asc"]
                    },
                    {
                        "sClass": "left", "sWidth": "150px", "aTargets": [2], "bSortable": true, "bVisible": true, "fnRender": function (oData, sVal) {
                            var status = oData.aData[2];
                            if (oData.aData[35] == "") {
                                status = "<div><span  style=\"color:green;cursor:pointer;\" onclick=\"javascript:openPopupStatus('" + oData.aData[3] + "','" + escape(oData.aData[35]) + "','" + escape(oData.aData[36]) + "');\" title=\"Status: " + oData.aData[35] + "\" />" + oData.aData[2] + "</div>";
                            }
                            else {
                                status = "<div><span  style=\"color:red;cursor:pointer;\" onclick=\"javascript:openPopupStatus('" + oData.aData[3] + "','" + escape(oData.aData[35]) + "','" + escape(oData.aData[36]) + "');\" title=\"Status: " + oData.aData[35] + "\" />" + oData.aData[2] + "</div>";
                            }
                            return status;
                        }
                    },
                    {
                        "fnRender": function (oData, sVal) {


                            var plateno = sVal;

                            if (oData.aData[7] == "--") {
                                return "<b style=\"color:gray;cursor:pointer;\" onclick=\"javascript:alertbox('No Data');\">" + plateno + "</b>";
                            }
                            else {
                                var s;
                                if (oData.aData[9] == "OFF") {
                                    s = "style=\"color:red;cursor:pointer;";
                                }
                                else {
                                    if (oData.aData[10] == 0) {
                                        s = "style=\"color:blue;cursor:pointer;";
                                    }
                                    else {
                                        s = "style=\"color:green;cursor:pointer;";
                                    }
                                }
                                var sb = new StringBuilder();

                                sb.append('<span ');
                                sb.append(s);
                                sb.append('"  onclick="openvehiclepath(\'');
                                sb.append(oData.aData[22]);
                                sb.append('\',\' ');
                                sb.append(oData.aData[24]);
                                sb.append('\',\' ');
                                sb.append(oData.aData[7]);
                                sb.append('\')"><b>');
                                sb.append(oData.aData[22]);
                                sb.append('</b></span>');
                                return sb.toString();

                            }
                        }, "aTargets": [3]
                    },
                    { "aTargets": [4], "sWidth": "150px", "bVisible": true, "asSorting": ["desc", "asc"] },
                    {
                        "sWidth": "50px", "aTargets": [5], "bSortable": true, "bVisible": true, "sType": "html", "fnRender": function (oData, sVal) {
                            var cont = new StringBuilder();
                            cont.append("<span style='cursor:pointer;color:blue;text-decoration:underline;'  title='View Details'  onclick=\"getJobData(\' ")
                            cont.append(oData.aData[22]);
                            cont.append("\')\" >");
                            cont.append(sVal);
                            cont.append("</span>");
                            if (oData.aData[22] == "--") {
                                return "--";
                            }
                            else {
                                return cont.toString();
                            }


                        }
                    },
                    { "sWidth": "135px", "aTargets": [6], "bSortable": true, "bVisible": false },

                    { "sType": "date", "sWidth": "135px", "aTargets": [7], "asSorting": ["desc", "asc"] },
                    {
                        "sClass": "left", "sType": "html", "sWidth": "30px", "aTargets": [8],
                        "fnRender": function (oData, sVal) {

                            sVal = oData.aData[8];

                            var sb = new StringBuilder();

                            if (sVal == 0) {
                                sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"PTOHistory.aspx?p=");
                                sb.append(oData.aData[22]);
                                sb.append("&u=");
                                sb.append(oData.aData[23]);
                                sb.append("\" ><b style=\"color:Red;\" title='PTO OFF'</b>OFF</a>");
                                return sb.toString();
                            }
                            else if (sVal == 1) {
                                sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"PTOHistory.aspx?p=");
                                sb.append(oData.aData[22]);
                                sb.append("&u=");
                                sb.append(oData.aData[23]);
                                sb.append("\"><b style=\"color:Green;\" title='PTO ON'</b>ON</a>");
                                return sb.toString();
                            }
                            else {
                                if (oData.aData[22] == "--") {
                                    return "--";
                                }
                                else {
                                    return "<img width=\"16px\" height=\"14px\" src=\"images/nofuel.gif\" title=\"PTO not installed\" />"
                                }
                            }

                        }
                    },
                    { "aTargets": [9], "sWidth": "40px", "bVisible": true, "asSorting": ["desc", "asc"] },

                    {
                        "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {
                            if (sVal == "--") {
                                return "--";
                            }
                            else {

                                var sb = new StringBuilder();
                                sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Odometer = ");
                                sb.append(oData.aData[11]);
                                sb.append(" KM\" target=\"_blank\" href=\"VehicleMileageChart.aspx?bdt=");
                                sb.append(oData.aData[24]);
                                sb.append("&edt=");
                                sb.append(oData.aData[7]);
                                sb.append("&u=");
                                sb.append(oData.aData[23]);
                                sb.append("&p=");
                                sb.append(oData.aData[22]);
                                sb.append("\">");
                                sb.append(oData.aData[11]);
                                sb.append("</a>");
                                return sb.toString();


                            }
                        }, "aTargets": [11], "asSorting": ["desc", "asc"]
                    },

                    {
                        "sClass": "right", "bVisible": false, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[12] == "-") {
                                return "--";
                            }
                            else {
                                return oData.aData[12];
                            }
                        }, "aTargets": [12], "asSorting": ["desc", "asc"]
                    },

                    {
                        "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[7] != "--") {

                                sVal = oData.aData[13];

                                if (sVal == "-2") {
                                    return "<img width=\"16px\" height=\"14px\" src=\"images/nofuel.gif\" title=\"no fuel sensor installed on this tank\" />";
                                }
                                else if (sVal == "-1") {
                                    return "<img width=\"14px\" height=\"14px\" src=\"images/fsp.gif\" title=\"fuel sensor problem, please contact customer service for checking\" />";
                                }
                                else {


                                    var sb = new StringBuilder();
                                    sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Tank 1 Volume = ");
                                    sb.append(sVal);
                                    sb.append(" Liters Remaining\" target=\"_blank\" href=\"FuelAnalysisReportChart.aspx?bdt=");
                                    sb.append(oData.aData[24]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[7]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[23]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[22]);
                                    sb.append("\">");
                                    sb.append(sVal);
                                    sb.append("</a>");
                                    return sb.toString();

                                }
                            }
                            else {
                                return "--";
                            }
                        }, "aTargets": [13], "asSorting": ["desc", "asc"]
                    },

                    {
                        "sClass": "right", "sWidth": "40px", "bVisible": <%=Fuel2Id %>, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[7] != "--") {

                                sVal = oData.aData[14];
                                if (sVal == "-2") {
                                    return "<img width=\"16px\" height=\"14px\" src=\"images/nofuel.gif\" title=\"no fuel sensor installed on this tank\" />";
                                }
                                else if (sVal == "-1") {
                                    return "<img width=\"14px\" height=\"14px\" src=\"images/fsp.gif\" title=\"fuel sensor problem, please contact customer service for checking\" />";
                                }
                                else {


                                    var sb = new StringBuilder();
                                    sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Tank 2 Volume = ");
                                    sb.append(sVal);
                                    sb.append(" Liters Remaining\" target=\"_blank\" href=\"FuelAnalysisReportChart.aspx?bdt=");
                                    sb.append(oData.aData[24]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[7]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[23]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[22]);
                                    sb.append("\">");
                                    sb.append(sVal);
                                    sb.append("</a>");
                                    return sb.toString();
                                }
                            }
                            else {
                                return "--";
                            }
                        }, "aTargets": [14], "asSorting": ["desc", "asc"]
                    },
                    {
                        "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[7] != "--") {

                                sVal = oData.aData[15];

                                if (sVal[0] == "--") {
                                    return "";
                                }
                                else {
                                    var sb = new StringBuilder();
                                    sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"VehicleIdlingChart.aspx?bdt=");
                                    sb.append(oData.aData[24]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[7]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[23]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[22]);
                                    sb.append("\">");

                                    if (sVal[2] == "") {
                                        sb.append("<b style=\"color:blue;\" title=\"From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\">");
                                        sb.append(sVal[2]);
                                        sb.append("</b></a>");
                                        return sb.toString();
                                    }
                                    if (parseInt(sVal[2]) >= 60) {
                                        sb.append("<b style=\"background-color:#FF8800;color:#FFFFFF;\" title=\"Idling for ");
                                        sb.append(sVal[2]);
                                        sb.append(" Mins Start From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\"><blink>");
                                        sb.append(sVal[2]);
                                        sb.append("</blink></b></a>");
                                        return sb.toString();
                                    }
                                    else if (parseInt(sVal[2]) >= 45) {
                                        sb.append("<b style=\"background-color:#FFFF00;color:#FF0066;\" title=\"Idling for ");
                                        sb.append(sVal[2]);
                                        sb.append(" Mins Start From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\"><blink>");
                                        sb.append(sVal[2]);
                                        sb.append("</blink></b></a>");
                                        return sb.toString();
                                    }
                                    else if (parseInt(sVal[2]) >= 30) {
                                        sb.append("<b style=\"background-color:#FFFF00;color:#FF0066;\" title=\"Idling for ");
                                        sb.append(sVal[2]);
                                        sb.append(" Mins Start From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\"><blink>");
                                        sb.append(sVal[2]);
                                        sb.append("</blink></b></a>");
                                        return sb.toString();
                                    }
                                    else if (parseInt(sVal[2]) >= 15) {
                                        sb.append("<b style=\"background-color:#FFFFF0;color:#FF6699;\" title=\"Idling for ");
                                        sb.append(sVal[2]);
                                        sb.append(" Mins Start From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\"><blink>");
                                        sb.append(sVal[2]);
                                        sb.append("</blink></b></a>");
                                        return sb.toString();
                                    }
                                    else {
                                        sb.append("<b style=\"color:blue;\" title=\"Idling for ");
                                        sb.append(sVal[2]);
                                        sb.append(" Mins Start From: ");
                                        sb.append(sVal[1]);
                                        sb.append("\">");
                                        sb.append(sVal[2]);
                                        sb.append("</b></a>");
                                        return sb.toString();
                                    }

                                }
                            }
                            else {
                                return ""
                            }

                        }, "aTargets": [15], "asSorting": ["desc"]
                    },
                    { "sClass": "right", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [16] },
                    { "sClass": "right", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [17] },
                    { "sClass": "center", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [18] },
                    {
                        "bSortable": true, "sType": "html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[7] != "--") {
                                var location = "";
                                var tp = oData.aData[19][0]
                                location = oData.aData[19][1];

                                var sb = new StringBuilder();
                                sb.append("<span><a href=\"https://maps.google.com/maps?f=q&hl=en&q=");
                                sb.append(oData.aData[16]);
                                sb.append(" + ");
                                sb.append(oData.aData[17]);
                                sb.append("&om=1&t=k\" target=\"_blank\" style=\"text-decoration:none;color:black;\">");
                                switch (tp) {
                                    case 0:
                                        sb.append(location);
                                        break;
                                    case 1:
                                        sb.append("<div class='g1' title='geofence'></div> <b>");
                                        sb.append(location);
                                        sb.append("</b>");
                                        break;
                                    case 2:
                                        sb.append("<div class='p1' title='POI'></div> <b>");
                                        sb.append(location);
                                        sb.append("</b>");
                                        break;
                                    case 3:
                                        sb.append("<div class='r1' title='road'></div>&nbsp");
                                        sb.append(location);
                                        break;
                                }
                                sb.append("</a></span>");
                                return sb.toString();
                            }
                            else {
                                return "--";
                            }


                        },

                        "aTargets": [19]
                    },
                    {
                        "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {


                            if (sVal == "--") {
                                return "--";
                            }
                            else {



                                var sb = new StringBuilder();
                                sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Speed = ");
                                sb.append(oData.aData[10]);
                                sb.append(" KM/H\" target=\"_blank\" href=\"VehicleSpeedChart.aspx?bdt=");
                                sb.append(oData.aData[24]);
                                sb.append("&edt=");
                                sb.append(oData.aData[7]);
                                sb.append("&u=");
                                sb.append(oData.aData[23]);
                                sb.append("&p=");
                                sb.append(oData.aData[22]);
                                sb.append("\">");
                                sb.append(oData.aData[10]);
                                sb.append("</a>");
                                return sb.toString();
                            }
                        }, "aTargets": [10], "asSorting": ["desc", "asc"]
                    },

                    { "sClass": "left", "bVisible": true, "bSortable": true, "aTargets": [20] },
                    { "sClass": "left", "bVisible": false, "bSortable": true, "aTargets": [21] },


                    {
                        "sClass": "left", "sWidth": "90px", "aTargets": [23], "bSortable": true, "bVisible": false,
                        "fnRender": function (oData, sVal) {
                            return oData.aData[25];
                        }

                    },
                    {
                        "sClass": "center", "sWidth": "90px", "aTargets": [24], "bSortable": true, "bVisible": false,
                        "fnRender": function (oData, sVal) {
                            var cont = new StringBuilder();
                            var clsV = 'gv.png';
                            var vData = parseFloat(oData.aData[26]).toFixed(1);
                            if (vData >= 25) {
                                clsV = "gv.png";
                            }
                            else if (vData < 25 && vData >= 23) {
                                clsV = "yv.png";
                            }
                            else if (vData < 23 && vData > 0) {
                                clsV = "ov.png";
                            }
                            else if (vData == 0) {
                                clsV = "rv.png";
                            }
                            cont.append("<img style='cursor:pointer;height:16px;' alt='" + vData + "' src='images/" + clsV + "' title='" + vData + "' onclick=\"showExternalVolt(\'")
                            cont.append(oData.aData[27]);
                            cont.append("\',\'");
                            cont.append(oData.aData[7]);
                            cont.append("\')\" />");
                            //cont.append(vData);
                            //cont.append("</span>");
                            if (oData.aData[27] == "--") {
                                return "--";
                            }
                            else {
                                return cont.toString();
                            }
                        }
                    },
                    {
                        "sClass": "left", "sWidth": "90px", "aTargets": [25], "bSortable": true, "bVisible": true,
                        "fnRender": function (oData, sVal) {
                            return oData.aData[31];
                        }
                    },
                    {
                        "sClass": "left", "sWidth": "90px", "aTargets": [26], "bSortable": true, "bVisible": true,
                        "fnRender": function (oData, sVal) {
                            return oData.aData[32];
                        }
                    },
                    {
                        "sClass": "left", "sWidth": "90px", "aTargets": [27], "bSortable": true, "bVisible": true,
                        "fnRender": function (oData, sVal) {
                            return oData.aData[33];
                        }
                    },
                    {
                        "sClass": "center", "sWidth": "30px", "aTargets": [28], "bSortable": false, "bVisible": true,
                        "fnRender": function (oData, sVal) {
                            var cont = new StringBuilder();
                            cont.append("<img style='cursor:pointer;' src='images/poll.gif' title='Poll' alt='Poll' onclick=\"pollit(\' ")
                            cont.append(oData.aData[22]);
                            cont.append("\')\" />");
                            if (oData.aData[22] == "--") {
                                return "--";
                            }
                            else {
                                return cont.toString();
                            }


                        }

                    },
                    {
                        "sClass": "left", "sWidth": "90px", "aTargets": [29], "bSortable": true, "bVisible": true,
                        "fnRender": function (oData, sVal) {
                            return oData.aData[37];
                        }
                    }
                ],
                "sDom": '<"H"Cl<"MyButton">f>tr<"F"iT>',
                "oColReorder": {
                    // "iFixedColumns": 4
                },
                "oColVis": {
                    "aiExclude": varexclu,
                    "buttonText": "Show / Hide Columns",
                    "sRestore": "Restore original",
                    "sSize": "100%"
                },
                "oTableTools": { "aButtons": ["xls", "copy", "print"], "sSwfPath": "cssfiles/copy_csv_xls_pdf.swf" }
            });


            oTable.fnClearTable(this);
            oTable.fnAdjustColumnSizing();

            if (<%=puserid %> == 1911) {
                oTable.fnSetColumnVis(6, false);

            }
            if (<%=puserid %> == 6896) {
                oTable.fnSetColumnVis(10, false);

            }


            $("div.MyButton").html('<div><%=opt %>  <button class="ColVis_Button TableTools_Button ui-button ui-state-default ColVis_MasterButton" id="refreshbtn" onclick="return refreshTable()";><span>Refresh </span></button></div>');

            jQuery(".chosen").data("placeholder", "SELECT USERNAME").chosen();

        });
        function openvehiclepath(plateno, bdt, edt) {
            document.getElementById("idlingpage").style.visibility = "visible";
            document.getElementById("idlingpage").src = "GMap.aspx?plateno=" + plateno + "&bdt=" + bdt + "&edt=" + edt + "&scode=1&sf=1";
            $("#dialog-message").dialog("open");
        }

        function getJobData(plateno) {
            document.getElementById("jobPage").style.visibility = "visible";
            document.getElementById("jobPage").src = "GetJobData.aspx?plateno=" + plateno;
            $("#OssDiv").dialog("open");
        }
        function showExternalVolt(plateno, dttm) {
            document.getElementById("idlingpage").style.visibility = "visible";
            document.getElementById("idlingpage").src = "GetExtVoltage.aspx?plateno=" + plateno + "&d=" + dttm;
            $("#dialog-message").dialog("open");
        }

        function pollit(plateno) {
            document.getElementById("pollingPage").style.visibility = "visible";
            document.getElementById("pollingPage").src = "Polling.aspx?plateno=" + plateno;
            $("#PollDiv").dialog("open");
        }

        function closeDiv() {
            $("#PollDiv").dialog("close");
        }
        function alertbox(message) {
            document.getElementById("displayp").innerHTML = message;
            $("#Div1").dialog("open");
        }

        function openPopup(status, pno, u, sdate, sourcename, remarks) {
            $('#spnLastStatusDate').text(sdate);
            $('#spnUpdatedBy').text(sourcename);
            $('#spnStatus').text(status);
            $('#spnRemarks').text(remarks);
            // $("#txtrecentstatus").val(recentstatus);
            if ((status == "Data Not Coming") || (status == "Running")) {
                $('#plate_no').text(pno);
                $('#ddlstatus').val("Select Status");
                $('#txtna').val(u);
            }
            else {
                $('#plate_no').text(pno);
                $('#ddlstatus').val(status);
                $('#txtna').val(u);
            }


            $("#dialog-form").dialog("open");

        }

        function openPopupStatus(pno, remarks, recentstatus) {
            $("#txtrecentstatus").val(unescape(recentstatus));
            $("#txtstatusremarks").val(unescape(remarks));
            $('#plate_no_status').text(pno);
            $("#dialog-formstatus").dialog("open");
        }

        function UpdateData() {

            var str = "updatevehiclestatus.aspx?s=" + $('#ddlstatus').val() + "&pno=" + $('#plate_no').text() + "&u=" + $("#txtna").val() + "&re=" + $("#txtRemarks").val();
            $.get(str, function (data) {
                alertbox("Updated Successfully");
                $("#dialog-message").dialog("close");
                refreshTable();
            });
            $('#plate_no').val() == "";
            $('#ddlstatus').val() == "";
            refreshTable();
        }
        function UpdateRecentStatus() {
            var type = 0;
            if ($("#chkrunning").prop("checked")) {
                type = 1;
            }
            else {
                type = 0;
            }
            if ($("#txtrecentstatus").val().trim() == "" && type == 0) {
                alertbox("Please enter truck recent status");
            }
            else {

                var str = "updatevehiclerecentstatus.aspx?pno=" + $('#plate_no_status').text() + "&re=" + $("#txtstatusremarks").val() + "&status=" + $("#txtrecentstatus").val() + "&type=" + type + "";
                $.get(str, function (data) {
                    alertbox("Updated Successfully");
                    $("#dialog-formstatus").dialog("close");
                    refreshTable();
                });
                $('#plate_no_status').val() == "";
                $('#txtrecentstatus').val() == "";
                $('#txtstatusremarks').val() == "";
                refreshTable();
            }



        }
    </script>
    <style type="text/css">
        .chzn-container-single .chzn-single {
            height: 24px;
            line-height: 24px;
        }

        .chzn-search {
            width: 203px;
        }

        .chzn-container .chzn-results {
            max-height: 300px;
        }
    </style>
    <style type="text/css">
        .ui-button {
            font-size: 12px;
        }
    </style>
</head>
<body id="dt_example" style="margin: 0px; font-size: 11px; font-family: Verdana;"
    onresize="resize()" onload="load()" onunload="unload()">
    <form id="Form1" runat="server">
        <table cellpadding="0" cellspacing="0" border="0" class="display" id="example" style="font-size: 11px; font-family: Verdana;">
            <thead style="text-align: left;">
                <tr>
                    <th width="30px">No
                    </th>
                    <th width="30px">Status
                    </th>
                    <th width="150px" title="Primer Mover">PM ID
                    </th>
                    <th width="135px">Plate No
                    </th>
                    <th width="150px">Group Name
                    </th>
                    <th width="50px">Job
                    </th>
                    <th width="150px">Trailer ID
                    </th>
                    <th width="135px">Date Time
                    </th>
                    <th width="30px">PTO
                    </th>
                    <th width="40px">Ignition
                    </th>
                    <th width="40px">Speed
                    </th>
                    <th width="40px">Odometer
                    </th>
                    <th width="40px">M.Odo
                    </th>
                    <th width="40px">Fuel1
                    </th>
                    <th width="40px">Fuel2
                    </th>
                    <th width="40px">Idling
                    </th>
                    <th width="40px">Lat
                    </th>
                    <th width="40px">Lon
                    </th>
                    <th width="30px">Dir
                    </th>
                    <th>Location
                    </th>
                    <th>Nearest Town
                    </th>
                    <th>Mile Point
                    </th>
                    <th width="20px">Poll
                    </th>
                    <th>Type
                    </th>
                    <th>Battery
                    </th>
                    <th>ETA
                    </th>
                    <th>Total KM
                    </th>
                    <th>Remain KM
                    </th>
                    <th>CMD
                    </th>
                    <th>Geofence In DateTime
                    </th>
                </tr>
            </thead>
            <tbody>
            </tbody>
            <tfoot style="text-align: left; font-weight: bold;">
                <tr>
                    <th width="30px">No
                    </th>
                    <th width="30px">Status
                    </th>
                    <th width="150px" title="Primer Mover">PM ID
                    </th>
                    <th width="135px">Plate No
                    </th>
                    <th width="150px">Group Name
                    </th>
                    <th width="50px">Job
                    </th>
                    <th width="150px">Trailer ID
                    </th>

                    <th width="135px">Date Time
                    </th>
                    <th width="30px">PTO
                    </th>
                    <th width="40px">Ignition
                    </th>
                    <th width="40px">Speed
                    </th>
                    <th width="40px">Odometer
                    </th>
                    <th width="40px">M.Odo
                    </th>
                    <th width="40px">Fuel1
                    </th>
                    <th width="40px">Fuel2
                    </th>
                    <th width="40px">Idling
                    </th>
                    <th width="40px">Lat
                    </th>
                    <th width="40px">Lon
                    </th>
                    <th width="30px">Dir
                    </th>
                    <th>Location
                    </th>
                    <th>Nearest Town
                    </th>
                    <th>Mile Point
                    </th>
                    <th width="20px">Poll
                    </th>
                    <th>Type
                    </th>
                    <th>Battery
                    </th>
                    <th>ETA
                    </th>
                    <th>Total KM
                    </th>
                    <th>Remain KM
                    </th>
                    <th>CMD
                    </th>
                    <th>Geofence In DateTime
                    </th>
                </tr>
            </tfoot>
        </table>

        <script type="text/javascript">
            window.setInterval("refreshTable()", 60000);
        </script>
        <div id="dialog-form" title="Update Vehicle's Status" style="padding-top: 1px; padding-right: 0px; padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;">
            <table border="0" cellpadding="1" cellspacing="1" style="width: 500px; font-size: 11px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Plate No</b> &nbsp;:&nbsp;&nbsp;
                    </td>
                    <td>
                        <span id="plate_no"></span>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Previous Status Date</b>
                    </td>
                    <td>:<span id="spnLastStatusDate" class="boldunderline"></span>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Previous Updated By </b>
                    </td>
                    <td>:<span id="spnUpdatedBy" class="boldunderline"></span>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Previous  Status</b>
                    </td>
                    <td>:<span id="spnStatus" class="boldunderline"></span>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Previous Remarks</b>
                    </td>
                    <td>:<span id="spnRemarks" class="boldunderline"></span>
                    </td>
                </tr>
                <tr>
                    <br />
                    <td align="left">
                        <b style="color: #4E6CA3;">Status</b> &nbsp;&nbsp;&nbsp; :&nbsp;&nbsp;
                    </td>
                    <td>
                        <asp:DropDownList runat="server" ID="ddlstatus" Width="156px" Height="21px" EnableViewState="False">
                            <asp:ListItem Text="Select Status" Value="Select Status"></asp:ListItem>
                            <asp:ListItem Text="WORKSHOP" Value="Workshop"></asp:ListItem>
                            <asp:ListItem Text="BATTERY TAKEN OUT" Value="Battery Taken Out"></asp:ListItem>
                            <asp:ListItem Text="POWER CUT" Value="Power Cut"></asp:ListItem>
                            <asp:ListItem Text="SPARE TRUCK" Value="Spare Truck"></asp:ListItem>
                            <asp:ListItem Text="NOT IN OPERATION" Value="Not in Operation"></asp:ListItem>
                            <asp:ListItem Text="ACCIDENT" Value="Accident"></asp:ListItem>
                            <asp:ListItem Text="SERVICE SCHEDULED" Value="Service Scheduled"></asp:ListItem>
                            <asp:ListItem Text="PENDING SERVICE SCHEDULE" Value="Pending Service Schedule"></asp:ListItem>
                        </asp:DropDownList>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Latest Remarks</b>
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtRemarks" TextMode="MultiLine" Width="150px" Height="30px" />
                    </td>
                </tr>
            </table>
        </div>

        <div id="dialog-formstatus" title="Update Vehicle's Status" style="padding-top: 1px; padding-right: 0px; padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;">
            <table border="0" cellpadding="1" cellspacing="1" style="width: 500px; font-size: 11px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Plate No</b> &nbsp;:&nbsp;&nbsp;
                    </td>
                    <td>
                        <span id="plate_no_status"></span>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Latest Truck Status</b>
                    </td>
                    <td>
                        <input type="checkbox" id="chkrunning" />
                        <label for="chkrunning">Running</label>
                        <br />
                        <asp:TextBox runat="server" ID="txtrecentstatus" TextMode="MultiLine" Width="300px" Height="30px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Remarks</b>
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtstatusremarks" TextMode="MultiLine" Width="300px" Height="30px" />
                    </td>
                </tr>
            </table>
        </div>

        <div id="dialog-message" title="vehicle's Information" style="padding-top: 1px; padding-right: 0px; padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
            <iframe id="idlingpage" name="idlingpage" src="" frameborder="0" scrolling="auto"
                height="512" width="998px" style="visibility: hidden; border: solid 1px #aac6ff;"></iframe>
        </div>
        <div id="PollDiv" title="Polling" style="padding: 0px;">
            <iframe id="pollingPage" name="pollingPage" src="" frameborder="0" scrolling="no"
                height="400" width="998px" style="visibility: hidden; border: solid 0px white;"></iframe>
        </div>
        <div id="OssDiv" title="Job Details" style="padding: 0px;">
            <iframe id="jobPage" name="jobPage" src="" frameborder="0" scrolling="no"
                height="400" width="998px" style="visibility: hidden; border: solid 0px white;"></iframe>
        </div>
        <div class="demo">
            <div id="Div1" title="Alert">
                <p id="displayp">
                    <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;"></span>
                </p>
            </div>
        </div>
        <input type="hidden" name="txtna" value="" id="txtna" />
        <input type="hidden" id="unname" name="unname" value="<%=unname%>" />
    </form>
</body>

</html>

