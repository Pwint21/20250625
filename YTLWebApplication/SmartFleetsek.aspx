<%@ Page Language="VB" AutoEventWireup="false" Inherits="YTLWebApplication.SmartFleetsek" Codebehind="SmartFleetsek.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
    <meta content="text/html; charset=utf-8" http-equiv="Content-type">
    <title>Smart Fleet</title>
    <%-- <link href="GMap/chosen/chosen.css" rel="stylesheet" type="text/css" />--%>
    <style type="text/css" title="currentStyle">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
        @import "cssfiles/jquery-ui.css";
        @import "cssfiles/jquery.ui.dialog.css";
        @import "cssfiles/TableTools.css";
        @import "cssfiles/ColVis.css";
        
        .pk
        {
          padding-left: 30px;
          color:Black;
          font-weight:normal;  
        }
        
        table.display td
        {
            padding: 2px 2px;
            border: 1px solid lightblue;
            nowrap: nowrap;
            white-space: nowrap;
        }
        th
        {
            width: auto;
            min-width: 5px;
            nowrap: nowrap;
            white-space: nowrap;
        }
        
        
        #refreshbtn
        {
            position: fixed;
        }
        .dataTables_filter
        {
            width: 300px;
        }
        
        input
        {
            margin: 0px;
            font-size: 19px;
            border: 0px solid gray;
        }
        
        .MyButton
        {
            text-align: left;
            float: left;
            width: 350px;
        }
        
        #ddluser
        {
            margin: 0px;
            position: absolute;
            top: 4px;
            text-decoration: none;
            height: 25px;
        }
        tr.odd
        {
            background-color: white;
        }
        tr.even
        {
            background-color: #f7fbff;
        }
        tr.even:hover
        {
            background-color: #00cccc;
        }
        tr.odd:hover
        {
            background-color: #00cccc;
        }
        tr.odd td.sorting_1
        {
            background-color: white;
        }
        tr.even td.sorting_1
        {
            background-color: #f7fbff;
        }
        
        tr.even:hover td.sorting_1
        {
            background-color: #00cccc;
        }
        tr.odd:hover td.sorting_1
        {
            background-color: #00cccc;
        }
        .g1
{
    background-image: url(images/g.png);
    background-repeat: no-repeat;
    width: 16px;
    height: 16px;
    vertical-align:middle;
    display:inline-table;
}
.p1
{
    background-image: url(images/p.png);
    background-repeat: no-repeat;
    width: 16px;
    height: 16px;
    vertical-align:middle;
    display:inline-table;
}
.r1
{
    background-image: url(images/r.png);
    background-repeat: no-repeat;
    width: 13px;
    height: 13px;
    vertical-align:middle;
    display:inline-table;
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
            $.getJSON('GetSmartFleetsek.aspx?u=' + $("#ddluser").val(), null, function (json) {
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
                    //closeDiv();
                    return false;
                }
                else {
                    alertbox("<b style='Color:Red;'>Sorry.Please try again..!!!</b>");
                    // closeDiv();
                    var x;
                    return false;
                }
            });

        }

        $(document).ready(function () {

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
                width: 320,
                minHeight: 150,
                height: 175,
                buttons: {
                    Update: function () {
                        UpdateData();
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

              $("#MOdodetails_dialog").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                minWidth: 1000,
                minHeight: 529
            });
            var h = getWindowHeight() - 135 + "px";
            oTable = $('#example').dataTable({
                "bProcessing": true,
                "bJQueryUI": true,
                "bServerSide": false,
                "sPaginationType": "full_numbers",
                "sAjaxSource": "GetSmartFleetsek.aspx?u=<%=suserid %>",
                "sScrollY": h,
                "sScrollX": "100%",
                "bScrollCollapse": true,
                "bLengthChange": false,
                "iDisplayLength": 2000,
                "bInfo": true,
                "bAutoWidth": false,
                "aaSorting": [[4, "desc"]],
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

                "aoColumnDefs": [
                    { "bVisible": true, "bSortable": false, "sWidth": "30px", "aTargets": [0] },
	                { "bVisible": true, "sWidth": "30px", "fnRender": function (oData, sVal) {
	                    var ppp = "";
	                    var s = "";
	                    var vehicleicon = "<img src='images/PT.png' style='height:16px;width:16px;' title='Travelling' />";

	                    if (oData.aData[4] == "--") {
	                        return "";
	                    }
	                    else {

	                        if (oData.aData[6] == "OFF") {
	                            ppp = "Stop";
	                            s = "style=\"color:red;cursor:pointer;";
	                            vehicleicon = "<img src='images/PS.png' style='height:16px;width:16px;' title='Stopped' alt='Stopped' />";

	                        }
	                        else {
	                            if (oData.aData[7] == 0) {
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
	                            //	                            status.append("<img src=\"images/");
	                            //	                            status.append(statusimg);
	                            //	                            status.append("\" width=\"16px\" alt=\"");
	                            //	                            status.append(sVal[0][1]);
	                            //	                            status.append("\" height=\"16px\" title=\"Date Time: ");
	                            //	                            status.append(sVal[0][0]);
	                            //	                            status.append("\nUnit Status: ");
	                            //	                            status.append(sVal[0][1]);
	                            //	                            status.append("\" />");

	                            status = "<div " + s + "\"><img src=\"images/" + statusimg + "\" width=\"16px\" height=\"16px\" style=\"color:gray;cursor:pointer;\" onclick=\"javascript:openPopup('" + sVal[0][1] + "','" + oData.aData[2] + "','" + oData.aData[23] + "');\" title=\"Date Time: " + sVal[0][0] + "\nUnit Status: " + sVal[0][1] + "\" />" + vehicleicon + "</div>";

	                            return status;
	                        }
	                        else {
//	                            var st = new StringBuilder();
//	                            var imgg = "us1.gif";
//	                            st.append("<img src=\"images/");
//	                            st.append(imgg);
//	                            st.append("\" width=\"16px\" alt=\"");
//	                            st.append(ppp);
//	                            st.append("\"  height=\"16px\" title=\"Status:Running\" />");

	                            //	                            return st.toString();
	                            var statusimg = "us1.gif";
	                            var stst = "Running";
	                            status = "<div " + s + "\"><img src=\"images/" + statusimg + "\" width=\"16px\" height=\"16px\"  style=\"color:gray;cursor:pointer;\" onclick=\"javascript:openPopup('" + stst + "','" + oData.aData[2] + "','" + oData.aData[23] + "');\" title=\"Status: " + stst + "\" />" + vehicleicon + "</div>";

	                            return status;
	                        }
	                    }
	                }, "aTargets": [1], "asSorting": ["desc", "asc"]
	                },
	                { "fnRender": function (oData, sVal) {


	                    var plateno = sVal;

	                    if (oData.aData[4] == "--") {
	                        return "<b style=\"color:gray;cursor:pointer;\" onclick=\"javascript:alertbox('No Data');\">" + plateno + "</b>";
	                    }
	                    else {
	                        var s;
	                        if (oData.aData[6] == "OFF") {
	                            s = "style=\"color:red;cursor:pointer;";
	                        }
	                        else {
	                            if (oData.aData[7] == 0) {
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
	                        sb.append(oData.aData[19]);
	                        sb.append('\',\' ');
	                        sb.append(oData.aData[21]);
	                        sb.append('\',\' ');
	                        sb.append(oData.aData[4]);
	                        sb.append('\')"><b>');
	                        sb.append(oData.aData[19]);
	                        sb.append('</b></span>');
	                        return sb.toString();

	                    }
	                }, "aTargets": [2]
	                },
                    { "aTargets": [3], "sWidth": "150px", "bVisible": true, "asSorting": ["desc", "asc"] },
                    { "sType": "date", "sWidth": "135px", "aTargets": [4], "asSorting": ["desc", "asc"] },

                    { "aTargets": [6], "sWidth": "40px", "bVisible": false, "asSorting": ["desc", "asc"] },

                    { "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {



                            if (sVal == "--") {
                                return "--";
                            }
                            else {


                                var sb = new StringBuilder();
                                sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Odometer = ");
                                sb.append(oData.aData[8]);
                                sb.append(" KM\" target=\"_blank\" href=\"VehicleMileageChart.aspx?bdt=");
                                sb.append(oData.aData[21]);
                                sb.append("&edt=");
                                sb.append(oData.aData[4]);
                                sb.append("&u=");
                                sb.append(oData.aData[20]);
                                sb.append("&p=");
                                sb.append(oData.aData[19]);
                                sb.append("\">");
                                sb.append(oData.aData[8]);
                                sb.append("</a>");
                                return sb.toString();


                            }
                        }, "aTargets": [8], "asSorting": ["desc", "asc"]
                    },

                     { "sClass": "right", "sWidth": "40px", "bVisible": false, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            var plateno = oData.aData[19];
                             
                            if (sVal[0] == "--") {
                                return "--";
                            }
                            else {

                                
                               return '<span style=\"cursor:pointer;\"  title="Maintenance Odometer = ' + sVal[2] + ' KM\" onclick=\"openOdometerDetails(\'' + plateno + '\',\' ' + sVal[0] + '\',\' ' + sVal[1] + '\')">' + sVal[2] + '</span>';
                            
                              // return sVal;

                            }
                        }, "aTargets": [9], "asSorting": ["desc", "asc"]
                    },

                    { "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[4] != "--") {

                                sVal = oData.aData[10];

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
                                    sb.append(oData.aData[21]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[4]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[20]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[19]);
                                    sb.append("\">");
                                    sb.append(sVal);
                                    sb.append("</a>");
                                    return sb.toString();

                                }
                            }
                            else {
                                return "--";
                            }
                        }, "aTargets": [10], "asSorting": ["desc", "asc"]
                    },
                     { "sClass": "left", "sType": "html", "sWidth": "30px", "aTargets": [5],
                         "fnRender": function (oData, sVal) {

                             sVal = oData.aData[5];

                             var sb = new StringBuilder();

                             if (sVal == 0) {
                                 sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"PTOHistory.aspx?p=");
                                 sb.append(oData.aData[19]);
                                 sb.append("&u=");
                                 sb.append(oData.aData[20]);
                                 sb.append("\" ><b style=\"color:Red;\" title='PTO OFF'</b>OFF</a>");
                                 return sb.toString();
                             }
                             else if (sVal == 1) {
                                 sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"PTOHistory.aspx?p=");
                                 sb.append(oData.aData[19]);
                                 sb.append("&u=");
                                 sb.append(oData.aData[20]);
                                 sb.append("\"><b style=\"color:Green;\" title='PTO ON'</b>ON</a>");
                                 return sb.toString();
                             }
                             else {
                                 if (oData.aData[19] == "--") {
                                     return "--";
                                 }
                                 else {
                                     return "<img width=\"16px\" height=\"14px\" src=\"images/nofuel.gif\" title=\"PTO not installed\" />"
                                 }
                             }

                         }
                     },
                    { "sClass": "right", "sWidth": "40px", "bVisible": <%=Fuel2Id %>, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[4] != "--") {

                                sVal = oData.aData[11];
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
                                    sb.append(oData.aData[21]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[4]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[20]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[19]);
                                    sb.append("\">");
                                    sb.append(sVal);
                                    sb.append("</a>");
                                    return sb.toString();
                                }
                            }
                            else {
                                return "--";
                            }
                        }, "aTargets": [11], "asSorting": ["desc", "asc"]
                    },
                    { "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {

                            if (oData.aData[4] != "--") {

                                sVal = oData.aData[12];

                                if (sVal[0] == "--") {
                                    return "";
                                }
                                else {
                                    var sb = new StringBuilder();
                                    sb.append("<a style=\"cursor:pointer;\" target=\"_blank\" href=\"VehicleIdlingChart.aspx?bdt=");
                                    sb.append(oData.aData[21]);
                                    sb.append("&edt=");
                                    sb.append(oData.aData[4]);
                                    sb.append("&u=");
                                    sb.append(oData.aData[20]);
                                    sb.append("&p=");
                                    sb.append(oData.aData[19]);
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

                        }, "aTargets": [12], "asSorting": ["desc"]
                    },
                    { "sClass": "right", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [13] },
                    { "sClass": "right", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [14] },
                    { "sClass": "center", "sWidth": "40px", "bVisible": false, "bSortable": false, "aTargets": [15] },
		            { "bSortable": true, "sType": "html",
		                "fnRender": function (oData, sVal) {

		                    if (oData.aData[4] != "--") {
		                        var location = "";
		                        var tp = oData.aData[16][0]
		                        location = oData.aData[16][1];

		                        var sb = new StringBuilder();
		                        sb.append("<span><a href=\"https://maps.google.com/maps?f=q&hl=en&q=");
		                        sb.append(oData.aData[13]);
		                        sb.append(" + ");
		                        sb.append(oData.aData[14]);
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

		                "aTargets": [16]
		            },
                    { "sClass": "right", "sWidth": "40px", "bVisible": true, "sType": "num-html",
                        "fnRender": function (oData, sVal) {


                            if (sVal == "--") {
                                return "--";
                            }
                            else {



                                var sb = new StringBuilder();
                                sb.append("<a style=\"cursor:pointer;color:black;\" title=\"Speed = ");
                                sb.append(oData.aData[7]);
                                sb.append(" KM/H\" target=\"_blank\" href=\"VehicleSpeedChart.aspx?bdt=");
                                sb.append(oData.aData[21]);
                                sb.append("&edt=");
                                sb.append(oData.aData[4]);
                                sb.append("&u=");
                                sb.append(oData.aData[20]);
                                sb.append("&p=");
                                sb.append(oData.aData[19]);
                                sb.append("\">");
                                sb.append(oData.aData[7]);
                                sb.append("</a>");
                                return sb.toString();
                            }
                        }, "aTargets": [7], "asSorting": ["desc", "asc"]
                    },

                    { "sClass": "left", "bVisible": true, "bSortable": true, "aTargets": [17] },
                     { "sClass": "left", "bVisible": false, "bSortable": true, "aTargets": [18] },

                     { "sClass": "center", "sWidth": "30px", "aTargets": [19], "bSortable": false, "bVisible": false,
                         "fnRender": function (oData, sVal) {
                             var cont = new StringBuilder();
                             cont.append("<img style='cursor:pointer;' src='images/poll.gif' title='Poll' alt='Poll' onclick=\"pollit(\' ")
                             cont.append(oData.aData[19]);
                             cont.append("\')\" />");
                             if (oData.aData[19] == "--") {
                                 return "--";
                             }
                             else {
                                 return cont.toString();
                             }


                         }

                     },
                      { "sClass": "left", "sWidth": "90px", "aTargets": [20], "bSortable": true, "bVisible": false,
                          "fnRender": function (oData, sVal) {
                              return oData.aData[22];
                          }

                      }

                ],

                "sDom": '<"H"Cl<"MyButton">f>tr<"F"iT>',
                "oColReorder": {
                    "iFixedColumns": 4
                },
                 "oColVis": {

                    "aiExclude": [5],
                    "buttonText": "Show / Hide Columns",
                    "sRestore": "Restore original",
                    "sSize": "100%"
                },

                "oTableTools": { "aButtons": ["xls", "copy", "print"], "sSwfPath": "cssfiles/copy_csv_xls_pdf.swf" }
            });

            oTable.fnClearTable(this);
            oTable.fnAdjustColumnSizing();

            if (<%=pravinid %> == 1911 || <%=pravinid %> == 6826) {
                oTable.fnSetColumnVis(5, false);              
               
            }
           


            $("div.MyButton").html('<div><%=opt %>  <button class="ColVis_Button TableTools_Button ui-button ui-state-default ColVis_MasterButton" id="refreshbtn" onclick="return refreshTable()";><span>Refresh </span></button></div>');

            jQuery(".chosen").data("placeholder", "SELECT USERNAME").chosen();

        });
        function openvehiclepath(plateno, bdt, edt) {
            document.getElementById("idlingpage").style.visibility = "visible";
            document.getElementById("idlingpage").src = "GMap.aspx?plateno=" + plateno + "&bdt=" + bdt + "&edt=" + edt + "&scode=1&sf=1";
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

        function openPopup(status, pno, u) {
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

        function openOdometerDetails(plateno,setodometer,setdate)
        {
          document.getElementById("MOdodetails").src = "MOdometerDetails.aspx?plateno=" + plateno + "&odo=" + setodometer + "&date=" + setdate + "";
          $("#MOdodetails_dialog").dialog("open");
        }

        function UpdateData() {

            var str = "updatevehiclestatus.aspx?s=" + $('#ddlstatus').val() + "&pno=" + $('#plate_no').text() + "&u=" + $("#txtna").val();
            $.get(str, function (data) {
                alertbox("Updated Successfully");
                $("#dialog-message").dialog("close");
                refreshTable();
            });

//            $.ajax({
//                type: "POST",
//                url: "SmartFleet.aspx/UpdateData",
//                data: '{s:\"' + $('#ddlstatus').val() + '\",pno: \"' + $('#plate_no').text() + '\",u: \"' + $("#txtna").val() + '\"}',
//                contentType: "application/json; charset=utf-8",
//                dataType: "json",
//                success: function (response) {
//                    if (parseInt(response) > 0) {
//                        alertbox("Updated Successfully");
//                    }
//                    else if ($('#ddlstatus').val() == "Select Status") {
//                        alertbox("Please select another selection");
//                        return false;
//                    }
//                    else {
//                        alertbox("Your Record was not Updated");
//                        return false;
//                    }
//                    var json = response.d;
//                    table = oTable.dataTable();
//                    table._fnProcessingDisplay(true);
//                    oSettings = table.fnSettings();
//                    table.fnClearTable(this);
//                    for (var i = 0; i < response.length; i++) {
//                        table.oApi._fnAddData(oSettings, response[i]);
//                    }
//                    oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
//                    table._fnProcessingDisplay(false);
//                    table.fnDraw();
//                    return false;
//                },
//                failure: function (response) {
//                    alert("Failed");
//                }
//            });

//            $("#dialog-form").dialog("close");

            $('#plate_no').val() == "";
            $('#ddlstatus').val() == "";
            refreshTable();
        }
    </script>
    <style type="text/css">
        .chzn-container-single .chzn-single
        {
            height: 24px;
            line-height: 24px;
        }
        .chzn-search
        {
            width: 203px;
        }
        .chzn-container .chzn-results {  
          max-height: 300px;
        }
    </style>
    <style type="text/css">
        .ui-button
        {
            font-size: 12px;
        }
    </style>
</head>
<body id="dt_example" style="margin: 0px; font-size: 11px; font-family: Verdana;"
    onresize="resize()" onload="load()" onunload="unload()">
      <form id="Form1" runat="server">
    <table cellpadding="0" cellspacing="0" border="0" class="display" id="example" style="font-size: 11px;
        font-family: Verdana;">
        <thead style="text-align: left;">
             <tr>
                <th width="30px">
                    No
                </th>
                <th width="30px">
                    Status
                </th>
                <th width="135px">
                    Plate No
                </th>
                <th width="150px">
                    Group Name
                </th>
                <th width="135px">
                    Date Time
                </th>
                <th width="30px">
                    PTO
                </th>
                <th width="40px">
                    Ignition
                </th>
                <th width="40px">
                    Speed
                </th>
                <th width="40px">
                    Odometer
                </th>
                <th width="40px">
                    M.Odo
                </th>
                <th width="40px">
                    Fuel1
                </th>
                <th width="40px">
                    Fuel2
                </th>
                <th width="40px">
                    Idling
                </th>
                <th width="40px">
                    Lat
                </th>
                <th width="40px">
                    Lon
                </th>
                <th width="30px">
                    Dir
                </th>
                <th>
                    Location
                </th>
               
                <th>
                    Nearest Town
                </th>
                 <th>
                    Mile Point
                </th>
                <th width="20px">
                    Poll
                </th>
                  <th >
                   Type
                </th>
            </tr>
        </thead>
        <tbody>
        </tbody>
        <tfoot style="text-align: left; font-weight: bold;">
             <tr>
                <th width="30px">
                    No
                </th>
                <th width="30px">
                    Status
                </th>
                <th width="135px">
                    Plate No
                </th>
                <th width="150px">
                    Group Name
                </th>
                <th width="135px">
                    Date Time
                </th>
                <th width="30px">
                    PTO
                </th>
                <th width="40px">
                    Ignition
                </th>
                <th width="40px">
                    Speed
                </th>
                <th width="40px">
                    Odometer
                </th>
                <th width="40px">
                    M.Odo
                </th>
                <th width="40px">
                    Fuel1
                </th>
                <th width="40px">
                    Fuel2
                </th>
                <th width="40px">
                    Idling
                </th>
                <th width="40px">
                    Lat
                </th>
                <th width="40px">
                    Lon
                </th>
                <th width="30px">
                    Dir
                </th>
                <th>
                    Location
                </th>
               
                <th>
                    Nearest Town
                </th>
                 <th>
                    Mile Point
                </th>
                <th width="20px">
                    Poll
                </th>
                  <th >
                   Type
                </th>
            </tr>
        </tfoot>
    </table>
   
    <script type="text/javascript">
        window.setInterval("refreshTable()", 60000);
    </script>
    <div id="dialog-form" title="Update Vehicle's Status" style="padding-top: 1px; padding-right: 0px;
        padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;">
        <table border="0" cellpadding="1" cellspacing="1" style="width: 266px; font-size: 11px;
            font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
            <tr>
                <td align="left">
                    <b style="color: #4E6CA3;">Plate No</b> &nbsp;:&nbsp;&nbsp;
                </td>
                <td>
                    <span id="plate_no"></span>
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
                        <asp:ListItem Text="SMS PENDING" Value="SMS Pending"></asp:ListItem>
                        <asp:ListItem Text="WORKSHOP" Value="Workshop"></asp:ListItem>
                        <asp:ListItem Text="BATTERY TAKEN OUT" Value="Battery Taken Out"></asp:ListItem>
                        <asp:ListItem Text="POWER CUT" Value="Power Cut"></asp:ListItem>
                        <asp:ListItem Text="SPARE TRUCK" Value="Spare Truck"></asp:ListItem>
                        <asp:ListItem Text="NOT IN OPERATION" Value="Not in Operation"></asp:ListItem>
                        <asp:ListItem Text="ACCIDENT" Value="Accident"></asp:ListItem>
                    </asp:DropDownList>
                </td>
            </tr>
        </table>
    </div>
    <div id="dialog-message" title="vehicle's Information" style="padding-top: 1px; padding-right: 0px;
        padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
        <iframe id="idlingpage" name="idlingpage" src="" frameborder="0" scrolling="auto"
            height="512" width="998px" style="visibility: hidden; border: solid 1px #aac6ff;">
        </iframe>
    </div>
    <div id="PollDiv" title="Polling" style="padding: 0px;">
        <iframe id="pollingPage" name="pollingPage" src="" frameborder="0" scrolling="no"
            height="400" width="998px" style="visibility: hidden; border: solid 0px white;">
        </iframe>
    </div>
    <div id="MOdodetails_dialog" title="Maintenance Odometer Details" style="padding-top: 1px;
    padding-right: 0px; padding-bottom: 0px; font-size: 80%/10px; padding-left: 0px;
    font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
    <iframe id="MOdodetails" name="MOdodetails" src="" frameborder="0" scrolling="auto"
        height="512" width="998px" style="border: solid 1px #aac6ff;"></iframe>
</div>
    <div class="demo">
       <div id="Div1" title="Alert">
            <p id="displayp">
                <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;">
                </span>
            </p>
        </div>
    </div>
       <input type="hidden" name="txtna" value="" id="txtna" />
    </form>
</body>

</html>
