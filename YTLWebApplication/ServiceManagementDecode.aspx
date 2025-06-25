<%@ Page Language="VB" AutoEventWireup="false"
    Inherits="YTLWebApplication.ServiceManagementDecode" Codebehind="ServiceManagementDecode.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Servicing Management</title>
    <style type="text/css" media="screen">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
        @import "cssfiles/jquery-ui.css";
        @import "cssfiles/jquery.ui.dialog.css";
        @import "cssfiles/TableTools.css";
        @import "cssfiles/ColVis.css";
    </style>
    <style type="text/css">
        .dataTables_filter
        {
            width: 50%;
            float: right;
            text-align: right;
            margin-top: -24px;
        }
        .chzn-container .chzn-results li
        {
            line-height: 80%;
            padding-bottom: 8px;
            padding-top: 8px;
            margin: 0;
            list-style: none;
            z-index: 1;
            color: #4E6CA3;
        }
        .dataTables_filter
        {
            width: 50%;
            float: right;
            text-align: right;
            margin-top: -27px;
        }
        
        div.dataTables_wrapper .ui-widget-header
        {
            font-weight: normal;
            float: left;
            text-align: left;
        }
        .dataTables_wrapper .ui-toolbar
        {
            padding: 5px;
            width: 1188px;
        }
        
        table.display thead th div.DataTables_sort_wrapper
        {
            font-size: 11px;
            font-family: verdana;
        }
        table.display tfoot th
        {
            font-weight: bold;
            font-family: verdana;
            font-size: 11px;
        }
        table.display td
        {
            padding-left: 12px;
        }
        .table
        {
            font-size: 11px;
            font-weight: normal;
            font-family: verdana;
        }
        
        tfoot input
        {
            margin: 0.2em 0;
            width: 100%;
            margin-left: -0.7em;
            color: #444;
        }
    </style>
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
        .chzn-container .chzn-results
        {
            max-height: 300px;
        }
    </style>
    <style type="text/css">
        .ui-button
        {
            font-size: 12px;
        }
    </style>
    <link type="text/css" href="cssfiles/css3-buttons.css" rel="stylesheet" />
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.js"></script>
    <link href="cssfiles/chosen.css" rel="stylesheet" type="text/css" />
    <script type="text/javascript" src="jsfiles/chosen.jquery.js"></script>
    <script src="jsfiles/jquery-ui.min.js" type="text/javascript"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.dataTables.js"></script>
    <script type="text/javascript" language="javascript">
        function checkall(chkobj) {
            var chkvalue = chkobj.checked;
            for (i = 0; i < document.forms[0].elements.length; i++) {
                elm = document.forms[0].elements[i]
                if (elm.type == 'checkbox') {
                    document.forms[0].elements[i].checked = chkvalue;
                }
            }
        }
        function deleteconfirmation() {
            var checked = false;
            for (i = 0; i < document.forms[0].elements.length; i++) {
                elm = document.forms[0].elements[i]
                if (elm.type == 'checkbox') {
                    if (elm.checked == true) {
                        checked = true;
                        break;
                    }
                }
            }
            if (checked) {
                var result = confirm("Are you sure you want to delete selected service(s) ?");
                if (result) {
                    return true;
                }
                return false;
            }
            else {
                alertbox("Please select checkboxes");
                return false;
            }
        }
        
        function UpdateData() {
            $.ajax({
                type: "POST",
                url: "GetServiceData.aspx?i=3",
                //ByVal userid As String, ByVal plateno As String, ByVal hodo As String, ByVal htime As String, ByVal odolimit As String, ByVal timelimit As String, ByVal enginlimit As String, ByVal emailid1 As String, ByVal emailid2 As String, ByVal mobile1 As String, ByVal mobile2 As String, ByVal id As String) As String
                data: 'userid=' + $("#ddlusera").val() + '&plateno=' + $('#ddlplate1').val() + '&hodo=' + $('#txthodo').val() + '&htime=' + $('#txthtime').val() + '&odolimit=' + $('#txtodolimit').val() + '&timelimit=' + $('#txttimelimit').val() + '&enginelimit=' + $('#txtenginelimit').val() + '&emailid1=' + $('#txtemailid1').val() + '&emailid2=' + $('#txtemailid2').val() + '&mobile1=' + $('#txtmobile1').val() + '&mobile2=' + $('#txtmobile2').val() + '&id=' + $('#sid').val() + '&remarks=' + $('#txtRemarks').val() + '',
                contentType: "application/x-www-form-urlencoded",
                dataType: "json",
                success: function (response) {
                    var json = response.d;
                    table = oTable.dataTable();
                    table._fnProcessingDisplay(true);
                    oSettings = table.fnSettings();
                    table.fnClearTable(this);
                    for (var i = 0; i < response.length; i++) {
                        table.oApi._fnAddData(oSettings, response[i]);
                    }
                    oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                    table._fnProcessingDisplay(false);
                    table.fnDraw();
                    return false;
                },
                failure: function (response) {
                    alert("Failed");
                }
            });
            $("#dialog-message").dialog("close");
            $('#ddlusername').val() == "";
            $('#groupnametextbox').val() == "";
            $('#descriptiontextbox').val() == "";
            refreshTable();
        }

           function ExcelReport() {
            refreshTable();
            var excelformobj = document.getElementById("excelform");
            excelformobj.submit();
        }

        function DeleteGroup() {

            var checked = false;
            var matches = [];
            $(".group1:checked").each(function () {
                matches.push(this.value);
            });

            $.ajax({
                type: "POST",
                url: "GetServiceData.aspx?i=2",

                data: 'ugData=' + matches + '',
               contentType: "application/x-www-form-urlencoded",
                dataType: "json",
                success: function (response) {
                    var json = response.d;
                    table = oTable.dataTable();
                    table._fnProcessingDisplay(true);
                    oSettings = table.fnSettings();
                    table.fnClearTable(this);
                    for (var i = 0; i < response.length; i++) {
                        table.oApi._fnAddData(oSettings, response[i]);
                    }
                    oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                    table._fnProcessingDisplay(false);
                    table.fnDraw();
                    return false;
                },
                failure: function (response) {
                    alert("Failed");
                }
            });

            refreshTable();
            //                checked = false;
            $(".group1:checked").each(function () {
                $(this).removeAttr('checked');
            });
        }

        function refreshTable() {
            $.ajax({
                type: "POST",
                url: "GetServiceData.aspx?i=1",
                // url: "GetServiceData.aspx",
                data: 'ugData=' + $('#ddluser').val() + '&role=' + $('#rle').val() + '&userslist=' + $('#ulist').val() + '',
                contentType: "application/x-www-form-urlencoded",
                dataType: "json",
                success: function (response) {
                    var json = response.d;
                    table = oTable.dataTable();
                    table._fnProcessingDisplay(true);
                    oSettings = table.fnSettings();
                    table.fnClearTable(this);
                    for (var i = 0; i < response.length; i++) {
                        table.oApi._fnAddData(oSettings, response[i]);
                    }
                    oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                    table._fnProcessingDisplay(false);
                    table.fnDraw();
                    return false;
                },
                failure: function (response) {
                    alert("Failed");
                }
            });
        }


        function fnFeaturesInit() {

            $('ul.limit_length>li').each(function (i) {
                if (i > 10) {
                    this.style.display = 'none';
                }
            });

            $('ul.limit_length').append('<li class="css_link">Show more<\/li>');
            $('ul.limit_length li.css_link').click(function () {
                $('ul.limit_length li').each(function (i) {
                    if (i > 5) {
                        this.style.display = 'list-item';
                    }
                });
                $('ul.limit_length li.css_link').css('display', 'none');
            });
        }
        $(document).ready(function () {
            $("#dialog:ui-dialog").dialog("destroy");
            $("#dialog-message").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 390,
                buttons: {
                    "Update": function () {
                        var emailRegEx = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z0-9]{2,4})+$/;
                        if ($('#ddlusera').val() == "0") {
                            alertbox("Please select user name");
                            return false;
                        }

                        if ($('#ddlplate1').val() == "0") {
                            alertbox("Please select a plate number");
                            return false;
                        }
                        if ($('#txthtime').val() == "") {
                            alertbox("Please select service completed date.");
                            return false;
                        }

                      if ($('#txtodolimit').val() == "" && $('#txttimelimit').val() == "" && $('#txtenginelimit').val() == "") {
                          alertbox("Please provide Maintenance odometer/Time/Engine any one of them..");
                            return false;
                        }

                         if ($('#txtodolimit').val() != "" && isNaN($('#txtodolimit').val())) {
                             alertbox("Please enter valid odometer limit");
                            return false;
                        }
                        if ($('#txtenginelimit').val() != "" && isNaN($('#txtenginelimit').val())) {
                            alertbox("Please enter valid engine limit.");
                            return false;
                        }
                        if ($('#txtemailid1').val() == "") {
                            alertbox("Please enter emailid.");
                            return false;
                        }

                        if (!emailRegEx.test(document.getElementById("txtemailid1").value)) {
                            alertbox("Please  enter valid emailid.1");
                            return false;
                        }

                        if ($('#txtemailid2').val() != "") {
                            var arr;
                            var emls = document.getElementById("txtemailid2").value;
                            if (emls.indexOf(",") > 0) {
                                var mar = new Array();
                                mar=emls.split(",");
                                arr = new Array();
                                for (var i = 0; i < mar.length; i++) {
                                    arr.push($.trim(mar[i]));
                                }
                            }
                            else if (emls.indexOf(";") > 0) {
                                arr = new Array();
                                var mar = new Array();
                                mar = emls.split(";");
                                for (var i = 0; i < mar.length; i++) {
                                    arr.push($.trim(mar[i]));
                                }
                            }
                            else {
                                arr = new Array();
                                arr.push(emls);
                            }
                            for (var i = 0; i < arr.length; i++) {
                                if (!emailRegEx.test(arr[i])) {
                                    alertbox("Please valid enter EMail Id (CC).");
                                    return false;
                                }
                            }

                        }

                        UpdateData();
                    },
                    "Close": function () {
                        $(this).dialog("close");
                    }
                }
            });

            $("#dialog-form").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 390,
                buttons: {
                    "Add": function () {
                        AddData();
                    },
                    "Close": function () {
                        $(this).dialog("close");
                    }
                }
            });
            $("#dialog-msg").dialog({
                autoOpen: false,
                resizable: false,
                height: 140,
                modal: true,
                buttons: {
                    "Ok": function () {
                        $(this).dialog("close");
                    }

                }
            });
            $("#div1").dialog(
        {
            title: "Confirmation",
            modal: true,
            resizable: false,
            width: 320,
            autoOpen: false,
            buttons: {
                "Yes": function () {
                    // This will invoke the form's action - putatively deleting the resources on the server
                    //                    $(form).submit();
                    DeleteGroup();
                    $(this).dialog("close");
                },
                "No": function () {
                    // Don't invoke the action, just close the dialog
                    $(this).dialog("close");
                }
            }
        });

            fnFeaturesInit();
            oTable = $('#examples').dataTable({
                "bJQueryUI": true,
                "sPaginationType": "full_numbers",
                "iDisplayLength": 100,
                "aLengthMenu": [10, 25, 50, 100, 200, 500],
                "bLengthChange": false,
                "fnDrawCallback": function (oSettings) {
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(1)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },
                 "oLanguage": {
                    "oPaginate": {

                        "sNext": "Next",
                        "sFirst": "First",
                        "sLast": "Last",
                        "sPrevious": "Previous"
                    },

                     "sSearch": "Search",
                     "sEmptyTable": "No data available in table",
                     "sInfo": "Got a total of _TOTAL_ entries to show (_START_ to _END_)",
                     "sInfoEmpty": "No entries to show",
                     "sInfoFiltered": "#NAME?",
                     "sZeroRecords": "No records to display",
                     "sInfoEmpty": "No entries to show",
                     "sLoadingRecords": "Please wait - loading...",
                     "sProcessing": "DataTables is currently busy",
                },
                "sDom": '<"H"Cl<"MyButton">f>rt<"F"iTp>',
                "aoColumnDefs": [
                          { "bVisible": true, "bSortable": false, "aTargets": [1] },
                            { "bVisible": true, "bSortable": false, "aTargets": [0] }
                             ]


            });
            $("div.MyButton").html('<div><table><tr><td>Username </td><td><%=opt %></td></tr> </table></div>');
            jQuery(".chosen").data("placeholder", "Select Frameworks...").chosen();
            refreshTable();
        });

        function alertbox(message) {
            if (message == "") {
                document.getElementById("displayp").innerHTML = message;

            }
            else {
                document.getElementById("displayp").innerHTML = message;
                $("#dialog-msg").dialog("open");
            }
        }
        function confirm(message) {

            document.getElementById("P1").innerHTML = message;
            $("#div1").dialog("open");

        }

        function openPopup(userid, plateno, lastservicingdate, lastservicingodometer, servicingodometerlimit, servicingtimelimit,servicingenginelimit, emailid1,emailid2,mobile1,mobile2, id,remarks) {

            document.getElementById("plateno").value = plateno;
            LoadGrouplist2(userid, ddlusera)
            $('#ddlusera').val(userid);
            $('#ddlplate1').val(plateno);

            if (lastservicingdate.indexOf("-") > 0) {
                lastservicingdate = lastservicingdate.replace("-", "/");
                lastservicingdate = lastservicingdate.replace("-", "/");
            }
            if (servicingtimelimit.indexOf("-") > 0) {
                servicingtimelimit = servicingtimelimit.replace("-", "/");
                servicingtimelimit = servicingtimelimit.replace("-", "/");
            }

            $('#txthtime').val(lastservicingdate);
            $('#txthodo').val(lastservicingodometer);

            $('#txtodolimit').val(servicingodometerlimit);
            $('#txttimelimit').val(servicingtimelimit);
            $('#txtenginelimit').val(servicingenginelimit);
            $('#txtemailid1').val(emailid1);
            $('#txtemailid2').val(emailid2);
            $('#txtRemarks').val(remarks);
            document.getElementById("sid").value = id;
            $("#dialog-message").dialog("open");


        }

        function LoadGrouplist(userid, ddlgroup) {
            $("#ddlplate").attr("disabled", "disabled");
            var user = document.getElementById(userid).value;
            if (user == "--Select User Name--") {
                ddlgroup.empty().append('<option selected="selected"  value="0">PLEASE SELECT USERNAME></option>');

            }
            else {
                $('#ddlplate').empty().append('<option selected="selected" value="0">PLEASE SELECT USERNAME...</option>');

                $.ajax({
                    type: "POST",
                    url: "GetServiceData.aspx?i=4",
                  data: 'userId=' + user + '',
                     contentType: "application/x-www-form-urlencoded",
                    dataType: "json",
                    success: OnLoadVehicles,
                    failure: function (response) {
                        alert(response.d);
                    }
                });
            }
        }
        function OnLoadVehicles(response) {
            PopulateControl(response, $("#ddlplate"));
        }
        function PopulateControl(list, control) {
            if (list.length > 0) {
                control.removeAttr("disabled");
                control.empty().append('<option selected="selected" value="0">Please select vehicle</option>');
                for (var i = 0; i < list.length; i++) {
                 control.append($("<option></option>").val(list[i][0]).html(list[i][0]));
                }
            }
            else {
                control.empty().append('<option selected="selected" value="0">No vehicles<option>');
            }

        }
        function LoadGrouplist1(userid, ddlgroup, plateno) {
            $("#ddlplate1").attr("disabled", "disabled");
            var user = document.getElementById(userid).value;
            if (user == "--Select User Name--") {
                ddlgroup.empty().append('<option selected="selected"  value="0">PLEASE SELECT USERNAME</option>');
            }
            else {
                $('#ddlplate1').empty().append('<option selected="selected" value="0">Loading...</option>');

                $.ajax({
                    type: "POST",
                    url: "GetServiceData.aspx?i=5",
                    data: 'userId=' + user + '',
                     contentType: "application/x-www-form-urlencoded",
                    dataType: "json",
                    success: OnLoadVehicles2,
                    failure: function (response) {
                        alert(response.d);
                    }
                });
            }
        }
        function OnLoadVehicles2(response) {
            PopulateControl2(response, $("#ddlplate1"));
        }
        function PopulateControl2(list, control) {
            if (list.length > 0) {
                control.removeAttr("disabled");
                control.empty().append('<option selected="selected" value="0">Please select vehicle</option>');
                 for (var i = 0; i < list.length; i++) {
                 control.append($("<option></option>").val(list[i][0]).html(list[i][0]));
                }
                
            }
            else {
                control.empty().append('<option selected="selected" value="0">No vehicles<option>');
            }
            control.style.disabled = "true";
        }
        function LoadGrouplist2(userid, ddlgroup) {
            $("#ddlplate1").attr("disabled", "disabled");
            var user = userid;
            if (user == "--Select User Name--") {
                ddlgroup.empty().append('<option selected="selected"  value="0">PLEASE SELECT USERNAME</option>');

            }
            else {
                $('#ddlplate1').empty();

                $.ajax({
                    type: "POST",
                    url: "GetServiceData.aspx?i=6",
                     data: 'userId=' + user + '',
                     contentType: "application/x-www-form-urlencoded",
                    dataType: "json",
                    success: OnLoadVehiclesp,
                    failure: function (response) {
                        alert(response.d);
                    }
                });
            }
        }
        function OnLoadVehiclesp(response) {
            PopulateControlp(response, $("#ddlplate1"));
        }
        function PopulateControlp(list, control) {
            if (list.length > 0) {
                control.removeAttr("disabled");
                control.empty();

                for (var i = 0; i < list.length; i++) {
                   if (document.getElementById("plateno").value == list[i][0]) {
                        control.append('<option selected="selected" value="' + document.getElementById("plateno").value + '"> ' + document.getElementById("plateno").value + '</option>');
                    }
                    else {
                        control.append($("<option></option>").val(list[i][0]).html(list[i][0]));
                    }
                }
            }
            else {
                control.empty().append('<option selected="selected" value="0">No vehicles<option>');
            }
            control[0].disabled = "true";
            document.getElementById("dialog-message").click();
        }
    </script>
    <script type="text/javascript" src="js/chosen.jquery.js"></script>
    <script type="text/javascript" language="javascript">
        $(function () {
            $("#txthtime").datepicker({ dateFormat: 'yy/mm/dd', changeMonth: true, changeYear: true, numberOfMonths: 2, minDate: new Date(2014, 1, 1)
            });

            $("#txttimelimit").datepicker({ dateFormat: 'yy/mm/dd', changeMonth: true, changeYear: true, numberOfMonths: 2, minDate: 0
            });

        });
    </script>
</head>
<body style="margin-left: 5px; margin-top: 0px; margin-bottom: 11px; margin-right: 5px;
    font-size: 11px; font-family: Verdana;">
    <form id="vehicleform" runat="server" enableviewstate="false">
    <center>
        <br />
        <b style="font-family: Verdana; font-size: 20px; color: #38678B;">Servicing Management</b>
        <br />
        <br />
        <table style="font-family: Verdana; font-size: 11px; width: 1000px">
            <tr>
                <td align="left">
                <a href="javascript:deleteconfirmation();" class="button" style="vertical-align:top; width:55px;"><span class="ui-button-text"
                                                        title="Delete Checked Services">Delete</a>
                   
                </td>
                <td align="center">
                </td>
                <td align="right" valign="middle">
                  <a href="#" onclick="javascript:ExcelReport()" class="button" title="Download All Settings"
                            style="width: 59px; margin-right: 0px;"><span class="ui-button-text">Download </span>
                        </a>
                </td>
            </tr>
            <tr>
                <td colspan="3">
                    <div id="fw_container" align="left" style="width: 1200px;">
                        <table cellpadding="0" cellspacing="0" border="0" class="display" id="examples">
                            <thead>
                                <tr style="text-align: left">
                                    <th style="width: 15px;">
                                        <input type="checkbox" name="chk" class="group1" onclick="javascript:checkall(this);" />
                                    </th>
                                    <th style="width: 60px;">
                                        No
                                    </th>
                                    <th>
                                        Plate No
                                    </th>
                                    <th>
                                        Service Completed Date
                                    </th>
                                    <th>
                                        Service Completed Odometer
                                    </th>
                                    <th>
                                        Maintenance Odometer Limit
                                    </th>
                                    <th>
                                        Time Limit
                                    </th>
                                    <th>
                                        Engine Limit
                                    </th>
                                    <th>
                                        Email Id
                                    </th>
                                    <th>
                                        Email Id (CC)
                                    </th>
                                    <th>
                                        Remarks
                                    </th>
                                </tr>
                            </thead>
                            <tbody>
                            </tbody>
                            <tfoot>
                                <tr style="text-align: left">
                                    <th style="width: 15px;">
                                        <input type="checkbox" name="chk" class="group1" onclick="javascript:checkall(this);" />
                                    </th>
                                    <th style="width: 60px;">
                                        No
                                    </th>
                                    <th>
                                        Plate No
                                    </th>
                                    <th>
                                        Service Completed Date
                                    </th>
                                    <th>
                                        Service Completed Odometer
                                    </th>
                                    <th>
                                        Maintenance Odometer Limit
                                    </th>
                                    <th>
                                        Time Limit
                                    </th>
                                    <th>
                                        Engine Limit
                                    </th>
                                    <th>
                                        Email Id
                                    </th>
                                    <th>
                                        Email Id (CC)
                                    </th>
                                    <th>
                                        Remarks
                                    </th>
                                </tr>
                            </tfoot>
                        </table>
                    </div>
                </td>
            </tr>
            <tr>
                <td align="left">
                     <a href="javascript:deleteconfirmation();" class="button" style="vertical-align:top; width:55px;"><span class="ui-button-text"
                                                        title="Delete Checked Services">Delete</a>
                </td>
                <td align="center">
                </td>
                <td align="right" valign="middle">
                </td>
            </tr>
            <tr>
                <td colspan="3" style="color: Blue; text-align: center; font-family: Verdana; font-size: 12px;
                    font-weight: Bolder;">
                    Details and Email Conditions for Servicing Alert
                </td>
            </tr>
            <tr>
                <td style="text-align: left;">
                    <span style="color: navy; font-family: Verdana; font-size: 11px; font-weight: normal;">
                        <b>Handover DateTime</b>
                        <br />
                        Last Servicing Date<br />
                        <br />
                        <b>Maintenance Odometer Limit (KM)</b>
                        <br />
                        Total Milage for Next Servicing<br />
                        <br />
                        <b>Time Limit</b>
                        <br />
                        Next Servicing Date of the Vehicle<br />
                        <br />
                        <b>Engine Limit (Hrs)</b>
                        <br />
                        Total Engine ON time for Next Servicing (in Hours)<br />
                        <br />
                        <b>Email Id</b>
                        <br />
                        Mail Receiver Email Id (Mendatory)<br />
                        <br />
                        <b>Email CC</b>
                        <br />
                        Carbon Copy Email Id (Optional)<br />
                        <br />
                        <b>Remarks</b>
                        <br />
                        Your Comments or Statements (Optional)
                        <br />
                        <br />
                    </span>
                </td>
                <td align="center">
                </td>
                <td style="text-align: left;" valign="middle">
                    <span style="color: Red; font-family: Verdana; font-size: 11px; font-weight: normal;">
                        <b>Email will be send by the below conditions :</b>
                        <br />
                        1. Vehicle Travelled the Milage given in "Maintenance Odometer Limit Field"
                        <br />
                        OR
                        <br />
                        2. Vehicle Engine ON time in Hrs reached the assigned value in "Engine Limit Field"
                        <br />
                        OR
                        <br />
                        3. Date Reached given in "Time Limit Field" </span>
                    <br />
                    <br />
                   
                </td>
            </tr>
        </table>
        <div id="dialog-message" title="Update Service>" style="padding-top: 1px; padding-right: 0px;
            padding-bottom: 0px; font-size: 10px; padding-left: 0px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;
            height: 244px; margin-bottom: 0px;">
            <table border="0" cellpadding="1" cellspacing="1" style="width: 367px; font-size: 11px;
                font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;
                height: 280px;">
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Username</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:DropDownList runat="server" ID="ddlusera" Width="238px" Height="21px" EnableViewState="False"
                            disabled="true" onchange="LoadGrouplist1(this.id,$('#ddlusera'));">
                        </asp:DropDownList>
                    </td>
                </tr>
                <tr>
                    <br />
                    <td align="left">
                        <b style="color: #4E6CA3;">Plate No</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:DropDownList runat="server" ID="ddlplate1" Width="238px" Height="21px" EnableViewState="False"
                            disabled="true">
                        </asp:DropDownList>
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Handover DateTime</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txthtime" Width="234px" ReadOnly="true" />
                    </td>
                </tr>
                <tr style="display: none;">
                    <td align="left">
                        <b style="color: #4E6CA3;">Service Completed Odometer</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txthodo" Width="234px" Text="0" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Maintenance Odometer Limit (KM)</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtodolimit" Width="234px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Time Limit</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txttimelimit" Width="234px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Engine Limit (Hrs)</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtenginelimit" Width="234px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Email Id</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtemailid1" Width="234px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Email Id (CC)</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtemailid2" Width="234px" />
                    </td>
                </tr>
                <tr style="display: none;">
                    <td align="left">
                        <b style="color: #4E6CA3;">Mobile</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtmobile1" Width="234px" />
                    </td>
                </tr>
                <tr style="display: none;">
                    <td align="left">
                        <b style="color: #4E6CA3;">Mobile2</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtmobile2" Width="234px" />
                    </td>
                </tr>
                <tr>
                    <td align="left">
                        <b style="color: #4E6CA3;">Remarks</b>
                    </td>
                    <td style="color: #4E6CA3;">
                        :
                    </td>
                    <td>
                        <asp:TextBox runat="server" ID="txtRemarks" Width="234px" TextMode="MultiLine" />
                    </td>
                </tr>
            </table>
        </div>
        <input type="hidden" value="" runat="server" id="plateno" />
        <input type="hidden" runat="server" value="" id="sid" />
        <input type="hidden" value="" id="ss" runat="server" />
        <input type="hidden" name="uid" value="" runat="server" id="uid" />
        <input type="hidden" name="rle" value="" runat="server" id="rle" />
        <input type="hidden" name="ulist" value="" runat="server" id="ulist" />
        <input type="hidden" id="gid" value="" runat="server" />
    </center>
    </form>
     <form id="excelform" method="get" action="ExcelReport.aspx">
    <input type="hidden" id="title" name="title" value="Servicing Alerts Settings" />
    <input type="hidden" id="Hidden1" name="plateno" value="" />
    </form>
    <div id="div1" title="Confirmation">
        <p id="P1">
            <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;">
            </span>
        </p>
    </div>
    <div id="dialog-msg" title="Alert">
        <p id="displayp">
            <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;">
            </span>
        </p>
    </div>
    <iframe id="idlingpage" name="idlingpage" src="" frameborder="0" scrolling="no" height="120px"
        width="300px" style="visibility: hidden;" onclick="return idlingpage_onclick()"
        onclick="return idlingpage_onclick()" />
</body>
</html>
