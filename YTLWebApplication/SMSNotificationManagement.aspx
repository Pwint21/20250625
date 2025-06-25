<%@ Page Language="VB" AutoEventWireup="false"
    Inherits="YTLWebApplication.SMSNotificationManagement" Codebehind="SMSNotificationManagement.aspx.vb" %>

<!DOCTYPE html>
<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>SMS Notification Management</title>
    <style type="text/css" media="screen">
        @import "css/demo_table_jui.css";
        @import "css/jquery-ui.css";
        @import "css/TableTools.css";
        @import "css/ColVis.css";
        @import "css/common1.css";
    </style>
    <script type="text/javascript" language="javascript" src="js/jquery.js"></script>
    <script type="text/javascript" src="js/jquery_ui.js"></script>
    <script type="text/javascript" language="javascript" src="js/jquery.dataTables.js"></script>
    
    <style type="text/css">
        .dataTables_info
        {
            width: 32%;
            float: left;
        }
        
        
        .ui-widget-header
        {
            border: 0px solid #4297d7;
        }
        
        
        table.display thead th div.DataTables_sort_wrapper
        {
            position: relative;
            padding-right: 6px;
        }
        
        table.display tfoot th
        {
            padding: 0px 0px 0px 0px;
            padding-left: 3px;
        }
        
        table.display thead th
        {
            padding: 0px 0px 0px 0px;
            padding-left: 3px;
            height: 31px;
        }
        
        table.display td
        {
            padding: 2px 2px;
        }
        
        .dataTables_filter
        {
            width: 240px;
            margin-top: 7px;
        }
        
        .MyButton
        {
            text-align: left;
            float: left;
            width: 350px;
        }
        
        
        .chzn-container .chzn-results
        {
            color: #4E6CA3;
        }
        
        .chzn-container .chzn-results
        {
            max-height: 300px;
        }
        
        .textbox1
        {
            height: 18px;
            width: 180px;
            border-right: #cbd6e4 1px solid;
            border-top: #cbd6e4 1px solid;
            border-left: #cbd6e4 1px solid;
            color: #0b3d62;
            border-bottom: #cbd6e4 1px solid;
        }
        
        .button
        {
            text-decoration: none;
            text-shadow: 0 1px 0 #fff;
            text-align: center;
            font: bold 11px Helvetica, Arial, sans-serif;
            color: #444;
            height: 24px;
            display: inline-block;
            width: 60px;
            margin: 5px;
            padding: 0px 3px 2px 2px;
            background: #F3F3F3;
            border: solid 1px #D9D9D9;
            border-radius: 2px;
            -webkit-border-radius: 2px;
            -moz-border-radius: 2px;
            -webkit-transition: border-color .20s;
            -moz-transition: border-color .20s;
            -o-transition: border-color .20s;
            transition: border-color .20s;
        }
        
        button
        {
            cursor: pointer;
        }
        
        a.button:active
        {
            border-color: #4B8DF8;
        }
        
        a.button:hover
        {
            color: White;
            text-shadow: 0 1px 0 #fff;
            border: 1px solid #2F5BB7 !important;
            background: #3F83F1;
            background: -webkit-linear-gradient(top, #4D90FE, #357AE8);
            background: -moz-linear-gradient(top, #4D90FE, #357AE8);
            background: -ms-linear-gradient(top, #4D90FE, #357AE8);
            background: -o-linear-gradient(top, #4D90FE, #357AE8);
        }
        
        a.button
        {
            text-align: center;
            font: bold 11px Helvetica, Arial, sans-serif;
            cursor: pointer;
            text-shadow: 0 1px 0 #fff;
            display: inline-block;
            width: 74px;
            border: 1px solid #3079ED !important;
            color: White;
            height: 14px;
            background: #4B8DF8;
            background: -webkit-linear-gradient(top, #4C8FFD, #4787ED);
            background: -moz-linear-gradient(top, #4C8FFD, #4787ED);
            background: -ms-linear-gradient(top, #4C8FFD, #4787ED);
            background: #4B8DF8;
            -webkit-transition: border .20s;
            -moz-transition: border .20s;
            -o-transition: border .20s;
            transition: border .20s;
            margin: 5px;
            padding: 3px 5px 5px 3px;
        }
        
        button, .button
        {
            width: inherit;
            height: inherit;
        }
        
        .ui-widget .ui-widget
        {
            font-size: 12px;
        }
        
        .ui-button-text-only .ui-button-text
        {
            padding: .4em;
        }
        .ui-widget
        {
            font-family: Lucida Grande, Lucida Sans, Arial, sans-serif;
            font-size: 12px;
        }
    </style>
    
    
    <script type="text/javascript" >
        var Excheck = false;
        var oTable;
        var chekitems = new Array();
        var confirmresult = false;
        var checkids = "";

        $(document).ready(function () {
        
            $("#dialog-message").hide();
            $("#div1").hide();
            $("#dialog-msg").hide();
            
            $("#dialog:ui-dialog").dialog("destroy");
            $("#dialog-message").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 650,
                minHeight: 280,
                height: 280

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
            $("#div1").dialog({
                resizable: false,
                draggable: false,
                height: 160,
                modal: true,
                autoOpen: false,
                buttons: {
                    "Yes": function () {
                        confirmresult = true;
                        DeleteSatus();
                        $(this).dialog("close");
                    },
                    "No": function () {
                        confirmresult = false;
                        $(this).dialog("close");

                    }
                }
            });

            $('#txtmobile1').on('input', function (event) {
                this.value = this.value.replace(/[^0-9 +]/g, '');
            });
            $('#txtmobile2').on('input', function (event) {
                this.value = this.value.replace(/[^0-9 +]/g, '');
            });
            $('#txtmobile3').on('input', function (event) {
                this.value = this.value.replace(/[^0-9 +]/g, '');
            });
            $('#txtmobile4').on('input', function (event) {
                this.value = this.value.replace(/[^0-9 +]/g, '');
            });
            $('#txtmobile5').on('input', function (event) {
                this.value = this.value.replace(/[^0-9 +]/g, '');
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

                "sDom": '<"H"Cl<"MyButton">f>rt<"F"iTp>',
                "aoColumnDefs": [

                          {
                              "sClass": "center", "sWidth": "10px", "aTargets": [0], "bSortable": false, "bVisible": true,
                              "fnRender": function (oData, sVal) {
                                  if (sVal != "--") {
                                      return "<input type='checkbox' onclick='check(this)' value='" + sVal + "' class=\"group1\"  />";
                                  }
                                  else {
                                      return "--";
                                  }

                              }

                          },

                              {
                                  "sClass": "left", "aTargets": [1], "bSortable": false, "sWidth": "15px"


                              },
                            { "bVisible": true, "bSortable": true, "sWidth": "100px", "aTargets": [2], "fnRender": function (oData, sVal) {

                                return " <span style='cursor:pointer;text-decoration:underline;'  onclick='javascript: openUpdatePopup(\"" + escape(oData.aData[2]) + "\",\"" + oData.aData[3] + "\",\"" + oData.aData[4] + "\",\"" + oData.aData[6] + "\")'>" + oData.aData[2] + "</span>";
                            }
                            },
                            { "bVisible": true, "bSortable": true, "aTargets": [3] },
                            { "bVisible": true, "sWidth": "400px", "bSortable": true, "aTargets": [4] },
                            { "bVisible": true, "sWidth": "70px", "bSortable": true, "aTargets": [5] }


                ]
            });
            $("div.MyButton").html('<div></div>');

            refreshTable();

        });

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

        function refreshTable() {

            $.getJSON('GetSMSNotificationData.aspx?opr=0&r=' + Math.random(), null, function (json) {
                table = oTable.dataTable();
                table._fnProcessingDisplay(true);
                oSettings = table.fnSettings();
                table.fnClearTable(this);
                if (json.length > 0) {
                    Excheck = true;
                }
                else {
                      Excheck = false;
                }
                for (var i = 0; i < json.length; i++) {
                    table.oApi._fnAddData(oSettings, json[i]);
                }
                oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                table._fnProcessingDisplay(false);
                table.fnDraw();
                return false;
            });

        }
       

        function alertbox(message) {
            if (message == "") {
                document.getElementById("displayp").innerHTML = message;

            }
            else {
                document.getElementById("displayp").innerHTML = message;
                $("#dialog-msg").dialog("open");
            }
        }

        function Confirmdeletepop(message) {
            if (message != "") {
                document.getElementById("p1").innerHTML = message;
                $("#div1").dialog("open");
            }
        }

        function openAddPopup() {
            Loadunitlist('single');
         var extracond = "&opr=1";
            $("#Tr1").hide();
            $("#txttr").show();
            Clearfields();
            $("#dialog-message").dialog({
                title: "Add Notification",
                width: 650,
                buttons: {
                    "Add": function () {
                        UpdateData("0", "0");
                    },
                    "Close": function () {
                        $(this).dialog("close");
                    }
                }
            });
            $("#table1").css("width", "600px");
            $("#dialog-message").dialog("open");
        }
        function Loadunitlist() {
            $('#single').empty().append('<option selected="selected" value="0">Loading...</option>');
            $.getJSON('GetSMSNotificationData.aspx?opr=4&r=' + Math.random(), null, function (json) {
                 OnLoadunits(json);
            });
//            $.ajax({
//                type: "POST",
//                url: "VehicleManagement.aspx/LoadUnitlist",
//                data: '{userId: \"' + " " + '\"}',
//                contentType: "application/json; charset=utf-8",
//                dataType: "json",
//                success: OnLoadunits,
//                failure: function (response) {
//                    alert(response.d);
//                }
//            });
        }
        $("#single").attr("disabled", "disabled");

        function OnLoadunits(response) {
            PopulateUnitControl(response, $("#single"));
        }
        function PopulateUnitControl(list, control) {
            if (list.length > 0) {
                control.removeAttr("disabled");
                control.empty().append('<option selected="selected" value="0">SELECT SHIP TO CODE</option>');
                for (var i = 0; i < list.length; i++) {
                    control.append($("<option></option>").val(list[i][1]).html(list[i][0]));
                   // table.oApi._fnAddData(oSettings, json.aaData[i]);
                }

//                $.each(list, function () {
//                    control.append($("<option></option>").val(this['Value']).html(this['Text']));
//                });
            }
            else {
                control.empty().append('<option selected="selected" value="">No Units<option>');
            }
        }
        function Clearfields() {
            $("#single").val(0);
            $("#chkOTP").prop('checked', false);
            var placeholder = "SELECT SHIP TO CODE";

            $(".select2-single, .select2-multiple").select2({
                placeholder: placeholder,
                width: null,
                containerCssClass: ':all:'
            });

            $(".select2-allow-clear").select2({
                allowClear: true,
                placeholder: placeholder,
                width: null,
                containerCssClass: ':all:'
            });
            $("#txtmobile1").val("");
            $("#txtmobile2").val("");
            $("#txtmobile3").val("");
            $("#txtmobile4").val("");
            $("#txtmobile5").val("");
        }
        function UpdateData(op, sid) {
            var res = Validate();
            var ischecked= "0";
            if ($('#chkOTP').prop('checked')) {
                ischecked = "1";
            }
            var listcond = "&chkotp=" + ischecked +"&mobile1=" + encodeURIComponent($("#txtmobile1").val()) + "&mobile2=" + encodeURIComponent($("#txtmobile2").val()) + "&mobile3=" + encodeURIComponent($("#txtmobile3").val()) + "&mobile4=" + encodeURIComponent($("#txtmobile4").val()) + "&mobile5=" + encodeURIComponent($("#txtmobile5").val());
            var extracond = "&opr=1";
            var geoid = $("#ddlGeofence").val();
            if (res == true) {
                $.get('GetSMSNotificationData.aspx?scode=' + $('#single').val() + extracond + listcond + '&r=' + Math.random(), null, function (json) {
                    if (json == 1) {
                        alertbox("Notification added successfully..");
                        refreshTable();
                    }
                    else {
                        alertbox("Notification not added successfully...");
                    }
                });
                $("#dialog-message").dialog("close");
            }
        }
        function UpdateData1(op, sid) {
            // var res = Validate();
            var ischecked = "0";
            if ($('#chkOTP').prop('checked')) {
                ischecked = "1";
            }
            var listcond = "&chkotp=" + ischecked +"&mobile1=" + encodeURIComponent($("#txtmobile1").val()) + "&mobile2=" + encodeURIComponent($("#txtmobile2").val()) + "&mobile3=" + encodeURIComponent($("#txtmobile3").val()) + "&mobile4=" + encodeURIComponent($("#txtmobile4").val()) + "&mobile5=" + encodeURIComponent($("#txtmobile5").val());
            var extracond = "&opr=2";
            var geoid = $("#ddlGeofence").val();
            // if (res == true) {
            $.get('GetSMSNotificationData.aspx?scode=' + $('#txtscode').text() + extracond + listcond + '&r=' + Math.random(), null, function (json) {
                if (json == 1) {
                    alertbox("Notification updated successfully..");
                    refreshTable();
                }
                else {
                    alertbox("Notification not updated successfully...");
                }
            });
            $("#dialog-message").dialog("close");
            // }
        }


        function Validate() {
            if ($('#single').val() == 0) {
                alertbox("Please Select Ship To Code");
                return false;
            }

            return true;
        }

        function openUpdatePopup(scode, name, mobilelist,otpFlag) {
            Clearfields();
            $("#Tr1").show();
            $("#txttr").hide();
            $('#txtscode').text(scode);
            var str = [];
            if (otpFlag == "0") {
                $("#chkOTP").prop('checked', false);
            }
            else {
                $("#chkOTP").prop('checked', true);
            }
            str = mobilelist.split(",");
            for (i = 0; i < str.length; i++) {
                $('#txtmobile' + (i + 1)).val(str[i]);
            }
            $("#dialog-message").dialog({
                title: "Update Notification",
                width: 350,
                buttons: {
                    "Update": function () {
                        UpdateData1("1", scode);
                    },
                    "Close": function () {
                        $(this).dialog("close");

                    }
                }
            });

            $("#table1").css("width", "320px");
            $("#dialog-message").dialog("open");

        }

        function checkall(chkobj) {
            var chkvalue = chkobj.checked;
            for (i = 0; i < document.forms[0].elements.length; i++) {
                elm = document.forms[0].elements[i]
                if (elm.type == 'checkbox') {
                    document.forms[0].elements[i].checked = chkvalue;
                }
            }
            var checked = false;

            $(".group1:checked").each(function () {
                chekitems.push(this.value);
            });
        }
        function check(chkobj) {
            var chkvalue = chkobj.checked;
            if (chkvalue == false) {
                chekitems.splice($.inArray($(chkobj).val(), chekitems), 1);
            }
            else {
                chekitems.push($(chkobj).val());
            }
        }
        function Conformdelete() {
            if (chekitems.length > 0) {
                Confirmdeletepop("Do you really want to delete the selected Notification(s) ?");
            }
            else {
                alertbox("Please Select Atleast One Notification To Delete");
            }

        }
        function DeleteSatus() {


            
            $.getJSON('GetSMSNotificationData.aspx?geoid=' + JSON.stringify(chekitems) + '&opr=3&r=' + Math.random(), null, function (json) {
                if (json == "1") {
                    refreshTable();
                    checkall(false);
                }
                else {
                    refreshTable();
                }

            });

        }

        function ExcelReport()
        {
            if(Excheck ==true)
            {
                //var plateno=document.getElementById("ddlplate").value;
               
                //document.getElementById("plateno").value=plateno;
            
                var excelformobj=document.getElementById("excelform");
                excelformobj.submit();
            }
            else
            {
                alert("First click submit button");
            }
        }
    </script>
    <link href="css/select2.min.css" rel="stylesheet" type="text/css" />
   
    <link rel="stylesheet" href="css/select2-bootstrap.css"/>
    <script src="js/select2.full.js" type="text/javascript"></script>
   
    <script src="js/anchor.min.js"></script>
    <script type="text/javascript">
        $(function () {
            anchors.options.placement = 'left';
            anchors.add('.container h1, .container h2, .container h3, .container h4, .container h5');


            $.fn.select2.defaults.set("theme", "bootstrap");

            var placeholder = "SELECT SHIP TO CODE";

            $(".select2-single, .select2-multiple").select2({
                placeholder: placeholder,
                width: null,
                containerCssClass: ':all:'
            });

            $(".select2-allow-clear").select2({
                allowClear: true,
                placeholder: placeholder,
                width: null,
                containerCssClass: ':all:'
            });

        });
		   

    </script>
</head>
<body style="font-size: 11px; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
    <form id="form1" runat="server">
    <center>
        <br />
        <br />
        <div class="c1">
            &nbsp;SMS Notification Management
        </div>
        <br />
        <table style="font-family: Verdana; font-size: 11px; width: 800px">
            <tr>
                <td align="left">
                    <a class="button" title="Delete " style="width: 59px;"><span class="ui-button-text"
                        onclick="Conformdelete()">Delete </span></a>
                </td>
                <td align="center">
                </td>
               
                <td align="right" valign="middle" style="margin-right: 0px;">
                      <a class="button" title="Add" style="width: 100px;" href="javascript:ExcelReport();"><span
                        class="ui-button-text">Download Excel</span></a>
                    <a class="button" title="Add" style="width: 79px;" onclick="openAddPopup()"><span
                        class="ui-button-text">Add </span></a>
                </td>
            </tr>
            <tr>
                <td colspan="3" style="width: 1100px;">
                    <div id="fw_container">
                        <table style="font-family: Verdana; font-size: 11px;">
                            <tr>
                                <td colspan="3" align="center">
                                    <table cellpadding="0" cellspacing="0" border="0" class="display" id="examples" style="font-family: Verdana;
                                        font-size: 11px; width: 1100px">
                                        <thead align="left">
                                            <tr>
                                                <th align="center" style="width: 20px;">
                                                    <input type="checkbox" id="chkh" onclick=" checkall(this)" />
                                                </th>
                                                <th style="width: 50px;">
                                                    No
                                                </th>
                                                <th>
                                                    Ship To Code
                                                </th>
                                                <th>
                                                    Name
                                                </th>
                                                <th>
                                                    Mobiles List
                                                </th>
                                                <th>
                                                    OTP
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                        </tbody>
                                        <tfoot align="left">
                                            <tr>
                                                <th align="center" style="width: 20px;">
                                                    <input type="checkbox" id="Checkbox1" onclick=" checkall(this)" />
                                                </th>
                                                <th style="width: 50px;">
                                                    No
                                                </th>
                                                <th>
                                                    Ship To Code
                                                </th>
                                                <th>
                                                    Name
                                                </th>
                                                <th>
                                                    Mobiles List
                                                </th>
                                                 <th>
                                                    OTP
                                                </th>
                                            </tr>
                                        </tfoot>
                                    </table>
                                </td>
                            </tr>
                        </table>
                    </div>
                </td>
            </tr>
            <tr>
                <td align="left">
                    <a class="button" title="Delete " style="width: 59px;"><span class="ui-button-text"
                        onclick="Conformdelete()">Delete </span></a>
                </td>
                <td align="center">
                </td>
               
                <td align="right" valign="middle" style="margin-right: 0px;">
                      <a class="button" title="Add" style="width: 100px;" href="javascript:ExcelReport();"><span
                        class="ui-button-text">Download Excel</span></a>
                    <a class="button" title="Add" style="width: 79px;" onclick="openAddPopup()"><span
                        class="ui-button-text">Add </span></a>
                   
                </td>
            </tr>
        </table>
    </center>
    <div id="div1" title="Confirmation">
        <p id="p1">
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
    <div id="dialog-message" title="Add " align="center" style="padding-top: 1px; padding-right: 0px;
        padding-bottom: 0px; font-size: 11px; padding-left: 5px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
        <table id="table1" border="0" cellpadding="1" cellspacing="1" style="width: 600px;
            font-size: 11px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Verdana,sans-serif;
            vertical-align: middle;">
            <br />
            <tr id="txttr" align="left">
                <td style="width: 80px;" align="left">
                    <b style="color: #4E6CA3;">Ship To Code </b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td style="width: 500px;">
                    <div class="container">
                        <div class="form-group">
                            <select id="single" style="width: auto;" onchange="Loadunitlist(this.id));" class="form-control select2-single">
                                <option></option>
                                <option value="0">SELECT SHIP TO CODE </option>
                               <%-- <%=opt %>--%><%=session("opt")%>
                            </select>
                        </div>
                    </div>
                </td>
            </tr>
            <tr id="Tr1" align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Ship To Code </b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <span id="txtscode" cssclass="textbox1"></span>
                </td>
            </tr>
            <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Mobile 1</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:TextBox ID="txtmobile1" runat="Server" CssClass="textbox1" TabIndex="11" MaxLength="200" />
                </td>
            </tr>
            <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Mobile 2</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:TextBox ID="txtmobile2" runat="Server" CssClass="textbox1" TabIndex="11" MaxLength="200" />
                </td>
            </tr>
            <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Mobile 3</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:TextBox ID="txtmobile3" runat="Server" CssClass="textbox1" TabIndex="11" MaxLength="200" />
                </td>
            </tr>
            <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Mobile 4</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:TextBox ID="txtmobile4" runat="Server" CssClass="textbox1" TabIndex="11" MaxLength="200" />
                </td>
            </tr>
            <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">Mobile 5</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:TextBox ID="txtmobile5" runat="Server" CssClass="textbox1" TabIndex="11" MaxLength="200" />
                </td>
            </tr>
             <tr align="left">
                <td align="left">
                    <b style="color: #4E6CA3;">OTP Flag</b>
                </td>
                <td style="color: #4E6CA3;">
                    :
                </td>
                <td>
                    <asp:CheckBox Text="Check for OTP" ID="chkOTP" runat="server" CssClass="textbox1" TabIndex="12" MaxLength="200" />
                </td>
            </tr>
        </table>
    </div>
   
    </form>
       <form id="excelform" method="get" action="ExcelReport.aspx">
    <input type="hidden" id="title" name="title" value="SMS Notification Management" />
   <%-- <input type="hidden" id="plateno" name="plateno" value="" />--%>
    </form>
</body>
</html>
