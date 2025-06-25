<%@ Page Language="vb" AutoEventWireup="false" CodeBehind="ShipToCodeManagementTest.aspx.vb" Inherits="YTLWebApplication.ShipToCodeManagementTest" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <title>ShipToCode Management</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.8/css/select2.css" rel="stylesheet">
    <style type="text/css" media="screen">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
        @import "css/jquery.mloading.css";
        .dataTables_info
        {
            width: 25%;
            float: left;
        }
 
    </style>
    <style>
        .select2-container--open .select2-dropdown--below {
    border-top: none;
    border-top-left-radius: 0;
    border-top-right-radius: 0;
    margin-left: 8px;
}
               .ui-button-text-only .ui-button-text {
    padding: 0px !important;
}
    </style>

    <link type="text/css" href="cssfiles/jquery-ui.css" rel="stylesheet" />
    <link href="cssfiles/css3-buttons.css" rel="stylesheet" type="text/css" />
    <script type="text/javascript" src="jsfiles/jquery.js"></script>
    
    <script type="text/javascript" src="jsfiles/jquery-ui-1.8.20.custom.min.js"></script>
    <script type="text/javascript" src="jsfiles/jquery.dataTables.js"></script>
    <script type="text/javascript" src="jsfiles/FixedColumns.js"></script>
    <script type="text/javascript" src="js/jquery.mloading.js"></script>
     <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/select2/4.0.8/js/select2.js"></script>
    <script type="text/javascript">
        var geofenceID = "";
        var check = true;
        var prevgeofenceID = "";
        var loadingBit1 = "0";
        var loadingBit2 = "0";
        var Anewshiptocode, Aname;
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
            $("#div1").dialog({
                resizable: false,
                draggable: false,
                width: 450,
                minHeight: 150,
                height: 150,
                modal: true,
                autoOpen: false,
                buttons: {
                    "Yes": function () {
                        updateData();
                        $(this).dialog("close");
                    },
                    "No": function () {
                        $(this).dialog("close");

                    }
                }
            });

            $("#dialog-message").dialog({
                resizable: false,
                draggable: false,
                modal: true,
                autoOpen: false,
                width: 300,
                minHeight: 150,
                height: 150,
                buttons: {
                    "Ok": function () {
                        $(this).dialog("close");
                    }
                }
            });


            $("#ddlGeofence").select2({
                allowClear: true,
                placeholder: 'Select Geofencename'
            });
            oTable1 = $('#examples').dataTable({
                "bJQueryUI": true,
                "bProcessing": true,
                "sPaginationType": "full_numbers",
                "iDisplayLength": 20,
                "aaSorting": [[1, "asc"]],
                "aLengthMenu": [20, 50, 100, 200, 500],
                "fnDrawCallback": function (oSettings) {
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(0)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },

                "aoColumnDefs": [{ "sClass": "left", "bVisible": true, "sWidth": "35px", "bSortable": false, "aTargets": [0] },
                { "bVisible": true, "sWidth": "130px", "aTargets": [1] },
                { "sClass": "right", "sWidth": "80px", "bVisible": true, "aTargets": [2] },
                { "sClass": "left", "bVisible": true, "aTargets": [3] },
                { "sClass": "right", "bVisible": true, "sWidth": "30px", "bSortable": false, "aTargets": [4] }
                ]
            });

            oTable2 = $('#examples1').dataTable({
                "bJQueryUI": true,
                "bProcessing": true,
                "sPaginationType": "full_numbers",
                "iDisplayLength": 20,
                "aaSorting": [[1, "asc"]],
                "aLengthMenu": [20, 50, 100, 200, 500],
                "fnDrawCallback": function (oSettings) {
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(0)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },

                "aoColumnDefs": [{ "sClass": "left", "bVisible": true, "bSortable": false, "aTargets": [0] },
                { "bVisible": true, "aTargets": [1] },
                { "sClass": "left", "bVisible": true, "aTargets": [2] },
                { "sClass": "right", "bVisible": true, "aTargets": [3] }

                ]
            });

            $("body").mLoading();
            refreshTable1();
            refreshTable2();


        });

        function confirm(message) {
            document.getElementById("P1").innerHTML = message;
            $("#div1").dialog("open");
        }
        function Alert(message) {
            document.getElementById("P2").innerHTML = message;
            $("#dialog-message").dialog("open");
        }
        function getData() {
            if (validate()) {
                refreshTable1();
                refreshTable2();

            }
        }
        function selectSTC(obj) {
            geofenceID = obj.id;
            if (prevgeofenceID == geofenceID) {
                $("#" + obj.id).css("background-color", "")
                check = true;
                geofenceID = "";
                prevgeofenceID = "";

            }
            else {
                if (check) {
                    check = false;
                    $("#" + obj.id).css("background-color", "Yellow");
                    prevgeofenceID = obj.id;

                }
                else {
                    var cursor = $("#" + prevgeofenceID).css("cursor");
                    if (cursor == "default") {
                        check = false;
                        $("#" + obj.id).css("background-color", "Yellow");
                        prevgeofenceID = obj.id;
                    } else {
                        $("#" + prevgeofenceID).css("background-color", "");
                        $("#" + obj.id).css("background-color", "Yellow");
                        prevgeofenceID = obj.id;
                    }


                }
            }


        }

        function validate1() {
            if (geofenceID == "") {
                Alert("Please select Geofencename");
                return false;
            }
            return true;
        }
        function refreshTable1() {
            $.get("GetGeofenceData.aspx?op=0", function (response) {
                loadingBit1 = "1"
                if (loadingBit1 == "1" && loadingBit2 == "1") {

                    $("body").mLoading('hide');
                    loadingBit1 = "0";
                    loadingBit2 = "0"
                }
                var json = JSON.parse(response);
                table = oTable1.dataTable();
                table._fnProcessingDisplay(true);
                oSettings = table.fnSettings();
                table.fnClearTable(this);
                for (var i = 0; i < json.length; i++) {
                    table.oApi._fnAddData(oSettings, json[i]);
                }
                oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                table._fnProcessingDisplay(false);
                table.fnDraw();
            });
        }
        function refreshTable2() {
            $.get("GetGeofenceData.aspx?op=1", function (response) {
                loadingBit2 = "1"
                if (loadingBit1 == "1" && loadingBit2 == "1") {

                    $("body").mLoading('hide');
                    loadingBit1 = "0";
                    loadingBit2 = "0"
                }
                var json = JSON.parse(response);
                table = oTable2.dataTable();
                table._fnProcessingDisplay(true);
                oSettings = table.fnSettings();
                table.fnClearTable(this);
                for (var i = 0; i < json.length; i++) {
                    table.oApi._fnAddData(oSettings, json[i]);
                }
                oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                table._fnProcessingDisplay(false);
                table.fnDraw();
            });
        }

        function updateData() {
            $.get("GetGeofenceData.aspx?geofenceID=" + geofenceID + "&op=2&newSTC=" + Anewshiptocode + "&name=" + Aname + "", function (response) {
                var json = JSON.parse(response);
                if (json[0] == "1") {
                    $("#" + Anewshiptocode + "a").css("pointer-events", "none")
                    $("#" + Anewshiptocode + "i").css("background-color", "#32ef32")
                    $("#" + geofenceID).text(Aname);
                    $("#" + geofenceID + "s").text(Anewshiptocode);
                    $("#" + geofenceID).prop("onclick", null).off("click");
                    $("#" + geofenceID).css("cursor", "default");
                    $("#" + geofenceID).css("background-color", "#32ef32");
                    $("#" + geofenceID + "s").css("background-color", "#32ef32");
                    Anewshiptocode = "";
                    Aname = "";
                    geofenceID = "";
                    //$("body").mLoading();
                    //refreshTable1();
                    //refreshTable2();
                }

            });
        }
        function MoveShipToCode(newshiptocode, name) {
            Anewshiptocode = "";
            Aname = "";

            if (validate1()) {
                Anewshiptocode = newshiptocode;
                Aname = name;

                var result = confirm("Are you sure you want to update shiptocode=<b style='color:brown;'>" + newshiptocode + "</b> , geofencename=<b style='color:brown;'>" + name + "</b>  ?");
            }
        }


    </script>
    
</head>
<body id="index" style="font-size: 11px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
    <form id="Form1" method="post" runat="server">
    <center>
        <div>
            <br />
            <b style="font-family: Verdana; font-size: 20px; color: #38678B;">ShipToCode Management</b>
            <br />
            <br />
        </div>

        <table style="width:100%">
            <tr>
                <td style="width:48%;">
                      <div>
                          <h3 style="text-align:center;color:brown;font-weight:bold;">OSS ShipToCode Table</h3>
                      <table cellpadding="0" cellspacing="0" border="0" class="display" id="examples">
                          <thead>
                              <tr>
                                  <th style="width:35px;" >S No</th>
                                  <th style="width:200px;">Name</th>
                                  <th style="width:100px;">Ship To Code</th>
                                  <th style="width:120px;">Address</th>
                                  <th style="width:35px;"></th>
                              </tr>
                          </thead>
                          <tbody>

                          </tbody>
                          <tfoot>
                              <tr>
                                  <th style="width:35px;" >S No</th>
                                  <th style="width:200px;">Name</th>
                                  <th style="width:100px;">Ship To Code</th>
                                  <th style="width:120px;">Address</th>
                                  <th style="width:35px;"></th>
                              </tr>
                          </tfoot>           
                     </table>                    
                    </div>
                </td>
                 <td>
                    
                </td>
                 <td style="width:48%;">
                        <div> 
                            <h3 style="text-align:center;color:brown;font-weight:bold;">AVLS Geofence Table</h3>
             <table cellpadding="0" cellspacing="0" border="0" class="display" id="examples1">
                          <thead>
                              <tr>
                                   <th style="width:35px;" >S No</th>
                                   <th>Geofence Name</th>
                                   <th>Address</th>
                                  <th style="width:100px;">Ship To Code</th>
                                                             
                              </tr>
                          </thead>
                 <tbody>

                 </tbody>
                 <tfoot>
                      <tr>
                                  <th style="width:35px;" >S No</th>
                                  <th>Geofence Name</th>
                                  <th>Address</th>
                                  <th style="width:100px;">Ship To Code</th>
                                                              
                              </tr>
                 </tfoot>        
          </table>        
         </div>
                </td>
            </tr>
        </table>
                   
    </center>

    <div id="div1" title="Confirmation">
        <p id="P1" style="color:#333;font-size:12px">
            <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;">
            </span>
        </p>
    </div>
     <div id="dialog-message" title="Alert">
        <p id="P2">
            <span class="ui-icon ui-icon-circle-check" style="float: left; margin: 0 7px 50px 0;">
            </span>
        </p>
    </div>

    </form>  
</body>
</html>