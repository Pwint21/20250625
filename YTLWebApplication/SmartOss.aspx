<%@ Page Language="VB" AutoEventWireup="false" Inherits="YTLWebApplication.SmartOss" Codebehind="SmartOss.aspx.vb" %>

<!DOCTYPE >
<html>
<head>
    <meta http-equiv="X-UA-Compatible" content="IE=7" />
    <title>Smart OSS</title>
    <style type="text/css" title="currentStyle">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
        @import "cssfiles/ColVis.css";
         @import "cssfiles/TableTools.css";

        
        
        .dataTables_processing
        {
            background-color: #000;
            color: #FFF;
        }
        table.display td
        {
            padding: 2px 2px;
            border: 1px solid lightblue;
            nowrap: nowrap;
            white-space: nowrap;
        }
        #history, #history1
        {
            width: 80px;
            font-size: 14px;
            cursor: pointer;
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
            font-size: 14px;
            border: 0px solid gray;
        }
        .MyButton
        {
            text-align: left;
            float: left;
            width: 600px;
        }
        .btnrefresh
        {
            margin-left: 5px;
            background-color: rgb(227, 241, 252);
            border-radius: 2px;
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
        .driverinfo
        {
            font-style: normal;
            cursor: pointer;
        }
        .driverinfo1
        {
            font-style: normal;
            cursor: pointer;
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
        div.ColVis_collection
        {
            position: relative;
            vertical-align: middle;
            height: auto;
            width: 120px !important;
            background-color: #f3f3f3;
            padding: 3px;
            border: 1px solid #ccc;
            z-index: 1102;
            overflow-y: scroll;
            overflow-x: hidden;
        }
        
        body
        {
            overflow: hidden;
        }
        
        /*.ui-dialog .ui-dialog-titlebar {
            padding: .4em 1em;
            position: relative;
            width: 0px;
            margin-left: 275px;
        }*/
        .hoverclass
        {
            margin-left: 25px;
            width: 16px;
            height: 16px;
            cursor: pointer;
            border: 1px solid rgb(122, 123, 119);
            margin-top: 22px;
            position: absolute;
            border-radius: 25px;
            background: url(images/gtk_close.png); /*background-image: url(images/cross_script.png);*/
            background-repeat: no-repeat;
            background-position: center;
        }
        .hoverclass:hover
        {
            background: url(images/gtk_close.png);
            border: 2px solid rgb(144, 178, 203);
            background-repeat: no-repeat;
            background-position: center;
            cursor: pointer;
        }
        div.ui-dialog.ui-widget.ui-widget-content.ui-corner-all.transparent
        {
            background: none transparent;
            border: none;
        }
        #dialog-form
        {
            background-image: url("images/loaderTEst.gif");
            background-position: center;
            background-repeat: no-repeat;
        }
        #Historydata
        {
            padding-top: 1px;
            padding-right: 0px;
            padding-bottom: 0px;
            font-size: 12px;
            padding-left: 0px;
            font-weight: normal;
            font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif;
        }
        #Historydata
        {
            border-collapse: collapse;
            width: 100%;
            border: 1px solid #ADD8E6;
            height: 100%;
        }
        
        
        
        
        
        
        
        
        #Historydata th
        {
            text-align: left;
            background: #DFEFFC;
            color: rgb(0, 82, 161);
            padding: 1px;
            border: 1px solid #ADD8E6; /*border-width:0 1px 1px 0;*/
        }
        #Historydata td
        {
            border: 1px solid #ADD8E6;
        }
        .odd
        {
            background: #F7FBFF;
            border: 1px solid #ADD8E6;
        }
        .even
        {
            background: #FFFFFF;
            border: 1px solid #ADD8E6;
        }
    </style>
    <link type="text/css" href="cssfiles/jquery-ui.css" rel="stylesheet" />
    <link href="cssfiles/css3-buttons.css" rel="stylesheet" type="text/css" />
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery-ui-1.8.20.custom.min.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.dataTables.js"></script>
    <script type="text/javascript" src="jsfiles/TableTools.min.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/ColVis.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/FixedColumns.js"></script>
    <script type="text/javascript" charset="utf-8">
        function getWindowWidth() { if (window.self && self.innerWidth) { return self.innerWidth; } if (document.documentElement && document.documentElement.clientWidth) { return document.documentElement.clientWidth; } return document.documentElement.offsetWidth; }
        function getWindowHeight() { if (window.self && self.innerHeight) { return self.innerHeight; } if (document.documentElement && document.documentElement.clientHeight) { return document.documentElement.clientHeight; } return document.documentElement.offsetHeight; }
        function resize() {
            table = oTable.dataTable();
            table.fnSettings().oScroll.sY = getWindowHeight() - 150 + "px";
            table.fnDraw();
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

        function unload() {
            window.parent.document.getElementById("mainframe").scrolling = "yes";
        }

        function refreshTable() {
            table = oTable.dataTable();
            table._fnProcessingDisplay(true);
            oSettings = table.fnSettings();
            $.getJSON('GetDMSLafargeT.aspx?fdt=' + $('#history').val() + ' 00:00:00&tdt=' + $('#history1').val() + ' 23:59:59', null, function (json) {
                table.fnClearTable(this);
                for (var i = 0; i < json.length; i++) {
                    table.oApi._fnAddData(oSettings, json[i]);
                }
                oSettings.aiDisplay = oSettings.aiDisplayMaster.slice();
                table._fnProcessingDisplay(false);

                table.fnDraw();
                
            });
            return false;
        }


        var oTable;
        var oTable1;

        $(document).ready(function () {
            $("#dialog-form").hide();
            $("#dialog-formStatus").hide();
            $("#dialog-formHistory").hide();
            var h = getWindowHeight() - 150 + "px";
            oTable = $('#example').dataTable({
                "bProcessing": true,
                "bJQueryUI": true,
                "bServerSide": false,
                "sPaginationType": "full_numbers",
                //"sAjaxSource": "GetTmsDMSLafarge.aspx",
                "sScrollY": h,
                "sScrollX": "100%",
                "bScrollCollapse": true,
                "bLengthChange": false,
                "iDisplayLength": 2000,
                "bInfo": true,
                "oLanguage": { "sProcessing": " Loading...", "sEmptyTable": "" },
                "bAutoWidth": false,
                "aaSorting": [[1, "asc"]],
                "bStateSave": false,
                "fnStateSave": function (oSettings, oData) {
                    localStorage.setItem('DataTables_' + $("#unname").val(), JSON.stringify(oData));
                },
                "fnStateLoad": function (oSettings) {
                    return JSON.parse(localStorage.getItem('DataTables_' + $("#unname").val()));
                },
                "fnDrawCallback": function (oSettings) {
                    /* Need to redo the counters if filtered or sorted */
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(0)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },

                "aoColumnDefs": [
                   {
                       "bVisible": true, "sWidth": "15px", "bSortable": false, "aTargets": [0]
                   },
                    { "bVisible": true,  "bSortable": true, "aTargets": [1] },
                    { "bVisible": true, "bSortable": true,  "aTargets": [2] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [3] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [4] },
                     { "bVisible": true,  "bSortable": true, "aTargets": [5] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [6] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [7] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [8] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [9] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [10]},
                    { "bVisible": true,  "bSortable": true,  "aTargets": [11] },
                    { "bVisible": true,  "bSortable": true,  "aTargets": [12] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [13] },
                    { "bVisible": true,  "bSortable": true,  "aTargets": [14] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [15]},
                    { "bVisible": true,  "bSortable": true, "aTargets": [16] },
                    { "bVisible": true,  "bSortable": true,  "aTargets": [17] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [18] },
                    { "bVisible": true,  "bSortable": true, "sType": "num-html", "aTargets": [19] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [20] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [21] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [22] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [23] },
                    { "bVisible": true,  "bSortable": true, "aTargets": [24] }
                ],
                "sDom": '<"H"Cl<"MyButton">f>rt<"F"iT>',
                // "sDom": '<Cl<"MyButton">f>rt<"F"iT>',
                "oColReorder": {
                    "iFixedColumns": 4
                },
                "oTableTools": { "aButtons": ["xls", "copy", "print"], "sSwfPath": "cssfiles/copy_csv_xls_pdf.swf" }

            });
            oTable.fnClearTable(this);
            oTable.fnAdjustColumnSizing();
            $("div.MyButton").html('<div>From Date : <input type="text" id="history" value="<%= curdate %>" title="Required Date From" /> To Date : <input type="text" id="history1" value="<%= curdateto %>"  title="Required Date To"/><input type="button" value="Refresh" class="btnrefresh" onclick="javascript:refreshTable();"/></div>');
            $("#history").datepicker({ dateFormat: 'yy/mm/dd', minDate: -180, maxDate: 0, changeMonth: true, changeYear: true, numberOfMonths: 2, gotoCurrent: false });
            $("#history1").datepicker({ dateFormat: 'yy/mm/dd', minDate: -180, maxDate: 0, changeMonth: true, changeYear: true, numberOfMonths: 2, gotoCurrent: false });
            $(".ColVis_Button").hide();
            refreshTable();
        });
        
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
        
        .chzn-container .chzn-results
        {
            max-height: 300px;
        }
    </style>
</head>
<body id="dt_example" style="margin: 0px; font-size: 11px; font-family: verdana"
    scroll="no" onresize="resize()" onunload="unload()">
    <form runat="server">
    <table cellpadding="0" cellspacing="0" width="100%" border="0" class="display" id="example"
        style="font-size: 11px; font-family: verdana;">
        <thead style="text-align: left;">
            <tr>
                <th rowspan="2">
                    No
                </th>
                <th rowspan="2">
                    DN No
                </th>
                <th rowspan="2">
                    Transporter
                </th>
                <th rowspan="2">
                    Plate No
                </th>
                <th rowspan="2">
                    Driver
                </th>
                <th rowspan="2">
                    Source
                </th>
                <th colspan="2" style=' text-align: center; color: #2E6E9E;'>
                    Destination
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Loading
                </th>
                <th rowspan="2">
                    Travelling Time
                </th>
                <th rowspan="2" >
                    Distance
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Waiting
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Unloading
                </th>
            </tr>
            <tr align="left">
                <th>
                    Name
                </th>
                <th>
                    Ship To Code
                </th>
                <th>
                    Plant In Date
                </th>
                <th>Time</th>
                <th>
                    Weight Out Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
                <th>
                    Wait Start Date
                </th>
                <th>Time</th>
                <th>
                    PTO On Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
                <th>
                    PTO ON Date
                </th>
                <th>Time</th>
                <th>
                    PTO OFF Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
            </tr>
        </thead>
        <tbody>
        </tbody>
        <tfoot style="text-align: left; font-weight: bold;">
           <tr>
                <th rowspan="2">
                    No
                </th>
                <th rowspan="2">
                    DN No
                </th>
                <th rowspan="2">
                    Transporter
                </th>
                <th rowspan="2">
                    Plate No
                </th>
                <th rowspan="2">
                    Driver
                </th>
                <th rowspan="2">
                    Source
                </th>
                <th colspan="2" style=' text-align: center; color: #2E6E9E;'>
                    Destination
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Loading
                </th>
                <th rowspan="2">
                    Travelling Time
                </th>
                <th rowspan="2" >
                    Distance
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Waiting
                </th>
                <th colspan="5" style=' text-align: center; color: #2E6E9E;'>
                    Unloading
                </th>
            </tr>
            <tr align="left">
                <th>
                    Name
                </th>
                <th>
                    Ship To Code
                </th>
                <th>
                    Plant In Date
                </th>
                <th>Time</th>
                <th>
                    Weight Out Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
                <th>
                    Wait Start Date
                </th>
                <th>Time</th>
                <th>
                    PTO On Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
                <th>
                    PTO ON Date
                </th>
                <th>Time</th>
                <th>
                    PTO OFF Date
                </th>
                <th>Time</th>
                <th>
                    Duration
                </th>
            </tr>
        </tfoot>
    </table>
    </form>
</body>
</html>
