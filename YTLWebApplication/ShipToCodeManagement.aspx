<%@ Page Language="VB" AutoEventWireup="false"
    Inherits="YTLWebApplication.ShipToCodeManagement" Codebehind="ShipToCodeManagement.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Ship To Code Management</title>
     <style type="text/css" media="screen">
        @import "cssfiles/demo_page.css";
        @import "cssfiles/demo_table_jui.css";
        @import "cssfiles/themes/redmond/jquery-ui-1.8.4.custom.css";
         </style>
          <link type="text/css" href="cssfiles/jquery-ui.css" rel="stylesheet" />
    <link href="cssfiles/css3-buttons.css" rel="stylesheet" type="text/css" />
    <style media="print" type="text/css">
        body
        {
            color: #000000;
            background: #ffffff;
            font-family: verdana,arial,sans-serif;
            font-size: 12pt;
        }
        #fcimg
        {
            display: none;
        }
        

        </style>
   <style type="text/css">
   
   
.dataTables_length {
width: 18%;
float: left;
}
div.dataTables_wrapper .ui-widget-header {
font-weight: normal;
float: left;
text-align: left;
}
   .dataTables_wrapper .ui-toolbar {

padding: 5px;
width: 788px;
}
table.display tfoot th {
padding: 0px 0px 0px 0px;
font-weight: bold;
}
table.display thead th {
padding: 0px 0px 0px 0px;
font-weight: bold;
}
   table.display thead th div.DataTables_sort_wrapper {
position: relative;
padding-right: 0px;
padding-left: 0px;
}
 tfoot input {
margin: 0.2em 0;
width: 100%;
color: #444;
} 
     </style>
      <script type="text/javascript" language="javascript" src="jsfiles/jquery.js"></script>
    <script type="text/javascript" src="jsfiles/jquery-ui-1.8.20.custom.min.js"></script>
    <script type="text/javascript" language="javascript" src="jsfiles/jquery.dataTables.js"></script>
    <script type="text/javascript" language="javascript">

  
     var ec=<%=ec %>;
      
    function checkall(chkobj)
	{
	    var chkvalue=chkobj.checked;
	    for(i = 0; i < document.forms[0].elements.length; i++) 
        {
            elm = document.forms[0].elements[i]
            if (elm.type == 'checkbox') 
            {
                document.forms[0].elements[i].checked =chkvalue;
            }
        }
    }
    function deleteconfirmation()
	{
	    var checked=false;
	    for(i = 0; i < document.forms[0].elements.length; i++) 
        {
           elm = document.forms[0].elements[i]
           if (elm.type == 'checkbox') 
            {
                if(elm.checked == true)
                {
                    checked=true;
                    break;
                }
            }
        }
        if(checked)
        {
		    var result=confirm("Are you delete checked Ship To Code  information ?");
		    if(result)
		    {
		        return true;
		    }
		    return false;
		}
		else
		{
		    alert("Please select checkboxes");
		    return false;
		}
	    }
      </script>
      <script type="text/javascript">
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

        $(document).ready(function () {
            fnFeaturesInit();
            $('#examples').dataTable({
                "bJQueryUI": true,
                "sPaginationType": "full_numbers",
                "iDisplayLength": 100,
                "aaSorting": [[2, "asc"]],
                "aLengthMenu": [10, 25, 50, 100, 200, 500],
                "fnDrawCallback": function (oSettings) {
                    if (oSettings.bSorted || oSettings.bFiltered) {
                        if (oSettings.aoColumns[0].bVisible == true) {
                            for (var i = 0, iLen = oSettings.aiDisplay.length; i < iLen; i++) {
                                $('td:eq(1)', oSettings.aoData[oSettings.aiDisplay[i]].nTr).html(i + 1);
                            }
                        }
                    }
                },
                "aoColumnDefs": [
                          { "bSortable": false, "aTargets": [0] },
                          { "bSortable": false, "aTargets": [1] },
                          { "sType": "num-html", "aTargets": [2] }
                              ]
            });
        });


    </script> 
    <script type="text/javascript">
        function ExcelReport() {
            var excelformobj = document.getElementById("excelform");
            excelformobj.submit();
            return false;
        }
    </script>
</head>
<body  style="font-size: 11px; font-weight: bold; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif">
    <form id="fuelform" runat="server">
    <center>
        <br />
        <b style="font-family: Verdana; font-size: 20px; color: #38678B;">Ship To Code Management</b>
        <table style="font-family: Verdana; font-size: 11px; width:800px">
            <tr>
                <td align="left">
                <% If Request.Cookies("userinfo")("customrole") <> "transporter" Then%>
                    <asp:Button ID="ImageButton1" OnClientClick="deleteconfirmation()" class="action blue"
                        runat="server" Text="Delete" ToolTip="Delete" />
                        <% End If %>
                </td>
                <td align="center">
                </td>
                <td align="right" valign="middle">
                 <a href="" onclick="javascript:return ExcelReport();" class="button" title="Import to Excel" style="width: 59px;">
                        <span class="ui-button-text">Excel</span></a>
                        <% If Request.Cookies("userinfo")("customrole") <> "transporter" Then%>
                    <a href="<%=addShiptocode %>" class="button" title="Add Ship To Code" style="width: 59px;"><span class="ui-button-text">Add </span></a>
                        <% End If %>
                </td>
            </tr>
           <br />
            <tr>
                <td align="center" colspan="3">
                <br />
                     <table cellpadding="0" cellspacing="0" border="0" class="display" id="examples" style="font-size: 10px;
            font-weight: normal; font-family: Myriad Pro,Lucida Grande,Helvetica,Arial,sans-serif"; width="800px">
            <%=sb1.ToString()%>
          </table> 
                </td>
            </tr>
            <% If Request.Cookies("userinfo")("customrole") <> "transporter" Then%>
            <tr>
                <td align="left">
                    <asp:Button ID="ImageButton3" OnClientClick="deleteconfirmation()" class="action blue"
                        runat="server" Text="Delete" ToolTip="Delete" />
                </td>
                <td align="center" >
                </td>
                <td align="right" valign="middle">
                    <a href="<%=addShiptocode %>" class="button" title="Add Ship To Code" style="width: 59px;">
                        <span class="ui-button-text">Add </span></a>
                </td>
            </tr>
            <%End If%>
        </table>
    </center>
    </form>

    <form id="excelform" method="post" action="ShipExcelReport.aspx">
    </form>

</body>
</html>
