<%@ Page Language="VB" AutoEventWireup="false" Inherits="YTLWebApplication.ShowCompetitorInformation" Codebehind="ShowCompetitorInformation.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Vehicle Idealings</title>
    <script type="text/javascript" src="jsfiles/jquery.min.js"></script>
    <script type="text/javascript" src="jsfiles/jquery-ui.min.js"></script>
    <script type="text/javascript">
        function panMapToPos(lat, lon) {
            window.frames[0].ShowIdlingLocation(lat, lon);
        }
        function SetValues() {
            var shiptocode, name, siteaddress;
            shiptocode = document.getElementById("txtShipToName").innerHTML;
            name = escape( document.getElementById("txtSTC").innerHTML);
            siteaddress = escape( document.getElementById("txtShiptoaddress").innerHTML);
            window.frames[0].SetValuesAuto(shiptocode, name,siteaddress);
        }
        function callgmappage() {
            document.getElementById("gmappage").src = <%= source %> ;
        }
        function SetSource(plateno,bdt,edt) {
            document.getElementById("gmappage").src = "Gmap.aspx?scode=1&plateno=" + plateno + "&bdt=" + bdt+ "&edt="+edt ;
        }

        function getWindowWidth() { if (window.self && self.innerWidth) { return self.innerWidth; } if (document.documentElement && document.documentElement.clientWidth) { return document.documentElement.clientWidth; } return document.documentElement.offsetWidth; }
        function getWindowHeight() { if (window.self && self.innerHeight) { return self.innerHeight; } if (document.documentElement && document.documentElement.clientHeight) { return document.documentElement.clientHeight; } return document.documentElement.offsetHeight; }

        $(function () {
            $("#gmappage").height(getWindowHeight());
            $("#gmappage").width(getWindowWidth() - 250);
            $("#GridView1").height(getWindowHeight() - 30);
        });

        //function SetValues() {
        //    if (document.getElementById("shiptocode") != null) {
        //        document.getElementById("geofenceaddress").value = document.getElementById("txtShiptoaddress").innerHTML;
        //        document.getElementById("geofencenametextbox").value = document.getElementById("txtSTC").innerHTML;
        //        document.getElementById("shiptocode").value = document.getElementById("txtShipToName").innerHTML;
        //    }
            
        //}
    </script>
</head>
<body style="margin:0px;" onload="callgmappage()">
    <form id="form1" runat="server">
    <table border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td valign="top" style="width: 200px">
                <div style="font-family: Verdana; font-size: 11px;">
                    <input type="hidden" name="enddate" id="enddate" runat="server" value="" />
                     <br />
                     <span>Trips</span>
                    <asp:GridView ID="GridView1" runat="server"  HeaderStyle-Font-Size="12px"
                        HeaderStyle-ForeColor="#FFFFFF" HeaderStyle-BackColor="#465AE8" HeaderStyle-Font-Bold="True"
                        HeaderStyle-Height="22px" HeaderStyle-HorizontalAlign="Center" AutoGenerateColumns="false" style="overflow-y:scroll" >
                        <AlternatingRowStyle BackColor="Lavender"  />
                        <Columns>
                            <asp:BoundField DataField="sno" HeaderText="S No" Visible="false">
                                <ItemStyle HorizontalAlign="center" Width="35" />
                            </asp:BoundField>
                            <asp:BoundField DataField="plateno" HeaderText="Plate Number" HtmlEncode="False"
                                Visible="true"></asp:BoundField>
                            <asp:BoundField DataField="begindatetime" HeaderText="Begin DateTime" HtmlEncode="False"
                                Visible="true"></asp:BoundField>
                            <asp:BoundField DataField="enddatetime" HeaderText="End DateTime" HtmlEncode="False"
                                Visible="true">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                            <asp:BoundField DataField="details" HeaderText="Info" HtmlEncode="false">
                                <ItemStyle HorizontalAlign="Right" />
                            </asp:BoundField>                             
                        </Columns>
                    </asp:GridView>
                   
                </div>
            </td>
            <td align="right">
                <div id="dialog-message" title="G Map" style="padding: 0;">
                    <iframe id="gmappage" name="gmappage" src="" frameborder="0" scrolling="auto" height="512"
                        width="1021" style="" />
                </div>
            </td>
        </tr>
    </table>
    <input type="hidden" runat="server"  name="iscode" id="iscode" value="" />
    </form>
</body>
</html>