<%@ Page Language="VB" AutoEventWireup="false" Inherits="YTLWebApplication.ShowInformation" Codebehind="ShowInformation.aspx.vb" %>

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
        function getWindowWidth() { if (window.self && self.innerWidth) { return self.innerWidth; } if (document.documentElement && document.documentElement.clientWidth) { return document.documentElement.clientWidth; } return document.documentElement.offsetWidth; }
        function getWindowHeight() { if (window.self && self.innerHeight) { return self.innerHeight; } if (document.documentElement && document.documentElement.clientHeight) { return document.documentElement.clientHeight; } return document.documentElement.offsetHeight; }

        $(function () {
            $("#gmappage").height(getWindowHeight());
            $("#gmappage").width(getWindowWidth() - 245);

            if ($("#reqfrom").val() == "Client") {
                $("#btncopy").hide();
            }
            else {
                $("#btncopy").show();
            }
            $("#event5hrs").change(function () {
                if (this.checked) {
                    if (window.location.href.split("&").length == 2) {
                        window.location.href = window.location.href.split("&")[0] + "&events=5";
                    }
                    else {
                        window.location.href = window.location.href + "&events=5";
                    }
                    
                }
                else {
                    if (window.location.href.split("&").length == 2) {
                        window.location.href = window.location.href.split("&")[0] + "&events=2";
                    }
                    else {
                        window.location.href = window.location.href + "&events=2";
                    }
                }
            });
        });

        //function SetValues() {
        //    if (document.getElementById("shiptocode") != null) {
        //        document.getElementById("geofenceaddress").value = document.getElementById("txtShiptoaddress").innerHTML;
        //        document.getElementById("geofencenametextbox").value = document.getElementById("txtSTC").innerHTML;
        //        document.getElementById("shiptocode").value = document.getElementById("txtShipToName").innerHTML;
        //    }
            
        //}
    </script>
    <style>
        table#GridView4 td {
    white-space: nowrap;
}
    </style>
</head>
<body style="margin:0px;" onload="callgmappage()">
    <form id="form1" runat="server">
    <table border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td valign="top" style="width: 200px">
                <div style="font-family: Verdana; font-size: 11px;">
                    <input type="hidden" name="enddate" id="enddate" runat="server" value="" />
                    <input type="hidden" name="dn_id" id="dn_id" runat="server" value="" />
                     <input type="hidden" name="reqfrom" id="reqfrom" runat="server" value="" />
                    
                    <b style="color: #5f7afc;">Plate No: </b>
                    <br />
                    <asp:Label ID="txtPlateno" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">DN ID: </b>
                    <br />
                    <asp:Label ID="txtdnid" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">DN NO: </b>
                    <br />
                    <asp:Label ID="txtdnno" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Name: </b>
                    <br />
                    <asp:Label ID="Label2" runat="server" ForeColor="Maroon"></asp:Label>
                    <b style="color: #5f7afc;">Code: </b>
                    <br />
                    <asp:Label ID="txtShipToName" runat="server" ForeColor="Maroon"></asp:Label> 

                    <input type ="button" value="Auto Fill" title="Auto Fill Ship To Code Data" runat ="server"  id="btncopy" onclick="javascript:SetValues()" />
                    <br />
                    <b style="color: #5f7afc;">Name: </b>
                    <br />
                    <asp:Label ID="txtSTC" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Plant In Time: </b>
                    <br />
                    <asp:Label ID="txtPlantinTime" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Out Time: </b>
                    <br />
                    <asp:Label ID="txtOutTime" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Next Plant In Time: </b>
                    <br />
                    <asp:Label ID="txtNxtPlantinTime" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Next Weight Out Time: </b>
                    <br />
                    <asp:Label ID="txtNextWeightoutTime" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Site Address: </b>
                    <br />
                    <asp:Label ID="txtShiptoaddress" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Transporter: </b>
                    <br />
                    <asp:Label ID="txtTransporter" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                   
                    <br />
                     <asp:CheckBox ID="event5hrs" runat="server"  Text="Show Events For 5 Days" style="display:none"   />
                     <br />

                     <span>Events Summary</span>
                    <asp:GridView ID="GridView4" runat="server"  HeaderStyle-Font-Size="12px"
                        HeaderStyle-ForeColor="#FFFFFF" HeaderStyle-BackColor="#465AE8" HeaderStyle-Font-Bold="True"
                        HeaderStyle-Height="22px" HeaderStyle-HorizontalAlign="Center" AutoGenerateColumns="false">
                        <AlternatingRowStyle BackColor="Lavender" />
                        <Columns>
                            <asp:BoundField DataField="sno" HeaderText="S No" Visible="false">
                                <ItemStyle HorizontalAlign="center" Width="35" />
                            </asp:BoundField>
                            <asp:BoundField DataField="plateno" HeaderText="Plate Number" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="shiptocode" HeaderText="Ship to Code" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="begindatetime" HeaderText="Begin DateTime" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="time" HeaderText="Date Time" HtmlEncode="False"></asp:BoundField>
                            <asp:BoundField DataField="enddatetime" HeaderText="End DateTime" HtmlEncode="False"
                                Visible="false">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                             <asp:BoundField DataField="status" HeaderText="Event" HtmlEncode="False"
                                Visible="true">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                            <asp:BoundField DataField="duration" HeaderText="Mins" HtmlEncode="false">
                                <ItemStyle HorizontalAlign="Right" />
                            </asp:BoundField>    
                           
                        </Columns>
                    </asp:GridView>

                     <span style ="display :none ">Idling</span>
                    <asp:GridView ID="GridView1" style="display:none " runat="server"  HeaderStyle-Font-Size="12px"
                        HeaderStyle-ForeColor="#FFFFFF" HeaderStyle-BackColor="#465AE8" HeaderStyle-Font-Bold="True"
                        HeaderStyle-Height="22px" HeaderStyle-HorizontalAlign="Center" AutoGenerateColumns="false">
                        <AlternatingRowStyle BackColor="Lavender" />
                        <Columns>
                            <asp:BoundField DataField="sno" HeaderText="S No" Visible="false">
                                <ItemStyle HorizontalAlign="center" Width="35" />
                            </asp:BoundField>
                            <asp:BoundField DataField="plateno" HeaderText="Plate Number" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="shiptocode" HeaderText="Ship to Code" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="begindatetime" HeaderText="Begin DateTime" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="time" HeaderText="Date Time" HtmlEncode="False"></asp:BoundField>
                            <asp:BoundField DataField="enddatetime" HeaderText="End DateTime" HtmlEncode="False"
                                Visible="false">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                            <asp:BoundField DataField="duration" HeaderText="Mins" HtmlEncode="false">
                                <ItemStyle HorizontalAlign="Right" />
                            </asp:BoundField>                             
                        </Columns>
                    </asp:GridView>
                    <span style ="display :none ">Stop</span>
                    <asp:GridView ID="GridView2" style="display:none " runat="server"  HeaderStyle-Font-Size="12px"
                        HeaderStyle-ForeColor="#FFFFFF" HeaderStyle-BackColor="#465AE8" HeaderStyle-Font-Bold="True"
                        HeaderStyle-Height="22px" HeaderStyle-HorizontalAlign="Center" AutoGenerateColumns="false">
                        <AlternatingRowStyle BackColor="Lavender"  />
                        <Columns>
                            <asp:BoundField DataField="sno" HeaderText="S No" Visible="false">
                                <ItemStyle HorizontalAlign="center" Width="35" />
                            </asp:BoundField>
                            <asp:BoundField DataField="plateno" HeaderText="Plate Number" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="shiptocode" HeaderText="Ship to Code" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="begindatetime" HeaderText="Begin DateTime" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="time" HeaderText="Date Time" HtmlEncode="False"></asp:BoundField>
                            <asp:BoundField DataField="enddatetime" HeaderText="End DateTime" HtmlEncode="False"
                                Visible="false">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                            <asp:BoundField DataField="duration" HeaderText="Mins" HtmlEncode="false">
                                <ItemStyle HorizontalAlign="Right" />
                            </asp:BoundField>                             
                        </Columns>
                    </asp:GridView>
                    <span style ="display :none ">PTO</span>
                    <asp:GridView ID="GridView3" runat="server" style="display:none "  HeaderStyle-Font-Size="12px"
                        HeaderStyle-ForeColor="#FFFFFF" HeaderStyle-BackColor="#465AE8" HeaderStyle-Font-Bold="True"
                        HeaderStyle-Height="22px" HeaderStyle-HorizontalAlign="Center" AutoGenerateColumns="false">
                        <AlternatingRowStyle BackColor="Lavender" />
                        <Columns>
                            <asp:BoundField DataField="sno" HeaderText="S No" Visible="false">
                                <ItemStyle HorizontalAlign="center" Width="35" />
                            </asp:BoundField>
                            <asp:BoundField DataField="plateno" HeaderText="Plate Number" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="shiptocode" HeaderText="Ship to Code" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="begindatetime" HeaderText="Begin DateTime" HtmlEncode="False"
                                Visible="false"></asp:BoundField>
                            <asp:BoundField DataField="time" HeaderText="Date Time" HtmlEncode="False"></asp:BoundField>
                            <asp:BoundField DataField="enddatetime" HeaderText="End DateTime" HtmlEncode="False"
                                Visible="false">
                                <ItemStyle HorizontalAlign="Left" />
                            </asp:BoundField>
                            <asp:BoundField DataField="duration" HeaderText="Mins" HtmlEncode="false">
                                <ItemStyle HorizontalAlign="Right" />
                            </asp:BoundField>                             
                            
                        </Columns>
                    </asp:GridView>

                    <br />
                    <b style="color: #5f7afc;">Remarks On Job: </b>
                    <br />
                    <asp:TextBox ID="txtremark"  runat="server"  ></asp:TextBox>

                    <br />
                    <asp:CheckBox ID="chkbox"  runat="server" Text="Visible To Admin Only" />
                   <%-- <asp:TextBox ID="TextBox1"  runat="server"  ></asp:TextBox>--%>
                    <br />
                    <asp:Button ID="btnSubmitremark" runat="server" Text="Submit Remarks" />

                </div>
            </td>
            <td valign="top">
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