<%@ Page Language="VB" AutoEventWireup="false" Inherits="YTLWebApplication.ShowMap" Codebehind="ShowMap.aspx.vb" %>

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
        function callgmappage() {
            document.getElementById("gmappage").src = <%= source %> ;
        }
       
    </script>
</head>
<body style="margin:0px;" onload="callgmappage()">
    <form id="form1" runat="server">
    <table border="0" cellpadding="0" cellspacing="0">
        <tr>
            <td valign="top" style="width: 200px">
                <div style="font-family: Verdana; font-size: 11px;">
                    <input type="hidden" name="enddate" id="enddate" runat="server" value="" />
                    <b style="color: #5f7afc;">Plate No: </b>
                    <br />
                    <asp:Label ID="txtPlateno" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Code: </b>
                    <br />
                    <asp:Label ID="txtSTC" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Name: </b>
                    <br />
                    <asp:Label ID="txtShipToName" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                    <b style="color: #5f7afc;">Out Time: </b>
                    <br />
                    <asp:Label ID="txtOutTime" runat="server" ForeColor="Maroon"></asp:Label>
                    <br />
                     <br />
                     <span>Idling</span>
                    <asp:GridView ID="GridView1" runat="server"  HeaderStyle-Font-Size="12px"
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
                    <span>Stop</span>
                    <asp:GridView ID="GridView2" runat="server"  HeaderStyle-Font-Size="12px"
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
                    <span>PTO</span>
                    <asp:GridView ID="GridView3" runat="server"  HeaderStyle-Font-Size="12px"
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
                </div>
            </td>
            <td align="right">
                <div id="dialog-message" title="G Map" style="padding: 0;">
                    <iframe id="gmappage" name="gmappage" src="" frameborder="0" scrolling="auto" height="512"
                        width="821" style="" ></iframe>
                </div>
            </td>
        </tr>
    </table>
    <input type="hidden" runat="server"  name="iscode" id="iscode" value="" />
    </form>
</body>
</html>
