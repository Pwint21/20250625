<%@ Page Language="VB" AutoEventWireup="false"
    Inherits="YTLWebApplication.ShowDiversionList" Codebehind="ShowDiversionList.aspx.vb" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Vehicle Diversion</title>
    <script type="text/javascript" src="jsfiles/jquery.min.js"></script>
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css"
        integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T"
        crossorigin="anonymous">
    <script>
        function divertNow() {
            if (document.getElementById("txtRemarks").value =="") {
                alert("Please enter Remarks.");
                return false;
            }
            return confirm("Are you sure, want to divert the selected job ?");
            //if (d) {
            //    return true;
            //    alert("Your job has been diverted[TEST]");
            //}
            //else {

            //}
        }

        function mysubmit() {
            if (isNaN(document.getElementById("txtDnNo").value)) {
                alert("Please enter a valid Load Id Number.");
                return false;
            }
            else
                return true;
        }
        function mysubmitonremark() {
            if (document.getElementById("txtremarksarea").value == "") {
                alert("Please enter remarks.");
                return false;
            }
            else
                return true;
        }
        function sendNoti() {
             var notiformobj = document.getElementById("notiform");
                notiformobj.submit();      
  }

    </script>
</head>
<body class="container-fluid">
    <form id="form1" runat="server" style="margin-top: 10px;">
       
        <div class="row">
            <div class="col-md-6 col-lg-6 col-sm-6">
                <div class="alert alert-info alert-heading">
                    Current Job
                </div>
                <table border="0" cellpadding="0" cellspacing="0" class="table table-condensed table-hover">
                    <tr>
                        <td>Plateno </td>
                        <td>:</td>
                        <td>
                            <asp:Label ID="txtPlateno" runat="server"></asp:Label>

                        </td>
                    </tr>
                    <tr style ="display :none ">
                        <td>Product Code:  </td>
                        <td>:</td>
                        <td>
                            <asp:Label ID="txtSTC" runat="server"></asp:Label>

                        </td>
                    </tr>
                    <tr>
                        <td>Item Name: </td>
                        <td>:</td>
                        <td>

                            <asp:Label ID="txtShipToName" runat="server"></asp:Label>


                        </td>
                    </tr>
                    <tr>
                        <td>DN No:  </td>
                        <td>:</td>
                        <td>
                            <asp:Label ID="txtDnNo1" runat="server"></asp:Label>
                        </td>
                    </tr>
                </table>
            </div>
            <div class="col-md-6 col-lg-6 col-sm-6">
                <div class="">
                    <table cellpadding="1">
                        <tr>
                            <td>
                               Remarks : <textarea runat="server" cols ="50" rows ="4" id="txtremarksarea" class ="form-control"></textarea>
                            </td>
                            <td>
                                <asp:Button Text="Divert Job" ID="btndivertjob"
                                    CssClass="btn btn-primary btn-block" runat="server" OnClientClick="javascript:return mysubmitonremark()"
                                    Width="106px" />
                                  <asp:Button Text="Cancel Divert Job" ID="btncanceldivertjob"
                                    CssClass="btn btn-warning  btn-block" runat="server"
                                    Width="106px" />
                            </td>
                        </tr>
                    </table>
                </div>
                <div class="">
                    <table cellpadding="1" style ="display :none ">
                        <tr>
                            <td>
                                <asp:TextBox runat="server" Width="250px" ID="txtDnNo" CssClass="form-control" placeholder="Please enter Load Id" />
                            </td>
                            <td>
                                <asp:Button Text="Search Job" ID="btnSearchDn"
                                    CssClass="btn btn-warning btn-block" runat="server" OnClientClick="javascript:return mysubmit()"
                                    Width="106px" />
                            </td>
                        </tr>
                    </table>
                </div>
                <table border="0" cellpadding="0" cellspacing="0" runat="server" id="tblDisplay"
                    class="table table-condensed table-hover">
                    <tr>
                        <td class="alert-heading alert-success">DN No </td>
                        <td>
                            <asp:Label Text="" ID="lblDnNo" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Product Name</td>
                        <td>
                            <asp:Label Text="" ID="lblProduct" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Tonnage</td>
                        <td>
                            <asp:Label Text="" ID="lblTonnage" runat="server" />
                              <input type="hidden" runat="server" id="hdnLid" />
                        </td>
                   
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Open Load(s)</td>
                        <td>
                            <asp:Label Text="" ID="lblOpenLoad" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Diversion Site</td>
                        <td>
                           <asp:Label Text="" ID="lblSiteId" runat="server" />
                        </td>
                    </tr>
                   
                    <tr>
                        <td class="alert-heading alert-success">Order No</td>
                        <td>
                            <asp:Label Text="" ID="lblONo" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Customer PO</td>
                        <td>
                            <asp:Label Text="" ID="lblCustomerPO" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Customer</td>
                        <td>
                            <asp:Label Text="" ID="lblCustomer" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Care of (C/O)</td>
                        <td>
                            <asp:Label Text="" ID="lblCo" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Delivered To</td>
                        <td>
                            <asp:Label Text="" ID="lblDelTo" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Destination</td>
                        <td>
                            <asp:Label Text="" ID="lblDestination" runat="server" />
                        </td>
                    </tr>
                    <tr>
                        <td class="alert-heading alert-success">Del. Instructions</td>
                        <td>
                            <asp:Label Text="" ID="lblSplIns" runat="server" />
                        </td>
                    </tr>
                     <tr>
                        <td class="alert-heading alert-success">Order No</td>
                        <td>
                            <asp:Textbox Text="" ID="txtOrderNo" runat="server" />
                        </td>
                    </tr>
                     <tr>
                        <td class="alert-heading alert-success">Remarks</td>
                        <td>
                            <asp:Textbox Text="" TextMode="MultiLine" ID="txtRemarks" runat="server" />
                        </td>
                    </tr>
                    <tr>

                        <td colspan="2">
                            <asp:Button OnClientClick="javascript:return divertNow();" Text="Divert Job" ID="btnDivert"
                                CssClass="btn btn-primary btn-block" runat="server" />
                        </td>
                    </tr>


                </table>
            </div>
        </div>


    </form>
    <form id="notiform" method="post" action="https://myservice.avls.com.my/SendNoti.aspx">
        <input type="hidden" id="t" name="t" runat="server" value="" />
        <input type="hidden" id="m" name="m" runat="server" value="" />
        <input name="d" type="hidden" id="d" runat="server" />
        <input type="hidden" id="skey" name="skey" runat="server" value="" />
        <input type="hidden" id="sid" name="sid" runat="server" value="" />
       
    </form></body>
</html>
