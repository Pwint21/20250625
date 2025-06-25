Imports System.Data.SqlClient
Imports AspMap
Partial Class ShowDiversionList
    Inherits System.Web.UI.Page
    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load

        Try
            If Not IsPostBack Then
                tblDisplay.Visible = False
                Dim id As String = Request.QueryString("id")
                Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
                Dim cmd As SqlCommand = New SqlCommand("Select top 1 o.dn_no,o.source_supply,isnull(L.Item_Name,'') as Item_Name,isnull(L.Item_Name,'') as Item_Name,l.UOM,o.dn_qty,o.plateno,o.weight_outtime,o.productcode,o.productname,o.div_remark from ((select * from  oss_patch_out where patch_no='" & id & "') o left outer join O2D_LoadTableData l on o.dn_no=l.DN_No ) ", conn2)
                Dim plateno As String = ""
                Dim shiptocode As String = ""
                Dim status As String = ""
                Dim shiptoname As String = ""
                Dim DiversionRemarks As String = ""
                Try
                    conn2.Open()
                    Dim dr2 As SqlDataReader = cmd.ExecuteReader()

                    While dr2.Read()
                        plateno = dr2("plateno")
                        txtDnNo1.Text = dr2("dn_no").ToString()
                        shiptocode = dr2("Item_Name").ToString()
                        shiptoname = dr2("productcode")
                        DiversionRemarks = dr2("div_remark").ToString()
                    End While

                Catch ex As Exception
                    Response.Write("Page Load" & ex.Message)
                Finally
                    conn2.Close()
                End Try

                txtPlateno.Text = plateno
                txtSTC.Text = shiptocode
                txtShipToName.Text = shiptoname
                txtremarksarea.Value = DiversionRemarks
                Dim driverIc As String = ""
                Dim deviceid As String = ""
                m.Value = "You job has been diverted. Please check your new diverted location."
                t.Value = "Diversion Notification Alert"
                skey.Value = "AAAAYk9xI5w:APA91bHcEWZlDNW9qvnzRnysep87KV2li1W8dMQ5JE-_2ER5SRjioR76ayMT810Isvs39qLv1DshkVxZU8vv_u9r5C0-nk7iSibsSECzVv1f6w9BpaoPROx4cIXy9kwUjMKpurou5GEa"
                sid.Value = "apktest089"


                Try
                    Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
                    Dim cmd2 As SqlCommand = New SqlCommand("select driver_ic from oss_patch_out where dn_no=@dn", conn)
                    cmd2.Parameters.AddWithValue("@dn", txtDnNo1.Text)
                    Try
                        conn.Open()
                        driverIc = cmd2.ExecuteScalar().ToString()
                    Catch Sqex As SqlException
                        Response.Write("3.1." & Sqex.Message)
                    Catch ex As Exception
                        Response.Write("3." & ex.Message)
                    Finally
                        conn2.Close()
                    End Try
                Catch ex As SystemException

                End Try
                Try
                    Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                    Dim cmd2 As SqlCommand = New SqlCommand("select IsNull(deviceId,'') as deviceId from driver where driver_ic =@dic", conn)
                    cmd2.Parameters.AddWithValue("@dic", driverIc)
                    Try
                        conn.Open()
                        deviceid = cmd2.ExecuteScalar()
                        d.Value = deviceid '"ciFBOUpJkFI:APA91bGlCKT15gcWDUZQWqZq7ALxUV4GwZKCLVS6H7B8TI3njOq7tdTisKycDYwMx0_69YW6HyNjqn8HL5riNx4tv2uAGUWR-n34-sKhDWQv01HRxhFmQlJxqava8VM1KgQJmMse-srV"
                        '  d.Value = "ciFBOUpJkFI:APA91bGlCKT15gcWDUZQWqZq7ALxUV4GwZKCLVS6H7B8TI3njOq7tdTisKycDYwMx0_69YW6HyNjqn8HL5riNx4tv2uAGUWR-n34-sKhDWQv01HRxhFmQlJxqava8VM1KgQJmMse-srV"
                    Catch Sqex As SqlException
                        ' Response.Write("3.1." & Sqex.Message)
                    Catch ex As Exception
                        ' Response.Write("3." & ex.Message)
                    Finally
                        conn.Close()
                    End Try
                Catch ex As SystemException

                End Try
            End If

        Catch ex As SystemException

        End Try
    End Sub


    Protected Sub btnSearchDn_Click(sender As Object, e As EventArgs) Handles btnSearchDn.Click
        tblDisplay.Visible = True
        Try

            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim cmd As SqlCommand = New SqlCommand("sp_LoadDivertedJobs", conn2)
            cmd.CommandType = Data.CommandType.StoredProcedure
            cmd.Parameters.AddWithValue("@loadid", txtDnNo.Text)
            hdnLid.Value = txtDnNo.Text

            Try
                conn2.Open()
                Dim dr2 As SqlDataReader = cmd.ExecuteReader()

                If dr2.Read() Then
                    lblCo.Text = dr2("co").ToString()
                    lblDnNo.Text = dr2("dn_no").ToString()
                    lblProduct.Text = dr2("productname").ToString()
                    lblTonnage.Text = dr2("dn_qty").ToString() & " " & dr2("uom").ToString()
                    lblOpenLoad.Text = dr2("OpenLoadCount").ToString()
                    lblONo.Text = dr2("Order_No").ToString()
                    txtOrderNo.Text = dr2("Order_No").ToString()
                    lblCustomerPO.Text = dr2("Cust_PO").ToString()
                    lblCustomer.Text = dr2("Cust_Name").ToString()
                    lblDelTo.Text = dr2("DelTo").ToString()
                    lblDestination.Text = dr2("Destination").ToString()
                    lblSplIns.Text = dr2("sp_ins").ToString()
                    lblSiteId.Text = dr2("shipto_id").ToString()
                End If

            Catch ex As Exception
                ' Response.Write(ex.Message)
            Finally
                conn2.Close()
            End Try

        Catch ex As SystemException

        End Try
    End Sub
    Protected Sub btnDivert_Click(sender As Object, e As EventArgs) Handles btnDivert.Click
        Dim result As Int16 = 0
        Try

            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim cmd As SqlCommand = New SqlCommand("insert into oss_diversion_log (DivSiteId,OrderNo,remarks,FromLoadDN,ToLoadDn,userid,timestamp) values (@DivSiteId,@OrderNo,@remarks,@FromLoadDN,@ToLoadDn,@userid,@timestamp)", conn2)
            cmd.Parameters.AddWithValue("@FromLoadDN", txtDnNo1.Text)
            cmd.Parameters.AddWithValue("@ToLoadDn", lblDnNo.Text)
            cmd.Parameters.AddWithValue("@remarks", txtRemarks.Text)
            cmd.Parameters.AddWithValue("@OrderNo", txtOrderNo.Text)
            cmd.Parameters.AddWithValue("@DivSiteId", lblSiteId.Text)
            cmd.Parameters.AddWithValue("@userid", Request.Cookies("userinfo")("userid"))
            cmd.Parameters.AddWithValue("@timestamp", DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss"))
            Try
                conn2.Open()
                cmd.ExecuteNonQuery()
            Catch ex As Exception
                Response.Write("1." & ex.Message)
            Finally
                conn2.Close()
            End Try

        Catch ex As SystemException

        End Try

        Try

            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim cmd As SqlCommand = New SqlCommand("sp_UpdateDiversionData", conn2)
            cmd.CommandType = Data.CommandType.StoredProcedure
            cmd.Parameters.AddWithValue("@dsid", lblSiteId.Text)
            cmd.Parameters.AddWithValue("@remark", txtRemarks.Text)
            cmd.Parameters.AddWithValue("@dn_no", txtDnNo1.Text)
            cmd.Parameters.AddWithValue("@OrderNo", txtOrderNo.Text)
            cmd.Parameters.AddWithValue("@loadid", hdnLid.Value)
            Try
                conn2.Open()
                result = cmd.ExecuteNonQuery()
                If result > 0 Then
                    Response.Write("<script>sendNoti(); alert('Job has been diverted successfully.'); this.parent.parent.closePopup();</script>")
                End If
            Catch Sqex As SqlException
                Response.Write("2.1." & Sqex.Message)
            Catch ex As Exception
                Response.Write("2." & ex.Message)
            Finally
                conn2.Close()
            End Try

        Catch ex As SystemException

        End Try
    End Sub

    Protected Sub btndivertjob_Click(sender As Object, e As EventArgs) Handles btndivertjob.Click
        Dim result As Int16 = 0
        Try
            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            'Dim cmd As SqlCommand = New SqlCommand("sp_UpdateDiversionData_new", conn2)
            Dim cmd As SqlCommand = New SqlCommand("update  oss_patch_out Set div_remark=@remark, status = 15 where dn_no=@dn_no  ", conn2)
            cmd.Parameters.AddWithValue("@remark", txtremarksarea.InnerText)
            cmd.Parameters.AddWithValue("@dn_no", txtDnNo1.Text)
            Try
                conn2.Open()
                Result = cmd.ExecuteNonQuery()
                If Result > 0 Then
                    Response.Write("<script>alert('Job has been diverted successfully.'); this.parent.closePopup();</script>")
                End If
            Catch Sqex As SqlException
                Response.Write("2.1." & Sqex.Message)
            Catch ex As Exception
                Response.Write("2." & ex.Message)
            Finally
                conn2.Close()
            End Try

        Catch ex As SystemException

        End Try
    End Sub

    Protected Sub btncanceldivertjob_Click(sender As Object, e As EventArgs) Handles btncanceldivertjob.Click
        Dim result As Int16 = 0
        Try
            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim cmd As SqlCommand = New SqlCommand("sp_UpdateCancelDivert", conn2)
            cmd.CommandType = Data.CommandType.StoredProcedure
            cmd.Parameters.AddWithValue("@dn_no", txtDnNo1.Text)
            Try
                conn2.Open()
                result = cmd.ExecuteNonQuery()
                If result > 0 Then
                    Response.Write("<script>alert('Job diversion has been cancelled successfully.'); this.parent.closePopup();</script>")
                End If
            Catch Sqex As SqlException
                Response.Write("2.1." & Sqex.Message)
            Catch ex As Exception
                Response.Write("2." & ex.Message)
            Finally
                conn2.Close()
            End Try

        Catch ex As SystemException

        End Try
    End Sub
End Class
