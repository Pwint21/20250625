Imports System.Data.SqlClient
Imports System.Data
Imports System.Collections.Generic

Partial Class ShipToCodeManagement
    Inherits System.Web.UI.Page
    Public show As Boolean = False
    Public addShiptocode As String = "AddShipToCode.aspx"
    Public divgrid As Boolean = False
    Public ec As String = "false"
    Public sb1 As New StringBuilder()
    Protected Overrides Sub OnInit(ByVal e As System.EventArgs)
        Try
            If Request.Cookies("userinfo") Is Nothing Then
                Response.Redirect("Login.aspx")
            End If
        Catch ex As Exception
        End Try
        MyBase.OnInit(e)
    End Sub
    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load
        Try
            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim role As String = Request.Cookies("userinfo")("role")
            Dim userslist As String = Request.Cookies("userinfo")("userslist")
            If Page.IsPostBack = False Then
                ImageButton1.Attributes.Add("onclick", "return deleteconfirmation();")
                ImageButton1.Attributes.Add("onclick", "return deleteconfirmation();")
            End If
            FillGrid()
        Catch ex As Exception

        End Try
    End Sub
    Public Sub FillGrid()
        Try

            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim userstable As New DataTable
            Dim ok As String = "no"
            Dim condition As String = ""
            Dim r As DataRow
            userstable.Rows.Clear()
            userstable.Columns.Add(New DataColumn("chk"))
            userstable.Columns.Add(New DataColumn("S No"))
            userstable.Columns.Add(New DataColumn("shiptocode"))
            userstable.Columns.Add(New DataColumn("name"))
            userstable.Columns.Add(New DataColumn("address1"))

            'Dim ShipToCodeDict As New Dictionary(Of String, String)

            'Dim conn2 As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            'Dim dr2 As SqlDataReader
            'Dim cmd2 As New SqlCommand("select shiptocode,data,geofencetype from geofence where accesstype=1", conn2)
            'Try
            '    conn2.Open()
            '    dr2 = cmd2.ExecuteReader()
            '    While dr2.Read()
            '        ShipToCodeDict.Add(dr2("shiptocode"), dr2("data"))
            '    End While

            'Catch ex As Exception

            'Finally
            '    conn2.Close()
            'End Try


            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            If Not userid = "--Select User Name--" Then

                Dim cmd As SqlCommand = New SqlCommand("select * from oss_ship_to_code", conn)
                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader()
                Dim i As Int32 = 1
                While dr.Read()
                    r = userstable.NewRow
                    r(0) = "<input type=""checkbox"" name=""chk"" value=""" & dr("shiptocode") & """/>"
                    r(1) = i.ToString()
                    r(2) = "<a href=UpdateShipToCode.aspx?Id=" & dr("shiptocode") & "> " & dr("shiptocode") & " </a>"
                    r(3) = dr("name")
                    Dim d = dr("address1").ToString.Trim() + dr("address2").ToString.Trim() + dr("address3").ToString.Trim() + dr("address4").ToString.Trim()
                    r(4) = d
                    userstable.Rows.Add(r)
                    i = i + 1
                    ok = "yes"
                End While

                conn.Close()
            End If
            If ok = "no" Then
                r = userstable.NewRow
                r(0) = "-"
                r(1) = "-"
                r(2) = "-"
                r(3) = "-"
                r(4) = "-"

                userstable.Rows.Add(r)

            End If

            Session.Remove("exceltable")
            Session.Remove("exceltable2")
            Session("exceltable") = userstable
            ec = "true"
            sb1.Length = 0
            sb1.Append("<thead><tr><th align=""center"" style=""width:20px;""><input type='checkbox' onclick=""javascript:checkall(this);""/></th><th style=""width:35px;"">S No</th><th  style=""width:100px;"">Ship To Code</th><th  style=""width:250px;"">Name</th><th>Address</th></tr></thead>")
            sb1.Append("<tbody>")
            Dim counter As Integer = 1
            For i As Integer = 0 To userstable.Rows.Count - 1

                sb1.Append("<td>")
                sb1.Append(userstable.DefaultView.Item(i)(0))
                sb1.Append("</td>")
                sb1.Append("<td>")
                sb1.Append(userstable.DefaultView.Item(i)(1))
                sb1.Append("</td>")
                sb1.Append("<td>")
                sb1.Append(userstable.DefaultView.Item(i)(2))
                sb1.Append("</td>")
                sb1.Append("<td>")
                sb1.Append(userstable.DefaultView.Item(i)(3))
                sb1.Append("</td>")
                sb1.Append("<td>")
                sb1.Append(userstable.DefaultView.Item(i)(4))
                sb1.Append("</td>")
                sb1.Append("</tr>")
                counter += 1
            Next
            sb1.Append("<tfoot><tr><th><input type='checkbox' onclick=""javascript:checkall(this);""/></th><th>S No</th><th>Ship To Code</th><th>Name</th><th>Address</th></tr></tfoot>")
            sb1.Append("</tbody>")
        Catch ex As Exception
        End Try
    End Sub

    Protected Sub DeleteDriver()

        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim command As SqlCommand
            Dim fuelid As String = ""

            Dim shiptocodeid() As String = Request.Form("chk").Split(",")

            For i As Int32 = 0 To shiptocodeid.Length - 1
                command = New SqlCommand("delete from oss_ship_to_code where shiptocode='" & shiptocodeid(i) & "'", conn)
                Try
                    conn.Open()
                    command.ExecuteNonQuery()
                Catch ex As Exception
                Finally
                    conn.Close()
                End Try
            Next
            FillGrid()
        Catch ex As Exception

        End Try
    End Sub

    Protected Sub ImageButton1_Click(sender As Object, e As System.EventArgs) Handles ImageButton1.Click
        DeleteDriver()
    End Sub
    Protected Sub ImageButton3_Click(sender As Object, e As System.EventArgs) Handles ImageButton3.Click
        DeleteDriver()
    End Sub
End Class
