Imports System.Data.SqlClient
Imports System.Data

Partial Class SmsOutboxReport
    Inherits System.Web.UI.Page

    Public show As Boolean = False
    Public ec As String = "false"

    Protected Overrides Sub OnInit(ByVal e As System.EventArgs)
        Try

            If Request.Cookies("userinfo") Is Nothing Then
                Response.Redirect("Login.aspx")
            End If

            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand
            Dim dr As SqlDataReader

            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim role As String = Request.Cookies("userinfo")("role")
            Dim userslist As String = Request.Cookies("userinfo")("userslist")

            cmd = New SqlCommand("select username,userid from userTBL where role='User' order by username", conn)

            If role = "User" Then
                cmd = New SqlCommand("select username,userid from userTBL where userid='" & userid & "' order by username", conn)
            ElseIf role = "SuperUser" Or role = "Operator" Then
                cmd = New SqlCommand("select username,userid from userTBL where userid in(" & userslist & ") order by username", conn)
            End If

            conn.Open()

            dr = cmd.ExecuteReader()

            If role = "Admin" Or role = "Super User" Or role = "Operator" Then
                ddluser.Items.Add(New ListItem("--Select User Name--", "--Select User Name--"))
                ddluser.Items.Add(New ListItem("--All Users--", "--All Users--"))
            End If
            While dr.Read()
                ddluser.Items.Add(New ListItem(dr("username"), dr("userid")))
            End While

            conn.Close()

        Catch ex As Exception

        End Try

        MyBase.OnInit(e)
    End Sub

    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        Try
            If Page.IsPostBack = False Then
                ImageButton1.Attributes.Add("onclick", "return mysubmit()")
                txtBeginDate.Value = Now().ToString("yyyy/MM/dd")
                txtEndDate.Value = Now().ToString("yyyy/MM/dd")
                Dim role As String = Request.Cookies("userinfo")("role")

                If role = "User" Then
                    DisplayGrid()
                End If

            End If
        Catch ex As Exception

        End Try
    End Sub

    Protected Sub ImageButton1_Click(ByVal sender As Object, ByVal e As System.Web.UI.ImageClickEventArgs) Handles ImageButton1.Click
        DisplayGrid()
    End Sub

    Protected Sub DisplayGrid()
        Dim begindatetime As String = txtBeginDate.Value & " " & ddlbh.SelectedValue & ":" & ddlbm.SelectedValue & ":00"
        Dim enddatetime As String = txtEndDate.Value & " " & ddleh.SelectedValue & ":" & ddlem.SelectedValue & ":59"

        Dim smstable As New DataTable

        smstable.Columns.Add(New DataColumn("S No"))
        smstable.Columns.Add(New DataColumn("Date Time"))
        smstable.Columns.Add(New DataColumn("Message"))
        smstable.Columns.Add(New DataColumn("SIM No"))
        smstable.Columns.Add(New DataColumn("Cost"))

        Dim userid As String = ddluser.SelectedValue
        Dim role As String = Request.Cookies("userinfo")("role")
        Dim userslist As String = Request.Cookies("userinfo")("userslist")

        Dim r As DataRow

        Dim totalcost As Int32 = 0

        If Not userid = "--Select User Name--" Then

            'Read data from database server
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim condition As String = ""
            If ddlmode.SelectedValue = 0 Then
                condition = ""
            ElseIf ddlmode.SelectedValue = 1 Then
                condition = " and mode=0"
            ElseIf ddlmode.SelectedValue = 2 Then
                condition = " and mode=1"
            End If
            Dim cmd As SqlCommand = New SqlCommand("select convert(varchar(19),datetime,120) as datetime,message,mobileno,mode from sms_outbox where message not like '(C%' and userid='" & userid & "'" & condition & " and datetime between '" & begindatetime & "' and '" & enddatetime & "' order by datetime", conn)

            If userid = "--All Users--" Then
                If role = "Admin" Then
                    cmd = New SqlCommand("select convert(varchar(19),datetime,120) as datetime,message,mobileno,mode from sms_outbox where message not like '(C%' and datetime between '" & begindatetime & "' and '" & enddatetime & "'" & condition & " order by datetime", conn)
                ElseIf role = "SuperUser" Or role = "Operator" Then
                    cmd = New SqlCommand("select convert(varchar(19),datetime,120) as datetime,message,mobileno,mode from sms_outbox where message not like '(C%' and userid in(" & userslist & ")" & condition & " and datetime between '" & begindatetime & "' and '" & enddatetime & "' order by datetime", conn)
                End If
            End If

            Dim dr As SqlDataReader

            conn.Open()
            dr = cmd.ExecuteReader()

            Dim i As Int32 = 1
            While dr.Read()
                r = smstable.NewRow
                r(0) = i
                r(1) = dr("datetime")
                r(2) = dr("Message")
                r(3) = dr("mobileno")
                r(4) = "20  &cent;"
                smstable.Rows.Add(r)
                totalcost = totalcost + 20
                i = i + 1
            End While
            conn.Close()
        End If


        If smstable.Rows.Count = 0 Then
            r = smstable.NewRow
            r(0) = "--"
            r(1) = "--"
            r(2) = "--"
            r(3) = "--"
            r(4) = "--"
            smstable.Rows.Add(r)
        Else
            r = smstable.NewRow
            r(0) = ""
            r(1) = ""
            r(2) = ""
            r(3) = "&nbsp;Total Cost"
            If totalcost > 100 Then
                Dim tempvalue As Double = totalcost / 100
                r(4) = tempvalue.ToString("0.00") & " RM"
            Else
                r(4) = totalcost & " &cent;"
            End If

            smstable.Rows.Add(r)
            If totalcost > 100 Then
                Dim tempvalue As Double = totalcost / 100
            End If
        End If
        Session.Remove("exceltable")
        Session.Remove("exceltable2")
        Session("exceltable") = smstable
        GridView1.PageSize = noofrecords.SelectedValue
        ec = "true"
        GridView1.DataSource = smstable
        GridView1.DataBind()

        If GridView1.PageCount > 1 Then
            show = True
        End If

    End Sub
    Protected Sub GridView1_PageIndexChanging(ByVal sender As Object, ByVal e As System.Web.UI.WebControls.GridViewPageEventArgs) Handles GridView1.PageIndexChanging
        Try

            GridView1.PageSize = noofrecords.SelectedValue
            GridView1.DataSource = Session("exceltable")
            GridView1.PageIndex = e.NewPageIndex
            GridView1.DataBind()

            ec = "true"
            show = True

        Catch ex As Exception

        End Try
    End Sub
End Class

