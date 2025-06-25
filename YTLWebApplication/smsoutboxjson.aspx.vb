Imports System.Data.SqlClient
Imports Newtonsoft.Json

Partial Class smsoutboxjson
    Inherits System.Web.UI.Page

    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load
        Dim ddlu As String = Request.QueryString("u")
        Dim ddlp As String = Request.QueryString("ddlp")
        Dim bdt As String = Request.QueryString("bdt")
        Dim edt As String = Request.QueryString("edt")

        Dim luid As String = Request.QueryString("luid")
        Dim role As String = Request.QueryString("role")
        Dim userlist As String = Request.QueryString("userslist")

        DisplayLogInformation(ddlu, ddlp, bdt, edt, luid, role, userlist)

    End Sub

    Public Sub DisplayLogInformation(ByVal ddlu As String, ByVal ddlp As String, ByVal bdt As String, ByVal edt As String, ByVal luid As String, ByVal role As String, ByVal userslist As String)
        Dim json As String
        Dim aa As New ArrayList()
        Dim a As ArrayList
        Try

            Dim begindatetime As String = bdt
            Dim enddatetime As String = edt
            Dim userid As String = ddlu
            Dim plateno As String = ddlp
            Dim uid As String = luid

            Dim t As New DataTable
            t.Columns.Add(New DataColumn("S No"))
            t.Columns.Add(New DataColumn("Plate No"))
            t.Columns.Add(New DataColumn("Date Time"))
            t.Columns.Add(New DataColumn("Message"))
            t.Columns.Add(New DataColumn("Mobile No"))
            t.Columns.Add(New DataColumn("Server"))
            t.Columns.Add(New DataColumn("Cost"))


            Dim query As String = ""
            If ddlu <> "--All Users--" Then
                If ddlp = "--All Plate No--" Then
                    query = "select m.plateno,m.datetime,m.message,m.mobileno,m.server from sms_outbox m where m.datetime between '" & begindatetime & "' and '" & enddatetime & "' and m.userid='" & ddlu & "'"
                Else
                    query = "select m.plateno,m.datetime,m.message,m.mobileno,m.server from sms_outbox m where m.datetime between '" & begindatetime & "' and '" & enddatetime & "' and m.plateno='" & ddlp & "'"
                End If
            Else
                If ddlp = "--All Plate No--" Then
                    If role = "SuperUser" Or role = "Operator" Then
                        query = "select m.plateno,m.datetime,m.message,m.mobileno,m.server from sms_outbox m where m.datetime between '" & begindatetime & "' and '" & enddatetime & "' and m.userid in (" & userslist & ")"
                    ElseIf role = "Admin" Then
                        query = "select m.plateno,m.datetime,m.message,m.mobileno,m.server from sms_outbox m where m.datetime between '" & begindatetime & "' and '" & enddatetime & "'"
                    End If
                Else
                    query = "select m.plateno,m.datetime,m.message,m.mobileno,m.server from sms_outbox m where m.datetime between '" & begindatetime & "' and '" & enddatetime & "' and m.plateno='" & ddlp & "'"
                End If
            End If
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand(query, conn)
            Try
                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader()

                Dim r As DataRow
                Dim i As Int64 = 1
                Dim cost As Single = 0.2

                While dr.Read
                    r = t.NewRow
                    r(0) = i.ToString()
                    r(1) = dr("plateno")
                    r(2) = Convert.ToDateTime(dr("datetime")).ToString("yyyy/MM/dd HH:mm:ss")
                    r(3) = dr("message").ToString()
                    r(4) = dr("mobileno").ToString()
                    r(5) = dr("server").ToString()
                    r(6) = cost.ToString("0.00")


                    t.Rows.Add(r)
                    i = i + 1
                End While

                If t.Rows.Count = 0 Then
                    r = t.NewRow
                    r(0) = "--"
                    r(1) = "--"
                    r(2) = "--"
                    r(3) = "--"
                    r(4) = "--"
                    r(5) = "--"
                    r(6) = "--"

                    t.Rows.Add(r)
                End If

            Catch ex As Exception

            Finally
                conn.Close()
            End Try


            If (t.Rows.Count > 0) Then
                For i As Integer = 0 To t.Rows.Count - 1
                    Try
                        a = New ArrayList
                        a.Add(t.DefaultView.Item(i)(0))
                        a.Add(t.DefaultView.Item(i)(1))
                        a.Add(t.DefaultView.Item(i)(2))
                        a.Add(t.DefaultView.Item(i)(3))
                        a.Add(t.DefaultView.Item(i)(4))
                        a.Add(t.DefaultView.Item(i)(5))
                        a.Add(Convert.ToSingle(t.DefaultView.Item(i)(6)))
                        aa.Add(a)
                    Catch ex As Exception

                    End Try
                Next
            Else

            End If

            HttpContext.Current.Session.Remove("exceltable")
            HttpContext.Current.Session.Remove("exceltable2")
            HttpContext.Current.Session.Remove("exceltable3")
            HttpContext.Current.Session.Remove("tempTable")

            HttpContext.Current.Session("exceltable") = t
            json = JsonConvert.SerializeObject(aa, Formatting.None)
            Response.Write(json)
        Catch ex As Exception
            json = ex.Message
        End Try
    End Sub

End Class
