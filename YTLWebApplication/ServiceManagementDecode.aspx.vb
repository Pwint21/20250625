Imports System.Data.SqlClient
Imports System.Collections.Generic
Imports Newtonsoft.Json
Partial Class ServiceManagementDecode
    Inherits System.Web.UI.Page
    Public sb1 As New StringBuilder()
    Public ec As String = "false"
    Public opt As String
    Public sb As New StringBuilder()
    Public suserid As String
    Public userid As String


    Protected Overrides Sub OnInit(ByVal e As System.EventArgs)
        Try

            If Request.Cookies("userinfo") Is Nothing Then
                Response.Redirect("Login.aspx")
            End If


            Dim userid As String = Request.Cookies("userinfo")("userid")
            uid.Value = userid
            Dim role As String = Request.Cookies("userinfo")("role")
            rle.Value = role
            Dim userslist As String = Request.Cookies("userinfo")("userslist")
            ulist.Value = userslist
            Dim suserid As String = Request.QueryString("userid")

            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand
            Dim dr As SqlDataReader
            sb = New StringBuilder()
            If role = "User" Then
                cmd = New SqlCommand("select userid,username from userTBL where userid='" & userid & "' order by username", conn)
            ElseIf role = "SuperUser" Or role = "Operator" Then
                cmd = New SqlCommand("select userid,username from userTBL where userid in(" & userslist & ") order by username", conn)
            Else
                cmd = New SqlCommand("select userid,username from userTBL where role='User' order by username", conn)
            End If
            Try
                conn.Open()
                dr = cmd.ExecuteReader()
                sb.Length = 0
                sb.Append("<select  id=""ddluser"" onchange=""javascript: return refreshTable()""   data-placeholder=""Select User Name"" style=""width:250px;"" class=""chosen""  tabindex=""5"">")
                sb.Append("<option id=""epty"" value=""""></option>")

                If role = "SuperUser" Or role = "Operator" Then
                    sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                    sb.Append("<option value=--AllUsers-->--ALL USERS--</option>")
                Else
                    sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                    sb.Append("<option value=--AllUsers-->--ALL USERS--</option>")
                End If

                Dim firstrecord As Boolean = True
                While dr.Read
                    sb.Append("<option  value=")
                    sb.Append(dr("userid"))
                    sb.Append(">")
                    sb.Append(dr("username").ToString().ToUpper())
                    sb.Append("</option>")
                End While
                sb.Append("</select>")
                dr.Close()
            Catch ex As Exception
                '  Response.Write(ex.Message)
            Finally
                conn.Close()
            End Try
            opt = sb.ToString()
        Catch ex As Exception
        End Try
        MyBase.OnInit(e)
    End Sub

    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        Try

            If Page.IsPostBack = False Then
                Dim userid As String = Request.Cookies("userinfo")("userid")
                Dim role As String = Request.Cookies("userinfo")("role")
                Dim userslist As String = Request.Cookies("userinfo")("userslist")

                Dim suserid As String = Request.QueryString("userid")

                Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
                Dim cmd As SqlCommand
                Dim dr As SqlDataReader
                sb = New StringBuilder()

                If role = "User" Then
                    cmd = New SqlCommand("select userid,username from userTBL where userid='" & userid & "' order by username", conn)
                ElseIf role = "SuperUser" Or role = "Operator" Then
                    cmd = New SqlCommand("select userid,username from userTBL where userid in(" & userslist & ") order by username", conn)

                Else
                    cmd = New SqlCommand("select userid,username from userTBL where role='User' order by username", conn)
                End If
                Try
                    conn.Open()
                    dr = cmd.ExecuteReader()
                    sb.Length = 0
                    sb.Append("<select  id=""ddluser"" onchange=""javascript: return refreshTable()""   data-placeholder=""Select User Name"" style=""width:250px;"" class=""chosen""  tabindex=""5"">")
                    sb.Append("<option id=""epty"" value=""""></option>")

                    If role = "SuperUser" Or role = "Operator" Then
                        sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                        sb.Append("<option value=--AllUsers-->--ALL USERS--</option>")
                    Else
                        sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                        sb.Append("<option value=--AllUsers-->--ALL USERS--</option>")
                    End If

                    Dim firstrecord As Boolean = True
                    If role <> "User" Then
                        ddlusera.Items.Add(New ListItem("-- SELECT USER NAME --", "-- Select User Name --"))
                    End If

                    While dr.Read
                        ddlusera.Items.Add(New ListItem(dr("username"), dr("userid")))
                        sb.Append("<option  value=")
                        sb.Append(dr("userid"))
                        sb.Append(">")
                        sb.Append(dr("username").ToString().ToUpper())
                        sb.Append("</option>")
                    End While
                    sb.Append("</select>")
                    dr.Close()



                Catch ex As Exception
                    '  Response.Write(ex.Message)
                Finally
                    conn.Close()
                End Try
                opt = sb.ToString()
            End If



            fillDrop()

        Catch ex As Exception

        End Try
    End Sub
    Private Sub fillDrop()
        Try
            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim role As String = Request.Cookies("userinfo")("role")
            Dim userslist As String = Request.Cookies("userinfo")("userslist")
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("select userid, username, dbip from userTBL where  role='User' order by username", conn)
            If role = "User" Then
                cmd = New SqlCommand("select userid,username from userTBL where userid='" & userid & "' order by username", conn)
            ElseIf role = "SuperUser" Or role = "Operator" Then
                cmd = New SqlCommand("select userid,username from userTBL where userid in(" & userslist & ") order by username", conn)
            Else
                cmd = New SqlCommand("select userid,username from userTBL where role='User' order by username", conn)
            End If
            Dim dr As SqlDataReader
            sb = New StringBuilder()
            Try
                conn.Open()
                dr = cmd.ExecuteReader()
                suserid = ss.Value
                sb.Length = 0
                sb.Append("<select  id=""ddluser"" onchange=""javascript: return refreshTable()""   data-placeholder=""Select User Group"" style=""width:250px;"" class=""chosen""  tabindex=""5"">")
                sb.Append("<option id=""epty"" value=""""></option>")
                If role <> "User" Then
                    sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                End If
                If suserid <> "--AllUsers--" Then
                    If role = "SuperUser" Or role = "Admin" Then
                        sb.Append("<option value=--AllUsers-->--ALL USERS--</option>")
                    End If

                End If
                Dim i As Integer = 0
                While dr.Read
                    userid = dr("userid")
                    If role = "User" Then
                        Dim ct As Integer = 0
                        Dim firstrecord As Boolean = True
                        If (firstrecord = True) Then
                            firstrecord = False
                            suserid = dr("userid")
                        End If
                        If ct = 0 Then
                            sb.Append("<option selected=""selected""  value=")
                            sb.Append(dr("userid"))
                            sb.Append(">")
                            sb.Append(dr("username").ToString().ToUpper())
                            sb.Append("</option>")

                        End If
                        ct = +1
                    Else
                    End If

                    If suserid = "--AllUsers--" Then
                        If i = 0 Then
                            sb.Append("<option selected=""selected"" value=--AllUsers-->--ALL USERS--</option>")
                            i = +1
                        End If

                    End If
                    If role <> "User" Then
                        If userid = suserid Then
                            sb.Append("<option selected=""selected""  value=")
                            sb.Append(">")
                            sb.Append(dr("username").ToString().ToUpper())
                            sb.Append("</option>")
                        Else
                            sb.Append("<option  value=")
                            sb.Append(dr("userid"))
                            sb.Append(">")
                            sb.Append(dr("username").ToString().ToUpper())
                            sb.Append("</option>")
                        End If

                    End If
                End While
                sb.Append("</select>")
                dr.Close()
            Catch ex As Exception
                '  Response.Write(ex.Message)
            Finally
                conn.Close()
            End Try

            opt = sb.ToString()
        Catch ex As Exception

        End Try
    End Sub


    Public Shared Function GetOdometer(ByVal bdt As String, ByVal plateno As String) As Double
        Dim odometer As Double = 0.0
        Try
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("select top 1 absolute   from  vehicle_odometer where plateno like '" & plateno & "%' and timestamp ='" & Convert.ToDateTime(bdt).ToString("yyyy/MM/dd") & " 00:00:00'and absolute > -1 order by timestamp ", conn)
            Try
                conn.Open()
                odometer = Convert.ToDouble(cmd.ExecuteScalar().ToString())
            Catch ex As Exception
                odometer = 0
            Finally
                conn.Close()
            End Try
        Catch ex As Exception
            odometer = 0
        End Try
        Return odometer
    End Function
End Class

