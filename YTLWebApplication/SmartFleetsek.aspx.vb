Imports System.Data.SqlClient

Partial Class SmartFleetsek
    Inherits System.Web.UI.Page
    Public opt As String
    Public opt1 As String
    Public suserid As String
    Public sb As StringBuilder
    Public pravinid As String = ""
    Public Fuel2Id As String = "false"
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        Try
            If Request.Cookies("userinfo") Is Nothing Then
                Response.Redirect("Login.aspx")
            End If

            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim role As String = Request.Cookies("userinfo")("role")
            Dim userslist As String = Request.Cookies("userinfo")("userslist")
            Dim query As String = ""
            Dim cmd2 As New SqlCommand()
            pravinid = userid
            If userid = "734" Then
                Fuel2Id = "true"
            End If

            Dim dr2 As SqlDataReader
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            cmd2.Connection = conn
            cmd2.CommandText = "select plateno,userid from vehicleTBL where plateno='' order by plateno "
            Dim cmd As SqlCommand = New SqlCommand("select u.userid, u.username,g.groupname from userTBL u join vehicle_group g on u.userid=g.userid and  u.role='User' and u.userid=0 order by u.username,g.groupname", conn)

            If role = "User" Then
                cmd = New SqlCommand("select u.userid, u.username,g.groupname from userTBL u join vehicle_group g on u.userid=g.userid and u.userid='" & userid & "' order by u.username ,g.groupname ", conn)
                cmd2.CommandText = "select plateno,userid from vehicleTBL where userid = '" & userid & "' order by plateno "
            ElseIf role = "SuperUser" Or role = "Operator" Then
                cmd = New SqlCommand("select u.userid, u.username,g.groupname from userTBL u join vehicle_group g on u.userid=g.userid and u.userid in (" & userslist & ") order by u.username ,g.groupname", conn)
                cmd2.CommandText = "select plateno,userid from vehicleTBL where userid in(" & userslist & ") order by plateno "
            ElseIf role = "Admin" Then
                cmd = New SqlCommand("select u.userid, u.username,g.groupname from userTBL u join vehicle_group g on u.userid=g.userid and  u.role='User' order by u.username,g.groupname", conn)
                cmd2.CommandText = "select plateno,userid from vehicleTBL  order by plateno "
            End If

            Dim dr As SqlDataReader
            sb = New StringBuilder()

            Try
                conn.Open()
                dr = cmd.ExecuteReader()
                sb.Append("<select  id=""ddluser"" onchange=""javascript: return refreshTable()""  data-placeholder=""Select User Group"" style=""width:250px;"" class=""chosen""  tabindex=""5"">")
                sb.Append("<option id=""epty"" value=""""></option>")
                Dim ct As Integer = 0
                Dim firstrecord As Boolean = True

                If (role <> "User") Then
                    sb.Append("<option selected=""selected"" value=""0"">SELECT USERNAME</option>")
                    sb.Append("<option  value=""All"">ALL USERS</option>")
                    suserid = 0
                    ct = 1
                Else
                    suserid = userid
                End If
                Dim lastUnm As String = ""
                userid = ""
                While dr.Read

                    If userid <> dr("userid") Then
                        If ct = 0 Then
                            sb.Append("<option selected=""selected""  value=")
                            sb.Append(dr("userid"))
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
                    ct += 1

                    Dim group As String = dr("groupname")
                    sb.Append("<option  value=")
                    sb.Append("""" & dr("userid") & "," & dr("groupname") & """")
                    sb.Append(">")
                    sb.Append("" & System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(dr("groupname").ToString().ToLower()) & "")
                    sb.Append("</option>")

                    userid = dr("userid")
                End While
                dr.Close()

                Try
                    dr2 = cmd2.ExecuteReader()
                    While dr2.Read()
                        sb.Append("<option  value=")
                        sb.Append("""" & dr2("userid") & ";" & dr2("plateno") & """")
                        sb.Append(">")
                        sb.Append("" & System.Globalization.CultureInfo.CurrentCulture.TextInfo.ToTitleCase(dr2("plateno").ToString().ToUpper()) & "")
                        sb.Append("</option>")
                    End While
                Catch ex As Exception

                Finally
                    conn.Close()
                    dr2.Close()
                End Try
                sb.Append("</select>")
            Catch ex As Exception

            Finally
                conn.Close()
            End Try

            opt = sb.ToString()

        Catch ex As Exception
            Response.Write(ex.Message)
        End Try
    End Sub


End Class
