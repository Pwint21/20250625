Imports System.Data
Imports System.Data.SqlClient
Imports Newtonsoft.Json
Imports System.Net.Mail

Partial Class ServiceingLogJson
    Inherits System.Web.UI.Page
    Private Sub GetTicketInformation(ByVal UID As String, ByVal role As String, ByVal dates As String, ByVal tdates As String)
        Dim aa As ArrayList = New ArrayList()
        Dim a As ArrayList
        Dim json As String
        Try

            Dim userid As String = UID
            Dim userstable As DataTable = New DataTable()
            userstable.Columns.Add("sno")
            userstable.Columns.Add("raiseddate")
            userstable.Columns.Add("plateno")
            userstable.Columns.Add("servicetype")
            userstable.Columns.Add("username")
            userstable.Columns.Add("reportedby")
            userstable.Columns.Add("remarks")
            userstable.Columns.Add("pic")
            userstable.Columns.Add("status")
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand
            If role = "Admin" Or role = "AdminViewer1" Or role = "AdminViewer2" Then
                cmd = New SqlCommand("select t1.plateno,t1.servicetype,t1.timestamp,t1.remarks,t2.username,t1.pic,dbo.fn_getusername_plateno (t1.plateno) as Uname,t1.status from vehicle_service_log t1 left outer join userTBL t2 on t2.userid=t1.reportedby where t1.timestamp between '" & Convert.ToDateTime(dates).ToString("yyyy/MM/dd 00:00:00") & "' and '" & Convert.ToDateTime(tdates).ToString("yyyy/MM/dd 23:59:59") & "' order by t1.timestamp", conn)
            Else
                If userid = "1967" Then
                    cmd = New SqlCommand("select t1.plateno,t1.servicetype,t1.timestamp,t1.remarks,t2.username,t1.pic,dbo.fn_getusername_plateno (t1.plateno) as Uname,t1.status from vehicle_service_log t1 left outer join userTBL t2 on t2.userid=t1.reportedby where t1.timestamp between '" & Convert.ToDateTime(dates).ToString("yyyy/MM/dd 00:00:00") & "' and '" & Convert.ToDateTime(tdates).ToString("yyyy/MM/dd 23:59:59") & "' order by t1.timestamp", conn)
                Else
                    cmd = New SqlCommand("select t1.plateno,t1.servicetype,t1.timestamp,t1.remarks,t2.username,t1.pic,dbo.fn_getusername_plateno (t1.plateno) as Uname,t1.status from vehicle_service_log t1 left outer join userTBL t2 on t2.userid=t1.reportedby where t1.userid=" & userid & " and t1.timestamp between '" & Convert.ToDateTime(dates).ToString("yyyy/MM/dd 00:00:00") & "' and '" & Convert.ToDateTime(tdates).ToString("yyyy/MM/dd 23:59:59") & "' order by t1.timestamp", conn)
                End If
            End If
            Dim dr As SqlDataReader
            conn.Open()
            dr = cmd.ExecuteReader()
            Dim i As Int32 = 0
            While (dr.Read())
                Dim r As DataRow
                r = userstable.NewRow()
                r("sno") = i.ToString()
                r("raiseddate") = Convert.ToDateTime(dr("timestamp")).ToString("yyyy/MM/dd HH:mm:ss")
                r("plateno") = dr("plateno")
                r("pic") = dr("pic")
                r("servicetype") = dr("servicetype")
                r("remarks") = dr("remarks")
                r("username") = dr("Uname")
                r("reportedby") = dr("username")
                r("status") = dr("status")
                userstable.Rows.Add(r)
                i += 1
            End While
            If userstable.Rows.Count = 0 Then
                Dim r As DataRow
                r = userstable.NewRow()
                r("sno") = ""
                r("raiseddate") = ""
                r("plateno") = ""
                r("pic") = ""
                r("servicetype") = ""
                r("remarks") = ""
                r("username") = ""
                r("reportedby") = ""
                r("status") = ""
                userstable.Rows.Add(r)
            End If

            For Each row As DataRow In userstable.Rows
                a = New ArrayList()
                a.Add(row(0))
                a.Add(row(4))
                a.Add(row(1))
                a.Add(row(2))
                a.Add(row(3))
                a.Add(row(8))
                a.Add(row(5))
                a.Add(row(7))
                a.Add(row(6))
                aa.Add(a)
            Next
            Session.Remove("exceltable")
            Session("exceltable") = userstable
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""aaData"":" & JsonConvert.SerializeObject(aa, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)
        Catch ex As Exception
            Response.Write(ex.Message)
        End Try

    End Sub

    Private Sub GetTrucks(ByVal uid As String)
        Dim a As New ArrayList
        Dim json As String
        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As New SqlCommand("select plateno from vehicletbl where userid=" & uid & "", conn)
            conn.Open()
            Dim dr As SqlDataReader = cmd.ExecuteReader()
            While dr.Read()
                a.Add(dr("plateno"))
            End While
        Catch ex As Exception

        End Try
        Dim jss As New Newtonsoft.Json.JsonSerializer()
        json = "{""aaData"":" & JsonConvert.SerializeObject(a, Formatting.None) & "}"
        Response.ContentType = "text/plain"
        Response.Write(json)
    End Sub
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        Dim UID As String = Request.QueryString("u")
        Dim role As String = Request.QueryString("role")
        Dim opr As String = Request.QueryString("opr")
        If (opr = "0") Then
            Dim ddate As String = Request.QueryString("d")
            If ddate = "" Then
                ddate = DateTime.Now().ToString("yyyy/MM/dd")
            End If
            Dim tddate As String = Request.QueryString("td")
            If tddate = "" Then
                tddate = DateTime.Now().ToString("yyyy/MM/dd")
            End If
            GetTicketInformation(UID, role, ddate, tddate)
        ElseIf opr = 1 Then
            Dim plateno As String = Request.QueryString("P")
            Dim servicetype As String = Request.QueryString("stype")
            Dim status As String = Request.QueryString("status")
            Dim remarks As String = Request.QueryString("rem")
            Dim serexpdt As String = Request.QueryString("expdt")
            Dim pic As String = Request.QueryString("pic")
            insertNewService(plateno, servicetype, status, remarks, serexpdt, pic)
        ElseIf opr = 2 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            GetServiceDetails(serviceid, UID)
        ElseIf opr = 3 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            Dim comment As String = Request.QueryString("Comment")
            insertComment(UID, serviceid, comment)
        ElseIf opr = 4 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            Dim st As String = Request.QueryString("st")
            Getcomments(serviceid, st)
        ElseIf opr = 5 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            Dim asto As String = Request.QueryString("asto")
            Dim remarks As String = Request.QueryString("remarks")
            AssignService(serviceid, asto, UID, remarks)
        ElseIf opr = 6 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            Dim username As String = Request.Cookies("userinfo")("username")
            Dim serviceddate As String = Request.QueryString("date")
            Dim compremarks As String = Request.QueryString("remarks")
            CloseService(serviceid, UID, username, serviceddate, compremarks)
        ElseIf opr = 7 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            ReceiveService(serviceid, UID)
        ElseIf opr = 8 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            Dim serdate As String = Request.QueryString("srvdt")
            changeServicedate(serviceid, UID, serdate)
        ElseIf opr = 9 Then
            Dim serviceid As String = Request.QueryString("serviceid")
            ReOpenService(serviceid, UID)
        ElseIf opr = 10 Then
            Dim plateno As String = Request.QueryString("P")
            Dim servicetype As String = Request.QueryString("stype")
            Dim prioryty As String = Request.QueryString("pre")
            Dim remarks As String = Request.QueryString("rem")
            Dim serexpdt As String = Request.QueryString("expdt")
            Dim seriveid As String = Request.QueryString("u")
            updateservice(seriveid, plateno, servicetype, prioryty, remarks, serexpdt)
        ElseIf opr = 11 Then
            Dim userid As String = Request.QueryString("u")
            GetTrucks(userid)
        End If


    End Sub

    Private Sub updateservice(ByVal serviceid As String, ByVal plateno As String, ByVal servicetype As String, ByVal prioryty As String, ByVal remarks As String, ByVal serexpdt As String)
        Dim res As String
        Dim json As String
        Dim Discription As String = remarks.Replace("\n", "<br/>")
        Try


            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("update vehicle_services set plateno='" & plateno & "',servicetype='" & servicetype & "', priority ='" & prioryty & "', remarks='" & remarks & "',serexpdtime ='" & serexpdt & "' where serviceid='" & serviceid & "'", conn)
            conn.Open()
            res = cmd.ExecuteNonQuery()
            conn.Close()
            If res = 1 Then
                ' sendemail(serviceid, plateno)
            End If
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)
        Catch ex As Exception
            Response.Write(ex.Message)
        End Try
    End Sub

    Private Sub insertNewService(ByVal plateno As String, ByVal servicetype As String, ByVal status As String, ByVal remarks As String, ByVal timestamp As String, ByVal pic As String)
        Dim res As String
        Dim json As String
        Dim Discription As String = remarks.Replace("\n", "<br/>")
        Try
            Dim userid As String = Request.Cookies("userinfo")("userid")
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("sp_InsertNewserviceLog", conn)
            cmd.CommandType = CommandType.StoredProcedure
            cmd.Parameters.AddWithValue("@plateno", plateno)
            cmd.Parameters.AddWithValue("@servicetype", servicetype)
            cmd.Parameters.AddWithValue("@status", status)
            cmd.Parameters.AddWithValue("@remarks", remarks)
            cmd.Parameters.AddWithValue("@userid", userid)
            cmd.Parameters.AddWithValue("@times", timestamp)
            cmd.Parameters.AddWithValue("@pic", pic)
            conn.Open()
            res = cmd.ExecuteNonQuery()
            conn.Close()
            If res = 1 Then
                'sendemail(UID, plateno)
            End If
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception
            Response.Write(ex.Message)
        End Try
    End Sub

    Public Sub sendemail(ByVal userid As String, ByVal plateno As String)
        Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
        Try

            Dim message As New MailMessage
            message.From = New MailAddress("alerts@g1.com.my", "LAFARGE SERVICING")

            Dim cmd As SqlCommand = New SqlCommand("select top 1 serviceId,servicetype,remarks,serexpdtime,vs.userid,ut.username,vs.timestamp from vehicle_services vs left outer join userTBL ut on vs.userid=ut.userid where vs.userid='" & userid & "' and plateno='" & plateno & "' order by vs.timestamp desc", conn)
            conn.Open()
            Dim dr As SqlDataReader
            dr = cmd.ExecuteReader()
            Dim sb As StringBuilder
            sb = New StringBuilder()
            If dr.Read() Then
                message.To.Add("cs.gstb@g1.com.my")
                'message.To.Add("anil@g1.com.my")
                message.Priority = MailPriority.High
                message.IsBodyHtml = True
                message.Subject = " Lafarge Service No: <" & dr("serviceid") & "> And Type : <" & dr("servicetype") & ">"
                sb.Append("Hi ")
                sb.Append("<br/> Following is the details of the service :")
                sb.Append("<br/><br/>User Name=")
                sb.Append(dr("username"))
                sb.Append("<br/>Plate Number=")
                sb.Append(plateno)
                sb.Append("<br/>Service Type= " & dr("servicetype"))
                If IsDBNull(dr("serexpdtime")) Then

                Else
                    sb.Append("<br/>Service Expected Date & Time= " & Convert.ToDateTime(dr("serexpdtime")).ToString("dd/MM/yyyy HH:mm"))
                End If

                sb.Append("<br/><u> Remarks :</u>")
                sb.Append("<br/>" & dr("remarks"))
                sb.Append("<br/><br/> Thanks.")
                sb.Append("<br/> Global Alerts Team ")
                message.Body = sb.ToString()
            End If

            Dim client As New SmtpClient("203.223.159.180", 25)
            ' client.Credentials = New NetworkCredential("alerts@g1.com.my", "1@3$5^7*")

            client.EnableSsl = False

            client.Send(message)
        Catch ex As Exception
        Finally
            conn.Close()
        End Try
    End Sub

    Private Sub insertComment(ByVal UID As String, ByVal Serviceid As String, ByVal Comment As String)
        Dim res As String
        Dim json As String

        Try
            Dim Discription As String = Comment.Replace("\n", "<br/>")
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("insert into services_comments_history(serviceid,commentedby,comment,timestamp) values('" & Serviceid & "','" & UID & "','" & Discription & "','" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "') ", conn)

            conn.Open()
            res = cmd.ExecuteNonQuery()
            conn.Close()

            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception
            Response.Write(ex.Message)
        End Try

    End Sub

    Private Sub AssignService(ByVal Serviceid As String, ByVal assignedto As String, ByVal assignedby As String, ByVal remarks As String)
        Dim res As String
        Dim json As String
        Dim dr As SqlDataReader
        Dim Discription As String = remarks.Replace("\n", "<br/>")
        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd2 As SqlCommand = New SqlCommand("select * from vehicle_services_history where serviceid='" & Serviceid & "'", conn)
            Dim cmd3 As SqlCommand = New SqlCommand("update  vehicle_services_history set assignedto='" & assignedto & "',timestamp='" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "' ,remarks='" & Discription & "' where serviceid='" & Serviceid & "'", conn)

            Dim cmd As SqlCommand = New SqlCommand("insert into vehicle_services_history(serviceid,timestamp,assignedto,remarks) values('" & Serviceid & "','" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "','" & assignedto & "','" & Discription & "') ", conn)
            Dim cmd1 As SqlCommand = New SqlCommand("update vehicle_services set status=1,assignedby='" & assignedby & "' where serviceid='" & Serviceid & "'", conn)

            conn.Open()
            dr = cmd2.ExecuteReader()
            If dr.Read() Then
                res = cmd3.ExecuteNonQuery()
                If res = "1" Then
                    cmd1.ExecuteNonQuery()
                End If
            Else
                res = cmd.ExecuteNonQuery()
                If res = "1" Then
                    cmd1.ExecuteNonQuery()
                End If
            End If
            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Sub CloseService(ByVal Serviceid As String, ByVal closedby As String, ByVal username As String, ByVal sercompdate As String, ByVal compremarks As String)
        Dim res As String
        Dim json As String
        Dim dr As SqlDataReader
        Try
            Dim Discription As String = compremarks.Replace("\n", "<br/>")
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd2 As SqlCommand = New SqlCommand("select * from vehicle_services_history where serviceid='" & Serviceid & "'", conn)
            Dim cmd3 As SqlCommand = New SqlCommand("insert into vehicle_services_history(serviceid,timestamp,assignedto,remarks) values('" & Serviceid & "','" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "','" & username & "','') ", conn)

            Dim cmd As SqlCommand = New SqlCommand("update  vehicle_services_history set status=2 ,closeddate='" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "', servicecomp_date='" & Convert.ToDateTime(sercompdate).ToString("yyyy/MM/dd") & "' ,compleated_remarks='" & Discription & "' where serviceid='" & Serviceid & "'", conn)
            Dim cmd1 As SqlCommand = New SqlCommand("update vehicle_services set status=2,closedby ='" & closedby & "' where serviceid='" & Serviceid & "'", conn)

            conn.Open()
            dr = cmd2.ExecuteReader()
            If dr.Read() Then
                res = cmd.ExecuteNonQuery()
                If res = "1" Then
                    cmd1.ExecuteNonQuery()
                End If
            Else
                res = cmd3.ExecuteNonQuery()
                If res = "1" Then
                    cmd1.ExecuteNonQuery()
                End If
            End If

            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)
        Catch ex As Exception

        End Try

    End Sub
    Private Sub ReOpenService(ByVal Serviceid As String, ByVal reopendby As String)
        Dim res As String
        Dim json As String

        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("update  vehicle_services_history set status=5 ,reopeneddate='" & DateTime.Now.ToString("yyyy/MM/dd HH:mm:ss") & "' where serviceid='" & Serviceid & "'", conn)
            Dim cmd1 As SqlCommand = New SqlCommand("update vehicle_services set status=5,reopenby ='" & reopendby & "' where serviceid='" & Serviceid & "'", conn)

            conn.Open()
            res = cmd.ExecuteNonQuery()
            If res = "1" Then
                cmd1.ExecuteNonQuery()
            End If
            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Sub changeServicedate(ByVal Serviceid As String, ByVal changedby As String, ByVal serdate As String)
        Dim res As String
        Dim json As String

        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("update  vehicle_services_history set status=4 ,servicedate='" & Convert.ToDateTime(serdate).ToString("yyyy/MM/dd HH:mm:ss") & "' where serviceid='" & Serviceid & "'", conn)
            Dim cmd1 As SqlCommand = New SqlCommand("update vehicle_services set status=4,sdatechangedby ='" & changedby & "' where serviceid='" & Serviceid & "'", conn)

            conn.Open()
            res = cmd.ExecuteNonQuery()
            If res = "1" Then
                cmd1.ExecuteNonQuery()
            End If
            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Sub ReceiveService(ByVal Serviceid As String, ByVal receiveddby As String)
        Dim res As String
        Dim json As String

        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("update vehicle_services set status=3,receivedby='" & receiveddby & "' where serviceid='" & Serviceid & "'", conn)

            conn.Open()
            res = cmd.ExecuteNonQuery()
            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""d"":" & JsonConvert.SerializeObject(res, Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Sub Getcomments(ByVal Serviceid As String, ByVal st As String)

        Dim json As String
        Dim dr As SqlDataReader
        Dim aa As ArrayList = New ArrayList()
        Dim a As ArrayList
        Dim comments As DataTable = New DataTable()
        comments.Columns.Add("commentedby")
        comments.Columns.Add("comment")
        comments.Columns.Add("timestamp")
        comments.Columns.Add("username")
        comments.Columns.Add("role")

        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("select ut.username,ut.role,sh.commentedby,sh.comment,sh.timestamp from services_comments_history sh inner join userTBL ut on sh.commentedby=ut.userid where serviceid='" & Serviceid & "' order by timestamp ", conn)

            conn.Open()
            dr = cmd.ExecuteReader()
            While dr.Read()
                Dim r As DataRow
                r = comments.NewRow
                r(0) = dr("commentedby")
                r(1) = dr("comment")
                r(2) = Convert.ToDateTime(dr("timestamp")).ToString("yyyy/MM/dd HH:mm")
                r(3) = dr("username")
                r(4) = dr("role")
                comments.Rows.Add(r)
            End While
            conn.Close()
            Dim sb As StringBuilder = New StringBuilder()
            If (comments.Rows.Count > 0) Then
                If st <> "1" Then
                    If (comments.Rows.Count > 3) Then
                        sb.Append("<li  class ='comment even thread-even depth-1'><span onclick='javascript:GetComments(1)' style='cursor:pointer;color:blue;'> View All" + (comments.Rows.Count).ToString() + " comments..</span></li>")
                        For r As Int32 = comments.Rows.Count - 3 To comments.Rows.Count - 1
                            ' sb.Append("<li  class ='comment even thread-even depth-1'>")
                            If comments.Rows(r)(4) = "User" Or comments.Rows(r)(4) = "SuperUser" Then
                                sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#EC5906;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                                sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;'>" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                            Else
                                sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#0BA01A;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                                sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;' >" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                            End If

                        Next
                    Else
                        For r As Int32 = 0 To comments.Rows.Count - 1
                            ' sb.Append("<li  class ='comment even thread-even depth-1'>")
                            If comments.Rows(r)(4) = "User" Or comments.Rows(r)(4) = "SuperUser" Then
                                sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#EC5906;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                                sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;'>" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                            Else
                                sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#0BA01A;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                                sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;' >" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                            End If

                        Next
                    End If
                Else
                    sb.Append("<li  class ='comment even thread-even depth-1'><span onclick='javascript:GetComments(0)' style='cursor:pointer;color:blue;'> Hide comments..</span></li>")

                    For r As Int32 = 0 To comments.Rows.Count - 1
                        'sb.Append("<li  class ='comment even thread-even depth-1'>")
                        If comments.Rows(r)(4) = "User" Or comments.Rows(r)(4) = "SuperUser" Then
                            sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#EC5906;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                            sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;'>" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                        Else
                            sb.Append("<table style ='font-size:10px;width:550px;'><tr ><td style ='color:#0BA01A;width:40%;vertical-align: top;'>[" & comments.Rows(r)(2) & "] " & comments.Rows(r)(3) & " : </td>")
                            sb.Append("<td style ='color:#216AB2;font-size:11px;text-align:left;' >" + comments.Rows(r)(1).ToString() + "</td><tr><table></li>")

                        End If

                    Next
                End If

            End If

            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = "{""Comments"":" & JsonConvert.SerializeObject(sb.ToString(), Formatting.None) & "}"
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Sub GetServiceDetails(ByVal Serviceid As String, ByVal userid As String)

        Dim json As String
        Dim dr As SqlDataReader
        Dim aa As ArrayList = New ArrayList()
        Dim a As ArrayList
        Try
            Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))

            Dim cmd As SqlCommand = New SqlCommand("select vs.userid,vs.serviceid,vs.plateno,convert(varchar(19),vsh.timestamp,120) as timestamp,vs.servicetype,vs.priority,vs.status,isnull(vsh.assignedto,'Not at Assigned') assignedto,convert(varchar(19),vsh.closeddate,120) closeddate,convert(varchar(19),vsh.servicedate,120) servicedate,vs.remarks,convert(varchar(19),vsh.servicecomp_date,120) servicecomp_date,vsh.compleated_remarks from vehicle_services vs left outer join vehicle_services_history vsh on vs.serviceid=vsh.serviceid  where vs.serviceid='" & Serviceid & "'", conn)
            Dim cmd1 As SqlCommand = New SqlCommand("update services_comments_history set commentread=1 where serviceid='" & Serviceid & "' and commentedby<>'" & userid & "'", conn)
            conn.Open()
            cmd1.ExecuteNonQuery()
            dr = cmd.ExecuteReader()
            If dr.Read() Then
                a = New ArrayList()
                a.Add(dr("serviceid"))
                a.Add(dr("plateno"))
                a.Add(dr("timestamp"))
                a.Add(dr("servicetype"))
                a.Add(dr("priority"))
                Select Case dr("status")
                    Case "0" : a.Add("Open")

                    Case "3" : a.Add("Request Received")

                    Case "1" : a.Add("Technician Assign")

                    Case "4"
                        If IsDBNull(dr("servicedate")) Then
                            a.Add("Service Date Changed ")
                        Else
                            a.Add("Service Date Changed To " & Convert.ToDateTime(dr("servicedate")).ToString("yyyy/MM/dd"))
                        End If

                    Case "2" : a.Add("Closed")
                    Case "5" : a.Add("ReOpen")

                End Select


                a.Add(dr("assignedto"))
                a.Add(dr("closeddate"))
                a.Add(dr("remarks"))

                If dr("servicecomp_date").ToString().Contains("1/1/1900") Or IsDBNull(dr("servicecomp_date")) Then
                    a.Add("--")
                Else
                    a.Add(Convert.ToDateTime(dr("servicecomp_date")).ToString("yyyy/MM/dd HH:mm:ss"))
                End If
                a.Add(dr("compleated_remarks").ToString())
                aa.Add(a)
            End If
            conn.Close()
            Dim jss As New Newtonsoft.Json.JsonSerializer()
            json = JsonConvert.SerializeObject(aa, Formatting.None)
            Response.ContentType = "text/plain"
            Response.Write(json)

        Catch ex As Exception

        End Try

    End Sub

    Private Function getusername(ByVal userid As String) As String
        Dim dr As SqlDataReader
        Dim username As String = "--"
        Dim conn As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))

        Try

            Dim cmd As SqlCommand = New SqlCommand("select username from userTBL where userid='" & userid & "'", conn)

            conn.Open()
            dr = cmd.ExecuteReader()
            If dr.Read() Then
                username = dr("username")
            End If
        Catch ex As Exception
        Finally
            conn.Close()
        End Try
        Return username
    End Function

End Class
