Imports System.Data.SqlClient
Imports Newtonsoft.Json

Partial Class smsdetailsjson
    Inherits System.Web.UI.Page

    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load
        Dim fromdate As String = Request.QueryString("fromdate")
        Dim todate As String = Request.QueryString("todate")
        Dim plateno As String = Request.QueryString("plateno")
        Dim userid As String = Request.QueryString("userid")
        Dim atype As String = Request.QueryString("atype")
        GetSMSDetails(fromdate, todate, plateno, userid, atype)
    End Sub

    Public Sub GetSMSDetails(ByVal fromdate As String, ByVal todate As String, ByVal plateno As String, ByVal userid As String, ByVal atype As String)
        Dim aa As New ArrayList()
        Dim a As ArrayList
        Dim json As String = ""

        Dim i As Int16 = 0

        Dim sb As StringBuilder
        Try


            Dim groupcondition As String = ""
            Dim vehiclestable As New DataTable

            vehiclestable.Columns.Add(New DataColumn("Sno"))
            vehiclestable.Columns.Add(New DataColumn("Username"))
            vehiclestable.Columns.Add(New DataColumn("Plateno"))
            vehiclestable.Columns.Add(New DataColumn("Date"))
            vehiclestable.Columns.Add(New DataColumn("Alert"))
            vehiclestable.Columns.Add(New DataColumn("mobile"))
            vehiclestable.Columns.Add(New DataColumn("Message"))

            Dim cmd As New SqlCommand
            Dim r As DataRow
            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            If atype <> "ALL" Then
                cmd = New SqlCommand("select ot.plateno,ot.userid,ut.username,  alert_type,ot.datetime,ot.message,ot.mobileno from sms_outbox ot inner join userTBL  ut on ot.userid=ut.userid where ot.userid='" & userid & "' and ot.plateno='" & plateno & "' and alert_type='" & atype & "' and  datetime between '" & fromdate & "' and '" & todate & "' order by datetime", conn)
            Else
                cmd = New SqlCommand("select ot.plateno,ot.userid,ut.username,  alert_type,ot.datetime,ot.message,ot.mobileno from sms_outbox ot inner join userTBL  ut on ot.userid=ut.userid where ot.userid='" & userid & "' and ot.plateno='" & plateno & "'  and datetime between '" & fromdate & "' and '" & todate & "' order by datetime", conn)
            End If

            Try
                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader
                Dim sno As Int16 = 1

                While dr.Read
                    r = vehiclestable.NewRow
                    r(0) = sno
                    r(1) = dr("username")
                    r(2) = dr("plateno")
                    r(3) = Convert.ToDateTime(dr("datetime")).ToString("yyyy/MM/dd HH:mm:ss")
                    Select Case dr("alert_type")
                        Case "0" : r(4) = "Pto On"
                        Case "1" : r(4) = "Immobilizer"
                        Case "2" : r(4) = "Overspeed"
                        Case "3" : r(4) = "Panic"
                        Case "4" : r(4) = "PowerCut"
                        Case "5" : r(4) = "Unlock"
                        Case "6" : r(4) = "Idling"
                        Case "7" : r(4) = "IgnitionOff"
                        Case "8" : r(4) = "IgnitionOn"
                        Case "9" : r(4) = "Overtime"
                        Case "10" : r(4) = "GeofenceIn"
                        Case "11" : r(4) = "GeofenceOut"
                        Case "12" : r(4) = "SignalLoss"
                        Case "13" : r(4) = "HarshBreaak"
                        Case "14" : r(4) = "TollPlaza"
                        Case "15" : r(4) = "Refuel"
                        Case "16" : r(4) = "FuelTheft"
                        Case "17" : r(4) = "Stop"
                        Case Else
                            r(4) = "Others"
                    End Select
                    r(5) = dr("message")
                    r(6) = dr("mobileno")
                    vehiclestable.Rows.Add(r)
                    sno = sno + 1
                End While

                sb = New StringBuilder()
                If (vehiclestable.Rows.Count > 0) Then
                    For j As Integer = 0 To vehiclestable.Rows.Count - 1
                        Try
                            a = New ArrayList
                            a.Add(vehiclestable.DefaultView.Item(j)(0))
                            a.Add(vehiclestable.DefaultView.Item(j)(1))
                            a.Add(vehiclestable.DefaultView.Item(j)(2))
                            a.Add(vehiclestable.DefaultView.Item(j)(3))
                            a.Add(vehiclestable.DefaultView.Item(j)(4))
                            a.Add(vehiclestable.DefaultView.Item(j)(5))
                            a.Add(vehiclestable.DefaultView.Item(j)(6))
                            aa.Add(a)
                        Catch ex As Exception
                            json = ex.Message
                        End Try
                    Next
                End If
                json = JsonConvert.SerializeObject(aa, Formatting.None)
                Response.Write(json)
                'If vehiclestable.Rows.Count > 0 Then

                '    sb.Append("<thead align='left' ><tr  ><td colspan='5' style='color:rgb(35, 135, 228)' >Plate No: " & plateno & "</td></tr>")
                '    sb.Append("<tr  ><td colspan='5' style='color:rgb(35, 135, 228)' >From: " & Convert.ToDateTime(fromdate).ToString("yyyy-MM-dd HH:mm:ss") & " " & "To: " & Convert.ToDateTime(todate).ToString("yyyy-MM-dd HH:mm:ss") & " </td></tr>")
                '    sb.Append("<tr ><th scope='col' style='width: 30px;'>S No</th><th   scope='col' style='width: 100px; '>User Name</th><th  scope='col' style='width: 30px;'>Plateno</th><th   scope='col' style='width: 100px; '>Date Time</th><th   scope='col' style='width: 70px; '>Alert Type</th><th   scope='col' style='width: 70px; '>Mobileno</th><th   scope='col'>Message</th></tr></thead>")

                '    sb.Append("<tbody>")
                '    For j As Integer = 0 To vehiclestable.Rows.Count - 1
                '        Try
                '            sb.Append("<tr ><td style='width:30px;'>" & vehiclestable.DefaultView.Item(j)(0) & "</td>")
                '            sb.Append("<td style='width: 80px;'>" & vehiclestable.DefaultView.Item(j)(1) & "</td>")
                '            sb.Append("<td style='width: 70px;'>" & vehiclestable.DefaultView.Item(j)(2) & "</td>")
                '            sb.Append("<td style='width: 100px;'>" & vehiclestable.DefaultView.Item(j)(3) & "</td>")
                '            sb.Append("<td style='width:70px;'>" & vehiclestable.DefaultView.Item(j)(4) & "</td>")
                '            sb.Append("<td style='width:70px;'>" & vehiclestable.DefaultView.Item(j)(6) & "</td>")
                '            sb.Append("<td>" & vehiclestable.DefaultView.Item(j)(5) & "</td></tr>")

                '        Catch ex As Exception

                '        End Try
                '    Next
                '    sb.Append("</tbody>")
                '    sb.Append("<tfoot align='left'><tr ><th style='width: 30px;'>S No</th><th   scope='col' style='width: 100px; '>User Name</th><th  scope='col' style='width: 30px;'>Plateno</th><th   scope='col' style='width: 100px; '>Date Time</th><th   scope='col' style='width: 70px; '>Alert Type</th><th   scope='col' style='width: 70px; '>Mobileno</th><th   scope='col' style='width: 70px; '>Message</th></tr></tfoot>")

                'Else
                '    sb.Append(cmd.CommandText)
                'End If
                'HttpContext.Current.Session("deatails") = vehiclestable
                'Response.Write(sb.ToString())
            Catch ex As Exception
                Response.Write(ex.Message)
            End Try

        Catch ex As Exception
            Response.Write(ex.Message)
        End Try
        'json = JsonConvert.SerializeObject(aa, Formatting.None)


    End Sub
End Class
