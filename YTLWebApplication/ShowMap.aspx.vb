Imports System.Data.SqlClient
Imports AspMap
Partial Class ShowMap
    Inherits System.Web.UI.Page
    Public qsa() As String
    Public qs As String = ""
    Public source As String = ""
    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load

        Try
            Dim id As String = Request.QueryString("id")
            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim cmd As SqlCommand = New SqlCommand("select  s.name,p.dn_id,p.dn_no,p.patch_no,p.plateno,p.journey_back_datetime,p.weight_outtime,p.source_supply,p.destination_siteid,p.insert_dt,p.unitid,p.status,p.ata_date,p.ata_time,p.ata_datetime,p.timestamp,p.lat,p.lon,p.transporter,p.remarks from (select * from oss_patch_out where patch_no= " & id & "  ) p Left Outer Join oss_ship_to_code s On s.shiptocode=p.destination_siteid ", conn2)
            Dim plateno As String = ""
            Dim bdt As DateTime
            Dim edt As DateTime
            Dim shiptocode As String = ""
            Dim status As String = ""
            Dim shiptoname As String = ""
            Try
                conn2.Open()
                Dim dr2 As SqlDataReader = cmd.ExecuteReader()

                While dr2.Read()
                    plateno = dr2("plateno")
                    bdt = Convert.ToDateTime(dr2("weight_outtime"))
                    status = dr2("status")

                    Select Case status
                        Case 1

                        Case 2
                            edt = bdt.AddHours(24)
                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss")
                        Case 3
                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"
                            Else
                                tr = dr2("transporter")
                            End If
                            edt = Now.ToString("yyyy/MM/dd HH:mm:ss")
                            source = "GMap.aspx?plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&scode=3"

                        Case 4

                        Case 5
                            edt = Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddMinutes(+10).ToString("yyyy/MM/dd HH:mm:ss")
                        Case 6

                        Case 7
                            Dim ts As DateTime = dr2("ata_time").ToString()
                            Dim dttm As DateTime = dr2("ata_date").ToString()
                            Dim atatime As DateTime = dttm.Add(ts.TimeOfDay)
                            edt = atatime.ToString("yyyy/MM/dd HH:mm:ss")
                            ' If IsDBNull(dr2("journey_back_datetime")) Then
                            'edt = atatime.ToString("yyyy/MM/dd HH:mm:ss")
                            'Else
                            'edt = Convert.ToDateTime(dr2("journey_back_datetime")).ToString("yyyy/MM/dd HH:mm:ss")
                            'End If


                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"
                            Else
                                tr = dr2("transporter")
                            End If
                            source = "GMap.aspx?markerlat=" & Convert.ToDouble(dr2("lat")).ToString("0.0000") & "&markerlon=" & Convert.ToDouble(dr2("lon")).ToString("0.0000") & "&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&pos=" & DateTime.Parse(dr2("ata_datetime")).ToString("yyyy/MM/dd HH:mm:ss") & "&ata=" & Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString() & "&scode=2"

                        Case 8
                            edt = Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"
                            Else
                                tr = dr2("transporter")
                            End If
                            source = "GMap.aspx?markerlat=" & Convert.ToDouble(dr2("lat")).ToString("0.0000") & "&markerlon=" & Convert.ToDouble(dr2("lon")).ToString("0.0000") & "&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&pos=" & DateTime.Parse(dr2("ata_datetime")).ToString("yyyy/MM/dd HH:mm:ss") & "&ata=" & Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString() & "&scode=2"
                        Case 9

                        Case 10
                            edt = DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd HH:mm:ss")
                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddHours(24).ToString("yyyy/MM/dd HH:mm:ss")
                        Case 11

                        Case Else

                    End Select


                    shiptocode = dr2("name")
                    shiptoname = dr2("destination_siteid")

                End While

            Catch ex As Exception

            Finally
                conn2.Close()
            End Try
            source = "'" & source & "'"
            txtOutTime.Text = bdt.ToString("yyyy/MM/dd HH:mm:ss")
            enddate.Value = edt.ToString("yyyy/MM/dd HH:mm:ss")

            txtPlateno.Text = plateno
            txtSTC.Text = shiptocode
            txtShipToName.Text = shiptoname
            Dim idlingtable As New DataTable
            idlingtable.Columns.Add(New DataColumn("sno"))
            idlingtable.Columns.Add(New DataColumn("plateno"))
            idlingtable.Columns.Add(New DataColumn("begindatetime"))
            idlingtable.Columns.Add(New DataColumn("enddatetime"))
            idlingtable.Columns.Add(New DataColumn("duration"))
            idlingtable.Columns.Add(New DataColumn("shiptocode"))
            idlingtable.Columns.Add(New DataColumn("time"))
            idlingtable.Columns.Add(New DataColumn("status"))

            Dim stoptable As New DataTable
            stoptable.Columns.Add(New DataColumn("sno"))
            stoptable.Columns.Add(New DataColumn("plateno"))
            stoptable.Columns.Add(New DataColumn("begindatetime"))
            stoptable.Columns.Add(New DataColumn("enddatetime"))
            stoptable.Columns.Add(New DataColumn("duration"))
            stoptable.Columns.Add(New DataColumn("shiptocode"))
            stoptable.Columns.Add(New DataColumn("time"))
            stoptable.Columns.Add(New DataColumn("status"))

            Dim ptotable As New DataTable
            ptotable.Columns.Add(New DataColumn("sno"))
            ptotable.Columns.Add(New DataColumn("plateno"))
            ptotable.Columns.Add(New DataColumn("begindatetime"))
            ptotable.Columns.Add(New DataColumn("enddatetime"))
            ptotable.Columns.Add(New DataColumn("duration"))
            ptotable.Columns.Add(New DataColumn("shiptocode"))
            ptotable.Columns.Add(New DataColumn("time"))
            ptotable.Columns.Add(New DataColumn("status"))

            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))


            Dim i As Int32 = 1

            Dim lat As Double = 0
            Dim lon As Double = 0

            Dim r As DataRow

            cmd = New SqlCommand("select distinct convert(varchar(19),timestamp,120) as datetime,plateno,speed,ignition,alarm,lat,lon from vehicle_history2 where plateno ='" & plateno & "' and (gps_av='A' or (gps_av='V' and ignition='0')) and timestamp between '" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "' and '" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "' order by datetime asc", conn)
            '   cmd = New SqlCommand("select distinct convert(varchar(19),timestamp,120) as datetime,alarm,plateno,speed,ignition,lat,lon from vehicle_history where plateno ='70-2514' and (gps_av='A' or (gps_av='V' and ignition='0')) and timestamp between '2012/09/24 00:00:00' and '2012/09/24 23:59:59' order by datetime asc", conn)

            Dim prevstatus As String = "stop"
            Dim currentstatus As String = "stop"
            Dim prevpto As String = "off"
            Dim currentpto As String = "off"

            Dim tempprevtime As DateTime = bdt
            Dim tempprevtimep As DateTime = bdt
            Dim prevtime As DateTime = bdt
            Dim currenttime As DateTime = bdt
            Dim prevtimep As DateTime = bdt
            Dim currenttimep As DateTime = bdt
            Try

                conn.Open()
                Dim dr As SqlDataReader = cmd.ExecuteReader()

                Dim lastlat As Double = 0
                Dim lastlon As Double = 0
                Dim minOption As Byte = 15
                Try
                    While dr.Read()

                        lastlat = dr("lat")
                        lastlon = dr("lon")
                        currenttime = dr("datetime")
                        currenttimep = dr("datetime")
                        If dr("ignition") And dr("speed") <> 0 Then
                            currentstatus = "moving"
                        ElseIf dr("ignition") And dr("speed") = 0 Then
                            currentstatus = "idle"
                        Else
                            currentstatus = "stop"
                        End If

                        If prevstatus <> currentstatus Then
                            Dim temptime As TimeSpan = tempprevtime - prevtime
                            Dim minutes As Integer = temptime.TotalMinutes()

                            Select Case prevstatus
                                Case "stop"
                                    If temptime.TotalMinutes >= 15 Then
                                        r = stoptable.NewRow
                                        r(0) = i
                                        r(1) = dr("plateno")
                                        r(2) = prevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(3) = tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(4) = "<span onclick=""javascript:panMapToPos(" & lastlat & "," & lastlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                                        r(5) = ""
                                        r(6) = prevtime.ToString("yyyy/MM/dd HH:mm:ss") & "-" & tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        stoptable.Rows.Add(r)
                                        i = i + 1
                                    End If

                                Case "moving"

                                Case "idle"
                                    If temptime.TotalMinutes >= minOption Then
                                        r = idlingtable.NewRow
                                        r(0) = i
                                        r(1) = dr("plateno")
                                        txtPlateno.Text = dr("plateno").ToString()
                                        txtSTC.Text = shiptocode
                                        txtShipToName.Text = shiptoname
                                        r(2) = prevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(3) = tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(4) = "<span onclick=""javascript:panMapToPos(" & lastlat & "," & lastlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                                        r(5) = shiptocode.ToString()
                                        r(6) = prevtime.ToString("yyyy/MM/dd HH:mm:ss") & "-" & tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        idlingtable.Rows.Add(r)
                                        i = i + 1
                                    End If
                            End Select
                            prevtime = currenttime
                            prevstatus = currentstatus
                        End If




                        If dr("alarm") Then
                            currentpto = "on"
                        Else
                            currentpto = "off"
                        End If

                        If prevpto <> currentpto Then
                            Dim temptime As TimeSpan = tempprevtimep - prevtimep
                            Dim minutes As Integer = temptime.TotalMinutes()
                            If temptime.TotalMinutes >= 30 Then
                                r = ptotable.NewRow
                                r(0) = i
                                r(1) = dr("plateno")
                                r(2) = prevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                                r(3) = tempprevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                                r(4) = "<span onclick=""javascript:panMapToPos(" & lastlat & "," & lastlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                                r(5) = ""
                                r(6) = prevtimep.ToString("yyyy/MM/dd HH:mm:ss") & "-" & tempprevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                                ptotable.Rows.Add(r)
                                i = i + 1
                            End If
                            prevtimep = currenttimep
                        End If

                        tempprevtime = currenttime
                        tempprevtimep = currenttimep

                    End While
                Catch ex As Exception
                    Response.Write(ex.Message)
                End Try
                If idlingtable.Rows.Count = 0 Then
                    r = idlingtable.NewRow()
                    r(0) = "--"
                    r(1) = "--"
                    r(2) = "--"
                    r(4) = "--"
                    r(5) = "--"
                    r(6) = "--"
                    idlingtable.Rows.Add(r)
                End If
                If stoptable.Rows.Count = 0 Then
                    r = stoptable.NewRow()
                    r(0) = "--"
                    r(1) = "--"
                    r(2) = "--"
                    r(4) = "--"
                    r(5) = "--"
                    r(6) = "--"
                    stoptable.Rows.Add(r)
                End If
                If ptotable.Rows.Count = 0 Then
                    r = ptotable.NewRow()
                    r(0) = "--"
                    r(1) = "--"
                    r(2) = "--"
                    r(4) = "--"
                    r(5) = "--"
                    r(6) = "--"
                    ptotable.Rows.Add(r)
                End If

            Catch ex As Exception

            End Try
            GridView1.DataSource = idlingtable
            GridView1.DataBind()
            GridView2.DataSource = stoptable
            GridView2.DataBind()
            GridView3.DataSource = ptotable
            GridView3.DataBind()
            conn.Close()
            conn.Dispose()

        Catch ex As SystemException

        End Try
    End Sub


End Class
