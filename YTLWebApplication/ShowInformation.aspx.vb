Imports System.Data.SqlClient
Imports AspMap
Imports DocumentFormat.OpenXml.Office2010.Excel

Partial Class ShowInformation
    Inherits System.Web.UI.Page
    Public qsa() As String
    Public qs As String = ""
    Public source As String = ""
    Public pid As String = ""
    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load

        Try
            Dim id As String = Request.QueryString("id")
            pid = id
            Dim events As String = "2"
            If Request.QueryString("events") Is Nothing Then
                events = 2
            Else
                events = Request.QueryString("events")
                If events = "5" Then
                    event5hrs.Checked = True
                Else
                    event5hrs.Checked = False
                End If

            End If
            Dim from As String = ""
            from = Request.QueryString("from")

            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
            Dim role As String = ""
            If Not from = "Client" Then
                role = Request.Cookies("userinfo")("role")
            End If
            reqfrom.Value = from
            Dim remarkfn As String = ""

            If from = "Client" Then
                ' btncopy.Visible = False
                txtremark.Visible = False
                btnSubmitremark.Visible = False
            Else
                ' btncopy.Visible = True
                txtremark.Visible = True
                btnSubmitremark.Visible = True
            End If

            If role = "Admin" Then
                remarkfn = "fn_GetOSSRemark_admin"
                chkbox.Visible = True

            Else
                remarkfn = "fn_GetOSSRemark"
                chkbox.Visible = False
            End If
            Dim cmd As SqlCommand = New SqlCommand("select  dbo.fn_getnextweightouttime(p.plateno ,p.weight_outtime ) as nextweightouttime, dbo.fn_getnextplantintime(p.plateno ,p.weight_outtime ) as nextplantintime, ISNULL( s.name,p.destination_sitename ) as name,p.dn_id,p.dn_no,p.patch_no,p.plateno,p.weight_outtime,p.source_supply,p.destination_siteid,p.insert_dt,p.unitid,p.status,p.ata_date,p.ata_time,p.ata_datetime,p.timestamp,p.lat,p.lon,p.transporter,p.remarks,isnull(s.address5,p.area_code_name  ) as address5,dbo." & remarkfn & "(p.dn_id) as Jremarks,case when start_odometer is null or end_odometer is null then 0 when end_odometer > start_odometer then end_odometer-start_odometer else 0 end as distancetravel,p.atd_datetime,p.plant_intime from (select * from oss_patch_out where patch_no= " & id & "  ) p Left Outer Join oss_ship_to_code s On s.shiptocode=p.destination_siteid  left outer join oss_job_remarks t2 on p.dn_id=t2.dn_id", conn2)
            Dim plateno As String = ""
            Dim bdt As DateTime
            Dim edt As DateTime
            Dim shiptocode As String = ""
            Dim status As String = ""
            Dim shiptoname As String = ""
            Dim shiptoaddress As String = ""
            Dim transportername As String = ""
            Dim tdnno As String = ""
            Dim dnid As String = ""
            Dim atddatetime As DateTime
            Dim plantintime As String = ""
            Dim nextweightouttime As String = ""
            Dim nextplantin As String = ""
            Try
                conn2.Open()
                Dim dr2 As SqlDataReader = cmd.ExecuteReader()

                While dr2.Read()
                    plateno = dr2("plateno")
                    tdnno = dr2("dn_no")
                    dnid = dr2("dn_id")
                    bdt = Convert.ToDateTime(dr2("weight_outtime"))
                    edt = Convert.ToDateTime(dr2("weight_outtime"))
                    status = dr2("status")
                    dn_id.Value = dr2("dn_id")
                    If IsDBNull(dr2("transporter")) Then
                        transportername = "--"
                    Else
                        transportername = dr2("transporter").ToString().ToUpper()
                    End If
                    atddatetime = bdt.AddHours(72)
                    If IsDBNull(dr2("plant_intime")) Then
                        plantintime = "-"
                    Else
                        plantintime = Convert.ToDateTime(dr2("plant_intime")).ToString("yyyy/MM/dd HH:mm:ss")
                    End If
                    If IsDBNull(dr2("nextweightouttime")) Then
                        nextweightouttime = "-"
                    Else
                        nextweightouttime = Convert.ToDateTime(dr2("nextweightouttime")).ToString("yyyy/MM/dd HH:mm:ss")
                    End If
                    If IsDBNull(dr2("nextplantintime")) Then
                        nextplantin = "-"
                    Else
                        nextplantin = Convert.ToDateTime(dr2("nextplantintime")).ToString("yyyy/MM/dd HH:mm:ss")
                    End If
                    'If IsDBNull(dr2("atd_datetime")) Then
                    '    If events = "2" Then
                    '        atddatetime = bdt.AddHours(48)
                    '    Else
                    '        atddatetime = bdt.AddHours(120)
                    '    End If
                    'Else
                    '    If events = "2" Then
                    '        atddatetime = Convert.ToDateTime(dr2("atd_datetime"))
                    '    Else
                    '        atddatetime = bdt.AddHours(120)
                    '    End If
                    'End If

                    Select Case status
                        Case 1
                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & atddatetime.ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""
                        Case 2
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(24)
                            End If

                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""
                        Case 3
                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"

                            Else
                                tr = dr2("transporter")

                            End If
                            edt = Now.ToString("yyyy/MM/dd HH:mm:ss")
                            source = "GMap.aspx?plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&scode=3&from=" & from & ""

                        Case 4

                        Case 5
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            End If

                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddMinutes(+10).ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""
                        Case 6

                        Case 7
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = atddatetime.ToString("yyyy/MM/dd HH:mm:ss")
                            End If

                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"
                            Else
                                tr = dr2("transporter")
                            End If
                            source = "GMap.aspx?markerlat=" & Convert.ToDouble(dr2("lat")).ToString("0.0000") & "&markerlon=" & Convert.ToDouble(dr2("lon")).ToString("0.0000") & "&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&pos=" & DateTime.Parse(dr2("ata_datetime")).ToString("yyyy/MM/dd HH:mm:ss") & "&ata=" & Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString() & "&scode=2&distance=" & CDbl(dr2("distancetravel")).ToString("0.00") & "&from=" & from & ""

                        Case 13
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(72) 'Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            End If

                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddMinutes(+10).ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""


                        Case 8
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(72) 'Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            End If
                            Dim tr As String = ""
                            If IsDBNull(dr2("transporter")) Then
                                tr = "--"
                            Else
                                tr = dr2("transporter")
                            End If
                            source = "GMap.aspx?markerlat=" & Convert.ToDouble(dr2("lat")).ToString("0.0000") & "&markerlon=" & Convert.ToDouble(dr2("lon")).ToString("0.0000") & "&plateno=" & plateno & "&bdt=" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&uid=" & dr2("unitid") & "&tr=" & tr & "&sr=" & dr2("source_supply") & "&dn=" & dr2("dn_no") & "&wo=" & DateTime.Parse(dr2("weight_outtime")).ToString("yyyy/MM/dd  HH:mm:ss") & "&sc=" & dr2("destination_siteid") & "&sn=" & dr2("name") & "&pos=" & DateTime.Parse(dr2("ata_datetime")).ToString("yyyy/MM/dd HH:mm:ss") & "&ata=" & Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString() & "&scode=2&distance=" & CDbl(dr2("distancetravel")).ToString("0.00") & "&from=" & from & ""
                        Case 9

                        Case 10
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(72) 'DateTime.Parse(dr2("weight_outtime")).AddHours(24).ToString("yyyy/MM/dd HH:mm:ss")
                            End If
                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""
                        Case 12
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(72) 'Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            End If

                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddMinutes(+10).ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""

                        Case 15
                            If event5hrs.Checked Then
                                edt = bdt.AddHours(120)
                            Else
                                edt = bdt.AddHours(72) 'Convert.ToDateTime(dr2("ata_date").ToString()).ToString("yyyy/MM/dd") & " " & dr2("ata_time").ToString()
                            End If

                            source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt.AddMinutes(-10).ToString("yyyy/MM/dd HH:mm:ss") & "&edt=" & edt.AddMinutes(+10).ToString("yyyy/MM/dd HH:mm:ss") & "&from=" & from & ""


                        Case Else

                    End Select

                    shiptoaddress = dr2("address5")
                    shiptocode = dr2("name")
                    shiptoname = dr2("destination_siteid")

                End While
                If Not Page.IsPostBack Then
                    dr2.Close()
                    If role = "Admin" Then
                        cmd.CommandText = "select * from oss_job_remarks where dn_id='" & dn_id.Value & "'"
                    Else
                        cmd.CommandText = "select * from oss_job_remarks where dn_id='" & dn_id.Value & "' admin=0"
                    End If

                    dr2 = cmd.ExecuteReader()
                    If dr2.HasRows() Then
                        If dr2.Read() Then
                            txtremark.Text = dr2("remark")
                            If dr2("Admin") Then
                                chkbox.Checked = True
                            Else
                                chkbox.Checked = False
                            End If
                        End If
                        btnSubmitremark.Text = "Update Remarks"
                    End If
                End If


            Catch ex As Exception

            Finally
                conn2.Close()
            End Try
            source = "'" & source & "'"
            txtOutTime.Text = bdt.ToString("yyyy/MM/dd HH:mm:ss")
            enddate.Value = edt.ToString("yyyy/MM/dd HH:mm:ss")
            txtdnid.Text = dn_id.Value
            txtdnno.Text = tdnno
            txtPlateno.Text = plateno
            txtSTC.Text = shiptocode
            txtShipToName.Text = shiptoname
            txtShiptoaddress.Text = shiptoaddress
            txtTransporter.Text = transportername
            txtPlantinTime.Text = plantintime
            txtNextWeightoutTime.Text = nextweightouttime
            txtNxtPlantinTime.Text = nextplantin
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

            Dim Newtable As New DataTable
            Newtable.Columns.Add(New DataColumn("sno"))
            Newtable.Columns.Add(New DataColumn("plateno"))
            Newtable.Columns.Add(New DataColumn("begindatetime"))
            Newtable.Columns.Add(New DataColumn("enddatetime"))
            Newtable.Columns.Add(New DataColumn("duration"))
            Newtable.Columns.Add(New DataColumn("shiptocode"))
            Newtable.Columns.Add(New DataColumn("time"))
            Newtable.Columns.Add(New DataColumn("status"))

            Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))


            Dim i As Int32 = 1

            Dim lat As Double = 0
            Dim lon As Double = 0

            Dim r As DataRow

            cmd = New SqlCommand("select distinct convert(varchar(19),timestamp,120) as datetime,plateno,speed,ignition_sensor,alarm,lat,lon from vehicle_history where plateno ='" & plateno & "' and (gps_av='A' or (gps_av='V' and ignition_sensor='0')) and timestamp between '" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "' and '" & atddatetime.ToString("yyyy/MM/dd HH:mm:ss") & "' order by datetime asc", conn)
            '   cmd = New SqlCommand("select distinct convert(varchar(19),timestamp,120) as datetime,alarm,plateno,speed,ignition_sensor,lat,lon from vehicle_history where plateno ='70-2514' and (gps_av='A' or (gps_av='V' and ignition_sensor='0')) and timestamp between '2012/09/24 00:00:00' and '2012/09/24 23:59:59' order by datetime asc", conn)

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
                Dim prevlat As Double = 0
                Dim prevlon As Double = 0
                Dim minOption As Byte = 15
                Try
                    While dr.Read()

                        lastlat = dr("lat")
                        lastlon = dr("lon")
                        currenttime = dr("datetime")
                        currenttimep = dr("datetime")
                        If dr("ignition_sensor") = 1 And dr("speed") <> 0 Then
                            currentstatus = "moving"
                        ElseIf dr("ignition_sensor") = 1 And dr("speed") = 0 Then
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
                                        r = Newtable.NewRow
                                        r(0) = i
                                        r(1) = dr("plateno")
                                        r(2) = prevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(3) = tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(4) = "<span onclick=""javascript:panMapToPos(" & lastlat & "," & lastlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                                        r(5) = ""
                                        r(6) = prevtime.ToString("d MMM HH:mm") & "-" & tempprevtime.ToString("d MMM HH:mm")
                                        r(7) = "Stop"
                                        Newtable.Rows.Add(r)
                                        i = i + 1
                                    End If

                                Case "moving"

                                Case "idle"
                                    If temptime.TotalMinutes >= minOption Then
                                        r = Newtable.NewRow
                                        r(0) = i
                                        r(1) = dr("plateno")
                                        txtPlateno.Text = dr("plateno").ToString()
                                        txtSTC.Text = shiptocode
                                        txtShipToName.Text = shiptoname
                                        r(2) = prevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(3) = tempprevtime.ToString("yyyy/MM/dd HH:mm:ss")
                                        r(4) = "<span onclick=""javascript:panMapToPos(" & prevlat & "," & prevlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                                        r(5) = shiptocode.ToString()
                                        r(6) = prevtime.ToString("d MMM HH:mm") & "-" & tempprevtime.ToString("d MMM HH:mm")
                                        r(7) = "Idling"
                                        Newtable.Rows.Add(r)
                                        i = i + 1
                                    End If
                            End Select
                            prevtime = currenttime
                            prevstatus = currentstatus
                            prevlat = lastlat
                            prevlon = lastlon
                        End If




                        If dr("alarm") = "ON" Then
                            currentpto = "on"
                        Else
                            currentpto = "off"
                        End If

                        'If prevpto <> currentpto Then
                        '    Dim temptime As TimeSpan = tempprevtimep - prevtimep
                        '    Dim minutes As Integer = temptime.TotalMinutes()
                        '    If temptime.TotalMinutes >= 30 Then
                        '        r = ptotable.NewRow
                        '        r(0) = i
                        '        r(1) = dr("plateno")
                        '        r(2) = prevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                        '        r(3) = tempprevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                        '        r(4) = "<span onclick=""javascript:panMapToPos(" & lastlat & "," & lastlon & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                        '        r(5) = ""
                        '        r(6) = prevtimep.ToString("yyyy/MM/dd HH:mm:ss") & "-" & tempprevtimep.ToString("yyyy/MM/dd HH:mm:ss")
                        '        ptotable.Rows.Add(r)
                        '        i = i + 1
                        '    End If
                        '    prevtimep = currenttimep
                        'End If

                        tempprevtime = currenttime
                        tempprevtimep = currenttimep

                    End While
                Catch ex As Exception
                    Response.Write(ex.Message & ":" & ex.StackTrace)
                End Try
                If Not dr.IsClosed() Then
                    dr.Close()
                End If

                Dim da2 As New SqlDataAdapter("select * from pto_history where plateno='" & plateno & "' and from_timestamp between '" & bdt.ToString("yyyy/MM/dd HH:mm:ss") & "' and '" & atddatetime.ToString("yyyy/MM/dd HH:mm:ss") & "' ", conn)
                Dim ds2 As New DataSet
                da2.Fill(ds2)
                Dim k As Integer = 1
                For c As Integer = 0 To ds2.Tables(0).Rows.Count - 1
                    Dim temptime As TimeSpan = Convert.ToDateTime(ds2.Tables(0).Rows(c)("to_timestamp")) - Convert.ToDateTime(ds2.Tables(0).Rows(c)("from_timestamp"))
                    If temptime.TotalMinutes > 5 Then
                        r = Newtable.NewRow
                        r(0) = k
                        r(1) = ds2.Tables(0).Rows(c)("plateno")
                        r(2) = Convert.ToDateTime(ds2.Tables(0).Rows(c)("from_timestamp")).ToString("yyyy/MM/dd HH:mm:ss")
                        r(3) = Convert.ToDateTime(ds2.Tables(0).Rows(c)("to_timestamp")).ToString("yyyy/MM/dd HH:mm:ss")
                        r(4) = "<span onclick=""javascript:panMapToPos(" & ds2.Tables(0).Rows(c)("lat") & "," & ds2.Tables(0).Rows(c)("lon") & ") "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">" & temptime.TotalMinutes.ToString("0") & "</span>"
                        r(5) = ""
                        r(6) = Convert.ToDateTime(ds2.Tables(0).Rows(c)("from_timestamp")).ToString("d MMM HH:mm") & "-" & Convert.ToDateTime(ds2.Tables(0).Rows(c)("to_timestamp")).ToString("d MMM HH:mm")
                        r(7) = "PTO On"
                        Newtable.Rows.Add(r)
                        k = k + 1
                    End If
                Next





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

                'If idlingtable.Rows.Count > 0 Then
                '    For i = 0 To idlingtable.Rows.Count
                '        r = idlingtable.Rows(i)
                '        r(7) = 1
                '        Newtable.Rows.Add(r)
                '    Next
                'End If

                'If stoptable.Rows.Count > 0 Then
                '    For i = 0 To stoptable.Rows.Count
                '        r = stoptable.Rows(i)
                '        r(7) = 2
                '        Newtable.Rows.Add(r)
                '    Next
                'End If

                'If ptotable.Rows.Count > 0 Then
                '    For i = 0 To ptotable.Rows.Count
                '        r = ptotable.Rows(i)
                '        r(7) = 3
                '        Newtable.Rows.Add(r)
                '    Next
                'End If

                If Newtable.Rows.Count = 0 Then
                    r = Newtable.NewRow
                    r(0) = "--"
                    r(1) = "--"
                    r(2) = "--"
                    r(3) = "--"
                    r(4) = "--"
                    r(5) = "--"
                    r(6) = "--"
                    r(7) = 0
                    Newtable.Rows.Add(r)
                Else
                    'Dim DataV As New DataView
                    'DataV = Newtable.DefaultView
                    'DataV.Sort = "begindatetime ASC"
                    Newtable.DefaultView.Sort = "begindatetime ASC"
                End If



            Catch ex As Exception

            End Try
            GridView1.DataSource = idlingtable
            GridView1.DataBind()
            GridView2.DataSource = stoptable
            GridView2.DataBind()
            GridView3.DataSource = ptotable
            GridView3.DataBind()
            GridView4.DataSource = Newtable
            GridView4.DataBind()
            conn.Close()
            conn.Dispose()

        Catch ex As SystemException
            Response.Write(ex.Message & ":" & ex.StackTrace)
        End Try
    End Sub



    Protected Sub btnSubmitremark_Click(sender As Object, e As EventArgs) Handles btnSubmitremark.Click
        Dim conn As New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection2"))
        Dim cmd As New SqlCommand()
        cmd.Connection = conn
        Dim adminbit As Int16 = 0
        Try
            conn.Open()
            If chkbox.Checked Then
                adminbit = 1
            Else
                adminbit = 0
            End If
            If btnSubmitremark.Text = "Update Remarks" Then
                cmd.CommandText = "Update oss_job_remarks set remark=@rekamrs,admin='" & adminbit & "' where dn_id='" & dn_id.Value & "'"
            Else
                cmd.CommandText = "Insert into oss_job_remarks (dn_id,remark,admin) values ('" & dn_id.Value & "',@rekamrs," & adminbit & ")"
            End If

            cmd.Parameters.AddWithValue("@rekamrs", txtremark.Text)
            cmd.ExecuteNonQuery()
        Catch ex As Exception
            Response.Write(ex.Message)

        Finally
            If conn.State = ConnectionState.Open Then
                conn.Close()
            End If
        End Try
    End Sub

    Protected Sub GridView4_RowDataBound(sender As Object, e As GridViewRowEventArgs) Handles GridView4.RowDataBound
        'Try
        '    For i As Integer = 0 To GridView4.Rows.Count - 1
        '        Dim status As String = GridView4.Rows(i).Cells(7).Text
        '        Response.Write(status)
        '        If status = "1" Then
        '            GridView4.Rows(i).BackColor = System.Drawing.Color.CornflowerBlue   '"#ff6666";
        '        ElseIf status = "2" Then
        '            GridView4.Rows(i).BackColor = System.Drawing.Color.PaleVioletRed  '"#6666ff"
        '        ElseIf status = "3" Then
        '            GridView4.Rows(i).BackColor = System.Drawing.Color.PaleGreen  '"#aaff80"
        '        End If
        '    Next
        'Catch ex As Exception
        '    Response.Write("Cell Color" & ex.Message)
        'End Try


    End Sub


End Class
