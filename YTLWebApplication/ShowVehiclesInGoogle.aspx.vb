Imports System.Data.SqlClient
Imports System.Xml

Partial Class ShowVehiclesInGoogle
    Inherits System.Web.UI.Page

    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        Try
            Dim path As String = "http://" & Request.Url.Host & Request.ApplicationPath
            Dim connectionstring As String = System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection")
            Dim conn As New SqlConnection(connectionstring)

            Dim userid As String = Request.QueryString("userid")

            Dim cmd As SqlCommand = New SqlCommand("select userslist,role from userTBL where userid='" & userid & "'", conn)
            Dim dr As SqlDataReader

            conn.Open()
            dr = cmd.ExecuteReader()
            Dim role As String = "User"
            Dim userids As String = ""
            If dr.Read() Then
                role = dr("role")
                userids = dr("userslist")
            End If
            conn.Close()

            Dim userslist1() As String = userids.Split(",")
            Dim usersstring As String = ""

            For i As Byte = 0 To userslist1.Length - 1
                usersstring &= "'" & userslist1(i) & "',"
            Next
            usersstring = usersstring.Remove(usersstring.Length - 1, 1)

            Dim smallimagepath = path & "/vehiclesmallimages/smallvehicle1.gif"
            Dim cmd1 As SqlCommand = New SqlCommand("select distinct vt.plateno,convert(varchar(19),timestamp,120) as datetime,gps_av,lat,lon,speed,ignition_sensor,voice,panic,alarm,unlock,geofence,zonetrip,overspeed,vtt.type,symbol,immobilizer,centerno,tm_format,fueltheft,powercut,bigimage,smallimage from vehicle_tracked vtt,vehicleTBL vt  where vtt.plateno in (select plateno from vehicleTBL) and vtt.plateno=vt.plateno", conn)
            cmd = New SqlCommand("select distinct smallimage from vehicleTBL", conn)
            If role = "User" Then
                cmd1 = New SqlCommand("select a.plateno,convert(varchar(19),timestamp,120) as datetime,a.lat,a.lon,a.speed,a.ignition_sensor,b.bigimage,b.smallimage from vehicle_tracked a,vehicleTBL b where  a.plateno in (select plateno from vehicleTBL where userid='" & userid & "') and a.plateno=b.plateno", conn)
                cmd = New SqlCommand("select distinct smallimage from vehicleTBL where userid='" & userid & "'", conn)
            ElseIf role = "SuperUser" Or role = "Operator" Then
                cmd1 = New SqlCommand("select a.plateno,convert(varchar(19),timestamp,120) as datetime,a.lat,a.lon,a.speed,a.ignition_sensor,b.bigimage,b.smallimage from vehicle_tracked a,vehicleTBL b where  a.plateno in (select plateno from vehicleTBL where userid in(" & usersstring & ") ) and a.plateno=b.plateno", conn)
                cmd = New SqlCommand("select distinct smallimage from vehicleTBL where userid in(" & usersstring & ")", conn)
            End If
            Dim dr1 As SqlDataReader
            Dim j As Integer = 0
            Dim himagevalue As New Hashtable()
            Response.Write("<?xml version='1.0' encoding='utf-8' ?><kml xmlns='http://earth.google.com/kml/2.0'>")
            Response.Write("<Document><name>Vehicles</name><description>Click on vehicle plate number to see vehicle position on map</description>")
            conn.Open()
            dr = cmd.ExecuteReader()
            While dr.Read()
                himagevalue.Add(dr("smallimage"), j + 1)
                Response.Write("<Style id='vehiclestyle" & j + 1 & "'><IconStyle><scale>0.5</scale><Icon><href>" & path & "/vehiclesmallimages/" & dr("smallimage") & "</href></Icon></IconStyle></Style>")
                j += 1
            End While
            conn.Close()
            Dim xmldoc As System.Xml.XmlDocument = New System.Xml.XmlDocument()
            Dim datetimevalues() As String
            Dim plateno As String
            Dim datestr As String
            Dim timestr As String
            Dim lat As Double
            Dim lon As Double
            Dim speed As Double
            Dim ignition As String
            Dim imagepath = path & "/vehiclebigimages/bigvehicle1.gif"
            conn.Open()
            dr1 = cmd1.ExecuteReader()
            While dr1.Read()
                datetimevalues = dr1("datetime").ToString().Split(" ")
                plateno = dr1("plateno")
                datestr = datetimevalues(0)
                timestr = datetimevalues(1)
                lat = Math.Round(dr1("lat"), 6)
                lon = Math.Round(dr1("lon"), 6)
                speed = Math.Round(dr1("speed"), 2)
                imagepath = path & "/vehiclebigimages/" & dr1("bigimage")
                If IsDBNull(dr1("ignition_sensor")) Then
                    ignition = "ON"
                Else
                    If dr1("ignition_sensor") = 1 Then
                        ignition = "ON"
                    Else
                        ignition = "OFF"
                    End If
                End If
                Response.Write("<Placemark>")
                Response.Write("<Snippet maxLines='1'></Snippet>")
                Response.Write("<name>" & plateno & "</name>")
                Response.Write("<description><![CDATA[<table width='300' border='0' style='font-family: Verdana; font-size: 11px;'><tr><td style='width: 150px;' align='center' valign='middle'><img src='" & imagepath & "' alt='vehicle image' /></td><td><table><tr><td colspan='2' align='center'></td></tr><tr><td>Date</td><td>: " & datestr & "</td></tr><tr><td>Time</td><td>: " & timestr & "</td></tr><tr><td>Latitude</td><td>: " & lat & "</td></tr><tr><td>Longitude</td><td>: " & lon & "</td></tr><tr><td>Speed</td><td>: " & speed & " km/h</td></tr><tr><td>Ignition</td><td>: " & ignition & "</td></tr></table></td></tr></table>]]></description>")
                Response.Write("<styleUrl>#vehiclestyle" & himagevalue.Item(dr1("smallimage")) & "</styleUrl><Point><coordinates>" & lon & "," & lat & ",0</coordinates></Point></Placemark>")
            End While
            conn.Close()
            Response.Write("</Document></kml>")
            Response.Buffer = True
            Response.ContentType = "application/vnd.google-earth.kml+xml"
            Response.AddHeader("Content-Disposition", "attachment; filename=Vehicles.kml;")
            xmldoc.Save(Response.Output)

        Catch ex As Exception

            Response.Write("<b style='color:red;'>" & ex.Message & "</b>")

        End Try
    End Sub
End Class
