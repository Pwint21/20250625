Imports System.Data.SqlClient
Imports AspMap
Partial Class ShowCompetitorInformation
    Inherits System.Web.UI.Page
    Public qsa() As String
    Public qs As String = ""
    Public source As String = ""
    Protected Sub Page_Load(sender As Object, e As System.EventArgs) Handles Me.Load

        Try
            Dim id As String = Request.QueryString("geoid")
            Dim tid As String = Request.QueryString("transid")
            Dim bdt As String = Convert.ToDateTime(Request.QueryString("bdt")).ToString("yyyy/MM/dd HH:mm:ss")
            Dim edt As String = Convert.ToDateTime(Request.QueryString("edt")).ToString("yyyy/MM/dd HH:mm:ss")
            Dim conn2 As SqlConnection = New SqlConnection(System.Configuration.ConfigurationManager.AppSettings("sqlserverconnection"))
            Dim cmd As SqlCommand = New SqlCommand("select plateno,intimestamp,outtimestamp from public_geofence_history where id='" & id & "' and plateno in (select plateno from vehicletbl where transporter_id='" & tid & "') and intimestamp between '" & bdt & "' and '" & edt & "'", conn2)

            Dim idlingtable As New DataTable
            idlingtable.Columns.Add(New DataColumn("sno"))
            idlingtable.Columns.Add(New DataColumn("plateno"))
            idlingtable.Columns.Add(New DataColumn("begindatetime"))
            idlingtable.Columns.Add(New DataColumn("enddatetime"))
            idlingtable.Columns.Add(New DataColumn("details"))
            Dim r As DataRow
            Dim counter As Int32 = 1
            Dim plateno As String = ""
            Try
                conn2.Open()
                Dim dr2 As SqlDataReader = cmd.ExecuteReader()

                While dr2.Read()
                    r = idlingtable.NewRow
                    r(0) = counter
                    If plateno = "" Then
                        plateno = dr2("plateno")
                    End If
                    r(1) = dr2("plateno")
                    r(2) = Convert.ToDateTime(dr2("intimestamp")).ToString("yyyy/MM/dd HH:mm:ss")
                    If IsDBNull(dr2("outtimestamp")) Then
                        r(3) = ""
                        r(4) = "<span onclick=""javascript:SetSource('" & plateno & "','" & Convert.ToDateTime(dr2("intimestamp")).AddHours(-12).ToString("yyyy/MM/dd HH:mm:ss") & "','" & Convert.ToDateTime(dr2("intimestamp")).AddHours(12).ToString("yyyy/MM/dd HH:mm:ss") & "') "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">View Map</span>"
                    Else
                        r(3) = Convert.ToDateTime(dr2("outtimestamp")).ToString("yyyy/MM/dd HH:mm:ss")
                        r(4) = "<span onclick=""javascript:SetSource('" & plateno & "','" & Convert.ToDateTime(dr2("intimestamp")).AddHours(-12).ToString("yyyy/MM/dd HH:mm:ss") & "','" & Convert.ToDateTime(dr2("outtimestamp")).AddHours(12).ToString("yyyy/MM/dd HH:mm:ss") & "') "" style=""cursor:pointer;text-decoration: underline; color: #000080;"" title=""View on map"">Map</span>"
                    End If
                    idlingtable.Rows.Add(r)
                    counter += 1
                End While

                source = "Gmap.aspx?scode=1&plateno=" & plateno & "&bdt=" & bdt & "&edt=" & edt





            Catch ex As Exception
                Response.Write(ex.Message)
            Finally
                If conn2.State = ConnectionState.Open Then
                    conn2.Close()
                End If

            End Try
            source = "'" & source & "'"
            GridView1.DataSource = idlingtable
            GridView1.DataBind()


        Catch ex As SystemException
            Response.Write(ex.Message)
        End Try
    End Sub


End Class
