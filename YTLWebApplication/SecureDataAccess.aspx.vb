Imports System.Data.SqlClient
Imports System.Text.RegularExpressions
Imports System.Web.Script.Serialization
Imports System.Security.Cryptography

Partial Class SecureDataAccess
    Inherits System.Web.UI.Page
    
    Private Const MAX_RECORDS_PER_PAGE As Integer = 100
    Private Const MAX_SEARCH_LENGTH As Integer = 50
    
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        ' Ensure user is authenticated
        If Not IsUserAuthenticated() Then
            Response.StatusCode = 401
            Response.End()
            Return
        End If
        
        ' Add security headers
        AddSecurityHeaders()
        
        ' Handle AJAX requests
        If Request.HttpMethod = "POST" Then
            HandleAjaxRequest()
        End If
    End Sub
    
    Private Function IsUserAuthenticated() As Boolean
        Return Session("UserId") IsNot Nothing AndAlso 
               Session("LoginTime") IsNot Nothing AndAlso 
               DateTime.Now.Subtract(CType(Session("LoginTime"), DateTime)).TotalHours < 8
    End Function
    
    Private Sub AddSecurityHeaders()
        Response.Headers.Add("X-Content-Type-Options", "nosniff")
        Response.Headers.Add("X-Frame-Options", "DENY")
        Response.Headers.Add("X-XSS-Protection", "1; mode=block")
        Response.Headers.Add("Cache-Control", "no-cache, no-store, must-revalidate")
        Response.Headers.Add("Pragma", "no-cache")
        Response.Headers.Add("Expires", "0")
    End Sub
    
    Private Sub HandleAjaxRequest()
        Try
            Dim operation As String = Request.Form("operation")
            
            ' Validate operation
            If Not IsValidOperation(operation) Then
                Response.StatusCode = 400
                Response.Write("Invalid operation")
                Return
            End If
            
            ' Validate CSRF token
            If Not ValidateCSRFToken() Then
                Response.StatusCode = 403
                Response.Write("Invalid CSRF token")
                Return
            End If
            
            Select Case operation
                Case "GetVehicleData"
                    GetVehicleData()
                Case "GetServiceHistory"
                    GetServiceHistory()
                Case "GetUserData"
                    GetUserData()
                Case "GetReports"
                    GetReports()
                Case Else
                    Response.StatusCode = 400
                    Response.Write("Unknown operation")
            End Select
            
        Catch ex As Exception
            LogError("AJAX request error", ex)
            Response.StatusCode = 500
            Response.Write("An error occurred")
        End Try
    End Sub
    
    Private Function IsValidOperation(operation As String) As Boolean
        Dim validOperations() As String = {"GetVehicleData", "GetServiceHistory", "GetUserData", "GetReports"}
        Return validOperations.Contains(operation)
    End Function
    
    Private Sub GetVehicleData()
        Dim userId As String = Session("UserId").ToString()
        Dim userRole As String = Session("Role").ToString()
        
        ' Input validation and sanitization
        Dim filters As New Dictionary(Of String, Object)()
        
        ' Validate and sanitize page number
        Dim pageNumber As Integer = 1
        If Not String.IsNullOrEmpty(Request.Form("page")) Then
            If Not Integer.TryParse(Request.Form("page"), pageNumber) OrElse pageNumber < 1 Then
                pageNumber = 1
            End If
        End If
        
        ' Validate and sanitize page size
        Dim pageSize As Integer = 10
        If Not String.IsNullOrEmpty(Request.Form("pageSize")) Then
            If Not Integer.TryParse(Request.Form("pageSize"), pageSize) OrElse 
               pageSize < 1 OrElse pageSize > MAX_RECORDS_PER_PAGE Then
                pageSize = 10
            End If
        End If
        
        ' Validate and sanitize search term
        Dim searchTerm As String = ""
        If Not String.IsNullOrEmpty(Request.Form("search")) Then
            searchTerm = SanitizeSearchInput(Request.Form("search"))
            If searchTerm.Length > MAX_SEARCH_LENGTH Then
                searchTerm = searchTerm.Substring(0, MAX_SEARCH_LENGTH)
            End If
        End If
        
        ' Validate date range
        Dim fromDate As DateTime = DateTime.Now.AddDays(-30)
        Dim toDate As DateTime = DateTime.Now
        
        If Not String.IsNullOrEmpty(Request.Form("fromDate")) Then
            DateTime.TryParse(Request.Form("fromDate"), fromDate)
        End If
        
        If Not String.IsNullOrEmpty(Request.Form("toDate")) Then
            DateTime.TryParse(Request.Form("toDate"), toDate)
        End If
        
        ' Ensure date range is reasonable
        If toDate.Subtract(fromDate).TotalDays > 365 Then
            fromDate = toDate.AddDays(-365)
        End If
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_GetVehicleDataSecure"
                
                ' Use parameterized queries
                cmd.Parameters.AddWithValue("@UserId", userId)
                cmd.Parameters.AddWithValue("@UserRole", userRole)
                cmd.Parameters.AddWithValue("@PageNumber", pageNumber)
                cmd.Parameters.AddWithValue("@PageSize", pageSize)
                cmd.Parameters.AddWithValue("@SearchTerm", searchTerm)
                cmd.Parameters.AddWithValue("@FromDate", fromDate)
                cmd.Parameters.AddWithValue("@ToDate", toDate)
                
                conn.Open()
                
                Dim vehicles As New List(Of Object)()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    While reader.Read()
                        vehicles.Add(New With {
                            .VehicleId = reader("VehicleId").ToString(),
                            .PlateNumber = Server.HtmlEncode(reader("PlateNumber").ToString()),
                            .VehicleType = Server.HtmlEncode(reader("VehicleType").ToString()),
                            .Status = Server.HtmlEncode(reader("Status").ToString()),
                            .LastUpdate = Convert.ToDateTime(reader("LastUpdate")).ToString("yyyy-MM-dd HH:mm:ss"),
                            .Location = If(reader("Location") IsNot DBNull.Value, 
                                         Server.HtmlEncode(reader("Location").ToString()), "")
                        })
                    End While
                End Using
                
                ' Log data access
                LogDataAccess("VEHICLE_DATA_ACCESSED", userId, searchTerm)
                
                Dim serializer As New JavaScriptSerializer()
                Response.ContentType = "application/json"
                Response.Write(serializer.Serialize(vehicles))
            End Using
        End Using
    End Sub
    
    Private Sub GetServiceHistory()
        Dim userId As String = Session("UserId").ToString()
        Dim userRole As String = Session("Role").ToString()
        
        ' Validate vehicle ID
        Dim vehicleId As String = Request.Form("vehicleId")
        If Not IsValidGuid(vehicleId) Then
            Response.StatusCode = 400
            Response.Write("Invalid vehicle ID")
            Return
        End If
        
        ' Check if user has access to this vehicle
        If Not HasVehicleAccess(userId, userRole, vehicleId) Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_GetServiceHistorySecure"
                
                cmd.Parameters.AddWithValue("@VehicleId", vehicleId)
                cmd.Parameters.AddWithValue("@UserId", userId)
                cmd.Parameters.AddWithValue("@UserRole", userRole)
                
                conn.Open()
                
                Dim services As New List(Of Object)()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    While reader.Read()
                        services.Add(New With {
                            .ServiceId = reader("ServiceId").ToString(),
                            .ServiceType = Server.HtmlEncode(reader("ServiceType").ToString()),
                            .ServiceDate = Convert.ToDateTime(reader("ServiceDate")).ToString("yyyy-MM-dd"),
                            .Status = Server.HtmlEncode(reader("Status").ToString()),
                            .Description = Server.HtmlEncode(reader("Description").ToString()),
                            .Technician = Server.HtmlEncode(reader("Technician").ToString())
                        })
                    End While
                End Using
                
                ' Log data access
                LogDataAccess("SERVICE_HISTORY_ACCESSED", userId, vehicleId)
                
                Dim serializer As New JavaScriptSerializer()
                Response.ContentType = "application/json"
                Response.Write(serializer.Serialize(services))
            End Using
        End Using
    End Sub
    
    Private Sub GetUserData()
        ' Only admins can access user data
        Dim userRole As String = Session("Role").ToString()
        If userRole <> "Admin" Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        Dim userId As String = Session("UserId").ToString()
        
        ' Input validation
        Dim pageNumber As Integer = 1
        Dim pageSize As Integer = 10
        
        If Not String.IsNullOrEmpty(Request.Form("page")) Then
            Integer.TryParse(Request.Form("page"), pageNumber)
        End If
        
        If Not String.IsNullOrEmpty(Request.Form("pageSize")) Then
            Integer.TryParse(Request.Form("pageSize"), pageSize)
        End If
        
        pageNumber = Math.Max(1, pageNumber)
        pageSize = Math.Min(Math.Max(1, pageSize), MAX_RECORDS_PER_PAGE)
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_GetUserDataSecure"
                
                cmd.Parameters.AddWithValue("@PageNumber", pageNumber)
                cmd.Parameters.AddWithValue("@PageSize", pageSize)
                cmd.Parameters.AddWithValue("@RequestedBy", userId)
                
                conn.Open()
                
                Dim users As New List(Of Object)()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    While reader.Read()
                        users.Add(New With {
                            .UserId = reader("UserId").ToString(),
                            .Username = Server.HtmlEncode(reader("Username").ToString()),
                            .Email = Server.HtmlEncode(reader("Email").ToString()),
                            .Role = Server.HtmlEncode(reader("Role").ToString()),
                            .IsActive = Convert.ToBoolean(reader("IsActive")),
                            .LastLogin = If(reader("LastLogin") IsNot DBNull.Value, 
                                          Convert.ToDateTime(reader("LastLogin")).ToString("yyyy-MM-dd HH:mm:ss"), "")
                        })
                    End While
                End Using
                
                ' Log data access
                LogDataAccess("USER_DATA_ACCESSED", userId, "")
                
                Dim serializer As New JavaScriptSerializer()
                Response.ContentType = "application/json"
                Response.Write(serializer.Serialize(users))
            End Using
        End Using
    End Sub
    
    Private Sub GetReports()
        Dim userId As String = Session("UserId").ToString()
        Dim userRole As String = Session("Role").ToString()
        
        ' Validate report type
        Dim reportType As String = Request.Form("reportType")
        If Not IsValidReportType(reportType) Then
            Response.StatusCode = 400
            Response.Write("Invalid report type")
            Return
        End If
        
        ' Check permissions for report type
        If Not HasReportAccess(userRole, reportType) Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        ' Validate date range
        Dim fromDate As DateTime
        Dim toDate As DateTime
        
        If Not DateTime.TryParse(Request.Form("fromDate"), fromDate) OrElse
           Not DateTime.TryParse(Request.Form("toDate"), toDate) Then
            Response.StatusCode = 400
            Response.Write("Invalid date range")
            Return
        End If
        
        ' Limit date range to prevent performance issues
        If toDate.Subtract(fromDate).TotalDays > 90 Then
            Response.StatusCode = 400
            Response.Write("Date range too large (max 90 days)")
            Return
        End If
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_GetReportDataSecure"
                
                cmd.Parameters.AddWithValue("@ReportType", reportType)
                cmd.Parameters.AddWithValue("@UserId", userId)
                cmd.Parameters.AddWithValue("@UserRole", userRole)
                cmd.Parameters.AddWithValue("@FromDate", fromDate)
                cmd.Parameters.AddWithValue("@ToDate", toDate)
                
                conn.Open()
                
                Dim reportData As New List(Of Object)()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    While reader.Read()
                        Dim row As New Dictionary(Of String, Object)()
                        
                        For i As Integer = 0 To reader.FieldCount - 1
                            Dim fieldName As String = reader.GetName(i)
                            Dim fieldValue As Object = reader(i)
                            
                            If fieldValue IsNot DBNull.Value AndAlso TypeOf fieldValue Is String Then
                                row(fieldName) = Server.HtmlEncode(fieldValue.ToString())
                            Else
                                row(fieldName) = fieldValue
                            End If
                        Next
                        
                        reportData.Add(row)
                    End While
                End Using
                
                ' Log report access
                LogDataAccess("REPORT_ACCESSED", userId, reportType)
                
                Dim serializer As New JavaScriptSerializer()
                Response.ContentType = "application/json"
                Response.Write(serializer.Serialize(reportData))
            End Using
        End Using
    End Sub
    
    Private Function SanitizeSearchInput(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If
        
        ' Remove potentially dangerous characters
        input = input.Trim()
        input = Regex.Replace(input, "[<>""'%;()&+]", "")
        input = Regex.Replace(input, "\b(script|javascript|vbscript|onload|onerror)\b", "", RegexOptions.IgnoreCase)
        
        Return input
    End Function
    
    Private Function IsValidGuid(guid As String) As Boolean
        Dim guidValue As Guid
        Return Guid.TryParse(guid, guidValue)
    End Function
    
    Private Function IsValidReportType(reportType As String) As Boolean
        Dim validTypes() As String = {"VehicleUtilization", "ServiceSummary", "UserActivity", "SystemLogs"}
        Return validTypes.Contains(reportType)
    End Function
    
    Private Function HasVehicleAccess(userId As String, userRole As String, vehicleId As String) As Boolean
        If userRole = "Admin" Then
            Return True
        End If
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_CheckVehicleAccess"
                
                cmd.Parameters.AddWithValue("@UserId", userId)
                cmd.Parameters.AddWithValue("@VehicleId", vehicleId)
                
                conn.Open()
                
                Dim result As Object = cmd.ExecuteScalar()
                Return result IsNot Nothing AndAlso Convert.ToBoolean(result)
            End Using
        End Using
    End Function
    
    Private Function HasReportAccess(userRole As String, reportType As String) As Boolean
        Select Case userRole
            Case "Admin"
                Return True
            Case "Manager"
                Return reportType <> "SystemLogs"
            Case "User"
                Return reportType = "VehicleUtilization"
            Case Else
                Return False
        End Select
    End Function
    
    Private Function ValidateCSRFToken() As Boolean
        Dim sessionToken As String = TryCast(Session("CSRFToken"), String)
        Dim requestToken As String = Request.Headers("X-CSRF-Token")
        
        Return Not String.IsNullOrEmpty(sessionToken) AndAlso 
               Not String.IsNullOrEmpty(requestToken) AndAlso 
               String.Equals(sessionToken, requestToken, StringComparison.Ordinal)
    End Function
    
    Private Sub LogDataAccess(action As String, userId As String, details As String)
        Try
            Using conn As New SqlConnection(GetSecureConnectionString())
                Using cmd As New SqlCommand()
                    cmd.Connection = conn
                    cmd.CommandType = CommandType.StoredProcedure
                    cmd.CommandText = "sp_LogDataAccess"
                    
                    cmd.Parameters.AddWithValue("@Action", action)
                    cmd.Parameters.AddWithValue("@UserId", userId)
                    cmd.Parameters.AddWithValue("@Details", details)
                    cmd.Parameters.AddWithValue("@IPAddress", Request.UserHostAddress)
                    cmd.Parameters.AddWithValue("@UserAgent", Request.UserAgent)
                    cmd.Parameters.AddWithValue("@Timestamp", DateTime.Now)
                    
                    conn.Open()
                    cmd.ExecuteNonQuery()
                End Using
            End Using
        Catch ex As Exception
            ' Log error but don't fail the operation
            LogError("Data access logging failed", ex)
        End Try
    End Sub
    
    Private Sub LogError(message As String, ex As Exception)
        Try
            Using conn As New SqlConnection(GetSecureConnectionString())
                Using cmd As New SqlCommand()
                    cmd.Connection = conn
                    cmd.CommandType = CommandType.StoredProcedure
                    cmd.CommandText = "sp_LogError"
                    
                    cmd.Parameters.AddWithValue("@Message", message)
                    cmd.Parameters.AddWithValue("@Exception", ex.ToString())
                    cmd.Parameters.AddWithValue("@IPAddress", Request.UserHostAddress)
                    cmd.Parameters.AddWithValue("@Timestamp", DateTime.Now)
                    
                    conn.Open()
                    cmd.ExecuteNonQuery()
                End Using
            End Using
        Catch
            ' Fail silently
        End Try
    End Sub
    
    Private Function GetSecureConnectionString() As String
        Return ConfigurationManager.ConnectionStrings("SecureConnection").ConnectionString
    End Function
End Class