Imports System.Data.SqlClient
Imports System.Text.RegularExpressions
Imports System.Web.Script.Serialization
Imports System.ComponentModel.DataAnnotations

Partial Class SecureServiceManagement
    Inherits System.Web.UI.Page
    
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        ' Ensure user is authenticated
        If Not IsUserAuthenticated() Then
            Response.Redirect("~/Login.aspx", True)
            Return
        End If
        
        ' Validate user permissions
        If Not HasPermission("SERVICE_MANAGEMENT") Then
            Response.StatusCode = 403
            Response.End()
            Return
        End If
        
        ' Add security headers
        AddSecurityHeaders()
        
        If Not Page.IsPostBack Then
            LoadInitialData()
        End If
    End Sub
    
    Private Function IsUserAuthenticated() As Boolean
        Return Session("UserId") IsNot Nothing AndAlso 
               Session("LoginTime") IsNot Nothing AndAlso 
               DateTime.Now.Subtract(CType(Session("LoginTime"), DateTime)).TotalHours < 8
    End Function
    
    Private Function HasPermission(permission As String) As Boolean
        Dim userRole As String = TryCast(Session("Role"), String)
        
        Select Case userRole
            Case "Admin"
                Return True
            Case "Manager"
                Return permission = "SERVICE_MANAGEMENT" OrElse permission = "SERVICE_VIEW"
            Case "User"
                Return permission = "SERVICE_VIEW"
            Case Else
                Return False
        End Select
    End Function
    
    Private Sub AddSecurityHeaders()
        Response.Headers.Add("X-Content-Type-Options", "nosniff")
        Response.Headers.Add("X-Frame-Options", "SAMEORIGIN")
        Response.Headers.Add("X-XSS-Protection", "1; mode=block")
        Response.Headers.Add("Content-Security-Policy", 
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
    End Sub
    
    Protected Sub GetServiceData(ByVal operation As String)
        Try
            ' Validate operation parameter
            If Not IsValidOperation(operation) Then
                Response.StatusCode = 400
                Response.Write("Invalid operation")
                Return
            End If
            
            ' Validate CSRF token for state-changing operations
            If IsStateChangingOperation(operation) AndAlso Not ValidateCSRFToken() Then
                Response.StatusCode = 403
                Response.Write("Invalid CSRF token")
                Return
            End If
            
            Select Case operation
                Case "GetServices"
                    GetServices()
                Case "CreateService"
                    CreateService()
                Case "UpdateService"
                    UpdateService()
                Case "DeleteService"
                    DeleteService()
                Case Else
                    Response.StatusCode = 400
                    Response.Write("Unknown operation")
            End Select
            
        Catch ex As Exception
            LogError("Service operation error", ex)
            Response.StatusCode = 500
            Response.Write("An error occurred")
        End Try
    End Sub
    
    Private Function IsValidOperation(operation As String) As Boolean
        Dim validOperations() As String = {"GetServices", "CreateService", "UpdateService", "DeleteService"}
        Return validOperations.Contains(operation)
    End Function
    
    Private Function IsStateChangingOperation(operation As String) As Boolean
        Dim stateChangingOps() As String = {"CreateService", "UpdateService", "DeleteService"}
        Return stateChangingOps.Contains(operation)
    End Function
    
    Private Sub GetServices()
        Dim userId As String = Session("UserId").ToString()
        Dim userRole As String = Session("Role").ToString()
        
        ' Input validation
        Dim pageNumber As Integer = 1
        Dim pageSize As Integer = 10
        Dim searchTerm As String = ""
        
        If Not String.IsNullOrEmpty(Request.QueryString("page")) Then
            If Not Integer.TryParse(Request.QueryString("page"), pageNumber) OrElse pageNumber < 1 Then
                pageNumber = 1
            End If
        End If
        
        If Not String.IsNullOrEmpty(Request.QueryString("size")) Then
            If Not Integer.TryParse(Request.QueryString("size"), pageSize) OrElse pageSize < 1 OrElse pageSize > 100 Then
                pageSize = 10
            End If
        End If
        
        If Not String.IsNullOrEmpty(Request.QueryString("search")) Then
            searchTerm = SanitizeInput(Request.QueryString("search"))
        End If
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_GetServices"
                
                cmd.Parameters.AddWithValue("@UserId", userId)
                cmd.Parameters.AddWithValue("@UserRole", userRole)
                cmd.Parameters.AddWithValue("@PageNumber", pageNumber)
                cmd.Parameters.AddWithValue("@PageSize", pageSize)
                cmd.Parameters.AddWithValue("@SearchTerm", searchTerm)
                
                conn.Open()
                
                Dim services As New List(Of Object)()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    While reader.Read()
                        services.Add(New With {
                            .ServiceId = reader("ServiceId").ToString(),
                            .ServiceType = Server.HtmlEncode(reader("ServiceType").ToString()),
                            .PlateNumber = Server.HtmlEncode(reader("PlateNumber").ToString()),
                            .Priority = Server.HtmlEncode(reader("Priority").ToString()),
                            .Status = Server.HtmlEncode(reader("Status").ToString()),
                            .CreatedDate = Convert.ToDateTime(reader("CreatedDate")).ToString("yyyy-MM-dd HH:mm:ss"),
                            .Description = Server.HtmlEncode(reader("Description").ToString())
                        })
                    End While
                End Using
                
                Dim serializer As New JavaScriptSerializer()
                Response.ContentType = "application/json"
                Response.Write(serializer.Serialize(services))
            End Using
        End Using
    End Sub
    
    Private Sub CreateService()
        ' Validate permissions
        If Not HasPermission("SERVICE_MANAGEMENT") Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        ' Validate input
        Dim serviceData As ServiceModel = ValidateServiceInput()
        If serviceData Is Nothing Then
            Return
        End If
        
        Dim userId As String = Session("UserId").ToString()
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_CreateService"
                
                cmd.Parameters.AddWithValue("@ServiceType", serviceData.ServiceType)
                cmd.Parameters.AddWithValue("@PlateNumber", serviceData.PlateNumber)
                cmd.Parameters.AddWithValue("@Priority", serviceData.Priority)
                cmd.Parameters.AddWithValue("@Description", serviceData.Description)
                cmd.Parameters.AddWithValue("@CreatedBy", userId)
                
                conn.Open()
                
                Dim serviceId As Object = cmd.ExecuteScalar()
                
                If serviceId IsNot Nothing Then
                    LogAuditEvent("SERVICE_CREATED", serviceId.ToString(), userId)
                    Response.ContentType = "application/json"
                    Response.Write($"{{""success"": true, ""serviceId"": ""{serviceId}""}}")
                Else
                    Response.StatusCode = 500
                    Response.Write("Failed to create service")
                End If
            End Using
        End Using
    End Sub
    
    Private Sub UpdateService()
        ' Validate permissions
        If Not HasPermission("SERVICE_MANAGEMENT") Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        ' Validate service ID
        Dim serviceId As String = Request.QueryString("id")
        If Not IsValidGuid(serviceId) Then
            Response.StatusCode = 400
            Response.Write("Invalid service ID")
            Return
        End If
        
        ' Validate input
        Dim serviceData As ServiceModel = ValidateServiceInput()
        If serviceData Is Nothing Then
            Return
        End If
        
        Dim userId As String = Session("UserId").ToString()
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_UpdateService"
                
                cmd.Parameters.AddWithValue("@ServiceId", serviceId)
                cmd.Parameters.AddWithValue("@ServiceType", serviceData.ServiceType)
                cmd.Parameters.AddWithValue("@Priority", serviceData.Priority)
                cmd.Parameters.AddWithValue("@Status", serviceData.Status)
                cmd.Parameters.AddWithValue("@Description", serviceData.Description)
                cmd.Parameters.AddWithValue("@UpdatedBy", userId)
                
                conn.Open()
                
                Dim rowsAffected As Integer = cmd.ExecuteNonQuery()
                
                If rowsAffected > 0 Then
                    LogAuditEvent("SERVICE_UPDATED", serviceId, userId)
                    Response.ContentType = "application/json"
                    Response.Write("{""success"": true}")
                Else
                    Response.StatusCode = 404
                    Response.Write("Service not found")
                End If
            End Using
        End Using
    End Sub
    
    Private Sub DeleteService()
        ' Validate permissions
        If Not HasPermission("SERVICE_MANAGEMENT") Then
            Response.StatusCode = 403
            Response.Write("Access denied")
            Return
        End If
        
        ' Validate service ID
        Dim serviceId As String = Request.QueryString("id")
        If Not IsValidGuid(serviceId) Then
            Response.StatusCode = 400
            Response.Write("Invalid service ID")
            Return
        End If
        
        Dim userId As String = Session("UserId").ToString()
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_DeleteService"
                
                cmd.Parameters.AddWithValue("@ServiceId", serviceId)
                cmd.Parameters.AddWithValue("@DeletedBy", userId)
                
                conn.Open()
                
                Dim rowsAffected As Integer = cmd.ExecuteNonQuery()
                
                If rowsAffected > 0 Then
                    LogAuditEvent("SERVICE_DELETED", serviceId, userId)
                    Response.ContentType = "application/json"
                    Response.Write("{""success"": true}")
                Else
                    Response.StatusCode = 404
                    Response.Write("Service not found")
                End If
            End Using
        End Using
    End Sub
    
    Private Function ValidateServiceInput() As ServiceModel
        Dim serviceData As New ServiceModel()
        Dim errors As New List(Of String)()
        
        ' Validate service type
        serviceData.ServiceType = SanitizeInput(Request.Form("serviceType"))
        If String.IsNullOrWhiteSpace(serviceData.ServiceType) Then
            errors.Add("Service type is required")
        ElseIf Not IsValidServiceType(serviceData.ServiceType) Then
            errors.Add("Invalid service type")
        End If
        
        ' Validate plate number
        serviceData.PlateNumber = SanitizeInput(Request.Form("plateNumber"))
        If String.IsNullOrWhiteSpace(serviceData.PlateNumber) Then
            errors.Add("Plate number is required")
        ElseIf Not IsValidPlateNumber(serviceData.PlateNumber) Then
            errors.Add("Invalid plate number format")
        End If
        
        ' Validate priority
        serviceData.Priority = SanitizeInput(Request.Form("priority"))
        If String.IsNullOrWhiteSpace(serviceData.Priority) Then
            errors.Add("Priority is required")
        ElseIf Not IsValidPriority(serviceData.Priority) Then
            errors.Add("Invalid priority")
        End If
        
        ' Validate status (for updates)
        If Not String.IsNullOrEmpty(Request.Form("status")) Then
            serviceData.Status = SanitizeInput(Request.Form("status"))
            If Not IsValidStatus(serviceData.Status) Then
                errors.Add("Invalid status")
            End If
        End If
        
        ' Validate description
        serviceData.Description = SanitizeInput(Request.Form("description"))
        If String.IsNullOrWhiteSpace(serviceData.Description) Then
            errors.Add("Description is required")
        ElseIf serviceData.Description.Length > 1000 Then
            errors.Add("Description is too long")
        End If
        
        If errors.Count > 0 Then
            Response.StatusCode = 400
            Response.ContentType = "application/json"
            Dim serializer As New JavaScriptSerializer()
            Response.Write(serializer.Serialize(New With {.errors = errors}))
            Return Nothing
        End If
        
        Return serviceData
    End Function
    
    Private Function SanitizeInput(input As String) As String
        If String.IsNullOrEmpty(input) Then
            Return String.Empty
        End If
        
        ' Remove potentially dangerous characters
        input = input.Trim()
        input = Regex.Replace(input, "[<>""']", "")
        input = input.Replace("script", "").Replace("javascript", "").Replace("vbscript", "")
        
        Return input
    End Function
    
    Private Function IsValidServiceType(serviceType As String) As Boolean
        Dim validTypes() As String = {"Maintenance", "Repair", "Inspection", "Cleaning"}
        Return validTypes.Contains(serviceType)
    End Function
    
    Private Function IsValidPlateNumber(plateNumber As String) As Boolean
        ' Malaysian plate number format
        Dim pattern As String = "^[A-Z]{1,3}[0-9]{1,4}[A-Z]?$"
        Return Regex.IsMatch(plateNumber.ToUpper(), pattern)
    End Function
    
    Private Function IsValidPriority(priority As String) As Boolean
        Dim validPriorities() As String = {"Low", "Medium", "High", "Urgent"}
        Return validPriorities.Contains(priority)
    End Function
    
    Private Function IsValidStatus(status As String) As Boolean
        Dim validStatuses() As String = {"Open", "In Progress", "Completed", "Cancelled"}
        Return validStatuses.Contains(status)
    End Function
    
    Private Function IsValidGuid(guid As String) As Boolean
        Dim guidValue As Guid
        Return Guid.TryParse(guid, guidValue)
    End Function
    
    Private Function ValidateCSRFToken() As Boolean
        Dim sessionToken As String = TryCast(Session("CSRFToken"), String)
        Dim requestToken As String = Request.Headers("X-CSRF-Token")
        
        Return Not String.IsNullOrEmpty(sessionToken) AndAlso 
               Not String.IsNullOrEmpty(requestToken) AndAlso 
               String.Equals(sessionToken, requestToken, StringComparison.Ordinal)
    End Function
    
    Private Sub LogAuditEvent(action As String, resourceId As String, userId As String)
        Try
            Using conn As New SqlConnection(GetSecureConnectionString())
                Using cmd As New SqlCommand()
                    cmd.Connection = conn
                    cmd.CommandType = CommandType.StoredProcedure
                    cmd.CommandText = "sp_LogAuditEvent"
                    
                    cmd.Parameters.AddWithValue("@Action", action)
                    cmd.Parameters.AddWithValue("@ResourceType", "Service")
                    cmd.Parameters.AddWithValue("@ResourceId", resourceId)
                    cmd.Parameters.AddWithValue("@UserId", userId)
                    cmd.Parameters.AddWithValue("@IPAddress", Request.UserHostAddress)
                    cmd.Parameters.AddWithValue("@UserAgent", Request.UserAgent)
                    cmd.Parameters.AddWithValue("@Timestamp", DateTime.Now)
                    
                    conn.Open()
                    cmd.ExecuteNonQuery()
                End Using
            End Using
        Catch ex As Exception
            ' Log error but don't fail the operation
            LogError("Audit logging failed", ex)
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
    
    Private Sub LoadInitialData()
        ' Load any initial data needed for the page
    End Sub
    
    Public Class ServiceModel
        Public Property ServiceType As String
        Public Property PlateNumber As String
        Public Property Priority As String
        Public Property Status As String
        Public Property Description As String
    End Class
End Class