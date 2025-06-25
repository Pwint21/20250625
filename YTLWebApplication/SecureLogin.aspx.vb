Imports System.Data.SqlClient
Imports System.Security.Cryptography
Imports System.Text
Imports System.Web.Security
Imports System.ComponentModel.DataAnnotations

Partial Class SecureLogin
    Inherits System.Web.UI.Page
    
    Private Const MAX_LOGIN_ATTEMPTS As Integer = 5
    Private Const LOCKOUT_DURATION_MINUTES As Integer = 15
    
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load
        ' Implement HTTPS redirect
        If Not Request.IsSecureConnection AndAlso Not Request.IsLocal Then
            Dim secureUrl As String = Request.Url.ToString().Replace("http://", "https://")
            Response.Redirect(secureUrl, True)
        End If
        
        ' Add security headers
        Response.Headers.Add("X-Content-Type-Options", "nosniff")
        Response.Headers.Add("X-Frame-Options", "DENY")
        Response.Headers.Add("X-XSS-Protection", "1; mode=block")
        Response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        
        If Not Page.IsPostBack Then
            ' Clear any existing sessions
            Session.Clear()
            Session.Abandon()
            
            ' Generate CSRF token
            ViewState("CSRFToken") = GenerateCSRFToken()
        End If
    End Sub
    
    Protected Sub btnLogin_Click(ByVal sender As Object, ByVal e As System.EventArgs) Handles btnLogin.Click
        Try
            ' Validate CSRF token
            If Not ValidateCSRFToken() Then
                LogSecurityEvent("CSRF_TOKEN_INVALID", Request.UserHostAddress)
                ShowError("Invalid request. Please try again.")
                Return
            End If
            
            ' Input validation
            If Not ValidateInput() Then
                Return
            End If
            
            ' Rate limiting check
            If IsRateLimited() Then
                LogSecurityEvent("RATE_LIMIT_EXCEEDED", Request.UserHostAddress)
                ShowError("Too many login attempts. Please try again later.")
                Return
            End If
            
            ' Authenticate user
            Dim user As UserInfo = AuthenticateUser(txtUsername.Text.Trim(), txtPassword.Text)
            
            If user IsNot Nothing Then
                ' Successful login
                HandleSuccessfulLogin(user)
            Else
                ' Failed login
                HandleFailedLogin(txtUsername.Text.Trim())
            End If
            
        Catch ex As Exception
            LogError("Login error", ex)
            ShowError("An error occurred during login. Please try again.")
        End Try
    End Sub
    
    Private Function ValidateInput() As Boolean
        Dim isValid As Boolean = True
        
        ' Username validation
        If String.IsNullOrWhiteSpace(txtUsername.Text) Then
            ShowError("Username is required.")
            isValid = False
        ElseIf txtUsername.Text.Length > 50 Then
            ShowError("Username is too long.")
            isValid = False
        ElseIf Not IsValidUsername(txtUsername.Text) Then
            ShowError("Invalid username format.")
            isValid = False
        End If
        
        ' Password validation
        If String.IsNullOrWhiteSpace(txtPassword.Text) Then
            ShowError("Password is required.")
            isValid = False
        ElseIf txtPassword.Text.Length < 8 OrElse txtPassword.Text.Length > 128 Then
            ShowError("Password must be between 8 and 128 characters.")
            isValid = False
        End If
        
        Return isValid
    End Function
    
    Private Function IsValidUsername(username As String) As Boolean
        ' Allow only alphanumeric characters, underscore, and hyphen
        Dim pattern As String = "^[a-zA-Z0-9_-]+$"
        Return System.Text.RegularExpressions.Regex.IsMatch(username, pattern)
    End Function
    
    Private Function AuthenticateUser(username As String, password As String) As UserInfo
        Dim user As UserInfo = Nothing
        
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_AuthenticateUser"
                
                ' Use parameterized queries
                cmd.Parameters.AddWithValue("@Username", username)
                
                conn.Open()
                
                Using reader As SqlDataReader = cmd.ExecuteReader()
                    If reader.Read() Then
                        Dim storedHash As String = reader("PasswordHash").ToString()
                        Dim salt As String = reader("Salt").ToString()
                        Dim isActive As Boolean = Convert.ToBoolean(reader("IsActive"))
                        Dim failedAttempts As Integer = Convert.ToInt32(reader("FailedLoginAttempts"))
                        Dim lockoutEnd As Object = reader("LockoutEnd")
                        
                        ' Check if account is locked
                        If lockoutEnd IsNot DBNull.Value AndAlso DateTime.Now < Convert.ToDateTime(lockoutEnd) Then
                            LogSecurityEvent("LOGIN_ATTEMPT_LOCKED_ACCOUNT", Request.UserHostAddress, username)
                            Return Nothing
                        End If
                        
                        ' Check if account is active
                        If Not isActive Then
                            LogSecurityEvent("LOGIN_ATTEMPT_INACTIVE_ACCOUNT", Request.UserHostAddress, username)
                            Return Nothing
                        End If
                        
                        ' Verify password
                        If VerifyPassword(password, storedHash, salt) Then
                            user = New UserInfo()
                            user.UserId = reader("UserId").ToString()
                            user.Username = reader("Username").ToString()
                            user.Role = reader("Role").ToString()
                            user.Email = reader("Email").ToString()
                        End If
                    End If
                End Using
            End Using
        End Using
        
        Return user
    End Function
    
    Private Function VerifyPassword(password As String, storedHash As String, salt As String) As Boolean
        Try
            Dim computedHash As String = HashPassword(password, salt)
            Return String.Equals(computedHash, storedHash, StringComparison.Ordinal)
        Catch
            Return False
        End Try
    End Function
    
    Private Function HashPassword(password As String, salt As String) As String
        Using sha256 As SHA256 = SHA256.Create()
            Dim saltedPassword As String = password + salt
            Dim hashBytes As Byte() = sha256.ComputeHash(Encoding.UTF8.GetBytes(saltedPassword))
            Return Convert.ToBase64String(hashBytes)
        End Using
    End Function
    
    Private Sub HandleSuccessfulLogin(user As UserInfo)
        ' Reset failed login attempts
        ResetFailedLoginAttempts(user.Username)
        
        ' Update last login time
        UpdateLastLoginTime(user.UserId)
        
        ' Create secure session
        CreateSecureSession(user)
        
        ' Log successful login
        LogSecurityEvent("LOGIN_SUCCESS", Request.UserHostAddress, user.Username)
        
        ' Redirect to dashboard
        Response.Redirect("~/Dashboard.aspx", False)
    End Sub
    
    Private Sub HandleFailedLogin(username As String)
        ' Increment failed login attempts
        IncrementFailedLoginAttempts(username)
        
        ' Log failed login
        LogSecurityEvent("LOGIN_FAILED", Request.UserHostAddress, username)
        
        ' Show generic error message
        ShowError("Invalid username or password.")
    End Sub
    
    Private Sub CreateSecureSession(user As UserInfo)
        ' Regenerate session ID
        Session.Abandon()
        
        ' Create new session with secure data
        Session("UserId") = user.UserId
        Session("Username") = user.Username
        Session("Role") = user.Role
        Session("LoginTime") = DateTime.Now
        Session("CSRFToken") = GenerateCSRFToken()
        
        ' Set secure cookie
        Dim authCookie As New HttpCookie("AuthToken", GenerateSecureToken())
        authCookie.HttpOnly = True
        authCookie.Secure = Request.IsSecureConnection
        authCookie.SameSite = SameSiteMode.Strict
        authCookie.Expires = DateTime.Now.AddHours(8)
        Response.Cookies.Add(authCookie)
    End Sub
    
    Private Function GenerateCSRFToken() As String
        Using rng As New RNGCryptoServiceProvider()
            Dim tokenBytes(31) As Byte
            rng.GetBytes(tokenBytes)
            Return Convert.ToBase64String(tokenBytes)
        End Using
    End Function
    
    Private Function ValidateCSRFToken() As Boolean
        Dim sessionToken As String = TryCast(ViewState("CSRFToken"), String)
        Dim requestToken As String = Request.Form("__CSRFToken")
        
        Return Not String.IsNullOrEmpty(sessionToken) AndAlso 
               Not String.IsNullOrEmpty(requestToken) AndAlso 
               String.Equals(sessionToken, requestToken, StringComparison.Ordinal)
    End Function
    
    Private Function GenerateSecureToken() As String
        Using rng As New RNGCryptoServiceProvider()
            Dim tokenBytes(63) As Byte
            rng.GetBytes(tokenBytes)
            Return Convert.ToBase64String(tokenBytes)
        End Using
    End Function
    
    Private Function IsRateLimited() As Boolean
        Dim cacheKey As String = "LoginAttempts_" + Request.UserHostAddress
        Dim attempts As Object = HttpContext.Current.Cache(cacheKey)
        
        If attempts Is Nothing Then
            HttpContext.Current.Cache.Insert(cacheKey, 1, Nothing, 
                DateTime.Now.AddMinutes(15), TimeSpan.Zero)
            Return False
        End If
        
        Dim attemptCount As Integer = Convert.ToInt32(attempts)
        If attemptCount >= 10 Then
            Return True
        End If
        
        HttpContext.Current.Cache(cacheKey) = attemptCount + 1
        Return False
    End Function
    
    Private Sub IncrementFailedLoginAttempts(username As String)
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_IncrementFailedLoginAttempts"
                cmd.Parameters.AddWithValue("@Username", username)
                cmd.Parameters.AddWithValue("@LockoutDuration", LOCKOUT_DURATION_MINUTES)
                
                conn.Open()
                cmd.ExecuteNonQuery()
            End Using
        End Using
    End Sub
    
    Private Sub ResetFailedLoginAttempts(username As String)
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_ResetFailedLoginAttempts"
                cmd.Parameters.AddWithValue("@Username", username)
                
                conn.Open()
                cmd.ExecuteNonQuery()
            End Using
        End Using
    End Sub
    
    Private Sub UpdateLastLoginTime(userId As String)
        Using conn As New SqlConnection(GetSecureConnectionString())
            Using cmd As New SqlCommand()
                cmd.Connection = conn
                cmd.CommandType = CommandType.StoredProcedure
                cmd.CommandText = "sp_UpdateLastLoginTime"
                cmd.Parameters.AddWithValue("@UserId", userId)
                
                conn.Open()
                cmd.ExecuteNonQuery()
            End Using
        End Using
    End Sub
    
    Private Function GetSecureConnectionString() As String
        ' Use encrypted connection strings
        Return ConfigurationManager.ConnectionStrings("SecureConnection").ConnectionString
    End Function
    
    Private Sub LogSecurityEvent(eventType As String, ipAddress As String, Optional username As String = "")
        Try
            Using conn As New SqlConnection(GetSecureConnectionString())
                Using cmd As New SqlCommand()
                    cmd.Connection = conn
                    cmd.CommandType = CommandType.StoredProcedure
                    cmd.CommandText = "sp_LogSecurityEvent"
                    cmd.Parameters.AddWithValue("@EventType", eventType)
                    cmd.Parameters.AddWithValue("@IPAddress", ipAddress)
                    cmd.Parameters.AddWithValue("@Username", username)
                    cmd.Parameters.AddWithValue("@UserAgent", Request.UserAgent)
                    cmd.Parameters.AddWithValue("@Timestamp", DateTime.Now)
                    
                    conn.Open()
                    cmd.ExecuteNonQuery()
                End Using
            End Using
        Catch ex As Exception
            ' Log to system event log as fallback
            System.Diagnostics.EventLog.WriteEntry("Application", 
                $"Security event logging failed: {ex.Message}", 
                System.Diagnostics.EventLogEntryType.Error)
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
            ' Fail silently to prevent information disclosure
        End Try
    End Sub
    
    Private Sub ShowError(message As String)
        lblError.Text = Server.HtmlEncode(message)
        lblError.Visible = True
    End Sub
    
    Public Class UserInfo
        Public Property UserId As String
        Public Property Username As String
        Public Property Role As String
        Public Property Email As String
    End Class
End Class