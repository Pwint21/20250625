Imports System.Data.SqlClient
Imports System.IO
Imports System.Collections.Generic
Imports Newtonsoft.Json
Partial Class SmartOss
    Inherits System.Web.UI.Page
    Public curdate, curdateto As String
    Protected Overrides Sub OnInit(ByVal e As System.EventArgs)
        If Request.Cookies("userinfo") Is Nothing Then
            Response.Redirect("Login.aspx")
        Else
            curdate = Date.Now.AddDays(-1).ToString("yyyy/MM/dd")
            curdate = curdate.Replace("-", "/")
            curdateto = Date.Now.AddDays(-1).ToString("yyyy/MM/dd")
            curdateto = curdateto.Replace("-", "/")
        End If
    End Sub
    Protected Sub Page_Load(ByVal sender As Object, ByVal e As System.EventArgs) Handles Me.Load

    End Sub

End Class
