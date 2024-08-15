# Set Default MFA Method via Microsoft Graph API (PowerShell Function)

This repository contains a PowerShell function, `Set-DefaultMFA`, that uses the Microsoft Graph API to configure a user's default and system-preferred Multi-Factor Authentication (MFA) methods. The function authenticates using client credentials (client ID, tenant ID, and client secret) and updates the specified user's authentication preferences.

## Prerequisites

1. **Azure AD App Registration**: Ensure that you have an Azure AD App Registration with `UserAuthenticationMethod.ReadWrite.All` permissions.
2. **PowerShell**: Make sure you have PowerShell installed on your machine.
3. **Microsoft Graph API Access**: You need access to the Microsoft Graph API with the appropriate permissions.

## Function Overview

The function performs the following actions:
1. Requests an OAuth 2.0 token from Azure AD using the client credentials.
2. Uses the token to make a `PATCH` request to the Graph API to set the user's default and system-preferred MFA methods.
3. Updates the user's `signInPreferences` according to the provided parameters.

## Usage

1. **Clone the Repository**: Clone this repository to your local machine.
2. **Configure the Function**:
   - Update the following parameters when calling the function:
     - `$TenantId`: Your Azure AD tenant ID.
     - `$ClientId`: Your Azure AD app client ID.
     - `$ClientSecret`: Your Azure AD app client secret.
     - `$UserPrincipalName`: The user whose MFA method you want to update.
     - Optional: Modify the `UserPreferredMethodForSecondaryAuthentication` and `SystemPreferredAuthenticationMethod` parameters as needed.

3. **Run the Function**: Call the `Set-DefaultMFA` function with the appropriate parameters.

### Function Example

```powershell
function Set-DefaultMFA {
    param (
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$UserPrincipalName,
        [string]$UserPreferredMethodForSecondaryAuthentication = "oath", # Default method is "oath"
        [string]$SystemPreferredAuthenticationMethod = "PhoneAppNotification" # Default system preferred is "PhoneAppNotification"
    )

    # OAuth token endpoint
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    # Define the body for the token request
    $body = @{
        client_id     = $ClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }

    # Get the OAuth token
    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -ContentType "application/x-www-form-urlencoded" -Body $body

    # Extract the access token from the response
    $accessToken = $tokenResponse.access_token

    # Define the API endpoint for a specific user
    $apiUrl = "https://graph.microsoft.com/beta/users/$UserPrincipalName/authentication/signInPreferences"

    # Define the payload to set the user's preferred and system-preferred MFA methods
    $payload = @{
        "@odata.context" = "https://graph.microsoft.com/beta/$metadata#users('$UserPrincipalName')/authentication/signInPreferences"
        isSystemPreferredAuthenticationMethodEnabled = $true
        userPreferredMethodForSecondaryAuthentication = $UserPreferredMethodForSecondaryAuthentication
        systemPreferredAuthenticationMethod = $SystemPreferredAuthenticationMethod
    }

    # Convert the payload to JSON
    $jsonPayload = $payload | ConvertTo-Json

    # Define the headers with the OAuth token
    $headers = @{
        Authorization = "Bearer $accessToken"
        "Content-Type" = "application/json"
    }

    # Make the PATCH request to set the default authentication method for the user
    $response = Invoke-RestMethod -Method Patch -Uri $apiUrl -Headers $headers -Body $jsonPayload

    # Output the response (will typically be No Content - 204 if successful)
    if ($response -eq $null) {
        Write-Output "Successfully updated the default MFA method for $UserPrincipalName."
    } else {
        Write-Output $response
    }
}

# Example usage:
Set-DefaultMFA -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
               -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
               -ClientSecret "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" `
               -UserPrincipalName "user@domain.com" `
               -UserPreferredMethodForSecondaryAuthentication "oath" `
               -SystemPreferredAuthenticationMethod "PhoneAppNotification"


Example Call

powershell

Set-DefaultMFA -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
               -ClientId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
               -ClientSecret "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" `
               -UserPrincipalName "user@domain.com" `
               -UserPreferredMethodForSecondaryAuthentication "oath" `
               -SystemPreferredAuthenticationMethod "PhoneAppNotification"

This will set the user's default MFA method to oath (One-Time Passcode) and the system-preferred method to PhoneAppNotification.
Notes

    Security: Ensure that the client secret and other sensitive information are stored securely and not shared publicly.
    Permissions: The script requires UserAuthenticationMethod.ReadWrite.All permissions to work properly.
    Default Parameters: The function includes default values for UserPreferredMethodForSecondaryAuthentication and SystemPreferredAuthenticationMethod, but you can override them when calling the function.
