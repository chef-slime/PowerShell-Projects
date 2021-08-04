Function Get-CertificateInfo {
    [CmdletBinding()]
    Param([Parameter(Mandatory)][String]$url)

    $urlSubString = $url.Substring(0, 5)

    if ($urlSubString -ne 'https')
    {
        Write-Host("Certificate information cannot be retrieved. This domain doesn't use HTTPS.")
    }

    else
    {
        $webRequest = [Net.WebRequest]::CreateHttp($url)
        $webRequest.AllowAutoRedirect = $true
        $chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain

        #Request website
        try
        {
            $response = $webRequest.GetResponse()
        }
        catch {}

        #Creates Certificate
        $certificate = $webRequest.ServicePoint.Certificate.Handle

        #Build chain
        [void]$chain.Build($certificate)

        $rootIssuer = $chain.ChainElements[1].Certificate.IssuerName.Name
        $rootCommonAuthority = ($rootIssuer -split ',*..=')[1]
        $rootOrganization = ($rootIssuer -split ',*..=')[2]
        $rootCountry = ($rootIssuer -split ',*..=')[3]

        $issuer = $chain.ChainElements[0].Certificate.IssuerName.Name
        $commonAuthority = ($issuer -split ',*..=')[1]
        $organization = ($issuer -split ',*..=')[2]
        $country = ($issuer -split ',*..=')[3]

        Write-Host("`nRoot Certificate Authority: $rootCommonAuthority")
        Write-Host("Root Organization: $rootOrganization")
        Write-Host("Root Country: $rootCountry")
        Write-Host("`nCertificate Authority: $commonAuthority")
        Write-Host("Organization: $organization")
        Write-Host("Country: $country")
    }
}

Function Get-Label
{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory)]
        [String]$url
    )
    Write-Host("`nRunning query on $url")

    $queryResult = (Invoke-Sqlcmd -Query "Select Label From Urls Where Url = '$url'" -ConnectionString 'Data Source=Koushi\SQLExpress;Initial Catalog=Phishing;Integrated Security=True').Label

    if ($queryResult -eq $null)
    {
        Write-Host("`nThis site appears safe. Proceed with caution.")
        Get-CertificateInfo -url $url
        $userResponse = Read-Host('Do you want to open this link?')

        if ($userResponse.ToUpper().Trim() -eq 'YES')
        {
            Start-Process($url)
        }
    }

    else
    {
        Write-Host("`nThis is a phishing site. DO NOT CLICK ON IT.")
    }
}

$userInput = Read-Host ("Enter a website")
Get-Label -url $userInput