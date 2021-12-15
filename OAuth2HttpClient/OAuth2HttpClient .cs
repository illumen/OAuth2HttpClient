using System.Net;
using IdentityModel.Client;
using OAuth2HttpClient.Common.Enums;

namespace OAuth2HttpClient;

public class OAuth2HttpClient
{
    private string? _accessTokenUrl;
    private string? _address;
    private AuthorizationType _authorizationType;
    private string? _clientId;
    private string? _clientSecret;
    private bool _isAuthorized;
    private string? _scope;
    private TokenResponse? _token;

    private HttpClient Client { get; } = new();

    private async Task Authorize()
    {
        await GetTokenAsync();
        _isAuthorized = true;
    }

    public async Task<HttpResponseMessage> GetAsync(string url)
    {
        if (!_isAuthorized)
        {
            await GetTokenAsync();
        }

        var res = await Client.GetAsync(url);
        if (res.StatusCode != HttpStatusCode.Unauthorized)
        {
            return res;
        }

        await Authorize();
        return await Client.GetAsync(url);
    }

    public HttpClient GetClient()
    {
        return Client;
    }

    private async Task GetTokenAsync()
    {
        if (_token != null)
        {
            return;
        }

        var response = _authorizationType switch
        {
            AuthorizationType.ClientCredentials => await Client.RequestClientCredentialsTokenAsync(
                new ClientCredentialsTokenRequest
                {
                    Address = $"{_address}/{_accessTokenUrl}",
                    ClientId = _clientId,
                    ClientSecret = _clientSecret,
                    Scope = _scope
                }),
            AuthorizationType.AuthorizationCode => throw new NotImplementedException(),
            AuthorizationType.PKCE => throw new NotImplementedException(),
            AuthorizationType.DeviceCode => throw new NotImplementedException(),
            AuthorizationType.RefreshToken => throw new NotImplementedException(),
            _ => throw new ArgumentOutOfRangeException()
        };

        if (response.IsError)
        {
            throw new Exception(response.Error);
        }

        _token = response;
        Client.SetBearerToken(_token.AccessToken);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request)
    {
        if (!_isAuthorized)
        {
            await GetTokenAsync();
        }

        var res = await Client.SendAsync(request);
        if (res.StatusCode != HttpStatusCode.Unauthorized)
        {
            return res;
        }

        await Authorize();
        return await Client.SendAsync(request);
    }

    public void SetAccessTokenUrl(string? accessTokenUrl)
    {
        _accessTokenUrl = accessTokenUrl;
    }

    public void SetAddress(string? address)
    {
        _address = address;
    }

    public void SetAddress(string address, Dictionary<string, string> queryStringParameters)
    {
        _address = new RequestUrl(address).Create(new Parameters(queryStringParameters));
    }

    public void SetAuthorizationType(AuthorizationType authorizationType)
    {
        _authorizationType = authorizationType;
    }

    public void SetClientCredentials(string? clientId, string? clientSecret)
    {
        _clientId = clientId;
        _clientSecret = clientSecret;
    }

    public void SetScope(string? scope)
    {
        _scope = scope;
    }
}