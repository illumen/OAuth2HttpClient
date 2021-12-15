using System.Net;
using IdentityModel.Client;

namespace OAuth2HttpClientNS;

public class OAuth2HttpClient
{
    private readonly HttpClient _client;
    private readonly TokenRequest _tokenRequest;
    private bool _isAuthenticated;

    public OAuth2HttpClient(TokenRequest tokenRequest, HttpClient? client = null)
    {
        _tokenRequest = tokenRequest;
        _client = client ?? new HttpClient();
    }

    private async Task Authorize(CancellationToken cancellationToken = default)
    {
        var response = await _client.RequestTokenAsync(_tokenRequest, cancellationToken);

        if (response.IsError)
        {
            throw new Exception(response.Error);
        }

        _isAuthenticated = true;
        _client.SetBearerToken(response.AccessToken);
    }

    public void CancelPendingRequests()
    {
        _client.CancelPendingRequests();
    }

    public async Task<HttpResponseMessage> DeleteAsync(string requestUri, CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(async client => await client.DeleteAsync(requestUri, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> GetAsync(string requestUri, HttpCompletionOption httpCompletionOption,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(
            async client => await client.GetAsync(requestUri, httpCompletionOption, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> GetAsync(string requestUri, CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(async client => await client.GetAsync(requestUri, cancellationToken),
            cancellationToken);
    }

    public async Task<Stream> GetStreamAsync(string requestUri, CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(async client => await client.GetStreamAsync(requestUri, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> PatchAsync(string requestUri, HttpContent content,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(
            async client => await client.PatchAsync(requestUri, content, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> PostAsync(string requestUri, HttpContent content,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(
            async client => await client.PostAsync(requestUri, content, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> PutAsync(string requestUri, HttpContent content,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(
            async client => await client.PutAsync(requestUri, content, cancellationToken),
            cancellationToken);
    }

    public HttpResponseMessage Send(HttpRequestMessage request, CancellationToken cancellationToken = default)
    {
        return WithAuthorization(client => client.Send(request, cancellationToken), cancellationToken);
    }

    public HttpResponseMessage Send(HttpRequestMessage request, HttpCompletionOption httpCompletionOption,
        CancellationToken cancellationToken = default)
    {
        return WithAuthorization(client => client.Send(request, httpCompletionOption, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(client => client.SendAsync(request, cancellationToken),
            cancellationToken);
    }

    public async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
        HttpCompletionOption httpCompletionOption,
        CancellationToken cancellationToken = default)
    {
        return await WithAuthorizationAsync(
            client => client.SendAsync(request, httpCompletionOption, cancellationToken),
            cancellationToken);
    }

    private HttpResponseMessage WithAuthorization(Func<HttpClient, HttpResponseMessage> func,
        CancellationToken cancellationToken = default)
    {
        if (!_isAuthenticated)
        {
            Authorize(cancellationToken).Wait(cancellationToken);
        }

        var response = func(_client);
        if (response.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        Authorize(cancellationToken).Wait(cancellationToken);

        return func(_client);
    }

    private async Task<TResult> WithAuthorizationAsync<TResult>(Func<HttpClient, Task<TResult>> func,
        CancellationToken cancellationToken = default)
    {
        if (!_isAuthenticated)
        {
            await Authorize(cancellationToken);
        }

        var response = await func(_client);
        if (response is HttpResponseMessage message && message.StatusCode != HttpStatusCode.Unauthorized)
        {
            return response;
        }

        await Authorize(cancellationToken);

        return await func(_client);
    }
}