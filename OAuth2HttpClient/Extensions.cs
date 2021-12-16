using System.Runtime.CompilerServices;
using System.Text.Json;

namespace OAuth2HttpClientNS;

public static class Extensions
{
    public static async IAsyncEnumerable<TResult?> GetJsonResponseAsAsyncEnumerable<TResult>(
        this OAuth2HttpClient client, string requestUri, JsonSerializerOptions? jsonSerializerOptions = null,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        var response = await client.GetAsync(requestUri, HttpCompletionOption.ResponseHeadersRead, ct);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        await foreach (var item in JsonSerializer.DeserializeAsyncEnumerable<TResult>(stream,
                           jsonSerializerOptions, ct))
        {
            yield return item;
        }
    }

    public static async IAsyncEnumerable<TResult?> ParseJsonResponseAsAsyncEnumerable<TResult>(
        this HttpResponseMessage response, JsonSerializerOptions? jsonSerializerOptions = null,
        [EnumeratorCancellation] CancellationToken ct = default)
    {
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(ct);
        await foreach (var item in JsonSerializer.DeserializeAsyncEnumerable<TResult>(stream,
                           jsonSerializerOptions, ct))
        {
            yield return item;
        }
    }
}