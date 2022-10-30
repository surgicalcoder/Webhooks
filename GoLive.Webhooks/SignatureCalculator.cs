using System.Collections.Specialized;
using System.Globalization;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Http;

namespace GoLive.Webhooks.Core;

public class SignatureCalculator
{
    private readonly string secretKey;
    private readonly string service;

    public SignatureCalculator(string secretKey, string service)
    {
        this.secretKey = secretKey;
        this.service = service;
    }

    public static async Task<string> GetRawBodyAsync(
        HttpRequest request,
        Encoding encoding = null)
    {
        if (!request.Body.CanSeek)
        {
            request.EnableBuffering();
        }

        request.Body.Position = 0;
        var reader = new StreamReader(request.Body, encoding ?? Encoding.UTF8);
        var body = await reader.ReadToEndAsync().ConfigureAwait(false);
        request.Body.Position = 0;

        return body;
    }

    public string CalculateSignature(HttpRequestMessage request, string[] signedHeaders, DateTime requestDate)
    {
        signedHeaders = signedHeaders.Select(x => x.Trim().ToLowerInvariant()).OrderBy(x => x).ToArray();
        var canonicalRequest = GetCanonicalRequest(request, signedHeaders, async () => await request.Content.ReadAsStringAsync());
        var stringToSign = GetStringToSign(service, requestDate, canonicalRequest);

        return GetSignature(secretKey, service, requestDate, stringToSign);
    }

    public static string GetCanonicalHeaders(HttpRequest request, IEnumerable<string> signedHeaders)
    {
        var headers = request.Headers.ToDictionary(x => x.Key.Trim().ToLowerInvariant(),
            x => string.Join(" ", x.Value).Trim());

        if (request.Body != null)
        {
            var contentHeaders = request.Headers.ToDictionary(x => x.Key.Trim().ToLowerInvariant(), x => string.Join(" ", x.Value).Trim());

            foreach (var contentHeader in contentHeaders)
            {
                if (!headers.ContainsKey(contentHeader.Key))
                {
                    headers.Add(contentHeader.Key, contentHeader.Value);
                }
            }
        }

        var sortedHeaders = new SortedDictionary<string, string>(headers);

        var canonicalHeaders = new StringBuilder();

        foreach (var header in sortedHeaders.Where(header => signedHeaders.Contains(header.Key)))
        {
            canonicalHeaders.Append($"{header.Key}:{header.Value}\n");
        }

        return canonicalHeaders.ToString();
    }

    public static string GetStringToSign(string service, DateTime requestDate, string canonicalRequest)
    {
        var scope = $"{service}";
        var stringToSign = new StringBuilder();
        stringToSign.Append($"HMAC-SHA256\n{requestDate.ToUniversalTime().ToString(Statics.Iso8601DateTimeFormat, CultureInfo.InvariantCulture)}\n{scope}\n");
        stringToSign.Append(Utils.ToHex(Utils.Hash(canonicalRequest)));
        return stringToSign.ToString();
    }

    public static byte[] GetSigningKey(string secretKey, string service, DateTime requestDate)
    {
        var dateStamp = requestDate.ToString(Statics.Iso8601DateFormat, CultureInfo.InvariantCulture);
        var kDate = Utils.GetKeyedHash("KEY" + secretKey, dateStamp);
        var kService = Utils.GetKeyedHash(kDate, service);
        return Utils.GetKeyedHash(kService, "api_request");
    }
    
    public static string GetSignature(string secretKey, string service, DateTime requestDate, string stringToSign)
    {
        var kSigning = GetSigningKey(secretKey, service, requestDate);
        return Utils.ToHex(Utils.GetKeyedHash(kSigning, stringToSign));
    }

    public static string GetCanonicalRequest(HttpRequestMessage request, string[] signedHeaders, Func<Task<string>> BodyContents)
    {
        var canonicalRequest = new StringBuilder();
        canonicalRequest.Append($"{request.Method.Method}\n");
        canonicalRequest.Append($"{request.RequestUri.AbsolutePath}\n");
        canonicalRequest.Append($"{GetCanonicalQueryParameters(HttpUtility.ParseQueryString(request.RequestUri.Query))}\n");
        canonicalRequest.Append($"{GetCanonicalHeaders(request, signedHeaders)}\n");
        canonicalRequest.Append($"{string.Join(";", signedHeaders)}\n");
        canonicalRequest.Append(GetPayloadHash(request));
        return canonicalRequest.ToString();
    }

    public static string GetCanonicalQueryParameters(NameValueCollection queryParameters)
    {
        var canonicalQueryParameters = new StringBuilder();

        foreach (string key in queryParameters)
        {
            canonicalQueryParameters.Append($"{Utils.UrlEncode(key)}={Utils.UrlEncode(queryParameters[key])}&");
        }

        // remove trailing '&'
        if (canonicalQueryParameters.Length > 0)
        {
            canonicalQueryParameters.Remove(canonicalQueryParameters.Length - 1, 1);
        }

        return canonicalQueryParameters.ToString();
    }

    public static string GetCanonicalHeaders(HttpRequestMessage request, IEnumerable<string> signedHeaders)
    {
        var headers = request.Headers.ToDictionary(x => x.Key.Trim().ToLowerInvariant(), x => string.Join(" ", x.Value).Trim());

        if (request.Content != null)
        {
            var contentHeaders = request.Content.Headers.ToDictionary(x => x.Key.Trim().ToLowerInvariant(), x => string.Join(" ", x.Value).Trim());

            foreach (var contentHeader in contentHeaders.Where(contentHeader => !headers.ContainsKey(contentHeader.Key)))
            {
                headers.Add(contentHeader.Key, contentHeader.Value);
            }
        }

        var sortedHeaders = new SortedDictionary<string, string>(headers);

        var canonicalHeaders = new StringBuilder();

        foreach (var header in sortedHeaders.Where(header => signedHeaders.Contains(header.Key)))
        {
            canonicalHeaders.Append($"{header.Key}:{header.Value}\n");
        }

        return canonicalHeaders.ToString();
    }
    
    public static string GetPayloadHash(HttpRequestMessage request)
    {
        var payload = request.Content != null ? request.Content.ReadAsStringAsync().Result : string.Empty;
        return Utils.ToHex(Utils.Hash(payload));
    }
    
    public static async Task<string> GetPayloadHash(HttpRequest request)
    {
        var payload = request.Body != null ? await GetRawBodyAsync(request) : string.Empty;

        return Utils.ToHex(Utils.Hash(payload));
    }
}