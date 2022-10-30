using System.Globalization;
using System.Net;
using System.Text;
using System.Web;
using Microsoft.AspNetCore.Http;
using Microsoft.VisualBasic.CompilerServices;

namespace GoLive.Webhooks.Core;

public class Webhooks
{
    public record SecretKeyRequest(string ApiKey, string Scope);

    public static void SignRequest(ref HttpRequestMessage msg, string ApiKey, string SecretKey, string Service, string[] SignedHeaders, DateTime? RequestDateTime)
    {
        RequestDateTime ??= DateTime.UtcNow;
        
        msg.Headers.Add("x-api-key",ApiKey);
        msg.Headers.Add("x-api-date", RequestDateTime.Value.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'"));
        msg.Headers.Add("x-api-scope",Service);
        msg.Headers.Add("x-api-algorithm", "HMAC-SHA256");
        
        var sigCalc = new SignatureCalculator(SecretKey, Service);
        var signedHeaders = new List<string>{ "x-api-key","x-api-date", "x-api-scope","x-api-algorithm" };

        if (SignedHeaders is { Length: > 0 })
        {
            signedHeaders.AddRange(SignedHeaders);
        }

        msg.Headers.Add("x-api-signed-headers", string.Join(",", signedHeaders));
        var sec = sigCalc.CalculateSignature(msg, signedHeaders.ToArray(), RequestDateTime.Value);
        msg.Headers.TryAddWithoutValidation("Authorization", $"{sec}");
    }

    public static async Task<bool> VerifyRequest(HttpRequest Request, Func<SecretKeyRequest, Task<string>> SecretKeyFunc)
    {
        var signature = Request.Headers["Authorization"].FirstOrDefault();
        var signedDate = DateTime.ParseExact(Request.Headers["x-api-date"].FirstOrDefault(), "yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal); 
        var scope = Request.Headers["x-api-scope"].FirstOrDefault();
        var algorithm = Request.Headers["x-api-algorithm"].FirstOrDefault();
        var signedHeaders = Request.Headers["x-api-signed-headers"].FirstOrDefault();
        var apiKey = Request.Headers["x-api-key"].FirstOrDefault();
        var headersOrdered = signedHeaders.Split(",").OrderBy(f => f);

        var key = await SecretKeyFunc.Invoke(new SecretKeyRequest(apiKey, scope));
       
        var req = new StringBuilder();
        req.Append($"{Request.Method}\n");
        req.Append($"{Request.Path}\n");
        req.Append($"{SignatureCalculator.GetCanonicalQueryParameters(HttpUtility.ParseQueryString(Request.QueryString.ToString()))}\n");
        req.Append($"{SignatureCalculator.GetCanonicalHeaders(Request, headersOrdered)}\n");
        req.Append($"{string.Join(";", headersOrdered)}\n");
        req.Append(await SignatureCalculator.GetPayloadHash(Request));
        
        var stringToSign = SignatureCalculator.GetStringToSign(scope, signedDate, req.ToString());
        var calculatedSig = SignatureCalculator.GetSignature(key, scope, signedDate, stringToSign);

        return signature == calculatedSig;
    }
    
    
}