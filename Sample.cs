//Ref.: https://balugajjala.wordpress.com/2021/07/12/generate-oauth-token-using-client-id-and-client-secret/


using System.Net.Http;
using System.Net.Http.Headers;
using System.IO;
using System.Runtime.Serialization.Json;
//Below are the parameters required to generate OAuth Token.

private static string tenantid = "41gb9056-test-id63-a2b7-58bbc1198567";
private static string authString = "https://login.microsoftonline.com/" + tenantid;
private static string clientid = "90592890-4b8c-4135-8d50-balabramhagb";
private static string ClientSecret = "6gb4.X0R8ljeu0d_uEqA~4~wrv14VbaluG_";
private static string resource = "api://" + clientid + "/.default";

//In “Program.cs” file “Main” method write the  following line of code to first generate access token.

OAuthToken authToken = GetToken(authString, clientid, ClientSecret, resource).Result;
string token = authToken.Token;
Console.WriteLine(token);
//This method generates OAuth Token

public async Task<OAuthToken> GetToken(string authString, string clientid, string secret, string resource)
{
     using (var handler = new HttpClientHandler { ClientCertificateOptions = ClientCertificateOption.Manual })
     using (var client = new HttpClient(handler))
     {
         client.DefaultRequestHeaders.Accept.Clear();
         client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
         string baseAddress = authString + "/oauth2/v2.0/token";
         var form = new Dictionary
         {
             {"grant_type", "client_credentials"},
             {"client_id", clientid},
             {"client_secret", secret},
             {"scope",resource },
         };            

        HttpResponseMessage tokenResponse = await client.PostAsync(baseAddress,new FormUrlEncodedContent(form));
        var jsonContent = await tokenResponse.Content.ReadAsStringAsync();
        string token = this.GetDeserializedJson(jsonContent).access_token;
        var oAuthToken = new OAuthToken
        {
            Token = token 
        };

        return oAuthToken;
    }
}



//This method is required to deserialize Json Object.
public RootObject GetDeserializedJson(string json)
{
          
    if (!string.IsNullOrEmpty(json))
    {
        using (MemoryStream stream = new MemoryStream(Encoding.Unicode.GetBytes(json)))
        {
            DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(RootObject));
            return serializer.ReadObject(stream) as RootObject;
        }
     }

    return new RootObject() { access_token = string.Empty, expires_in = 0, token_type = string.Empty,       refresh_token = string.Empty };
}

//OAuth Token Reference Class

public class OAuthToken
{
    public string Token { get; set; }
}
  
 
//This class is required to deserilaize json response
    
public class RootObject
{
    public string access_token { get; set; }

    public string token_type { get; set; }

    public int expires_in { get; set; }

    public string refresh_token { get; set; }
}
