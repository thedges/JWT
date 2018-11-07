public class JWT
{

  public class Configuration
  {
    public String jwtUsername {get; set;}
    public String jwtConnectedAppConsumerKey {get; set;}
    public String jwtSigningCertificateName {get; set;}
    public String jwtHostname {get; set;}
  }

  private class Header
  {
    String alg;
    Header(String alg)
    {
      this.alg = alg;
    }
  }

  private class Body
  {
    String iss;
    String prn;
    String aud;
    String exp;
    Body(String iss, String prn, String aud, String exp)
    {
      this.iss = iss;
      this.prn = prn;
      this.aud = aud;
      this.exp = exp;
    }
  }

  private class JWTException extends Exception
  {
  }

  private Configuration config;

  public JWT(Configuration config)
  {

    this.config = config;
  }

  public String requestAccessToken()
  {

    Map<String, String> m = new Map<String, String>();
    m.put('grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer');
    m.put('assertion', createToken());

    HttpRequest req = new HttpRequest();
    req.setHeader('Content-Type', 'application/x-www-form-urlencoded');
    req.setEndpoint('https://' + config.jwtHostname + '/services/oauth2/token');
    req.setMethod('POST');
    req.setTimeout(60 * 1000);
    System.debug(formEncode(m));
    req.setBody(formEncode(m));

    HttpResponse res = new Http().send(req);
    if (res.getStatusCode() >= 200 && res.getStatusCode() < 300)
    {
      return extractJsonField(res.getBody(), 'access_token');
    }
    else
    {
      throw new JWTException(res.getBody());
    }
  }

  private String formEncode(Map<String, String> m)
  {

    String s = '';
    for (String key : m.keySet())
    {
      if (s.length() > 0)
      {
        s += '&';
      }
      s += key + '=' + EncodingUtil.urlEncode(m.get(key), 'UTF-8');
    }
    return s;
  }

  private String extractJsonField(String body, String field)
  {

    JSONParser parser = JSON.createParser(body);
    while (parser.nextToken() != null)
    {
      if (parser.getCurrentToken() == JSONToken.FIELD_NAME
          && parser.getText() == field)
      {
        parser.nextToken();
        return parser.getText();
      }
    }
    throw new JwtException(field + ' not found in response ' + body);
  }

  private String createToken()
  {

    String alg = 'RS256';

    String iss = config.jwtConnectedAppConsumerKey;
    String prn = config.jwtUsername;
    String aud = 'https://' + config.jwtHostname;
    String exp = String.valueOf(System.currentTimeMillis() + 60 * 60 * 1000);

    String headerJson = JSON.serialize(new Header(alg));
    String bodyJson =  JSON.serialize(new Body(iss, prn, aud, exp));

    String token = base64UrlSafe(Blob.valueOf(headerJson))
                   + '.' + base64UrlSafe(Blob.valueOf(bodyJson));
    String signature = base64UrlSafe(Crypto.signWithCertificate(
                                       'RSA-SHA256',
                                       Blob.valueOf(token),
                                       config.jwtSigningCertificateName
                                     ));
    token += '.' + signature;

    return token;
  }

  private String base64UrlSafe(Blob b)
  {

    return EncodingUtil.base64Encode(b).replace('+', '-').replace('/', '_');
  }

  public static void debug()
  {
    JWT.Configuration config = new JWT.Configuration();
    config.jwtUsername = 'thedges@jc-sdo.demo';
    config.jwtSigningCertificateName = 'JWT';
    config.jwtHostname = 'jconrad.my.salesforce.com';
    config.jwtConnectedAppConsumerKey = '3MVG9uudbyLbNPZMvnUmLyoztHtIrA_fzLeyFl8AFV3n9JJT77STSJJ2A3Gc7yz9aaGMguoUSwg_u7_lJYets';
    String accessToken = new JWT(config).requestAccessToken();
    System.debug('Access Token=' + accessToken);
  }
}