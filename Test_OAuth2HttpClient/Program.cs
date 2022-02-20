using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using OAuth2HttpClientNS;
using IdentityModel.Client;

namespace Test_OAuth2HttpClient
{
    internal class Program
    {
        static TokenRequest localToken;
        static void Main(string[] args)
        {
            OAuth2HttpClient newHttpCLient = new OAuth2HttpClient(localToken);
        }
    }
}
