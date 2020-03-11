using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using MyIdTravelService;
using MyIdTravelService.com.myidtravel;

namespace MyIdTravelUploadTest
{
    [TestClass]
    public class MyIdTravelUnitTest
    {
        [TestMethod]
        public void StaffProfilesUpload()
        {
            Console.WriteLine("Load X509Certificate2");
            string endpoint = "http://myidtravel.com/ws/services/UploadService";
            string pathServer = @"C:\Users\mazza\OneDrive - VRG Linhas Aéreas S A\Documents\MyIdTravel Avianca\svcMyIDTravelUpdate\svcMyIDTravelUpdate\O6.cer";
            string pathClient = @"C:\Users\mazza\OneDrive - VRG Linhas Aéreas S A\Documents\MyIdTravel Avianca\svcMyIDTravelUpdate\svcMyIDTravelUpdate\O6.pfx";
            string pwdClient = "ps4mO6q8vy";
            X509Certificate2 clientCertificate = new X509Certificate2(File.ReadAllBytes(pathClient), pwdClient);
            X509Certificate2 serverCertificate = new X509Certificate2(File.ReadAllBytes(pathServer));

            Console.WriteLine("Create MyIdTravelClient");
            MyIdTravelClient client = new MyIdTravelClient(endpoint, clientCertificate, serverCertificate);


            UploadProfilesRequest request = new UploadProfilesRequest();
            request.ac = "O6";
            request.aID = "247";
            request.updateRecord = new[] { new UpdateRecord() { } };
            var result = client.StaffProfilesUpload(request);

            if (result.MessageList.Any())
            {
                Assert.Fail(string.Join(Environment.NewLine, result.MessageList.Select(x => x.Text)));
            }
            Assert.IsTrue(true);

        }
    }
}
