using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Web.Services2;
using Microsoft.Web.Services2.Security;
using Microsoft.Web.Services2.Security.Tokens;
using Microsoft.Web.Services2.Security.X509;
using MyIdTravelService.com.myidtravel;

namespace MyIdTravelService
{

    /// <summary>
    /// MyIdTravelClient - Client for MyIdTravel Upload Satff
    /// </summary>
    public class MyIdTravelClient
    {
        /* ==================================================================================
         * = Altere o Metodo do WebService, a classe pricipal                               = 
         * = UploadService : System.Web.Services.Protocols.SoapHttpClientProtocol           = 
         * = UploadService : Microsoft.Web.Services2.WebServicesClientProtocol (WSE 2.0)    = 
         * = Para que possa ser utilizado o certificado digital                             = 
         * ==================================================================================
         */

        private readonly com.myidtravel.UploadService oWSProxy;
        private readonly Microsoft.Web.Services2.Security.X509.X509Certificate SigningTokenCertificate;
        private readonly Microsoft.Web.Services2.Security.X509.X509Certificate EncryptTokenCertificate;

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingToken">Certificate for Client pfx</param>
        /// <param name="serverCertificate">Certificate for Server cer</param>
        public MyIdTravelClient(string endPoint,
            System.Security.Cryptography.X509Certificates.X509Certificate2 signingToken,
            System.Security.Cryptography.X509Certificates.X509Certificate2 encryptToken)
            : this(endPoint, new System.Security.Cryptography.X509Certificates.X509Certificate(signingToken),
                  new System.Security.Cryptography.X509Certificates.X509Certificate(encryptToken))
        { }

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingTokenThumbprint">Thumbprint for Client pfx</param>
        /// <param name="encryptTokenThumbprint">Thumbprint for Server cer</param>
        public MyIdTravelClient(string endPoint,
            string signingTokenThumbprint,
            string encryptTokenThumbprint)
            : this(endPoint, new System.Security.Cryptography.X509Certificates.X509Certificate(X509CertificateByThumbprint(signingTokenThumbprint)),
                  new System.Security.Cryptography.X509Certificates.X509Certificate(X509CertificateByThumbprint(encryptTokenThumbprint)))
        { }

        /// <summary>
        /// Client for MyIdTravel - Staff Profiles Upload
        /// </summary>
        /// <param name="endPoint">Url for WebService</param>
        /// <param name="signingToken">Certificate for Client pfx</param>
        /// <param name="encryptToken">Certificate for Server cer</param>
        public MyIdTravelClient(string endPoint,
            System.Security.Cryptography.X509Certificates.X509Certificate signingToken,
            System.Security.Cryptography.X509Certificates.X509Certificate encryptToken)
        {

            oWSProxy = new com.myidtravel.UploadService();
            oWSProxy.Url = endPoint;
            oWSProxy.UseDefaultCredentials = false;
            oWSProxy.PreAuthenticate = true;
            oWSProxy.Timeout = 180000;
            oWSProxy.RequestSoapContext.Security.Timestamp.TtlInSeconds = 1800;
            oWSProxy.StaffProfilesUploadCompleted += OWSProxy_StaffProfilesUploadCompleted;

            this.SigningTokenCertificate = new Microsoft.Web.Services2.Security.X509.X509Certificate(signingToken.Handle);
            this.EncryptTokenCertificate = new Microsoft.Web.Services2.Security.X509.X509Certificate(encryptToken.Handle);

            AddSignature(oWSProxy);
            EncryptMessage(oWSProxy);
        }

        private TaskCompletionSource<UploadProfilesResponse> taskSource = new TaskCompletionSource<UploadProfilesResponse>();

        private void OWSProxy_StaffProfilesUploadCompleted(object sender, StaffProfilesUploadCompletedEventArgs e)
        {
            if (e.Cancelled)
                taskSource.SetCanceled();

            if (e.Error != null)
                taskSource.SetException(e.Error);

            if (e.Error == null && !e.Cancelled)
                taskSource.SetResult(e.Result);
        }

        /// <summary>
        /// StaffProfilesUploadAsync
        /// </summary>
        /// <param name="StaffProfilesUploadRequest">Request</param>
        /// <returns>UploadProfilesResponse</returns>
        public Task<UploadProfilesResponse> StaffProfilesUploadAsync(UploadProfilesRequest StaffProfilesUploadRequest)
        {
            taskSource = new TaskCompletionSource<UploadProfilesResponse>();
            oWSProxy.StaffProfilesUploadAsync(StaffProfilesUploadRequest);
            return taskSource.Task;
        }

        /// <summary>
        /// StaffProfilesUpload
        /// </summary>
        /// <param name="StaffProfilesUploadRequest">Request</param>
        /// <returns>UploadProfilesResponse</returns>
        public UploadProfilesResponse StaffProfilesUpload(UploadProfilesRequest StaffProfilesUploadRequest)
        {
            return oWSProxy.StaffProfilesUpload(StaffProfilesUploadRequest);
        }


        private void AddSignature(WebServicesClientProtocol oWSProxy)
        {
            SecurityToken signingToken = new X509SecurityToken(this.SigningTokenCertificate);

            if (!signingToken.SupportsDigitalSignature)
            {
                throw new CryptographicException("Certificate for signature must support digital signatures and have a private key available.");
            }

            if (signingToken.IsExpired)
            {
                throw new CryptographicException("Certificate for signature is expired.");
            }

            //Add the signature element to a security section on the request to sign the request
            oWSProxy.RequestSoapContext.Security.Tokens.Add(signingToken);
            oWSProxy.RequestSoapContext.Security.Elements.Add(new MessageSignature(signingToken));
        }

        private void EncryptMessage(WebServicesClientProtocol oWSProxy)
        {
            X509SecurityToken encryptToken = new X509SecurityToken(this.EncryptTokenCertificate);

            if (!encryptToken.SupportsDataEncryption)
            {
                throw new CryptographicException("Certificate for encryption must support data encryption.");
            }

            if (encryptToken.IsExpired)
            {
                throw new CryptographicException("Certificate for signature is expired.");
            }

            oWSProxy.RequestSoapContext.Security.Tokens.Add(encryptToken);
            oWSProxy.RequestSoapContext.Security.Elements.Add(new EncryptedData(encryptToken));
        }

        private static Microsoft.Web.Services2.Security.X509.X509Certificate X509CertificateByThumbprint(string Thumbprint)
        {
            X509Certificate x509 = null;

            if (string.IsNullOrEmpty(Thumbprint))
                throw new ArgumentNullException("Thumbprint is null or empty", new Exception("Thumbprint is mandatory"));

            Thumbprint = Thumbprint.Replace("\u200e", string.Empty).Replace("\u200f", string.Empty).Replace(" ", string.Empty).Replace(":", string.Empty);

            X509CertificateStore store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.LocalMachine, X509CertificateStore.RootStore);
            store.OpenRead();
            foreach (X509Certificate cert in store.Certificates)
            {
                if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                {
                    x509 = cert;
                    break;
                }
            }

            store.Close();

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.LocalMachine, X509CertificateStore.MyStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.CurrentUser, X509CertificateStore.RootStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                store = new X509CertificateStore(X509CertificateStore.StoreProvider.System, X509CertificateStore.StoreLocation.CurrentUser, X509CertificateStore.MyStore);
                store.OpenRead();
                foreach (X509Certificate cert in store.Certificates)
                {
                    if (cert.GetCertHashString().Trim().ToUpper() == Thumbprint.Trim().ToUpper())
                    {
                        x509 = cert;
                        break;
                    }
                }
                store.Close();
            }

            if (x509 == null)
            {
                if (!string.IsNullOrEmpty(Thumbprint))
                    throw new CryptographicException("A x509 certificate for " + Thumbprint + " was not found");
                else
                    throw new CryptographicException("A x509 certificate was not found");
            }
            return x509;
        }
    }
}
