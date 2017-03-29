/*
  Certificate-protected key provider for KeePass 
  Copyright (C) 2009 M Buchler <mbuchler@gmail.com>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

using System;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using System.Reflection;
using System.Diagnostics;
using System.Runtime.Serialization;
using System.Windows.Forms;

using KeePass.Plugins;
using KeePassLib.Keys;
using KeePassLib.Cryptography;
using KeePassLib.Serialization;

// for UI
using KeePass.UI;
using KeePassLib.Utility;

namespace CertKeyProviderPlugin
{
    /// <summary>
    /// Class for retrieving strings from resource file for the CertKeyProviderPlugin.
    /// </summary>
    internal class Res
    {
        public static string STR_KEY_PROVIDER_NAME = "KeyProviderName";
        public static string STR_OPEN_KEY_FILE = "OpenKeyFile";
        public static string STR_CREATE_KEY_FILE = "CreateKeyFile";
        public static string STR_CERT_PROT_KEY_FILE = "CertProtectedKeyFile";
        public static string STR_SELECT_CERT = "SelectEncCert";
        public static string STR_SELECT_CERT_LONG = "SelectEncCertLong";
        public static string STR_KEY_FILE_TOO_BIG = "KeyFileTooBig";
        public static string STR_APP_TITLE = STR_KEY_PROVIDER_NAME; // share this string
        public static string STR_CERT_INFO_TEMPLATE = "CertInfoTemplate";
        public static string STR_CERT_DIDNT_VALIDATE_CONTINUE = "CertInvalidContinue";
        public static string STR_NO_CERTS_LEFT = "NoCertsLeft";
        public static string STR_ERR_ENCRYPTING_KEY = "ErrEncryptingKey";
        public static string STR_ERR_DECRYPTING_KEY = "ErrDecryptingKey";
        public static string STR_ENC_KEY_INTRO = "EncryptingKeyIntro";
        public static string STR_NO_PRIV_KEY_IN_CERTS = "NoPrivKeyForCerts";

        static System.Resources.ResourceManager m_resMgr =
            new System.Resources.ResourceManager("CertKeyProviderPlugin.CertKeyProviderResources", Assembly.GetExecutingAssembly());
        static private string m_appTitle;

        static public string str(string strName)
        {
            string ret = m_resMgr.GetString(strName);
            Debug.Assert(ret != null);
            if (ret == null) throw new ArgumentOutOfRangeException("strName");
            return ret.Replace("\\n", "\n");
        }

        static public string AppTitle
        {
            get
            {
                if (m_appTitle == null) { m_appTitle = str(STR_APP_TITLE); }
                return m_appTitle;
            }
        }

    }

    /// <summary>
    /// A key provider plugin for KeePass that uses asymmetric key cryptography (public/private keys)
    /// to protect the password database
    /// </summary>
    public sealed class CertKeyProviderPluginExt : Plugin
    {
        private IPluginHost m_host = null;
        private CertBasedKeyProvider m_prov = new CertBasedKeyProvider();

        public override bool Initialize(IPluginHost host)
        {
            m_host = host;

            m_host.KeyProviderPool.Add(m_prov);
            return true;
        }

        public override void Terminate()
        {
            m_host.KeyProviderPool.Remove(m_prov);
        }
    }

    /// <summary>
    /// A key provider plugin for KeePass that, for new databases, generates a key and encrypts it using 
    /// a set of public keys contained in encryption certificates.  When opening a database, the key is
    /// decrypted using a private key.
    /// </summary>
    public sealed class CertBasedKeyProvider : KeyProvider
    {
        public static string CertProtKeyFileExtension = "p7mkey";
        private static int MAX_KEY_FILE_LENGTH = 1024*1024; // 1 MB ought to be way too much
        public override string Name
        {
            get { return Res.str(Res.STR_KEY_PROVIDER_NAME); }
        }

        /// <summary>
        /// Get a key for the database.
        /// </summary>
        /// <param name="ctx">Context - queried for whether a new key should be created, and the database path</param>
        /// <returns>A byte array with the key, or null if an error occurs.  If an error occurs, user is
        /// notified of the error.</returns>
        public override byte[] GetKey(KeyProviderQueryContext ctx)
        {
            return ctx.CreatingNewKey ? GetNewKey(ctx.DatabaseIOInfo.Path) : GetExistingKey(ctx.DatabaseIOInfo);
        }

        /// <summary>
        /// Get a key for an existing database.  First, the key file is located, either because its location
        /// and filename are the same as the database path (with the exception of the extension), or the user
        /// is asked.  Then, the key file is decrypted using a private key.
        /// </summary>
        /// <param name="strPath">Full filename of the database file.</param>
        /// <returns>A byte array with the key, or null if an error occurs.  If an error occurs, user is
        /// notified of the error.</returns>
        byte[] GetExistingKey(IOConnectionInfo ioc) 
        {
            Stream stream = null;
            try
            {
                string newpath = UrlUtil.StripExtension(ioc.Path) + "." + CertProtKeyFileExtension;
                IOConnectionInfo keyIoc = ioc.CloneDeep();
                keyIoc.Path = newpath;
                stream = IOConnection.OpenRead(keyIoc);
            }
            catch (Exception)
            {
                // strPath may be a URL (even if IsLocalFile returns true?), 
                // whatever the reason, fall through and the user can pick a 
                // local file as the key file
            }

            if (stream == null || !stream.CanRead)
            {
                // fall back on opening a local file
                // FUTURE ENHANCEMENT: allow user to enter a URL and name/pwd as well

                OpenFileDialog ofd = UIUtil.CreateOpenFileDialog(Res.str(Res.STR_OPEN_KEY_FILE),
                    UIUtil.CreateFileTypeFilter(CertProtKeyFileExtension, Res.str(Res.STR_CERT_PROT_KEY_FILE), true),
                    1, CertProtKeyFileExtension, false /* multi-select */, true);

                if (ofd.ShowDialog() != DialogResult.OK)
                {
                    return null;
                }
                stream = IOConnection.OpenRead(IOConnectionInfo.FromPath(ofd.FileName));
            }

            try
            {
                BinaryReader reader = new BinaryReader(stream);
                byte[] p7m = reader.ReadBytes(MAX_KEY_FILE_LENGTH);
                // URL streams don't support seeking, and so Position doesn't work
                //bool tooBig = stream.Position >= MAX_KEY_FILE_LENGTH;
                bool tooBig = p7m.Length >= MAX_KEY_FILE_LENGTH;
                reader.Close();

                if(tooBig) {
                    MessageBox.Show(Res.str(Res.STR_KEY_FILE_TOO_BIG), Res.AppTitle);
                    return null;
                }

                Cursor.Current = Cursors.WaitCursor;
                return CryptoCmsTools.DecryptMsg(p7m);
            }
            catch (SystemException ex)  // covers IOException and CryptographicException
            {
                String msg = String.Format(Res.str(Res.STR_ERR_DECRYPTING_KEY), ex.ToString());
                //String msg = String.Format(Res.str(Res.STR_ERR_DECRYPTING_KEY), getCryptoExceptionDetails(ex));
                MessageBox.Show(msg, Res.AppTitle);
                return null;
            }
            finally
            {
                Cursor.Current = Cursors.Default;
            }
        }

        /// <summary>
        /// Get a key for a new database.  The user is first asked for the key filename (by default
        /// same location and base filename as the database, but with a different extension).  Next,
        /// the user selects what certificates to encrypt for.  A 256-byte random key is generated.
        /// </summary>
        /// <param name="strPath">Full filename of the database file.</param>
        /// <returns>A byte array with the key, or null if an error occurs.  If an error occurs, user is
        /// notified of the error.</returns>
        byte[] GetNewKey(string strPath)
        {
            MessageBox.Show(Res.str(Res.STR_ENC_KEY_INTRO), Res.str(Res.STR_APP_TITLE), 
                MessageBoxButtons.OK, MessageBoxIcon.Information);

            SaveFileDialog sfd = UIUtil.CreateSaveFileDialog(Res.str(Res.STR_CREATE_KEY_FILE),
			    UrlUtil.StripExtension(UrlUtil.GetFileName(strPath)) + "." +
			    CertProtKeyFileExtension, UIUtil.CreateFileTypeFilter(CertProtKeyFileExtension,
                Res.str(Res.STR_CERT_PROT_KEY_FILE), true), 1, CertProtKeyFileExtension, true);

		    if(sfd.ShowDialog() != DialogResult.OK)
		    {
                return null;
		    }
            
            CryptoRandom rnd = CryptoRandom.Instance;
            byte[] key = rnd.GetRandomBytes(256);

            try
            {
                byte[] p7m = SelectCertsAndEncryptMsg(key);
                if (p7m == null) { return null; }

                BinaryWriter writer = new BinaryWriter(File.Open(sfd.FileName, FileMode.Create));
                writer.Write(p7m);
                writer.Close();

                return key;
            }
            catch (SystemException e)
            {
                String msg = String.Format(Res.str(Res.STR_ERR_ENCRYPTING_KEY), e.Message);
                MessageBox.Show(msg, Res.AppTitle);
                return null;
            }
        }

        /// <summary>
        /// Encrypt a byte array for a user-selected set of encryption certificates.  More than 1 certificate
        /// can be selected.  Certificates can be selected from the "My" store and the "AddressBook" store.
        /// </summary>
        /// <param name="key">Data to encrypt</param>
        /// <returns>Encrypted blob</returns>
        private byte[] SelectCertsAndEncryptMsg(byte[] data)
        {
            X509Store addrBookStore = new X509Store(StoreName.AddressBook, StoreLocation.CurrentUser);
            addrBookStore.Open(OpenFlags.ReadOnly);
            X509Store myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myStore.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection allCerts = (X509Certificate2Collection)addrBookStore.Certificates;
            allCerts.AddRange(myStore.Certificates);

            addrBookStore.Close();
            myStore.Close();

            X509Certificate2Collection fcollection = (X509Certificate2Collection)allCerts.Find(
                X509FindType.FindByTimeValid, 
                DateTime.Now, false);
            fcollection = fcollection.Find(X509FindType.FindByKeyUsage,
                X509KeyUsageFlags.KeyEncipherment, false);
            X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, 
                Res.str(Res.STR_SELECT_CERT), Res.str(Res.STR_SELECT_CERT_LONG), 
                X509SelectionFlag.MultiSelection);
            if (scollection == null || scollection.Count < 1)
            {
                return null;
            }

            // validate certificates
            X509Chain chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            X509Certificate2Collection toRemove = new X509Certificate2Collection();
            foreach(X509Certificate2 cert in scollection) {
                Boolean chainRc = false;
                try
                {
                    Cursor.Current = Cursors.WaitCursor;
                    chainRc = chain.Build(cert);
                }
                finally
                {
                    Cursor.Current = Cursors.Default;
                }

                if( !chainRc ) {
                    // certificate is invalid ... keep it?
                    String certInfoTemplate = String.Format(Res.str(Res.STR_CERT_INFO_TEMPLATE),
                        cert.Subject,
                        cert.Issuer,
                        cert.GetSerialNumberString());
                    String warning = String.Format(Res.str(Res.STR_CERT_DIDNT_VALIDATE_CONTINUE), certInfoTemplate);
                    StringBuilder reason = new StringBuilder();
                    for (int index = 0; index < chain.ChainStatus.Length; index++) {
                        reason.AppendLine(chain.ChainStatus[index].StatusInformation);
                    }
                    DialogResult decision = MessageBox.Show(warning + "\n\n" + reason.ToString(), Res.str(Res.STR_APP_TITLE), 
                        MessageBoxButtons.YesNoCancel, MessageBoxIcon.Exclamation, MessageBoxDefaultButton.Button3);
                    if(decision == DialogResult.Cancel) {
                        return null;
                    }
                    if(decision == DialogResult.No) {
                        toRemove.Insert(0, cert);
                    }
                }
            }

            foreach(X509Certificate2 cert in toRemove) {
                scollection.Remove(cert);
            }

            if (scollection.Count < 1)
            {
                MessageBox.Show(Res.str(Res.STR_NO_CERTS_LEFT), Res.str(Res.STR_APP_TITLE));
                return null;
            }

            // check to make sure the user can decrypt the key
            bool havePrivateKey = false;
            foreach (X509Certificate2 cert in scollection)
            {
                havePrivateKey |= cert.HasPrivateKey;
            }

            if (!havePrivateKey)
            {
                DialogResult decision = MessageBox.Show(Res.str(Res.STR_NO_PRIV_KEY_IN_CERTS), Res.str(Res.STR_APP_TITLE),
                    MessageBoxButtons.YesNo, MessageBoxIcon.Exclamation, MessageBoxDefaultButton.Button2);
                if (decision == DialogResult.No)
                {
                    return null;
                }
            }


            byte[] p7m = CryptoCmsTools.EncryptMsg(data, scollection);
            return p7m;
        }

        /*
        /// <summary>
        /// Get the details from an exception so we can provide as much info as possible to 
        /// the end user and for support purposes.  Liberated from the sample in 
        /// http://msdn.microsoft.com/en-us/library/system.security.cryptography.cryptographicexception.aspx
        /// </summary>
        /// <param name="ex"></param>
        /// <returns>A string with exception details</returns>
        static string getCryptoExceptionDetails(SystemException ex) {
            // Retrieve the link to the help file for the exception.
            string helpLink = ex.HelpLink;

            // Retrieve the exception that caused the current
            // CryptographicException exception.
            System.Exception innerException = ex.InnerException;
            string innerExceptionMessage = "";
            if (innerException != null)
            {
                innerExceptionMessage = innerException.ToString();
            }

            // Retrieve the message that describes the exception.
            string message = ex.Message;

            // Retrieve the name of the application that caused the exception.
            string exceptionSource = ex.Source;

            // Retrieve the call stack at the time the exception occured.
            string stackTrace = ex.StackTrace;

            // Retrieve the method that threw the exception.
            System.Reflection.MethodBase targetSite = ex.TargetSite;
            string siteName = targetSite.Name;

            // Retrieve the entire exception as a single string.
            string entireException = ex.ToString();

            // GetObjectData
            setSerializationInfo(ref ex);

            // Get the root exception that caused the current
            // CryptographicException exception.
            System.Exception baseException = ex.GetBaseException();
            string baseExceptionMessage = "";
            if (baseException != null)
            {
                baseExceptionMessage = baseException.Message;
            }

            string result = entireException + "\n\n" +
                "Properties of the exception are as follows:" + "\n" +
                "Message: " + message + "\n" +
                "Source: " + exceptionSource + "\n" +
                "Stack trace: " + stackTrace + "\n" +
                "Help link: " + helpLink + "\n" +
                "Target site's name: " + siteName + "\n" +
                "Base exception message: " + baseExceptionMessage + "\n" +
                "Inner exception message: " + innerExceptionMessage;

            return result;
        }

        static private void setSerializationInfo(ref SystemException ex)
        {
            // Insert information about the exception into a serialized object.
            FormatterConverter formatConverter = new FormatterConverter();
            SerializationInfo serializationInfo =
                new SerializationInfo(ex.GetType(), formatConverter);
            StreamingContext streamingContext =
                new StreamingContext(StreamingContextStates.All);

            ex.GetObjectData(serializationInfo, streamingContext);
        }
        */
    }
}