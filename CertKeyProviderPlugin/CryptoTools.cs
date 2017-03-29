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
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace CertKeyProviderPlugin
{
    class CryptoCmsTools
    {
        /// <summary>
        /// Encrypt data for the specified set of certificates.  
        /// Adapted from http://msdn.microsoft.com/en-us/library/bb924547.aspx
        /// </summary>
        /// <param name="msg">Data to encrypt</param>
        /// <param name="recipientCerts">Certificates to encrypt for</param>
        /// <returns>Encrypted blob</returns>
        static public byte[] EncryptMsg(
            Byte[] msg,
            X509Certificate2Collection recipientCerts)
        {
            //  Place the message in a ContentInfo object.
            //  This is required to build an EnvelopedCms object.
            ContentInfo contentInfo = new ContentInfo(msg);

            //  Instantiate an EnvelopedCms object with the ContentInfo
            //  above.
            //  Has default SubjectIdentifierType IssuerAndSerialNumber.
            //  Has default ContentEncryptionAlgorithm property value
            //  RSA_DES_EDE3_CBC.
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

            //  Formulate a CmsRecipient object collection that
            //  represent information about the recipients 
            //  to encrypt the message for.
            CmsRecipientCollection recips = new CmsRecipientCollection(SubjectIdentifierType.IssuerAndSerialNumber, recipientCerts);

            //  Encrypt the message for the recipient.
            envelopedCms.Encrypt(recips);

            //  The encoded EnvelopedCms message contains the message
            //  ciphertext and the information about each recipient 
            //  that the message was enveloped for.
            return envelopedCms.Encode();
        }

        /// <summary>
        /// Decrypt a message using a private key available on the system.
        /// </summary>
        /// <param name="encodedEnvelopedCms">Encrypted blob</param>
        /// <returns>Decrypted data, or null if there was an error</returns>
        static public byte[] DecryptMsg(byte[] encodedEnvelopedCms)
        {
            //  Prepare object in which to decode and decrypt.
            EnvelopedCms envelopedCms = new EnvelopedCms();

            //  Decode the message.
            envelopedCms.Decode(encodedEnvelopedCms);

            X509Store myStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            myStore.Open(OpenFlags.ReadOnly);
            envelopedCms.Decrypt(myStore.Certificates);
            myStore.Close();

            //  The decrypted message occupies the ContentInfo property
            //  after the Decrypt method is invoked.
            return envelopedCms.ContentInfo.Content;
        }
    }
}
