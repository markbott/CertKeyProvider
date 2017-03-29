Certificate-based key provider plugin readme
--------------------------------------------

Interim version 090906, to be used with KeePass build 090829b.

Installation
------------
Copy the PLGX file to the same folder where KeePass lives.  Next time you start KeePass, KeePass should load the plugin.

To uninstall, remove the PLGX file and consult KeePass documentation.

Instructions
------------
When creating a new database, select "Key file / provider" and choose "Certificate-protected key" from the drop-down list.

This key provider can be combined with other key sources (master password, Windows user account).

You will then be prompted to select the certificates for which the key should be encrypted.  The certificates that are presented were retrieved from the Windows certificate (CAPI) store (you can view it from Internet Explorer: Tools > Options > Content > Certificates).  You can select multiple certificates.  Encrypting the key for multiple certificates is useful in various scenarios -- you have two different keys and certificates on different machines, you want to share the password database with a group of people, etc.

IMPORTANT:  Make sure you have access to at least one private key corresponding to the certificates.  As well, be sure to back up those private keys or ensure that they are recoverable in some way.  You will not be able to open the database without it.

When opening the database, select the "Certificate-protected key" key provider again.  The system will automatically find a private key to decrypt the database.  If a key is not found, you will see an error.

Disclaimer
----------
You are using this software at your own risk.

In no event will we be liable for any loss or damage including without limitation, indirect or consequential loss or damage, or any loss or damage whatsoever arising from loss of data or profits arising out of or in connection with the use of this software.