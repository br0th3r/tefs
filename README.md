====
tefs
====

Transparent Encrypted Filesystem
================================

teFS is a transparent encrypted readonly file system

teFS will show the folder and subfolders you choose as encrypted, same structure, number of files and directories, but every name (file & folders) will show their names encrypted, including their contents which is encrypted as well. The name of files and directories are encrypted and encoded using base64 to make it compatible with any program that ususally works in a normal filesystem.


Why to write this virtual filesystem and why is readonly?
=========================================================

The main reason to write this virtual filesystem it was to allow my servers to synchronize their contents with another ones using a FTP connection (FTP is a plain text protocol and  not secure). So I decided to code it because my old hosting provider gave me free FTP account with the the same free space as I had in my server, but they only allowed the FTP protocol, no other. This situation meant two things to me: my files would be transfered with no security at all and would be stored with no standard encrypte, just waiting for the hosting provider to grab them or any good hacker.

I tried to convince them to give to their customers another kind of solutions, but I had no success. After a long time looking arround the Internet for some solution I realized no one I found was enought good to do this specific task, so I decided to code this virtual filesystem and then I was able to use normal tools to mirror my servers in my hosting provider FTP, and I was sure they wouldn't have access to any informaiton in it.


What should you be aware when using teFS?
=========================================

Be carefull about the different ways hackers can attack this sytem. There is a background heuristic information about how the filesystem, they know at least every Linux file system has directories named /bin, /etc, /bin, /sbin, /home and so on, so if you decide to transfer an encrypted version of your root filesystem, be aware they may know what is in inside, so the attacker will have to work less to decrypt the content.


What about cryptoloop and dm-crypt?
===================================

I didn't use Cryptoloop or dm-Crypt based solutions because they need to transfer a lot of data, plus every checkout takes too much time. When something changes in the filesystem (...and many files are touched when a Linux system is working), the full (cryptloop/dm-crypt) image wouuld have to be uploaded to the FTP server. It is not realistic to upload a 2-4 TBytes image to a FTP server every 4 hours just because few bytes have changed. Instead it is better to upload the files that have changed as normally rsync or unison would do.

What about the performance?
===========================

**Another warning about speed of this system:** big files are splitted on blocks with a fixed size that are encrypted independently, this provides a better performance when accessing to them but it may make thenm less secure. Also you should be aware that bigger files decrease performance drastically.

Because teFS split big files in several blocks which are encrypted independently, it will also make it easier for rsync and unison to work properly, since only blocks that have changed will be synchronized. This system also allows for random access to sectors on a file because the encryption time is linear since all blocks have the same or smaller size.

NOTE
====

teFS has been tested widely with the next encryption algorithms:
* AESECB
* BlowfishECB

TODO
====

It needs to improve the algorithms for realtime encryption, I am pretty sure there are better ways to encrypt/decrypt data blocks quicker than this script is doing.

License
=======

Copyright &copy; 2011 Juan Miguel Taboada Godoy.

APACHE LICENSE Version 2.0, January 2004
