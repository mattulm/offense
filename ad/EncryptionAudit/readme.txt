In Active Directory, the bitmask for AES is:
                        AES128: 0x08 (8)
                        AES256: 0x10 (16)
Combined AES (Modern Standard): 0x18 (24)


If an account hasn't changed its password since the era of Windows Server 2003, it 
likely cannot support AES until the password is reset, even if you flip the bit.


Just because you flip the bit to "Enabled" doesn't mean it's working. If the 
account's password was last set before AES was supported in your domain, the Kerberos 
keys for AES won't actually exist in the database.
