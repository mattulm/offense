Why these columns matter:
ParentOU: This is usually the best hint for finding the owner. If it's in OU=Finance,OU=Apps, you know exactly who to call.
PasswordAgeDays: This is the most important field. Even if an app owner says "I'm ready for AES," if that password hasn't been changed in 500 days, the AES keys don't exist in the AD database. They must reset the password to generate the AES keys.
Description: Often contains "Owned by [Name]" or "Created for Project X" in larger orgs.
RawBitmask: If this is 0, they are running on the Windows 2003-era defaults (RC4/DES). If it's 4, they specifically have RC4 pinned, which is even worse.


there are two steps to the "Fix":
Reset the account password (This generates the AES-specific hashes).
Flip the attribute (This tells AD it's allowed to use them).
