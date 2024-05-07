# KerberosrRT
Windows Access Tokens for Red Teamers

This  code is to be a low-level implementation for interacting with the Kerberos authentication system on Windows. Here's a summary of what it does:

Imports several libraries: The code imports various Rust libraries and the Windows API (WinAPI) to interact with the operating system.

Connection to LSA (Local Security Authority): The enumtickets() function connects to LSA using the LsaConnectUntrusted() function. LSA is a Windows component responsible for local authentication and security.

Searches for the Kerberos authentication package: It uses the LsaLookupAuthenticationPackage() function to search for the Kerberos authentication package.

Requests information from the Kerberos ticket cache: It creates a request to obtain information from the Kerberos ticket cache using the LsaCallAuthenticationPackage() function.

Processes the response: If the request is successful, it processes the response to extract information about the Kerberos tickets in the cache. This includes the server name, realm name, ticket flags, and ticket start, end, and renewal times.

Disconnects from LSA: Finally, it disconnects from LSA using the LsaDeregisterLogonProcess() function.

The getcachedtickets() function appears to do something similar to enumtickets(), but it returns a vector of KERB_TICKET_CACHE_INFO structures instead of printing the information.
