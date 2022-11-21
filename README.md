# BesoToken  
A tool to Impersonate logged on users without touching LSASS (Including non-Interactive sessions).

# Usage / Explaination  
Usually when a CreateProcessWithTokenW is used to start a process as a user who does not have an interactive sessions, the ACLs to the Window Object (Desktop)  
are not set correctly, open a new CMD using this kind of token will result in somthing like the following:  

![image](https://user-images.githubusercontent.com/50461376/203029688-d56ac57e-520b-483c-ba5a-dbe914fdd45a.png)  
  
We have a blank CMD which is not interactive due to insufficent ACL Permissions for `winsta0` and the `default` window objects, this got us  
to a point where we needed a tool that fixes the problem and gives us an interactive cmd session, this is pretty useful when you are in an  
engagement and you have an RDP session and you want to lauch a new sessions as another logged on Domain Admin, obviously this tool requires `Local Administrator` privileges.  
After using the `interactive` flag you can see that we are able to laucnch a new interactive CMD  
  

![image](https://user-images.githubusercontent.com/50461376/203030730-5220cadf-4f23-4483-8f9b-ba678548da92.png)  
  
Obviously the tool can also list available tokens but this can also be done using `tasklist /v` to view process which are running with the user  
you want to impersoante.  
Example usage:  
```powershell
PS C:\Users\stronglocal\Desktop> .\BesoToken.exe exec 6876 cmd interactive
[+] Enabled SeImpersonatePrivilege
[+] Enabled SeDebugPrivilege
[+] Opened Process Sucessufully!
[+] Opened Process Token Sucessufully!

[+] Changed ACL winsta0
[+] Called SetSecurityInfo

[+] Changed ACL default
[+] Called SetSecurityInfo

[+] Opend Process Sucessfully: cmd
```





# Credeits  
1.The CPP code was written by Omri Baso  
2. Most of the research work was done by my co-worker [Yair Mentesh](https://www.linkedin.com/in/yair-mentesh/) thank you for your amazing work, Here is his [C# Implementation](https://github.com/Yair-Men/TokenMen) of the tool  
3. A Microsoft [blog post](https://learn.microsoft.com/en-us/previous-versions/aa379608\(v=vs.85\)) that helped me a lot. 
