# PassFilter

PassFilter is a dll that can be loaded into LSASS to filter passwords which are included in an offline HIBP file.
This dll expects a binary version of the sha1 hash ordered txt from [HIBP](https://haveibeenpwned.com/Passwords). You may convert the file using my [convertHIBP](https://github.com/fblz/convertHIBP) tool.
This dll is perfect for usage on domain controlles, since they should not be allowed to speak to the internet if possible at all.

## Building
```
git clone https://github.com/fblz/convertHIBP.git
```
Then open `PassFilter.sln` in Visual Studio and build the PassFilter project in Release x64 mode.


## Installation
For more or less up2date instructions see [the official Microsoft documentation.](https://docs.microsoft.com/en-us/windows/win32/secmgmt/installing-and-registering-a-password-filter-dll)

### Get a binary hibp file
```
git clone https://github.com/fblz/convertHIBP.git
cd convertHIBP
go build
./convertHIBP -InputFile ./pwned-passwords-sha1-ordered-by-hash-v7.txt -OutputFile ./hibp-v7.bin
```
Copy `hibp-v7.bin` onto ***every*** domain controller (DC), or place it on a share that all DCs can reach.
Since it's quite a big file, *don't put it in SYSVOL*.
### Configure the hibp file
To point the dll to your local file, create the following registry key:
`Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Passfilter`
Under this key then create a `REG_EXPAND_SZ` property with name `HashFile`.
Set its value to the full path of your `hibp-v7.bin`.
### Install the dll
Grab `x64\Release\PassFilter.dll` from next to the `PassFilter.sln`.
Place it into `%WINDIR%\System32` on ***every*** DC.
### Register the dll
To register the dllnavigate to the following registry path
`Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
then add the dll name `PassFilter` to the `Notification Packages` attribute.
### Enable filtering
To finally enable the filtering, enable the password complexity policy.
Either open `Local Security Policy` navigate to `Account Policies\Password Policy` and enable `Password must meet complexity requirements`
or inside a group policy navigate to 
`Computer Configuration\Policies\Windows Settings\Security Settings\Account Policies\Password Policy` and enable `Password must meet complexity requirements`.

***To complete the installation, restart the computer so LSASS can load the dll.***
