use std::collections::HashMap;
use std::io::Read;
use ntapi::ntobapi::NtQueryObject;
use ntapi::ntobapi::OBJECT_INFORMATION_CLASS;
use ntapi::ntobapi::OBJECT_TYPE_INFORMATION;
use ntapi::ntpsapi::PROCESSINFOCLASS;
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use ntapi::ntrtl::RtlAnsiStringToUnicodeString;
use ntapi::ntrtl::RtlInitAnsiString;
use winapi::ctypes::*;
use winapi::shared::minwindef::FILETIME;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::shared::ntdef::STRING;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::shared::sddl::*;
use winapi::shared::windef::HFILE_ERROR;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::CREATE_NEW;
use winapi::um::handleapi::CloseHandle;
use winapi::um::handleapi::DuplicateHandle;
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::lsalookup::LSA_STRING;
use winapi::um::lsalookup::LSA_UNICODE_STRING;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::ntlsa::SECURITY_LOGON_SESSION_DATA;
use winapi::um::ntsecapi::*;
use winapi::um::processthreadsapi::*;
use winapi::um::securitybaseapi::*;
use winapi::um::timezoneapi::FileTimeToSystemTime;
use winapi::um::winbase::*;
use winapi::um::winnt::*;
use winapi::um::winnt::{TOKEN_INFORMATION_CLASS, TOKEN_USER};
use winapi::um::ntlsa::*;
use ntapi::ntexapi::*;
use winapi::um::synchapi::*;
use winapi::um::tlhelp32::*;
use winapi::shared::winerror::*;
use itertools::Itertools;
use winapi::um::memoryapi::*;
use winapi::um::subauth::*;
use winapi::um::minwinbase::*;
use crate::unicodetostring;
use winapi::um::fileapi::*;
pub mod tokens;
 
 
pub fn enumtickets(){
    unsafe{
 
        let mut lsahandle = 0 as *mut c_void;
        let ntstatus = LsaConnectUntrusted(&mut lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaConnectUntrusted failed: {}",ntstatus);
            return ();
        }
        println!("[+] LsaConnectUntrusted connection success");
 
 
        let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
        let mut buffer = "Kerberos".bytes().collect::<Vec<u8>>();
        lsastring.Length = buffer.len() as u16;
        lsastring.MaximumLength = buffer.len() as u16 ;
        lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;
 
        
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
             &mut lsastring, &mut packagehandle);
       
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
        }
        println!("packagehandle: {:x?}",packagehandle);
 
        
        let mut requestcache =std::mem::zeroed::<KERB_QUERY_TKT_CACHE_REQUEST>();
        requestcache.MessageType = KerbQueryTicketCacheMessage;
        requestcache.LogonId = std::mem::zeroed::<LUID>();
 
 
        let mut tcktresp = 0 as *mut c_void;
        let mut returnlen = 0;
        let mut pstatus = 0;
        let res =LsaCallAuthenticationPackage(lsahandle, 
            packagehandle,
             &mut requestcache as *mut _ as *mut c_void, 
             std::mem::size_of_val(&requestcache) as u32, 
             &mut tcktresp, 
             &mut returnlen,
              &mut pstatus);
        if res!=STATUS_SUCCESS{
            println!("LsaCallAuthenticationPackage failed: {}",res);
        }
        
        println!("res: {:x?}",res);
        println!("returned length: {}",returnlen);
        println!("ticket response: {:x?}",tcktresp);
        println!("protocol status: {:x?}",pstatus);
 
        if returnlen>0{
            let tickets = RemoteParse::<KERB_QUERY_TKT_CACHE_RESPONSE>(GetCurrentProcess(), tcktresp);
            if tickets.is_ok(){
                let ticketlist = tickets.unwrap();
                println!("Number of tickets in cache: {}",ticketlist.CountOfTickets);
                
                for i in 0..ticketlist.CountOfTickets{
                   
                   let ticketcacheinfo =  *((tcktresp as usize + 8 + (i as usize * std::mem::size_of::<KERB_TICKET_CACHE_INFO>())) as *mut KERB_TICKET_CACHE_INFO);
                    let servername = unicodetostring(std::mem::transmute(&ticketcacheinfo.ServerName), GetCurrentProcess());
                    let realmname = unicodetostring(std::mem::transmute(&ticketcacheinfo.RealmName), GetCurrentProcess());
                
                    println!("servername: {}",servername);
                    println!("realmname: {}",realmname);
                    println!("ticket flags: {:x?}",ticketcacheinfo.TicketFlags);
                    
                    let starttime = LargeIntegerToSystemTime(&ticketcacheinfo.StartTime).unwrap();
                    let endtime = LargeIntegerToSystemTime(&ticketcacheinfo.EndTime).unwrap();
                    let renewtime = LargeIntegerToSystemTime(&ticketcacheinfo.RenewTime).unwrap();
 
                    println!("Start Time: {}",starttime);
                    println!("End Time: {}",endtime);
                    println!("Renew Time: {}",renewtime);
                    println!();
 
 
                }
            
            }    
 
        }
 
        let ntstatus = LsaDeregisterLogonProcess(lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaDeregisterLogonProcess failed: {:x?}",ntstatus);
            return ();
        }
        println!("[+] Deregistering from lsa success");
 
    }
}
 
pub fn getcachedtickets() -> Result<Vec<KERB_TICKET_CACHE_INFO>,String>{
    unsafe{
 
        let mut mytickets:Vec<KERB_TICKET_CACHE_INFO> = Vec::new();
        let mut lsahandle = 0 as *mut c_void;
        let ntstatus = LsaConnectUntrusted(&mut lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            return Err(format!("LsaConnectUntrusted failed: {}",ntstatus));
           
        }
        println!("[+] LsaConnectUntrusted connection success");
 
 
        let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
        let mut buffer = "Kerberos".bytes().collect::<Vec<u8>>();
        lsastring.Length = buffer.len() as u16;
        lsastring.MaximumLength = buffer.len() as u16 ;
        lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;
 
        
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
             &mut lsastring, &mut packagehandle);
       
        if ntstatus!=STATUS_SUCCESS{
            LsaDeregisterLogonProcess(lsahandle);
            return Err(format!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus));
            
        }
        
         
        let mut requestcache =std::mem::zeroed::<KERB_QUERY_TKT_CACHE_REQUEST>();
        requestcache.MessageType = KerbQueryTicketCacheMessage;
        requestcache.LogonId = std::mem::zeroed::<LUID>();
 
 
        let mut tcktresp = 0 as *mut c_void;
        let mut returnlen = 0;
        let mut pstatus = 0;
        let res =LsaCallAuthenticationPackage(lsahandle, 
            packagehandle,
             &mut requestcache as *mut _ as *mut c_void, 
             std::mem::size_of_val(&requestcache) as u32, 
             &mut tcktresp, 
             &mut returnlen,
              &mut pstatus);
        if res!=STATUS_SUCCESS{
            LsaDeregisterLogonProcess(lsahandle);
            return Err(format!("LsaCallAuthenticationPackage failed: {}",res));
        }
        
        
 
        if returnlen>0{
            let tickets = RemoteParse::<KERB_QUERY_TKT_CACHE_RESPONSE>(GetCurrentProcess(), tcktresp);
            if tickets.is_ok(){
                let ticketlist = tickets.unwrap();
               
                
                for i in 0..ticketlist.CountOfTickets{
                   
                   let ticketcacheinfo =  *((tcktresp as usize + 8 + (i as usize * std::mem::size_of::<KERB_TICKET_CACHE_INFO>())) as *mut KERB_TICKET_CACHE_INFO);
                    let servername = unicodetostring(std::mem::transmute(&ticketcacheinfo.ServerName), GetCurrentProcess());
                    let realmname = unicodetostring(std::mem::transmute(&ticketcacheinfo.RealmName), GetCurrentProcess());
                
                    /*println!("servername: {}",servername);
                    println!("realmname: {}",realmname);
                    println!("ticket flags: {:x?}",ticketcacheinfo.TicketFlags);
                    */
                    let starttime = LargeIntegerToSystemTime(&ticketcacheinfo.StartTime).unwrap();
                    let endtime = LargeIntegerToSystemTime(&ticketcacheinfo.EndTime).unwrap();
                    let renewtime = LargeIntegerToSystemTime(&ticketcacheinfo.RenewTime).unwrap();
 
                    /*println!("Start Time: {}",starttime);
                    println!("End Time: {}",endtime);
                    println!("Renew Time: {}",renewtime);
                    println!();*/
 
                    mytickets.push(ticketcacheinfo);
                }
            
            }    
 
        }
 
        let ntstatus = LsaDeregisterLogonProcess(lsahandle);
        if ntstatus!=STATUS_SUCCESS{
            return Err(format!("LsaDeregisterLogonProcess failed: {:x?}",ntstatus));
            
        }
        return Ok(mytickets);
 
    }
}
 
 
pub fn purgeallcachedtickets() {
    unsafe{
 
        let res = getcachedtickets();
        if res.is_ok(){
            let tickets = res.unwrap();
 
            for i in 0..tickets.len(){
 
                let mut lsahandle = 0 as *mut c_void;
                let ntstatus = LsaConnectUntrusted(&mut lsahandle);
 
 
                let mut purgerequest = std::mem::zeroed::<KERB_PURGE_TKT_CACHE_REQUEST>();
                purgerequest.MessageType = KerbPurgeTicketCacheMessage;
                purgerequest.LogonId = std::mem::zeroed::<LUID>();
                purgerequest.ServerName = tickets[i].ServerName;
                purgerequest.RealmName = tickets[i].RealmName;
 
 
 
                let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
                let mut buffer = "Kerberos".bytes().collect::<Vec<u8>>();
                lsastring.Length = buffer.len() as u16;
                lsastring.MaximumLength = buffer.len() as u16 ;
                lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;
 
                
                let mut packagehandle = 0;
                let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
                    &mut lsastring, &mut packagehandle);
            
                if ntstatus!=STATUS_SUCCESS{
                    LsaDeregisterLogonProcess(lsahandle);
                    return ();
                    
                }
 
            
 
 
            }
 
        }
 
    }
}
 
 
pub fn createkerbs4ulogon(upn:String, realm: String) -> Vec<u8>{
    unsafe{
        let upnbuffer = upn.encode_utf16().collect::<Vec<u16>>();
        let realmbuffer = realm.encode_utf16().collect::<Vec<u16>>();
 
        let totalsize = std::mem::size_of::<KERB_S4U_LOGON>() + (upnbuffer.len()*2) + (realmbuffer.len()*2);
        let mut mys4u = vec![0u8;totalsize ];
 
 
 
        let mut kerbs4u = std::mem::zeroed::<KERB_S4U_LOGON>();
        kerbs4u.MessageType = KerbS4ULogon;
        kerbs4u.Flags = KERB_S4U_LOGON_FLAG_IDENTIFY;
 
        kerbs4u.ClientUpn.Buffer = (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>()) as *mut u16;
        kerbs4u.ClientUpn.Length = upnbuffer.len() as u16;
        kerbs4u.ClientUpn.MaximumLength = upnbuffer.len() as u16+1;
 
        kerbs4u.ClientRealm.Buffer =  (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() + (upnbuffer.len()*2)) as *mut u16;
        kerbs4u.ClientRealm.Length = realmbuffer.len() as u16;
        kerbs4u.ClientRealm.MaximumLength = realmbuffer.len() as u16+1;
 
        let mut byteswritten = 0;
        WriteProcessMemory(GetCurrentProcess(), 
        mys4u.as_mut_ptr() as *mut c_void, 
        &mut kerbs4u as *mut _ as *mut c_void, 
        std::mem::size_of::<KERB_S4U_LOGON>(), 
        &mut byteswritten);
 
 
        WriteProcessMemory(GetCurrentProcess(), 
        (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() )as *mut c_void, 
        upnbuffer.as_ptr() as *const c_void, 
        upnbuffer.len()*2, 
        &mut byteswritten);
 
 
 
        WriteProcessMemory(GetCurrentProcess(), 
        (mys4u.as_ptr() as usize + std::mem::size_of::<KERB_S4U_LOGON>() +(upnbuffer.len()*2))as *mut c_void, 
        realmbuffer.as_ptr() as *const c_void, 
        realmbuffer.len()*2, 
        &mut byteswritten);
 
        return mys4u;
    }
}
 
 
 
 
pub fn getkerbs4ulogontcbprivilege(){
    unsafe{
 
 
        let mut logonprocess = std::mem::zeroed::<LSA_STRING>();
        let mut buffer = "User32LogonProcess".bytes().collect::<Vec<u8>>();
        logonprocess.Length = buffer.len() as u16;
        logonprocess.MaximumLength = buffer.len() as u16+1;
        logonprocess.Buffer = buffer.as_mut_ptr() as *mut i8;
 
 
        let mut lsahandle = 0 as *mut c_void;
        let mut securitymode = 0;
        let ntstatus = LsaRegisterLogonProcess(&mut logonprocess,
             &mut lsahandle, &mut securitymode);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaRegisterLogonProcess error: {:x?}",ntstatus);
            return ();
        }
        
 
 
        let mut packagename = std::mem::zeroed::<LSA_STRING>();
        let mut buffer2 = "Kerberos".bytes().collect::<Vec<u8>>();
        packagename.Length = buffer2.len() as u16;
        packagename.MaximumLength = buffer2.len() as u16+1;
        packagename.Buffer = buffer2.as_mut_ptr() as *mut i8;
 
 
        let mut packagehandle = 0;
        let ntstatus = LsaLookupAuthenticationPackage(lsahandle, 
            &mut packagename, &mut packagehandle);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLookupAuthenticationPackage error: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
            return ();
        }
 
 
        let mut mys4u = createkerbs4ulogon("Administrator@theos.com.mx".to_string(), "theos.com.mx".to_string());
 
 
 
        let mut origin = std::mem::zeroed::<LSA_STRING>();
        let mut buffer3 = "Testingorigin".bytes().collect::<Vec<u8>>();
        origin.Length = buffer3.len() as u16;
        origin.MaximumLength = buffer3.len() as u16+1;
        origin.Buffer = buffer3.as_mut_ptr() as *mut i8;
 
 
 
 
        let mut token_source = std::mem::zeroed::<TOKEN_SOURCE>();
        token_source.SourceName = (*b"User32\0\0").map(|u| u as i8);
        token_source.SourceIdentifier = std::mem::zeroed::<LUID>();
 
 
        let mut profile = 0 as *mut c_void;
        let mut profilelength = 0;
        let mut newluid = std::mem::zeroed::<LUID>();
        let mut newtokenhandle = 0 as *mut c_void;
        let mut quota = std::mem::zeroed::<QUOTA_LIMITS>();
        let mut logonrejectstatus = 0;
        let ntstatus = LsaLogonUser(lsahandle, 
           &mut origin , 
            Network, 
            packagehandle, 
            mys4u.as_mut_ptr() as *mut c_void, 
            mys4u.len() as u32, 
            std::ptr::null_mut(),
             &mut token_source, 
             &mut profile, 
             &mut profilelength, 
             &mut newluid, 
             &mut newtokenhandle, 
             &mut quota, 
            &mut logonrejectstatus);
        if ntstatus!=STATUS_SUCCESS{
            println!("LsaLogonUser error: {:x?}",ntstatus);
            LsaDeregisterLogonProcess(lsahandle);
            return ();
        }
 
 
        println!("newtokenhandle: {:x?}",newtokenhandle);
        tokens::gettokenstatistics(newtokenhandle);
 
 
        let mut bytesneeded =0;
        GetUserNameA(std::ptr::null_mut(), &mut bytesneeded);
 
        let mut userbuffer=vec![0u8;bytesneeded as usize];
        GetUserNameA(userbuffer.as_mut_ptr() as *mut i8, &mut bytesneeded);
 
        println!("username: {}",String::from_utf8_lossy(&userbuffer));
  
 
        ImpersonateLoggedOnUser(newtokenhandle);
 
  
        let mut bytesneeded =0;
        GetUserNameA(std::ptr::null_mut(), &mut bytesneeded);
 
        let mut userbuffer=vec![0u8;bytesneeded as usize];
        GetUserNameA(userbuffer.as_mut_ptr() as *mut i8, &mut bytesneeded);
 
        println!("username: {}",String::from_utf8_lossy(&userbuffer));
 
  
        RevertToSelf();
 
        LsaDeregisterLogonProcess(lsahandle);
 
 
 
    }
}
 
 
pub fn createprocesswithlogon(username:String,password:String,domainname:String){
    unsafe{
 
        
 
    }
}
 
 
 
pub fn LargeIntegerToSystemTime(li: &LARGE_INTEGER)
-> Result<String, String>{
    unsafe{
 
        let mut st = std::mem::zeroed::<SYSTEMTIME>();
        let res = FileTimeToSystemTime(li as *const _ as *const FILETIME, &mut st);
        if res==0{
            return Err(format!("FileTimeToSystemTime failed: {}",GetLastError()));
        }
 
        return Ok(format!("day/month/year: {}/{}/{}, hr/min/sec: {}:{}:{}",
                st.wDay,st.wMonth,st.wYear,st.wHour,st.wMinute,st.wSecond));
 
    }
}
 
 
pub fn StringToLSASTRING<'a>(s:&'a String){
    
    unsafe{
        let mut buffer = s.bytes().collect::<Vec<u8>>();
        let mut lsastring = unsafe{std::mem::zeroed::<LSA_STRING>()};
        lsastring.Length = buffer.len() as u16;
        lsastring.MaximumLength = buffer.len() as u16 + 1;
        
        lsastring.Buffer = buffer.as_mut_ptr() as *mut i8;
 
       
    }
    
}
 
 
 
pub fn RemoteParse<T>(prochandle:*mut c_void, baseaddress:*const c_void)
 -> Result<T, String> where T:Copy,{
    unsafe{
        
        let ssize = std::mem::size_of::<T>();
        let mut buffer = vec![0u8;ssize];
        let mut bytesread = 0;
        let res = ReadProcessMemory(prochandle, baseaddress,
             buffer.as_mut_ptr() as *mut c_void, 
             buffer.len(), 
            &mut bytesread);
        if res==0{
            return Err(format!("readprocessmemory failed: {}",GetLastError()));
        }
 
        return Ok(*(buffer.as_mut_ptr() as *mut T));
    }
}
 
 
 
pub fn ReadStringFromMemory(prochandle: *mut c_void, base: *const c_void) -> String {
    unsafe {
        let mut i: isize = 0;
        let mut s = String::new();
        loop {
            let mut a: [u8; 1] = [0];
            ReadProcessMemory(
                prochandle,
                (base as isize + i) as *const c_void,
                a.as_mut_ptr() as *mut c_void,
                1,
                std::ptr::null_mut(),
            );
 
            if a[0] == 0 || i == 50 {
                return s;
            }
            s.push(a[0] as char);
            i += 1;
        }
    }
}
