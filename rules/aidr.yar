rule EICAR_Test
{
    meta:
        severity = "high"
        description = "EICAR 표준 테스트 파일"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $eicar
}

rule PE_Injection_Imports
{
    meta:
        severity = "low"
        description = "다른 프로세스에 코드를 넣을 때 쓰는 API 세 개가 함께 있음"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        uint16(0) == 0x5A4D and all of them
}