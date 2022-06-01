import pytest
from sigma.collection import SigmaCollection
from sigma.backends.qradar import QradarBackend
from sigma.exceptions import SigmaTransformationError


def test_qradar_windows_pipeline_simple():
    assert QradarBackend().convert(
        SigmaCollection.from_yaml(f"""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: val1
                    Image: val2
                condition: sel
        """),"savedsearches"
    ) == 'SELECT UTF8(payload) as search_payload from events where "Process CommandLine"=\'val1\' AND "Image"=\'val2\''

def test_qradar_pipeline_process_creation_field_mapping():
    assert QradarBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    ProcessId: 1962
                    Image: 'Paint it Black'
                    OriginalFileName: 'Wild Horses'
                    CommandLine: "Jumpin' Jack Flash"
                    User: 'Mick Jagger'
                    ParentProcessId: 1972
                    ParentImage: 'Muddy Waters'
                    md5: 'Steel Wheels'
                    sha1: 'Beggars Banquet'
                    sha256: 'Let it Bleed'
                condition: sel
        """),"savedsearches"
    ) == 'SELECT UTF8(payload) as search_payload from events where "Process Id"=1962 AND "Image"=\'Paint it Black\' AND "OriginalFileName"=\'Wild Horses\' AND "Process CommandLine"=\'Jumpin\' Jack Flash\' AND "username"=\'Mick Jagger\' AND "Parent Process ID"=1972 AND "ParentImage"=\'Muddy Waters\' AND "MD5 Hash"=\'Steel Wheels\' AND "SHA1 Hash"=\'Beggars Banquet\' AND "SHA256 Hash"=\'Let it Bleed\''

def test_qradar_pipeline_dns_field_mapping():
    assert QradarBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: dns
                product: windows
            detection:
                sel:
                    QueryName: 'My Generation'
                    Computer: 'Teenage Wasteland'
                    record_type: 'Pinball Wizard'
                condition: sel
        """)
    ) == ['"QueryName"=\'My Generation\' AND "Computer"=\'Teenage Wasteland\' AND "record_type"=\'Pinball Wizard\'']

def test_qradar_pipeline_web_proxy_field_mapping():
    assert QradarBackend().convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: proxy
            detection:
                sel:
                    c-uri: 'https://www.thebeatles.com/'
                    c-uri-query: 'songs'
                    cs-method: GET
                    r-dns: 'www.thebeatles.com'
                    src_ip|cidr: 192.168.1.0/24
                    dst_ip: '54.229.169.162'
                condition: sel
        """)
    ) == ['"c-uri"=\'https://www.thebeatles.com/\' AND "c-uri-query"=\'songs\' AND "cs-method"=\'GET\' AND "r-dns"=\'www.thebeatles.com\' AND INCIDR(\'192.168.1.0/24\', "src_ip") AND "dst_ip"=\'54.229.169.162\'']


def test_insight_idr_pipeline_unsupported_field_process_start():
    with pytest.raises(SigmaTransformationError, match="The QRadar savedsearches Sigma backend supports only the following fields for process_creation log source: event_id,EventID,dst,dst_ip,src,src_ip,c-ip,cs-ip,c-uri,c-uri-extension,c-useragent,c-uri-query,cs-method,r-dns,ClientIP,ServiceFileName,event_data.CommandLine,CommandLine,file_hash,hash,Event-ID,Event_ID,eventId,event-id,eventid,hashes,url.query,resource.URL,event_data.CallingProcessName,event_data.ComputerName,ComputerName,event_data.DestinationHostname,DestinationHostname,event_data.DestinationIp,event_data.DestinationPort,event_data.Details,Details,event_data.FileName,event_data.Hashes,Hashes,event_data.Image,event_data.ImageLoaded,event_data.ImagePath,ImagePath,Image,event_data.Imphash,Imphash,event_data.ParentCommandLine,ParentCommandLine,event_data.ParentImage,ParentImage,event_data.ParentProcessName,event_data.Path,Path,event_data.PipeName,event_data.ProcessCommandLine,ProcessCommandLine,event_data.ServiceFileName,event_data.ShareName,event_data.Signature,event_data.SourceImage,event_data.StartModule,event_data.SubjectUserName,event_data.SubjectUserSid,event_data.TargetFilename,TargetFilename,event_data.TargetImage,TargetImage,event_data.TicketOptions,event_data.User,User,user,OriginalFileName,ProcessId,ParentProcessId,md5,sha1,sha256"):
        QradarBackend().convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        CurrentDirectory|contains: hi
                        IntegrityLevel: hello
                        imphash: blah
                    condition: sel
            """),"savedsearches"
        )