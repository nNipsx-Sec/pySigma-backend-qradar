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
        """)
    ) == ['SELECT UTF8(payload) as search_payload from events where "Process CommandLine"=\'val1\' AND "Image"=\'val2\'']

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
        """)
    ) == ['SELECT UTF8(payload) as search_payload from events where "Process Id"=1962 AND "Image"=\'Paint it Black\' AND "ImageName"=\'Wild Horses\' AND "Process CommandLine"=\'Jumpin\' Jack Flash\' AND "username"=\'Mick Jagger\' AND "Parent Process ID"=1972 AND "ParentImage"=\'Muddy Waters\' AND "MD5 Hash"=\'Steel Wheels\' AND "SHA1 Hash"=\'Beggars Banquet\' AND "SHA256 Hash"=\'Let it Bleed\'']

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


def test_qradar_pipeline_unsupported_field_process_start():
    with pytest.raises(SigmaTransformationError, match="The QRadar savedsearches Sigma backend supports only the following fields for process_creation log source"):
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
            """)
        )