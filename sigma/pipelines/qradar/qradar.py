from sigma.processing.transformations import FieldMappingTransformation, DetectionItemFailureTransformation, SetStateTransformation,DropDetectionItemTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, RuleContainsDetectionItemCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

"""
List Windows Field not support:
AccessList
Action
Address
AllowedToDelegateTo
AttributeLDAPDisplayName
AttributeValue
AuditPolicyChanges
AuditSourceName
CallTrace
Caption
CertThumbprint
Channel
ClassName
Company
ContextInfo
Description
DestinationIsIpv6
Device
DeviceDescription
DeviceName
EngineVersion
EventType
FileVersion
HiveName
HostVersion
Initiated
KeyLength
LayerRTID
Level
LocalName
LogonId
LogonProcessName
NewName
PipeName
ParentUser
PasswordLastSet
PossibleCause
PrivilegeList
Product
Properties
Provider
ProviderName
Provider_Name
QNAME
Query
QueryName
QueryResults
QueryStatus
RelativeTargetName
RemoteAddress
Service
SearchFilter
ServerName
ServicePrincipalNames
ServiceStartType
ServiceType
SidHistory
Signed
Source_Name
StartAddress
StartFunction
StartModule
State
Status
SubjectDomainName
SubjectLogonId
SubjectUserSid
TargetLogonId
TargetName
TicketEncryptionType
TicketOptions
Type
User
UserName
Value
Workstation
WorkstationName
TargetUserSid
TargetSid
ObjectServer
ObjectClass
OldUacValue
Origin
ObjectValueName
OldTargetUserName
DestinationHostname
"""

qradar_windows_event = {
    "AccessMask": "Access Mask",
    "Accesses": "Accesses",
    "AccountName": "Username",
    "Account_Name": "Username",
    "ApplicationPath": "File Path",
    "AuthenticationPackageName": "Authentication Package ",
    "CallerProcessName": "Process Path",
    "CommandLine": "Process CommandLine",
    "Commandline": "Process CommandLine",
    "Computer": "Machine ID",
    "ComputerName": "Computer Name",
    "CurrentDirectory": "Process Path",
    "DestAddress": "Destination IP",
    "DestPort": "Destination Port",
    "Destination": "Destination IP",
    "DestinationIp": "Destination IP",
    "DestinationPort": "Destination Port",
    "Details": "Target Details",
    "ErrorCode": "Error Code",
    "EventID": "EventID",
    "FailureCode": "Error Code",
    "FileName": "Filename",
    "GrantedAccess": "Granted Access",
    "Hashes": "File Hash",
    "HostApplication": "Process Path",
    "HostName": "HostName",
    "Image ": "Image",
    "ImageLoaded": "LoadedImage",
    "ImagePath": "Image",
    "Imphash": "IMP Hash",
    "IntegrityLevel": "Integrity Level",
    "IpAddress": "Source IP",
    "Keywords": "Payload",
    "LogonType": "Logon Type",
    "MachineName": "Computer Name",
    "Message": "Message",
    "NewTargetUserName": "Target User Name",
    "ObjectName": "ObjectName",
    "ObjectType": "ObjectType ",
    "OriginalFileName": "ImageName",
    "OriginalFilename": "ImageName",
    "OriginalName": "ImageName",
    "ParentCommandLine": "ParentCommandLine",
    "ParentImage": "ParentImage",
    "Path": "File Path",
    "Payload": "Process CommandLine",
    "ProcessId": "Process Id",
    "ProcessName": "Process Name",
    "SamAccountName": "SAM Account Name",
    "ScriptBlockText": "Process CommandLine ",
    "ServiceFileName": "Service FileName",
    "ServiceName": "Service Name ",
    "ShareName": "ShareName",
    "SourceAddress": "Source IP",
    "SourceImage": "SourceImage",
    "SourcePort": "Source Port",
    "SubjectUserName": "AccountName ",
    "TargetFilename": "Filename",
    "TargetImage": "TargetImage",
    "TargetObject": "Target Object",
    "TargetPort": "Destination Port",
    "TargetServerName": "Destination IP",
    "TargetUserName": "Target User Name",
    "TaskName": "Task Name ",
    "param1": "Payload",
    "param2": "Payload",
    "processPath": "Process Path",
    "sha1": "SHA1 Hash",
    "event_id": "EventID",
    "dst": "destinationip",
    "dst_ip": "destinationip",
    "src": "sourceip",
    "src_ip": "sourceip",
    "c-ip": "sourceip",
    "cs-ip": "sourceip",
    "c-uri": "URL",
    "c-uri-extension": "URL",
    "c-useragent": "user_agent",
    "c-uri-query": "uri_query",
    "cs-method": "Method",
    "r-dns": "FQDN",
    "ClientIP": "sourceip",
    "event_data.CommandLine": "Process CommandLine",
    "file_hash": "File Hash",
    "hash": "File Hash",
    "Event-ID": "EventID",
    "Event_ID": "EventID",
    "eventId": "EventID",
    "event-id": "EventID",
    "eventid": "EventID",
    "hashes": "File Hash",
    "url.query": "URL",
    "resource.URL": "URL",
    "event_data.CallingProcessName": "CallingProcessName",
    "event_data.ComputerName": "Hostname/HOSTNAME",
    "event_data.DestinationHostname": "Hostname/HOSTNAME",
    "event_data.DestinationIp": "destinationip",
    "event_data.DestinationPort": "destinationip",
    "event_data.Details": "Target Details",
    "event_data.FileName": "Filename",
    "event_data.Hashes": "File Hash",
    "event_data.Image": "Image",
    "event_data.ImageLoaded": "LoadedImage",
    "event_data.ImagePath": "SourceImage",
    "Image": "Image",
    "event_data.Imphash": "IMP Hash",
    "event_data.ParentCommandLine": "ParentCommandLine",
    "event_data.ParentImage": "ParentImage",
    "event_data.ParentProcessName": "ParentImageName",
    "event_data.Path": "File Path",
    "event_data.PipeName": "PipeName",
    "event_data.ProcessCommandLine": "Process CommandLine",
    "ProcessCommandLine": "Process CommandLine",
    "event_data.ServiceFileName": "ServiceFileName",
    "event_data.ShareName": "ShareName",
    "event_data.Signature": "Signature",
    "event_data.SourceImage": "SourceImage",
    "event_data.StartModule": "StartModule",
    "event_data.SubjectUserName": "username",
    "event_data.SubjectUserSid": "SubjectUserSid",
    "event_data.TargetFilename": "Filename",
    "event_data.TargetImage": "TargetImage",
    "event_data.TicketOptions": "TicketOptions",
    "event_data.User": "username",
    "User": "username",
    "user": "username",
    "ParentProcessId": "Parent Process ID",
    "md5": "MD5 Hash",
    "sha256": "SHA256 Hash",
}



qradar_windows_qid = {
    4688: [5001828, 5000862],
    4624: [5000830],
    4625: [5000475],
    4719: [5000891],
    4739: [5000909],
    1102: [5001534],
    4698: [5000872],
    4699: [5000873],
    4700: [5000874],
    4701: [5000875],
    4702: [5000876],
    4720: [5000892],
    4722: [5000893],
    4723: [5000894],
    4724: [5002722],
    4728: [5000899],
    4740: [5000910],
    4768: [5000937],
    4769: [5000434],
    4770: [5000939],
    5140: [5001108],
    5142: [5002951],
    5143: [5001562],
    5144: [5001529],
    7045: [5002197],
    104: [5001534],
    521: [5001513],
    1074: [5001592],
    1100: [5001594],
    1104: [5002616],
    1108: [5002390],
    1: [5001828, 5000862],
    2: [5001838],
    3: [5001840],
    4: [5001841],
    5: [5001842],
    6: [5001843],
    7: [5001844],
    8: [5001845],
    9: [5001846],
    10: [5001829],
    11: [5001830],
    12: [5001831],
    13: [5001832],
    14: [5001833],
    15: [5001834],
    16: [5001835],
    17: [5001836],
    18: [5001837],
    19: [5001977],
    20: [5001978],
    21: [5001979],
    22: [5002343]

}
qradar_logsource_id ={
    "windows" : 12
}



def qradar_windows():
    return ProcessingPipeline(
        name="Qradar AQL field mapping",
        priority=20,
        items= [
            ProcessingItem(
                identifier="Qradar_savedsearches_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The QRadar savedsearches Sigma backend supports only the following fields for process_creation log source"),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ],
                rule_condition_linking=any,
                detection_item_conditions=[
                    ExcludeFieldCondition(
                        fields = qradar_windows_event.keys()
                    )
                ]
            ),
            ProcessingItem(     # Some optimizations searching for characteristic keyword for specific log sources
                identifier="qradar_windows_event_logs",
                transformation=FieldMappingTransformation(qradar_windows_event),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ]
            )

        ]
    )

def qradar_exetension():
    qid = []
    return ProcessingPipeline(
        name="Qradar extension format mappings",
        priority=20,
        items=
        [
            ProcessingItem(
                identifier='qradar_extension_mapping_logsources',
                transformation=SetStateTransformation("QradarLogSources",LogsourceID),
                rule_conditions=[
                    LogsourceCondition(
                        product=product
                    )
                ]
            )
            for product, LogsourceID in qradar_logsource_id.items()
        ] + [
            ProcessingItem(
                identifier='qradar_windows_eventid_mapping_qid',
                transformation=SetStateTransformation("qid-%d"%eventid,id),
                rule_conditions=[
                    RuleContainsDetectionItemCondition(
                        field="EventID",
                        value=eventid,
                    )
                ]
            )
            for eventid, id in qradar_windows_qid.items()
        ] + [
            ProcessingItem(
                identifier='qradar_windows_remove_eventid',

                transformation = DropDetectionItemTransformation(),
                detection_item_conditions=[ IncludeFieldCondition(fields=["EventID"]) ],
                # Keep EventID field when can't mapping to QID Qradar
                rule_conditions= [
                    RuleProcessingItemAppliedCondition("qradar_windows_eventid_mapping_qid"),
                ]
            )
        ] + [
            ProcessingItem(
                identifier="Qradar_extensions_unsupported_fields",
                transformation=DetectionItemFailureTransformation("The QRadar Extensions Sigma backend supports only the following fields for process_creation log source: " + ",".join(qradar_windows_event.keys())),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ],
                rule_condition_linking=any,
                detection_item_conditions=[
                    ExcludeFieldCondition(
                        fields = qradar_windows_event.keys()
                    )
                ]
            ),
            ProcessingItem(
                identifier="qradar_extentsion_windows_mapping",
                transformation=FieldMappingTransformation(qradar_windows_event),
                rule_conditions=[
                    LogsourceCondition(
                        product="windows"
                    )
                ],
                rule_condition_linking=any,
            )
        ]
    )
