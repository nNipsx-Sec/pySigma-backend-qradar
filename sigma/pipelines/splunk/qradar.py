from logging.config import IDENTIFIER
from sigma.processing.transformations import FieldMappingTransformation, DetectionItemFailureTransformation, SetStateTransformation,DropDetectionItemTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition, RuleContainsDetectionItemCondition 
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline



qradar_windows_event = {
  "event_id": "EventID",
  "EventID": "EventID",
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
  "ServiceFileName": "Service FileName",
  "event_data.CommandLine": "Process CommandLine",
  "CommandLine": "Process CommandLine",
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
  "ComputerName": "Hostname/HOSTNAME",
  "event_data.DestinationHostname": "Hostname/HOSTNAME",
  "DestinationHostname": "Hostname/HOSTNAME",
  "event_data.DestinationIp": "destinationip",
  "event_data.DestinationPort": "destinationip",
  "event_data.Details": "Target Details",
  "Details": "Target Details",
  "event_data.FileName": "Filename",
  "event_data.Hashes": "File Hash",
  "Hashes": "File Hash",
  "event_data.Image": "Image",
  "event_data.ImageLoaded": "LoadedImage",
  "event_data.ImagePath": "SourceImage",
  "ImagePath": "Image",
  "Image":"Image",
  "event_data.Imphash": "IMP Hash",
  "Imphash": "IMP Hash",
  "event_data.ParentCommandLine": "ParentCommandLine",
  "event_data.ParentImage": "ParentImage",
  "event_data.ParentProcessName": "ParentImageName",
  "event_data.Path": "File Path",
  "Path": "File Path",
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
  "TargetFilename": "Filename",
  "event_data.TargetImage": "TargetImage",
  "TargetImage": "TargetImage",
  "event_data.TicketOptions": "TicketOptions",
  "event_data.User": "username",
  "User": "username",
  "user": "username",
  "OriginalFileName": "OriginalFileName"
}

qradar_windows_qid = {
    4688: [5001828, 5000862],
    4624: [5000830],
    4625: [5000475],
    4719: [5000891],
    4739: [5000909],
    4698: [5000872],
    4699: [5000873],
    4700: [5000874],
    4701: [5000875],
    4702: [5000876],
    4723: [5000894],
    4724: [5002722],
    4728: [5000899],
    4740: [5000910],
    4768: [5000937],
    4769: [5000434],
    4770: [5000939],
    7045: [5002197],
    104: [5001534],
    521: [5001513],
    1074: [5001592],
    1100: [5001594],
    1104: [5002616],
    1108: [5002390],
    1: [5001828, 5000862]

}
qradar_logsource_id ={
    "windows" : 12
}



def qradar_windows_events_acceleration_keywords():
    return ProcessingPipeline(
        name="Qradar Windows Events/Sysmon acceleration keywords",
        priority=10,
        items= [
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

def qradar_cim_exetension():
    qid = []
    return ProcessingPipeline(
        name="Qradar Extensions Mapping",
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
