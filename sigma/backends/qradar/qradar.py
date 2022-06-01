from cgi import test
from unicodedata import name
from sigma.conversion.state import ConversionState
from sigma.rule import SigmaRule
from collections import defaultdict
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR
from sigma.types import SigmaCompareExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from sigma.pipelines.qradar import qradar_windows_events_acceleration_keywords, qradar_cim_exetension
import sigma
from typing import ClassVar, Dict, List, Optional, Tuple
# requirements
import urllib.parse
import base64
from xml.etree import cElementTree as et
from datetime import datetime as dt
import pytz
from zipfile import ZipFile
# Qradar Backend build base on Splunk Backend => Comming up in future: group-by on correlation action and Rule Extension.
# Author: Duc.Le - GTSC Team
# Supporting: ...
buildingblock ="""<rule owner="admin" scope="LOCAL" type="EVENT" roleDefinition="false" buildingBlock="true" enabled="true" id="-1">
	<name>BB: {name}</name>
	<notes></notes>
	<testDefinitions>
		<test requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION" groupId="10" group="jsp.qradar.rulewizard.condition.page.group.log" uid="0" name="com.q1labs.semsources.cre.tests.DeviceTypeID_Test" id="14">
			<parameter id="1">
				<initialText>these log source types</initialText>
				<selectionLabel>Select a Log Source type and click 'Add'</selectionLabel>
				<userOptions multiselect="true" method="com.q1labs.sem.ui.semservices.UISemServices.getDeviceTypeDescs" source="class" format="list"/>
				<userSelection>{logsourceID}</userSelection>
				<userSelectionTypes></userSelectionTypes>
				<userSelectionId>0</userSelectionId>
			</parameter>
		</test>
		<test requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION" groupId="3" group="jsp.qradar.rulewizard.condition.page.group.event" uid="1" name="com.q1labs.semsources.cre.tests.QID_Test" id="19">
			<parameter id="1">
				<initialText>QIDs</initialText>
				<selectionLabel>Browse or Search for QIDs below. Select the desired QIDs and click 'Add'</selectionLabel>
				<userOptions multiselect="true" method="com.q1labs.sem.ui.semservices.UISemServices.getQidsByLowLevelCategory" source="class" format="CustomizeParameter-QID.jsp"/>
				<userSelection>{qid}</userSelection>
				<userSelectionTypes></userSelectionTypes>
				<userSelectionId>0</userSelectionId>
			</parameter>
		</test>
		<test requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION" groupId="1" group="jsp.qradar.rulewizard.condition.page.group.common" uid="2" name="com.q1labs.semsources.cre.tests.AQL_Test" id="320">
			<parameter id="1">
				<initialText>this</initialText>
				<selectionLabel>Enter an AQL filter query</selectionLabel>
				<userOptions source="user" format="CustomizeParameter-AQL.jsp"/>
				<userSelection>{aql}</userSelection>
				<userSelectionTypes>property</userSelectionTypes>
				<userSelectionId>0</userSelectionId>
			</parameter>
			<parameter id="2">
				<initialText></initialText>
				<selectionLabel>Select a value</selectionLabel>
				<userSelection>events</userSelection>
				<userSelectionId>0</userSelectionId>
			</parameter>
		</test>
	</testDefinitions>
</rule>"""
xmlrule = """<rule overrideid="{ruleID}" owner="admin" scope="LOCAL" type="EVENT" roleDefinition="false" buildingBlock="false" enabled="true" id="{ruleID}">
	<name>{name}</name>
	<notes></notes>
	<testDefinitions>
		<test requiredCapabilities="EventViewer.RULECREATION|SURVEILLANCE.RULECREATION" groupId="7" group="jsp.qradar.rulewizard.condition.page.group.functions.simple" uid="0" name="com.q1labs.semsources.cre.tests.RuleMatch_Test" id="46">
			<parameter id="1">
				<initialText>any|all</initialText>
				<selectionLabel>Select an option</selectionLabel>
				<userOptions multiselect="false" source="xml" format="list">
					<option id="any">any</option>
					<option id="all">all</option>
				</userOptions>
				<userSelection>any</userSelection>
				<userSelectionId>0</userSelectionId>
			</parameter>
			<parameter id="2">
				<name>getEventRules</name>
				<initialText>rules</initialText>
				<selectionLabel>Select the rule(s) to match and click 'Add'</selectionLabel>
				<userOptions multiselect="true" method="com.q1labs.sem.ui.semservices.UISemServices.getEventRules" source="class" format="list"/>
				<userSelection>BB: {name}</userSelection>
				<userSelectionTypes></userSelectionTypes>
				<userSelectionId>0</userSelectionId>
			</parameter>
		</test>
	</testDefinitions>
	<actions flowAnalysisInterval="0" includeAttackerEventsInterval="0" forceOffenseCreation="true" offenseMapping="0"/>
	<responses referenceTableRemove="false" referenceMapOfMapsRemove="false" referenceMapOfSetsRemove="false" referenceMapRemove="false" referenceTable="false" referenceMapOfMaps="false" referenceMapOfSets="false" referenceMap="false">
		<newevent lowLevelCategory="7006" offenseMapping="0" forceOffenseCreation="true" qid="67500112" contributeOffenseName="true" overrideOffenseName="false" describeOffense="true" relevance="5" credibility="5" severity="3" description="BB:UC065" name="BB:UC065"/>
	</responses>
	<limiter hostType="ATTACKER" intervalType="m" intervalCount="30" responseCount="1"/>
</rule>"""
contentRule = """<custom_rule>
		<origin>USER</origin>
		<flags>0</flags>
		<mod_date>{date}</mod_date>
		<rule_data>{BBruledata}</rule_data>
		<uuid>BB: {name}</uuid>
		<rule_type>0</rule_type>
		<id>{BBruleID}</id>
		<create_date>{date}</create_date>
	</custom_rule>
	<fgroup_link>
		<fgroup_id>88888</fgroup_id>
		<item_id>{BBruleID}</item_id>
		<user_name>admin</user_name>
		<id>{BBruleID}</id>
	</fgroup_link>
	<custom_rule>
		<origin>USER</origin>
		<flags>0</flags>
		<mod_date>{date}</mod_date>
		<rule_data>{ruledata}</rule_data>
		<uuid>{name}</uuid>
		<rule_type>0</rule_type>
		<id>{ruleID}</id>
		<create_date>{date}</create_date>
	</custom_rule>
    <fgroup_link>
		<fgroup_id>88888</fgroup_id>
		<item_id>{ruleID}</item_id>
		<user_name>admin</user_name>
		<id>{ruleID}</id>
	</fgroup_link>
    """
ruleID =200000
UTC = pytz.timezone("UTC") 
date = dt.now(UTC).strftime("%FT%T%z")
# Convert time to qradar time format 
date = "{0}:{1}".format(
  date[:-2],
  date[-2:]
)
class QradarBackend(TextQueryBackend):
    """Qradar SPL backend."""
    group_expression : ClassVar[str] = "{expr}"

    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="
    field_quote: ClassVar[str] ="\""
    str_quote : ClassVar[str] = "'"
    escape_char : ClassVar[str] = ""
    wildcard_multi : ClassVar[str] = "%"
    wildcard_single : ClassVar[str] = "%"
    add_escaped : ClassVar[str] = ""

    re_expression : ClassVar[str] = "{field} IMATCHES '{regex}'"
    re_escape_char : ClassVar[str] = ""
    re_escape : ClassVar[Tuple[str]] = ('"',)


    cidr_expression : ClassVar[str] = "INCIDR('{value}', {field})"
    startswith_expression : ClassVar[str] = "{field} ILIKE '{value}%'"
    endswith_expression   : ClassVar[str] = "{field} ILIKE '%{value}'"
    contains_expression   : ClassVar[str] = "{field} ILIKE '%{value}%'"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"
    
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = "{field} is NULL"

    convert_or_as_in : ClassVar[bool] = True
    convert_and_as_in : ClassVar[bool] = False
    in_expressions_allow_wildcards : ClassVar[bool] = True
    field_in_list_expression : ClassVar[str] = "{field} {op}({list})"
    or_in_operator : ClassVar[Optional[str]] = "ILIKE ENUMERATION"
    list_separator : ClassVar[str] = ","

    unbound_value_str_expression : ClassVar[str] = "'{value}'"
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'
    deferred_start : ClassVar[str] = ""
    deferred_separator : ClassVar[str] = ""
    deferred_only_query : ClassVar[str] = ""

    output_format_processing_pipeline = defaultdict(ProcessingPipeline,
    # Mapping rules 
        savedsearches= qradar_windows_events_acceleration_keywords(),
        extensions = qradar_cim_exetension()
    )
    
    def __init__(self, processing_pipeline: Optional["sigma.processing.pipeline.ProcessingPipeline"] = None, collect_errors: bool = False, **kwargs):
        super().__init__(processing_pipeline, collect_errors, **kwargs)


    def finalize_query_savedsearches(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        
        
        if rule.logsource.product == "qflow" or rule.logsource.service == "netflow" or rule.logsource.product == "ipfix" or rule.logsource.category == "flow":
            aql_database = "flows"
        else:
            aql_database = "events"
        if len(rule.fields) != 0:
            qradar_prefix = "SELECT "+ ", ".join(rule.fields)
        else:
            qradar_prefix = "SELECT UTF8(payload) as search_payload"
        qradar_prefix += " from %s where " %(aql_database)
        escaped_query = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        qradar_prefix += escaped_query
        try:
            timeframe = rule.detection.timeframe
        except:
            timeframe = None
        if timeframe != None:
            time_unit = timeframe[-1:]
            duration = timeframe[:-1]
            timeframe_object = {}
            if time_unit == "s":
                timeframe_object['SECONDS'] = int(duration)
            elif time_unit == "m":
                timeframe_object['MINUTES'] = int(duration)
            elif time_unit == "h":
                timeframe_object['HOURS'] = int(duration)
            elif time_unit == "d":
                timeframe_object['DAYS'] = int(duration)
            else:
                timeframe_object['MONTHS'] = int(duration)
            for k,v in timeframe_object.items():
                qradar_prefix += f" LAST {v} {k}"
        return qradar_prefix

    def finalize_output_savedsearches(self, queries: List[str]) -> str:
        return f"\n".join(queries)

    def finalize_query_extensions(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        global ruleID, buildingblock
        qradar_prefix = " \\\n".join(query.split("\n"))      # escape line ends for multiline queries
        # ToDo: Process if qid or logsourceID = None => Using another format of BB ruledata => Done
        qid = []
        for key,id in state.processing_state.items():
            if "qid" in key:
                qid += id 
            
        logsourceID = state.processing_state["QradarLogSources"] if "QradarLogSources" in state.processing_state else []
        if not qid or not logsourceID:
            tr = et.ElementTree(et.fromstring(buildingblock))
            if not len(qid) :
                for element in tr.iter():
                    for subelement in element:
                        id = subelement.get('id')
                        if id is not None and id == "19":
                            element.remove(subelement)

            if not logsourceID:
                for element in tr.iter():
                    for subelement in element:
                        logid = subelement.get('id')
                        if logid is not None and logid == "14":
                            element.remove(subelement)
            buildingblock = et.tostring(tr.getroot()).decode("utf-8")

        # Process Building Block ruledata xml
        BBrule_data= buildingblock.format(name=rule.title, logsourceID=logsourceID, qid=", ".join(str(i) for i in qid),aql=urllib.parse.quote(qradar_prefix))
        BBrule_data = base64.b64encode(BBrule_data.encode('ascii')).decode('ascii')
        # Process Rule data xml
        rule_data = xmlrule.format(ruleID=ruleID, name=rule.title)
        rule_data = base64.b64encode(rule_data.encode('ascii')).decode('ascii')
        qradar_output =  contentRule.format(BBruledata=BBrule_data, name=rule.title, BBruleID=ruleID+1, ruledata=rule_data, ruleID=ruleID, date=date)
        #ruleID for identifier rules mapping group in Qradar
        ruleID += 2
        #write to xml and unzip if need add file manifest.json
        return qradar_output
    def finalize_output_extensions(self, queries: List[str]) -> str:
        xmlFile =  """<?xml version="1.0" encoding="UTF-8"?>
<content>
	<qradarversion>2020.11.0.20210517144015</qradarversion>
	<fgroup_type>
		<name>rule</name>
		<description>rule</description>
		<id>3</id>
		<class_name>com.q1labs.core.shared.group.RuleGroupFactory</class_name>
	</fgroup_type>
	<fgroup>
		<parent_id>3</parent_id>
		<type_id>3</type_id>
		<user_name>admin</user_name>
		<level_id>2</level_id>
		<name>Sigma</name>
		<description></description>
		<id>88888</id>
		<modified_date>{date}</modified_date>
	</fgroup>""".format(date=date)+f"".join(queries)+"</content>"
        xml_output = "sigmaQradar.xml"
        f = open(xml_output, "w")
        f.write(xmlFile)
        f.close()
        zip_file = "SigmaQradarExtensions-"+date+".zip"
        zipObj = ZipFile(zip_file, 'w')
        zipObj.write(xml_output)
        zipObj.close()
        return "Generate Qradar extension output here: "+zip_file
