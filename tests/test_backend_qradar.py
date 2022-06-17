from io import BytesIO
from zipfile import ZipFile
import pytest
from sigma.backends.qradar import QradarBackend
from sigma.collection import SigmaCollection

@pytest.fixture
def qradar_backend():
    return QradarBackend()

def test_qradar_in_expression(qradar_backend : QradarBackend):
    assert qradar_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA:
                        - valueA
                        - valueB
                        - valueC*
                condition: sel
        """),
    ) == ['SELECT UTF8(payload) as search_payload from events where "fieldA" ILIKE ENUMERATION(\'valueA\',\'valueB\',\'valueC%\')']

def test_qradar_regex_query(qradar_backend : QradarBackend):
    assert qradar_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ['SELECT UTF8(payload) as search_payload from events where "fieldA" IMATCHES \'foo.*bar\' AND "fieldB"=\'foo\' AND "fieldC"=\'bar\'']

def test_qradar_single_regex_query(qradar_backend : QradarBackend):
    assert qradar_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|re: foo.*bar
                condition: sel
        """)
    ) == ['SELECT UTF8(payload) as search_payload from events where "fieldA" IMATCHES \'foo.*bar\'']

def test_qradar_cidr_query(qradar_backend : QradarBackend):
    assert qradar_backend.convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: test_category
                product: test_product
            detection:
                sel:
                    fieldA|cidr: 192.168.0.0/16
                    fieldB: foo
                    fieldC: bar
                condition: sel
        """)
    ) == ['SELECT UTF8(payload) as search_payload from events where INCIDR(\'192.168.0.0/16\', "fieldA") AND "fieldB"=\'foo\' AND "fieldC"=\'bar\'']


def test_qradar_default_output(qradar_backend : QradarBackend):
    rules = """
title: Test 1
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    assert qradar_backend.convert(SigmaCollection.from_yaml(rules), ) == [
        """SELECT UTF8(payload) as search_payload from events where "fieldA" IMATCHES 'foo.*bar' AND "fieldB"='foo' AND "fieldC"='bar'""",
        """SELECT UTF8(payload) as search_payload from events where "fieldA"='foo' AND "fieldB"='bar'"""
    ]

def test_qradar_extension_output(qradar_backend : QradarBackend):
    rules = """
title: Test 1
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA|re: foo.*bar
        fieldB: foo
        fieldC: bar
    condition: sel
---
title: Test 2
status: test
logsource:
    category: test_category
    product: test_product
detection:
    sel:
        fieldA: foo
        fieldB: bar
    condition: sel
    """
    result = qradar_backend.convert(SigmaCollection.from_yaml(rules), "extension")
    assert isinstance(result, bytes)

    zip_io = BytesIO(result)
    zip_file = ZipFile(zip_io)
    xml = str(zip_file.read("sigmaQradar.xml"), "utf-8")
    assert xml.startswith('<?xml version="1.0" encoding="UTF-8"?>')