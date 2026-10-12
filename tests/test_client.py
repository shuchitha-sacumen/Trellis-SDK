import vcr
import os

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.models import (
    TrellixAuthenticationModels,
    TrellixAWSCredentialsModels,
    TrellixEPOAssignedPolicyModels,
    TrellixIncidentIdsModels,
    TrellixIncidentModels,
    TrellixPolicyModels,
    TrellixRuleSetModels,
)

my_vcr = vcr.VCR(
    cassette_library_dir="tests/cassettes",
    record_mode="once",
    match_on=["method", "uri", "query"],
    decode_compressed_response=True,
)


@my_vcr.use_cassette("fetch_incident_ids.yml")
def test_fetch_incident_ids():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    result = client.fetch_incident_ids(
        start_time=1790631785000,
        incident_nature=1,
    )

    assert isinstance(result, TrellixIncidentIdsModels)
    assert isinstance(result.incident_ids, list)
    assert not hasattr(result, "end_time")


@my_vcr.use_cassette("fetch_incident_details.yml")
def test_fetch_incident_details():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    incident_id = 1993
    incident_details = client.fetch_incident_details(
        incident_id=incident_id,
        incident_nature=1,
    )

    assert isinstance(incident_id, int)
    assert isinstance(incident_details, TrellixIncidentModels)


@my_vcr.use_cassette("fetch_rulesets.yml")
def test_fetch_rulesets():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    top = 5

    all_rulesets = client.fetch_rulesets(top=top)

    assert isinstance(all_rulesets, list)
    assert all_rulesets
    assert all(isinstance(ruleset, TrellixRuleSetModels) for ruleset in all_rulesets)


@my_vcr.use_cassette("find_policy.yml")
def test_find_policies():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )
    searchText = "UDLPSRVR2013"
    policies = client.find_policies(searchText=searchText)

    assert isinstance(policies, list)
    assert isinstance(policies[0], TrellixPolicyModels)


@my_vcr.use_cassette("fetch_epo_assigned_policies.yml")
def test_fetch_epo_assigned_policies():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    top = 5

    all_policies = client.fetch_epo_assigned_policies(top=top)

    # Verify the result is a list
    assert isinstance(all_policies, list)

    # Verify the returned records are Pydantic models
    assert all(
        isinstance(policy, TrellixEPOAssignedPolicyModels) for policy in all_policies
    )

    # Verify records are sorted by PolicyObjectID
    assert all_policies == sorted(
        all_policies,
        key=lambda policy: policy.policy_object_id,
    )

    # Verify there are no duplicate PolicyObjectIDs
    policy_ids = [policy.policy_object_id for policy in all_policies]

    assert len(policy_ids) == len(set(policy_ids))


@my_vcr.use_cassette("fetch_evidence.yml")
def test_fetch_evidence():
    authentication = TrellixAuthenticationModels(
        server_url="https://10.10.10:8443",
        username="test_user",
        password="DummyPass@2026",
    )

    client = TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )

    file_location = (
        r"\\EPO-SERVER\DLP-Evidence\B7\AF"
        r"\{46B7AF60-35E1-4966-FFBD-824E59ACB706}.jpg.dlpenc"
    )

    evidence = client.fetch_evidence(
        file_location=file_location,
    )

    # Evidence should be returned as raw bytes
    assert isinstance(evidence, bytes)

    # Evidence should not be empty
    assert evidence
