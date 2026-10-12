import json
from unittest.mock import Mock, patch

import pytest
import requests
from tenacity import stop_after_attempt

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import (
    TrellixAuthenticationModels,
    TrellixRuleSetModels,
)


@pytest.fixture
def client():
    authentication = TrellixAuthenticationModels(
        server_url="https://example.com",
        username="xxx",
        password="xxx",
    )
    return TrellixDataProtection(
        authentication=authentication,
        verify_ssl=False,
    )


def make_ruleset_response():
    return [
        {
            "UDLP_RuleSets.RuleSetID": "61B55D9D-3684-4BED-B24D-268371EB1EBA",
            "UDLP_RuleSets.CatalogID": "D3AB4ED4-EFAB-48D2-840D-714CBF76B801",
            "UDLP_RuleSets.Name": "Test Rule Set",
            "UDLP_RuleSets.Description": "Test description",
            "UDLP_RuleSets.Enabled": 1,
            "UDLP_RuleSets.Owner": 1,
            "UDLP_RuleSets.LastModifier": 1,
            "UDLP_RuleSets.ModificationTime": "2026-09-22T23:58:00-07:00",
        }
    ]


def make_response(text, status_code=200):
    response = Mock()
    response.status_code = status_code
    response.text = text

    if status_code >= 400:
        response.raise_for_status.side_effect = requests.exceptions.HTTPError(
            f"{status_code} HTTP Error"
        )
    else:
        response.raise_for_status.return_value = None

    return response


def test_fetch_rulesets_success(client):
    first_page = make_response(
        "OK: " + json.dumps(make_ruleset_response())
    )
    empty_page = make_response("OK: []")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[first_page, empty_page],
    ) as mock_get:
        result = client.fetch_rulesets()

    assert len(result) == 1
    assert isinstance(result[0], TrellixRuleSetModels)
    assert result[0].rule_set_id == "61B55D9D-3684-4BED-B24D-268371EB1EBA"
    assert result[0].catalog_id == "D3AB4ED4-EFAB-48D2-840D-714CBF76B801"
    assert result[0].name == "Test Rule Set"
    assert result[0].enabled == 1

    # One request retrieves the rule set; the next confirms there are no more.
    assert mock_get.call_count == 2


def test_fetch_rulesets_empty_response(client):
    response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_rulesets()

    assert result == []
    mock_get.assert_called_once()


def test_fetch_rulesets_request_parameters(client):
    response = make_response("OK: []")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_rulesets()

    kwargs = mock_get.call_args.kwargs
    params = kwargs["params"]

    assert kwargs["url"] == "https://example.com/remote/core.executeQuery"
    assert params[":output"] == "json"
    assert params["target"] == "UDLP_RuleSets"
    assert "(select (top 100)" in params["select"]
    assert params["order"] == "(order (asc UDLP_RuleSets.RuleSetID))"
    assert "where" not in params
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False


def test_fetch_rulesets_with_last_ruleset_id(client):
    response = make_response("OK: []")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_rulesets(
            top=10,
            last_ruleset_id="100",
        )

    params = mock_get.call_args.kwargs["params"]

    assert "(select (top 10)" in params["select"]
    assert params["where"] == '(gt UDLP_RuleSets.RuleSetID "100")'


def test_fetch_rulesets_epo_error_response(client):
    response = make_response(
        "ERROR: Insufficient permissions to execute query"
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="ePO Remote Command returned an error",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


def test_fetch_rulesets_invalid_json(client):
    response = make_response("OK: {invalid-json}")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Failed to parse response",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


def test_fetch_rulesets_repeated_cursor(client):
    # The same RuleSetID is returned on both pages.
    # The SDK should stop instead of looping indefinitely.
    repeated_page = make_response(
        "OK: " + json.dumps(make_ruleset_response())
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=repeated_page,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Pagination did not advance: repeated RuleSetID cursor",
        ):
            client.fetch_rulesets()

    assert mock_get.call_count == 2


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
    ],
)
def test_fetch_rulesets_non_retryable_http_errors(
    client,
    status_code,
    error_text,
):
    response = make_response(error_text, status_code=status_code)

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match=f"{status_code}--{error_text}",
        ):
            client.fetch_rulesets()

    mock_get.assert_called_once()


def test_fetch_rulesets_retries_then_succeeds(client, monkeypatch):
    # Limit retries in this test instead of waiting for the SDK's 60-second
    # retry window.
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "stop",
        stop_after_attempt(3),
    )
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "sleep",
        lambda _: None,
    )

    rate_limited = make_response(
        "Too Many Requests",
        status_code=429,
    )
    first_page = make_response(
        "OK: " + json.dumps(make_ruleset_response())
    )
    empty_page = make_response("OK: []")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[rate_limited, first_page, empty_page],
    ) as mock_get:
        result = client.fetch_rulesets()

    assert len(result) == 1
    assert result[0].rule_set_id == "61B55D9D-3684-4BED-B24D-268371EB1EBA"

    # First call: 429; second: retrieve the rule set; third: empty page.
    assert mock_get.call_count == 3


def test_fetch_rulesets_retries_500_three_times(client, monkeypatch):
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "stop",
        stop_after_attempt(3),
    )
    monkeypatch.setattr(
        client.fetch_rulesets.retry,
        "sleep",
        lambda _: None,
    )

    response = make_response(
        "Internal Server Error",
        status_code=500,
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RetryableError,
            match="500--Internal Server Error",
        ):
            client.fetch_rulesets()

    assert mock_get.call_count == 3