import json
from unittest.mock import Mock, patch

import pytest
import requests

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import TrellixAuthenticationModels


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


def make_assigned_policy_response(
    policy_object_id=123,
    node_name="Test-System",
):
    return [
        {
            "EPOAssignedPolicy.NodeName": node_name,
            "EPOAssignedPolicy.UserName": "test_user",
            "EPOAssignedPolicy.PolicyObjectID": policy_object_id,
            "EPOAssignedPolicy.PolicyDesc": "Test assigned policy",
            "EPOAssignedPolicy.FeatureTextID": "DLP",
            "EPOAssignedPolicy.upToDate": True,
            "EPOAssignedPolicy.ServerID": "server_1",
            "EPOAssignedPolicy.EditFlags": 0,
            "EPOAssignedPolicy.Origin": "ePO",
        }
    ]


def make_response(text, status_code=200, error=None):
    response = Mock()
    response.text = text
    response.status_code = status_code
    response.raise_for_status.side_effect = error
    if error is None:
        response.raise_for_status.return_value = None
    return response


@pytest.mark.parametrize("top", [0, -1, 1.5, "5", None, True])
def test_fetch_epo_assigned_policies_invalid_top(client, top):
    with pytest.raises(ValueError):
        client.fetch_epo_assigned_policies(top=top)


@pytest.mark.parametrize(
    "last_policy_object_id",
    [-1, 1.5, "123", True],
)
def test_fetch_epo_assigned_policies_invalid_cursor(
    client, last_policy_object_id
):
    with pytest.raises(ValueError):
        client.fetch_epo_assigned_policies(
            last_policy_object_id=last_policy_object_id
        )


def test_fetch_epo_assigned_policies_success(client):
    policy_response = make_response(
        "OK: " + json.dumps(make_assigned_policy_response())
    )
    empty_response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[policy_response, empty_response],
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert len(result) == 1
    assert result[0].node_name == "Test-System"
    assert result[0].policy_object_id == 123
    assert result[0].policy_desc == "Test assigned policy"
    assert result[0].feature_text_id == "DLP"
    assert result[0].up_to_date is True
    assert result[0].user_name == "test_user"
    assert result[0].server_id == "server_1"
    assert result[0].edit_flags == 0
    assert result[0].origin == "ePO"
    assert mock_get.call_count == 2


def test_fetch_epo_assigned_policies_empty_response(client):
    response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert result == []
    mock_get.assert_called_once()


def test_fetch_epo_assigned_policies_pagination(client):
    first_page = make_response(
        "OK: "
        + json.dumps(
            make_assigned_policy_response(
                policy_object_id=123,
                node_name="System-1",
            )
        )
    )
    second_page = make_response(
        "OK: "
        + json.dumps(
            make_assigned_policy_response(
                policy_object_id=456,
                node_name="System-2",
            )
        )
    )
    empty_page = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[first_page, second_page, empty_page],
    ) as mock_get:
        result = client.fetch_epo_assigned_policies(top=10)

    assert len(result) == 2
    assert [policy.policy_object_id for policy in result] == [123, 456]
    assert [policy.node_name for policy in result] == [
        "System-1",
        "System-2",
    ]

    assert mock_get.call_count == 3

    first_params = mock_get.call_args_list[0].kwargs["params"]
    second_params = mock_get.call_args_list[1].kwargs["params"]
    third_params = mock_get.call_args_list[2].kwargs["params"]

    assert "(select (top 10)" in first_params["select"]
    assert "where" not in first_params

    assert second_params["where"] == (
        "(gt EPOAssignedPolicy.PolicyObjectID 123)"
    )
    assert third_params["where"] == (
        "(gt EPOAssignedPolicy.PolicyObjectID 456)"
    )


def test_fetch_epo_assigned_policies_request_parameters(client):
    response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        client.fetch_epo_assigned_policies(
            top=10,
            last_policy_object_id=123,
        )

    kwargs = mock_get.call_args.kwargs
    params = kwargs["params"]

    assert kwargs["url"] == (
        "https://example.com/remote/core.executeQuery"
    )
    assert params[":output"] == "json"
    assert params["target"] == "EPOAssignedPolicy"
    assert "(select (top 10)" in params["select"]
    assert params["order"] == (
        "(order (asc EPOAssignedPolicy.PolicyObjectID))"
    )
    assert params["where"] == (
        "(gt EPOAssignedPolicy.PolicyObjectID 123)"
    )
    assert kwargs["timeout"] == 10
    assert kwargs["verify"] is False

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("response_text", "expected_error"),
    [
        (
            "ERROR: Insufficient permissions",
            "ePO Remote Command returned an error",
        ),
        (
            "OK: {invalid-json}",
            "Failed to parse response",
        ),
        (
            "OK: [{}]",
            "Failed to parse response",
        ),
    ],
    ids=["epo-error", "invalid-json", "missing-fields"],
)
def test_fetch_epo_assigned_policies_invalid_response(
    client, response_text, expected_error
):
    response = make_response(response_text)

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(RuntimeError, match=expected_error):
            client.fetch_epo_assigned_policies()

    mock_get.assert_called_once()


def test_fetch_epo_assigned_policies_repeated_cursor(client):
    first_page = make_response(
        "OK: " + json.dumps(make_assigned_policy_response(123))
    )
    repeated_page = make_response(
        "OK: " + json.dumps(make_assigned_policy_response(123))
    )

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[first_page, repeated_page],
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Pagination did not advance",
        ):
            client.fetch_epo_assigned_policies()

    assert mock_get.call_count == 2


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (400, "Bad Request"),
        (401, "Unauthorized"),
        (403, "Forbidden"),
    ],
)
def test_fetch_epo_assigned_policies_non_retryable_http(
    client, status_code, error_text
):
    response = make_response(
        error_text,
        status_code=status_code,
        error=requests.exceptions.HTTPError(
            f"{status_code} HTTP Error"
        ),
    )

    with patch(
        "trellix_dlp.client.requests.get",
        return_value=response,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match=f"{status_code}--{error_text}",
        ):
            client.fetch_epo_assigned_policies()

    mock_get.assert_called_once()


@pytest.mark.parametrize(
    ("status_code", "error_text"),
    [
        (429, "Too Many Requests"),
        (500, "Internal Server Error"),
    ],
)
def test_fetch_epo_assigned_policies_retries_then_succeeds(
    client, monkeypatch, status_code, error_text
):
    monkeypatch.setattr(
        client.fetch_epo_assigned_policies.retry,
        "sleep",
        lambda _: None,
    )

    failed_response = make_response(
        error_text,
        status_code=status_code,
        error=requests.exceptions.HTTPError(
            f"{status_code} HTTP Error"
        ),
    )
    success_response = make_response(
        "OK: " + json.dumps(make_assigned_policy_response())
    )
    empty_response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[
            failed_response,
            success_response,
            empty_response,
        ],
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert len(result) == 1
    assert result[0].policy_object_id == 123
    assert mock_get.call_count == 3


def test_fetch_epo_assigned_policies_timeout(client):
    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=requests.exceptions.Timeout,
    ) as mock_get:
        with pytest.raises(
            RuntimeError,
            match="Request timed out",
        ):
            client.fetch_epo_assigned_policies()

    mock_get.assert_called_once()


def test_fetch_epo_assigned_policies_connection_error_then_succeeds(
    client, monkeypatch
):
    monkeypatch.setattr(
        client.fetch_epo_assigned_policies.retry,
        "sleep",
        lambda _: None,
    )

    success_response = make_response(
        "OK: " + json.dumps(make_assigned_policy_response())
    )
    empty_response = make_response("OK:")

    with patch(
        "trellix_dlp.client.requests.get",
        side_effect=[
            requests.exceptions.ConnectionError("Connection failed"),
            success_response,
            empty_response,
        ],
    ) as mock_get:
        result = client.fetch_epo_assigned_policies()

    assert len(result) == 1
    assert result[0].policy_object_id == 123
    assert mock_get.call_count == 3