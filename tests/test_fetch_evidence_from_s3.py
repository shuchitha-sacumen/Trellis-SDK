from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import BotoCoreError, ClientError
from tenacity import stop_after_attempt

from trellix_dlp.client import TrellixDataProtection
from trellix_dlp.exceptions import RetryableError
from trellix_dlp.models import (
    TrellixAuthenticationModels,
    TrellixAWSCredentialsModels,
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


@pytest.fixture
def aws_credentials():
    return TrellixAWSCredentialsModels(
        aws_access_key="xxx",
        aws_secret_key="xxx",
        aws_region="us-east-1",
        bucket_name="test-bucket",
    )


def make_client_error(code):
    return ClientError(
        {
            "Error": {
                "Code": code,
                "Message": "Simulated S3 error",
            }
        },
        "GetObject",
    )


def make_s3_response(content=b"raw evidence"):
    body = Mock()
    body.read.return_value = content
    return {"Body": body}


@pytest.fixture
def three_attempts(client, monkeypatch):
    """Keep retry tests fast and deterministic."""
    monkeypatch.setattr(
        client.fetch_evidence_from_s3.retry,
        "stop",
        stop_after_attempt(3),
    )
    monkeypatch.setattr(
        client.fetch_evidence_from_s3.retry,
        "sleep",
        lambda _: None,
    )


# 1. AWS credentials are required
def test_fetch_missing_aws_credentials(client):
    with pytest.raises(
        RuntimeError,
        match="AWS credentials are required for S3 operations",
    ):
        client.fetch_evidence_from_s3(
            "incident-123",
            "evidence.jpg",
            aws_credentials=None,
        )


# 2. Invalid incident IDs
@pytest.mark.parametrize(
    "incident_id",
    [None, 123, True, [], {}, b"incident-123"],
)
def test_fetch_invalid_incident_id(client, aws_credentials, incident_id):
    with pytest.raises(ValueError, match="incident_id must be a string"):
        client.fetch_evidence_from_s3(incident_id, "evidence.jpg", aws_credentials)


# 3. Empty or whitespace-only incident IDs
@pytest.mark.parametrize("incident_id", ["", " ", "   ", "\t", "\n"])
def test_fetch_empty_incident_id(client, aws_credentials, incident_id):
    with pytest.raises(ValueError, match="incident_id must not be empty"):
        client.fetch_evidence_from_s3(incident_id, "evidence.jpg", aws_credentials)


# 4. Invalid file names
@pytest.mark.parametrize(
    "file_name",
    [None, 123, True, [], {}, b"evidence.jpg"],
)
def test_fetch_invalid_file_name(client, aws_credentials, file_name):
    with pytest.raises(ValueError, match="file_name must be a string"):
        client.fetch_evidence_from_s3("incident-123", file_name, aws_credentials)


# 5. Empty or whitespace-only file names
@pytest.mark.parametrize("file_name", ["", " ", "   ", "\t", "\n"])
def test_fetch_empty_file_name(client, aws_credentials, file_name):
    with pytest.raises(ValueError, match="file_name must not be empty"):
        client.fetch_evidence_from_s3("incident-123", file_name, aws_credentials)


# 6. Successful fetch returns the original bytes
@patch("trellix_dlp.client.boto3.client")
def test_fetch_success(mock_boto_client, client, aws_credentials):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.return_value = make_s3_response(b"\x00\x01raw evidence")

    result = client.fetch_evidence_from_s3(
        "incident-123", "evidence.jpg", aws_credentials
    )

    assert result == b"\x00\x01raw evidence"
    assert isinstance(result, bytes)

    mock_boto_client.assert_called_once_with(
        "s3",
        aws_access_key_id="xxx",
        aws_secret_access_key="xxx",
        region_name="us-east-1",
    )
    mock_s3.get_object.assert_called_once_with(
        Bucket="test-bucket",
        Key="trellix-dlp/incidents/incident-123/evidence.jpg",
    )


# 7. Empty evidence file is valid raw content
@patch("trellix_dlp.client.boto3.client")
def test_fetch_empty_evidence_file(mock_boto_client, client, aws_credentials):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.return_value = make_s3_response(b"")

    result = client.fetch_evidence_from_s3("incident-123", "empty.jpg", aws_credentials)

    assert result == b""
    assert isinstance(result, bytes)


# 8. Non-retryable S3 errors
@pytest.mark.parametrize(
    "error_code",
    [
        "AccessDenied",
        "NoSuchBucket",
        "NoSuchKey",
        "InvalidAccessKeyId",
        "SignatureDoesNotMatch",
        "InvalidBucketName",
    ],
)
@patch("trellix_dlp.client.boto3.client")
def test_fetch_non_retryable_s3_error(
    mock_boto_client, client, aws_credentials, error_code
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = make_client_error(error_code)

    with pytest.raises(RuntimeError, match="AWS S3 fetch failed"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)

    assert mock_s3.get_object.call_count == 1


# 9. Retryable S3 errors retry up to three attempts
@pytest.mark.parametrize(
    "error_code",
    [
        "429",
        "500",
        "502",
        "503",
        "504",
        "RequestTimeout",
        "SlowDown",
    ],
)
@patch("trellix_dlp.client.boto3.client")
def test_fetch_retryable_s3_errors(
    mock_boto_client,
    client,
    aws_credentials,
    error_code,
    three_attempts,
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = make_client_error(error_code)

    with pytest.raises(RetryableError, match=error_code):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)

    assert mock_s3.get_object.call_count == 3


# 10. BotoCoreError is retried
@patch("trellix_dlp.client.boto3.client")
def test_fetch_botocore_error(
    mock_boto_client, client, aws_credentials, three_attempts
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.side_effect = BotoCoreError()

    with pytest.raises(RetryableError, match="AWS S3 error"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)

    assert mock_s3.get_object.call_count == 3


# 11. Unexpected errors during S3 client creation
@patch("trellix_dlp.client.boto3.client")
def test_fetch_unexpected_client_creation_error(
    mock_boto_client, client, aws_credentials
):
    mock_boto_client.side_effect = ValueError("Unexpected failure")

    with pytest.raises(RuntimeError, match="Error while fetching evidence from S3"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)

    mock_boto_client.assert_called_once()


# 12. Missing Body in S3 response
@patch("trellix_dlp.client.boto3.client")
def test_fetch_response_missing_body(mock_boto_client, client, aws_credentials):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.return_value = {}

    with pytest.raises(RuntimeError, match="Error while fetching evidence from S3"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)


# 13. Error while reading the evidence body
@patch("trellix_dlp.client.boto3.client")
def test_fetch_body_read_error(mock_boto_client, client, aws_credentials):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3

    body = Mock()
    body.read.side_effect = OSError("Unable to read evidence")
    mock_s3.get_object.return_value = {"Body": body}

    with pytest.raises(RuntimeError, match="Error while fetching evidence from S3"):
        client.fetch_evidence_from_s3("incident-123", "evidence.jpg", aws_credentials)


# 14. AWS credentials are passed to boto3 and bucket lookup
@patch("trellix_dlp.client.boto3.client")
def test_fetch_uses_supplied_aws_configuration(
    mock_boto_client, client, aws_credentials
):
    mock_s3 = Mock()
    mock_boto_client.return_value = mock_s3
    mock_s3.get_object.return_value = make_s3_response(b"evidence")

    client.fetch_evidence_from_s3("incident-456", "report.pdf", aws_credentials)

    mock_boto_client.assert_called_once_with(
        "s3",
        aws_access_key_id=aws_credentials.aws_access_key,
        aws_secret_access_key=aws_credentials.aws_secret_key,
        region_name=aws_credentials.aws_region,
    )
    mock_s3.get_object.assert_called_once_with(
        Bucket=aws_credentials.bucket_name,
        Key="trellix-dlp/incidents/incident-456/report.pdf",
    )
