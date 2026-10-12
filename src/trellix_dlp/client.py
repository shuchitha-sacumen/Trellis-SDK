"""
This module implements the Trellix DLP On-Prem (ePO) API client for
incident, policy, and evidence retrieval.
"""

import json
from typing import List
from urllib.parse import quote

import boto3
import requests
from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError
from requests.auth import HTTPBasicAuth
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_delay,
    wait_exponential,
)

from .exceptions import RetryableError
from .models import (
    TrellixAuthenticationModels,
    TrellixAWSCredentialsModels,
    TrellixEPOAssignedPolicyModels,
    TrellixIncidentIdsModels,
    TrellixIncidentModels,
    TrellixPolicyModels,
    TrellixRuleSetModels,
)


class TrellixDataProtection:
    """
    Trellix DLP (ePO On-Prem) Data Protection API client.

    :param authentication: Trellix ePO server URL and Basic Auth credentials.
    :param verify_ssl: Whether to verify the ePO server's TLS certificate.
        Defaults to False for sandbox/self-signed environments.
    """

    def __init__(
        self,
        authentication: TrellixAuthenticationModels,
        verify_ssl: bool = False,
    ):
        self.authentication = authentication
        self.verify_ssl = verify_ssl

    @staticmethod
    def _validate_incident_nature(incident_nature: int | None) -> None:
        """Validate the incident nature value."""

        if incident_nature is None:
            raise ValueError("incident nature must not be null")

        if type(incident_nature) is not int:
            raise ValueError("incident_nature must be an integer")

        if incident_nature not in (1, 2, 3):
            raise ValueError(
                "incident_nature must be 1 (data-in-use/motion), "
                "2 (reserved - Endpoint Discovery), "
                "or 3 (data-at-rest - Network)"
            )

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_incident_ids(
        self,
        incident_nature: int = None,
        start_time: int = None,
    ) -> TrellixIncidentIdsModels:
        """
        Fetch all Trellix DLP incident IDs, handling pagination internally.

        Args:
            start_time:
                epoch timestamp in milliseconds from which
                incidents should be fetched.

            incident_nature:
                Incident data vector:
                    1 = data-in-use/motion
                    2 = reserved - Endpoint Discovery
                    3 = data-at-rest - Network

        Returns:
            TrellixIncidentIdsModels:
                A model containing the combined incident IDs from all pages.

        Raises:
            ValueError:
                If start_time or incident_nature has an invalid type/value.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On retryable HTTP or connection errors.
        """

        # Validate start_time
        if start_time is None:
            raise ValueError("Start time is required.")

        if type(start_time) is not int:
            raise ValueError("start_time must be an integer epoch milliseconds value")

        if start_time < 0:
            raise ValueError("start_time must be greater than or equal to zero")

        # Validate incident_nature
        self._validate_incident_nature(incident_nature)

        url = f"{self.authentication.server_url.rstrip('/')}" "/rest/dlp/incidents/ids"

        # Build query parameters
        params = {"startTime": start_time, "incidentNature": incident_nature}
        # Collect incident IDs from every page
        all_incident_ids = []

        try:
            while True:
                print("Request params:", params)
                response = requests.get(
                    url=url,
                    params=params,
                    auth=HTTPBasicAuth(
                        self.authentication.username,
                        self.authentication.password,
                    ),
                    timeout=10,
                    verify=self.verify_ssl,
                )
                print("Request params:", params)
                print("Request URL:", response.url)
                print("HTTP status:", response.status_code)
                print("Response body:", response.text)
                response.raise_for_status()

                # Parse JSON response
                data = response.json()

                page = TrellixIncidentIdsModels(
                    incident_ids=data.get("incidentIds", [])
                )
                all_incident_ids.extend(page.incident_ids)

                # Stop when Trellix indicates there are no more pages
                end_time = data.get("endTime")

                if end_time is None:
                    break
                # The API may return either JSON null or the string "null".
                if end_time is None or str(end_time).strip().lower() == "null":
                    break
                # Prevent an infinite loop if the API repeats a cursor
                next_start_time = str(end_time)

                # Use this page's endTime as the next page's startTime
                params["startTime"] = next_start_time

            # Return one combined model without exposing endTime
            return TrellixIncidentIdsModels(incident_ids=all_incident_ids)

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch incident IDs."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_incident_details(
        self,
        incident_id: int = None,
        incident_nature: int = None,
    ) -> TrellixIncidentModels:
        """
        Fetch detailed information for a specific Trellix DLP incident.

        Args:
            incident_id:
                Numeric ID of the DLP incident.

            incident_nature:
                Mandatory data vector of the incident.

                1 = Data-in-use / Data-in-motion
                2 = Data-at-rest / Endpoint
                3 = Data-at-rest / Network

                If omitted, the request is sent without the
                incidentNature parameter so that Trellix returns
                its native API validation error.

        Returns:
            TrellixIncidentModels:
                Parsed details of the requested incident.

        Raises:
            ValueError:
                If incident_id or incident_nature has an invalid value.

            RuntimeError:
                On non-retryable HTTP errors, timeout, response parsing,
                or other request errors.

            RetryableError:
                On HTTP 429, HTTP 5xx, or connection errors.
        """

        # Validate incident_id

        if incident_id is None:
            raise ValueError("incident_id must not be null")

        if type(incident_id) is not int:
            raise ValueError("incident_id must be an integer")

        if incident_id < 0:
            raise ValueError("incident_id must be greater than or equal to zero")

        # Validate incident_nature using the reusable method

        self._validate_incident_nature(incident_nature)

        # Build URL
        url = (
            f"{self.authentication.server_url.rstrip('/')}"
            f"/rest/dlp/incidents/{incident_id}"
        )

        # Build query parameters

        # If incident_nature is None, don't add the parameter.
        # This allows Trellix to return its native 400 response.
        params = {}

        params["incidentNature"] = incident_nature

        try:
            # Make API request
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            # Raise HTTPError for 4xx/5xx
            response.raise_for_status()

            # Parse JSON response
            incident_response = response.json()

            # Convert API response into Pydantic model
            return TrellixIncidentModels(**incident_response)

        # HTTP errors
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc
        # Timeout
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to get incident details."
            ) from exc

        # Connection error
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        # Pydantic / JSON parsing errors
        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        # Other requests errors
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_rulesets(
        self,
        top: int = 100,
        last_ruleset_id: str | None = None,
    ) -> List[TrellixRuleSetModels]:
        """
        Fetch all DLP rule sets from the Trellix ePO server,
        handling pagination internally.

        Args:
            top: Maximum number of rule sets to fetch per batch. Default is 100
            last_ruleset_id: Optional RuleSetID to start fetching after.

        Returns:
            A single list containing the fetched rule sets.

        Raises:
            RuntimeError: On HTTP, parsing, timeout, or request errors.
            RetryableError: On 5xx, 429, or connection errors.
        """

        url = (
            f"{self.authentication.server_url.rstrip('/')}" "/remote/core.executeQuery"
        )

        all_rulesets = []
        current_ruleset_id = last_ruleset_id

        try:
            while True:
                select = (
                    f"(select (top {top}) "
                    "UDLP_RuleSets.RuleSetID "
                    "UDLP_RuleSets.CatalogID "
                    "UDLP_RuleSets.Name "
                    "UDLP_RuleSets.Description "
                    "UDLP_RuleSets.Enabled "
                    "UDLP_RuleSets.Owner "
                    "UDLP_RuleSets.LastModifier "
                    "UDLP_RuleSets.ModificationTime)"
                )

                params = {
                    ":output": "json",
                    "target": "UDLP_RuleSets",
                    "select": select,
                    "order": "(order (asc UDLP_RuleSets.RuleSetID))",
                }

                if current_ruleset_id is not None:
                    params["where"] = (
                        f'(gt UDLP_RuleSets.RuleSetID "{current_ruleset_id}")'
                    )

                response = requests.get(
                    url=url,
                    params=params,
                    auth=HTTPBasicAuth(
                        self.authentication.username,
                        self.authentication.password,
                    ),
                    timeout=10,
                    verify=self.verify_ssl,
                )

                response.raise_for_status()
                text = response.text.strip()

                if text.startswith("ERROR:"):
                    raise RuntimeError(f"ePO Remote Command returned an error: {text}")

                elif text.startswith("OK:"):
                    payload = text[len("OK:") :].strip()
                else:
                    payload = text

                data = json.loads(payload) if payload else []

                # Stop when no more rule sets are returned
                if not data:
                    break

                page = [TrellixRuleSetModels(**item) for item in data]
                all_rulesets.extend(page)

                # Update the cursor using the last rule set in this batch
                next_ruleset_id = str(data[-1]["UDLP_RuleSets.RuleSetID"])

                # Prevent an infinite loop if the cursor does not advance
                if next_ruleset_id == current_ruleset_id:
                    raise RuntimeError(
                        "Pagination did not advance: repeated RuleSetID cursor"
                    )

                current_ruleset_id = next_ruleset_id

            return all_rulesets

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch rule sets."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError(
                "ConnectionError: Unable to connect to Trellix ePO."
            ) from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def find_policies(
        self,
        searchText: str = "",
    ) -> List[TrellixPolicyModels]:
        """
        Fetch DLP policies from the Trellix ePO server.

        Args:
            searchText:
                Optional search text to filter policies by name or description.
        Returns:
            List[TrellixPolicyModels]: Parsed DLP policies.

        Raises:
            RuntimeError: On HTTP, parsing, timeout, or request errors.
            RetryableError: On 5xx, 429, or connection errors.
        """

        url = f"{self.authentication.server_url.rstrip('/')}" "/remote/policy.find"

        params = {
            ":output": "json",
            "searchText": searchText,
        }

        try:
            response = requests.get(
                url=url,
                params=params,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            response.raise_for_status()
            text = response.text.strip()

            if text.startswith("ERROR:"):
                raise RuntimeError(f"ePO Remote Command returned an error: {text}")

            elif text.startswith("OK:"):
                payload = text[len("OK:") :].strip()
            else:
                payload = text

            data = json.loads(payload) if payload else []

            return [TrellixPolicyModels(**item) for item in data]

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch DLP policies."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_epo_assigned_policies(
        self,
        top: int = 100,
        last_policy_object_id: int | None = None,
    ) -> List[TrellixEPOAssignedPolicyModels]:
        """
        Fetch all EPO assigned policies from the Trellix ePO server,
        handling pagination internally.

        Args:
            top:
                Maximum number of records to fetch per batch. Default is 100.

            last_policy_object_id:
                Optional PolicyObjectID to start fetching after.

        Returns:
            A single list containing all fetched EPO assigned policies.

        Raises:
            ValueError:
                If top or last_policy_object_id has an invalid type/value.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On HTTP 5xx, HTTP 429, or connection errors.
        """

        # Validate top
        if not isinstance(top, int) or isinstance(top, bool):
            raise ValueError("top must be an integer")

        if top <= 0:
            raise ValueError("top must be greater than zero")

        # Validate last_policy_object_id
        if last_policy_object_id is not None:
            if not isinstance(last_policy_object_id, int) or isinstance(
                last_policy_object_id, bool
            ):
                raise ValueError("last_policy_object_id must be an integer")

            if last_policy_object_id < 0:
                raise ValueError(
                    "last_policy_object_id must be greater than or equal to zero"
                )

        url = (
            f"{self.authentication.server_url.rstrip('/')}" "/remote/core.executeQuery"
        )

        all_policies = []
        current_policy_object_id = last_policy_object_id

        try:
            while True:
                select = (
                    f"(select (top {top}) "
                    "EPOAssignedPolicy.NodeName "
                    "EPOAssignedPolicy.UserName "
                    "EPOAssignedPolicy.PolicyObjectID "
                    "EPOAssignedPolicy.PolicyDesc "
                    "EPOAssignedPolicy.FeatureTextID "
                    "EPOAssignedPolicy.upToDate "
                    "EPOAssignedPolicy.ServerID "
                    "EPOAssignedPolicy.EditFlags "
                    "EPOAssignedPolicy.Origin)"
                )

                params = {
                    ":output": "json",
                    "target": "EPOAssignedPolicy",
                    "order": ("(order (asc EPOAssignedPolicy.PolicyObjectID))"),
                    "select": select,
                }

                if current_policy_object_id is not None:
                    params["where"] = (
                        "(gt EPOAssignedPolicy.PolicyObjectID "
                        f"{current_policy_object_id})"
                    )

                response = requests.get(
                    url=url,
                    params=params,
                    auth=HTTPBasicAuth(
                        self.authentication.username,
                        self.authentication.password,
                    ),
                    timeout=10,
                    verify=self.verify_ssl,
                )

                response.raise_for_status()

                text = response.text.strip()

                if text.startswith("ERROR:"):
                    raise RuntimeError(f"ePO Remote Command returned an error: {text}")

                if text.startswith("OK:"):
                    payload = text[len("OK:") :].strip()
                else:
                    payload = text

                data = json.loads(payload) if payload else []

                # Stop when no more records are returned
                if not data:
                    break

                # Validate response items using the model aliases
                page = [
                    TrellixEPOAssignedPolicyModels.model_validate(item) for item in data
                ]

                all_policies.extend(page)

                # Update the cursor using the last record in this batch
                next_policy_object_id = data[-1]["EPOAssignedPolicy.PolicyObjectID"]

                if next_policy_object_id == current_policy_object_id:
                    raise RuntimeError(
                        "Pagination did not advance: repeated PolicyObjectID cursor"
                    )

                current_policy_object_id = next_policy_object_id

            return all_policies

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch EPO assigned policies."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError("ConnectionError: Unable to connect") from exc

        except (KeyError, ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_evidence(
        self,
        file_location: str,
    ) -> bytes:
        """
        Fetch raw DLP evidence from the Trellix ePO server.

        Args:
            file_location:
                Network share path of the evidence file returned by
                the DLP incident details.

        Returns:
            bytes:
                Decrypted raw evidence content returned by the
                Trellix DLP REST API.

        Raises:
            ValueError:
                If file_location has an invalid type or is empty.

            RuntimeError:
                On non-retryable HTTP, timeout, parsing, or request errors.

            RetryableError:
                On HTTP 5xx, HTTP 429, or connection errors.
        """

        # Validate file_location
        if not isinstance(file_location, str):
            raise ValueError("file_location must be a string")

        if not file_location.strip():
            raise ValueError("file_location must not be empty")

        # URL-encode the network share path
        encoded_file_location = quote(
            file_location,
            safe="",
        )

        # Build URL
        url = (
            f"{self.authentication.server_url.rstrip('/')}"
            "/rest/dlp/event/evidence/get"
            f"?fileLocation={encoded_file_location}"
        )

        try:
            # Make API request
            response = requests.post(
                url=url,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=30,
                verify=self.verify_ssl,
            )

            # Raise HTTPError for 4xx/5xx responses
            response.raise_for_status()

            # Return decrypted evidence as bytes
            return response.content

        # HTTP errors
        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code}--{response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code}--{response.text}") from exc

        # Timeout
        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to fetch DLP evidence."
            ) from exc
        # Connection error
        except requests.exceptions.ConnectionError as exc:
            raise RetryableError(
                "ConnectionError: Unable to connect to Trellix ePO"
            ) from exc

        # Other requests errors
        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during request: {exc}") from exc

        # Unexpected errors
        except Exception as err:
            raise err

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def upload_evidence_to_s3(
        self,
        incident_id: str,
        file_name: str,
        evidence: bytes,
        aws_credentials: TrellixAWSCredentialsModels,
    ) -> str:
        """
        Upload raw DLP evidence to the configured AWS S3 bucket.

        Args:
            incident_id:
                ID of the DLP incident associated with the evidence.

            file_name:
                Name of the evidence file.

            evidence:
                Raw evidence content as bytes.

        Returns:
            str:
                S3 object key of the uploaded evidence.

        Raises:
            ValueError:
                If input values are invalid.

            RuntimeError:
                If AWS credentials are not configured or the upload fails.

            RetryableError:
                If a retryable AWS error occurs.
        """

        # Validate AWS configuration
        if aws_credentials is None:
            raise RuntimeError("AWS credentials are required for S3 operations.")

        # Validate incident_id
        if not isinstance(incident_id, str):
            raise ValueError("incident_id must be a string")

        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        # Validate file_name
        if not isinstance(file_name, str):
            raise ValueError("file_name must be a string")

        if not file_name.strip():
            raise ValueError("file_name must not be empty")

        # Validate evidence
        if not isinstance(evidence, bytes):
            raise ValueError("evidence must be bytes")

        if not evidence:
            raise ValueError("evidence must not be empty")

        # Build S3 object key
        object_key = f"trellix-dlp/incidents/" f"{incident_id}/{file_name}"

        try:
            # Create S3 client
            s3 = boto3.client(
                "s3",
                aws_access_key_id=aws_credentials.aws_access_key,
                aws_secret_access_key=aws_credentials.aws_secret_key,
                region_name=aws_credentials.aws_region,
            )

            # Upload evidence
            s3.put_object(
                Bucket=aws_credentials.bucket_name,
                Key=object_key,
                Body=evidence,
            )

            return object_key

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")

            if error_code in {
                "429",
                "500",
                "502",
                "503",
                "504",
                "RequestTimeout",
                "SlowDown",
            }:
                raise RetryableError(f"{error_code}--{exc}") from exc

            raise RuntimeError(f"AWS S3 upload failed: {exc}") from exc

        except BotoCoreError as exc:
            raise RetryableError(f"AWS S3 error: {exc}") from exc

        except Exception as exc:
            raise RuntimeError(f"Error while uploading evidence to S3: {exc}") from exc

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=2, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def fetch_evidence_from_s3(
        self,
        incident_id: str,
        file_name: str,
        aws_credentials: TrellixAWSCredentialsModels,
    ) -> bytes:
        """
        Fetch raw evidence from the configured AWS S3 bucket.

        Args:
            incident_id:
                ID of the DLP incident associated with the evidence.

            file_name:
                Name of the evidence file.

        Returns:
            bytes:
                Raw evidence content retrieved from S3.

        Raises:
            ValueError:
                If incident_id or file_name is invalid.

            RuntimeError:
                If AWS credentials are not configured or the
                S3 operation fails.

            RetryableError:
                If a retryable AWS error occurs.
        """

        # Validate AWS configuration
        if aws_credentials is None:
            raise RuntimeError("AWS credentials are required for S3 operations.")

        # Validate incident_id
        if not isinstance(incident_id, str):
            raise ValueError("incident_id must be a string")

        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")

        # Validate file_name
        if not isinstance(file_name, str):
            raise ValueError("file_name must be a string")

        if not file_name.strip():
            raise ValueError("file_name must not be empty")

        # Build S3 object key
        object_key = f"trellix-dlp/incidents/" f"{incident_id}/{file_name}"

        try:
            # Create S3 client
            s3 = boto3.client(
                "s3",
                aws_access_key_id=aws_credentials.aws_access_key,
                aws_secret_access_key=aws_credentials.aws_secret_key,
                region_name=aws_credentials.aws_region,
            )

            # Fetch evidence from S3
            response = s3.get_object(
                Bucket=aws_credentials.bucket_name,
                Key=object_key,
            )

            # Read object content
            evidence = response["Body"].read()

            return evidence

        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code")

            if error_code in {
                "429",
                "500",
                "502",
                "503",
                "504",
                "RequestTimeout",
                "SlowDown",
            }:
                raise RetryableError(f"{error_code}--{exc}") from exc

            raise RuntimeError(f"AWS S3 fetch failed: {exc}") from exc

        except BotoCoreError as exc:
            raise RetryableError(f"AWS S3 error: {exc}") from exc

        except Exception as exc:
            raise RuntimeError(f"Error while fetching evidence from S3: {exc}") from exc
