"""
This module handles authentication and connection validation for Trellix
Data Loss Prevention (DLP) On-Prem via ePolicy Orchestrator (ePO).
"""

import requests
from pydantic import ValidationError
from requests.auth import HTTPBasicAuth
from tenacity import retry, retry_if_exception_type, wait_exponential, stop_after_delay

from .exceptions import RetryableError
from .models import TrellixAuthenticationModels


class TrellixDLPAuth: 
    """
    Trellix DLP (ePO On-Prem) Authentication Helper.

    :param authentication: Trellix ePO server URL and Basic Auth credentials.
    :param verify_ssl: Whether to verify the ePO server's TLS certificate.
        Defaults to False for sandbox/self-signed environments -- set True
        once a trusted certificate is installed on the ePO server.
    """

    def __init__(
        self,
        authentication: TrellixAuthenticationModels,
        verify_ssl: bool = False,
    ):
        self.authentication = authentication
        self.verify_ssl = verify_ssl

    @retry(
        retry=retry_if_exception_type(RetryableError),
        wait=wait_exponential(multiplier=1, max=3),
        stop=stop_after_delay(60),
        reraise=True,
    )
    def validate_connection(self) -> bool:
        """
        Validate the Trellix ePO server URL and Basic Auth credentials by
        calling a lightweight ePO Remote Command (core.help).
        Automatically retries on transient network/server failures.

        :return: True if the connection and credentials are valid.
        :raises RuntimeError: on authentication, HTTP, or request errors
            that are not safe to retry (e.g. 4xx other than 429, timeouts,
            response-parsing failures).
        :raises RetryableError: on 5xx/429 responses or connection errors;
            consumed internally by the @retry decorator and only surfaced
            to the caller if all retry attempts are exhausted.
        """

        url = (
            f"{self.authentication.server_url.rstrip('/')}"
            "/remote/core.help?:output=json"
        )

        try:
            response = requests.get(
                url,
                auth=HTTPBasicAuth(
                    self.authentication.username,
                    self.authentication.password,
                ),
                timeout=10,
                verify=self.verify_ssl,
            )

            response.raise_for_status()

            response.json()

            return True

        except requests.exceptions.HTTPError as exc:
            if response.status_code >= 500 or response.status_code == 429:
                raise RetryableError(
                    f"{response.status_code} - {response.text}"
                ) from exc

            raise RuntimeError(f"{response.status_code} - {response.text}") from exc

        except requests.exceptions.Timeout as exc:
            raise RuntimeError(
                "Request timed out while trying to connect to Trellix ePO."
            ) from exc

        except requests.exceptions.ConnectionError as exc:
            raise RetryableError(
                "ConnectionError: Unable to connect to Trellix ePO."
            ) from exc

        except (ValidationError, ValueError) as exc:
            raise RuntimeError(f"Failed to parse Trellix ePO response: {exc}") from exc

        except requests.exceptions.RequestException as exc:
            raise RuntimeError(f"Error during Trellix ePO request: {exc}") from exc
