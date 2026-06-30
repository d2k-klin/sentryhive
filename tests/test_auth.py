"""Tests for sentryhive.auth — credential resolution with mocked AWS (botocore Stubber).

No real AWS credentials or network access required.
"""

from unittest.mock import patch

import boto3
import pytest
from botocore.stub import Stubber

from sentryhive.auth import (
    AuthError,
    build_contexts,
    default_regions,
    discover_eks_clusters,
    resolve_session,
    verify_identity,
)


class TestVerifyIdentity:
    def test_returns_identity_on_success(self):
        session = boto3.Session(region_name="us-east-1")
        client = session.client("sts")
        stubber = Stubber(client)
        stubber.add_response(
            "get_caller_identity",
            {
                "UserId": "AIDAEXAMPLE",
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/auditor",
            },
        )
        with stubber, patch.object(session, "client", return_value=client):
            identity = verify_identity(session)
        assert identity.account_id == "123456789012"
        assert identity.arn == "arn:aws:iam::123456789012:user/auditor"
        assert identity.user_id == "AIDAEXAMPLE"

    def test_raises_auth_error_on_failure(self):
        session = boto3.Session(region_name="us-east-1")
        client = session.client("sts")
        stubber = Stubber(client)
        stubber.add_client_error("get_caller_identity", "ExpiredTokenException")
        with stubber, patch.object(session, "client", return_value=client):
            with pytest.raises(AuthError, match="Could not verify"):
                verify_identity(session)


class TestResolveSession:
    def test_no_role_returns_base_session(self):
        session = resolve_session(region="us-east-1")
        assert session.region_name == "us-east-1"

    def test_assume_role_uses_sts(self):
        with patch("sentryhive.auth.boto3.Session") as mock_cls:
            base_session = mock_cls.return_value
            sts_client = base_session.client.return_value
            sts_client.assume_role.return_value = {
                "Credentials": {
                    "AccessKeyId": "ASIA_ASSUMED",
                    "SecretAccessKey": "secret_assumed",
                    "SessionToken": "token_assumed",
                }
            }
            resolve_session(role_arn="arn:aws:iam::999:role/Audit", external_id="ext123")
            sts_client.assume_role.assert_called_once()
            call_kwargs = sts_client.assume_role.call_args[1]
            assert call_kwargs["RoleArn"] == "arn:aws:iam::999:role/Audit"
            assert call_kwargs["ExternalId"] == "ext123"
            assert call_kwargs["RoleSessionName"] == "sentryhive"

    def test_assume_role_failure_raises_auth_error(self):
        from botocore.exceptions import ClientError

        with patch("sentryhive.auth.boto3.Session") as mock_cls:
            base_session = mock_cls.return_value
            sts_client = base_session.client.return_value
            sts_client.assume_role.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "AssumeRole"
            )
            with pytest.raises(AuthError, match="Failed to assume role"):
                resolve_session(role_arn="arn:aws:iam::999:role/NoAccess")


class TestDefaultRegions:
    def test_uses_session_region(self):
        session = boto3.Session(region_name="eu-central-1")
        assert default_regions(session) == ["eu-central-1"]

    def test_falls_back_to_us_east_1(self, monkeypatch):
        monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
        monkeypatch.delenv("AWS_REGION", raising=False)
        session = boto3.Session(region_name=None)
        # If the session resolved a region from config, patch it out.
        monkeypatch.setattr(type(session), "region_name", property(lambda self: None))
        result = default_regions(session)
        assert result == ["us-east-1"]


class TestBuildContexts:
    def test_no_role_arns_yields_single_context(self):
        with (
            patch("sentryhive.auth.resolve_session") as mock_resolve,
            patch("sentryhive.auth.verify_identity") as mock_verify,
        ):
            mock_resolve.return_value = boto3.Session(region_name="us-east-1")
            mock_verify.return_value = type(
                "Id",
                (),
                {
                    "account_id": "123456789012",
                    "arn": "arn:aws:iam::123456789012:user/me",
                    "user_id": "AIDA",
                },
            )()
            contexts = build_contexts(profile="default")
            assert len(contexts) == 1
            assert contexts[0].identity.account_id == "123456789012"

    def test_multiple_role_arns_yield_multiple_contexts(self):
        call_count = {"n": 0}

        def mock_build_context(**kwargs):
            call_count["n"] += 1
            ctx = type(
                "Ctx",
                (),
                {
                    "session": boto3.Session(region_name="us-east-1"),
                    "identity": type(
                        "Id",
                        (),
                        {
                            "account_id": f"00000000000{call_count['n']}",
                            "arn": f"arn::{call_count['n']}",
                            "user_id": "AIDA",
                        },
                    )(),
                    "regions": ["us-east-1"],
                    "client": lambda self, svc, region=None: None,
                },
            )()
            return ctx

        with patch("sentryhive.auth.build_context", side_effect=mock_build_context):
            contexts = build_contexts(
                role_arns=["arn:aws:iam::111:role/A", "arn:aws:iam::222:role/B"],
                external_id="shared",
            )
        assert len(contexts) == 2


class TestDiscoverEksClusters:
    def test_returns_clusters(self):
        session = boto3.Session(region_name="eu-central-1")
        client = session.client("eks", region_name="eu-central-1")
        stubber = Stubber(client)
        stubber.add_response("list_clusters", {"clusters": ["prod-eks", "staging-eks"]})

        ctx = type(
            "Ctx",
            (),
            {
                "regions": ["eu-central-1"],
                "client": lambda self, svc, region=None: client,
            },
        )()

        with stubber:
            clusters = discover_eks_clusters(ctx)
        assert clusters == ["prod-eks", "staging-eks"]

    def test_returns_empty_on_error(self):
        from botocore.exceptions import ClientError

        client_mock = type(
            "C",
            (),
            {
                "get_paginator": lambda self, _: (_ for _ in ()).throw(
                    ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListClusters")
                ),
            },
        )()

        ctx = type(
            "Ctx",
            (),
            {
                "regions": ["us-east-1"],
                "client": lambda self, svc, region=None: client_mock,
            },
        )()

        result = discover_eks_clusters(ctx)
        assert result == []
