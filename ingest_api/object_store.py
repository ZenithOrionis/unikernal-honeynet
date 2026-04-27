from __future__ import annotations

from ingest_api.config import get_settings


settings = get_settings()


def get_s3_client():
    try:
        import boto3
        from botocore.client import Config
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Object storage support requires boto3/botocore. Install the ingest_api "
            "dependencies to use MinIO or another S3-compatible backend."
        ) from exc

    return boto3.client(
        "s3",
        endpoint_url=settings.artifact_endpoint_url,
        aws_access_key_id=settings.artifact_access_key,
        aws_secret_access_key=settings.artifact_secret_key,
        region_name=settings.artifact_region,
        use_ssl=settings.artifact_secure,
        config=Config(signature_version="s3v4"),
    )


def ensure_bucket_exists(bucket: str | None = None) -> str:
    name = bucket or settings.artifact_bucket
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=name)
    except Exception:
        client.create_bucket(Bucket=name)
    return name


def put_bytes(key: str, body: bytes, content_type: str, bucket: str | None = None) -> tuple[str, str]:
    name = ensure_bucket_exists(bucket)
    client = get_s3_client()
    client.put_object(Bucket=name, Key=key, Body=body, ContentType=content_type)
    return name, key


def get_bytes(bucket: str, key: str) -> tuple[bytes, str]:
    client = get_s3_client()
    response = client.get_object(Bucket=bucket, Key=key)
    content_type = response.get("ContentType", "application/octet-stream")
    return response["Body"].read(), content_type
