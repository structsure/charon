import boto3
import base64
import json
from flask import g, current_app
from botocore.client import Config


def include_s3_data(endpoint, documents):
    """Replaces a list of S3 IDs in the `attachments` field with data from S3 stored under those IDs."""
    # If not configured to use S3 Attachments, don't modify documents array
    if not current_app.config.get('S3_ATTACHMENTS') == "True":
        return documents

    current_app.logger.info('Fetching data for attachments from S3.')

    s3 = boto3.client(
        's3',
        aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY'),
        aws_secret_access_key=current_app.config.get('AWS_SECRET_KEY'),
        config=Config(signature_version='s3v4')
    )

    # v1 - brute force, get each id in serial. Replace with multi-stream download
    for doc in documents:
        try:
            attachment_data = []
            attachments = doc.get('attachments', {}).get('documents')
            if attachments is not None and len(attachments) > 0:
                for s3key in attachments:
                    attachment_data.append(get_s3_object(s3, s3key))
            doc['attachments'] = attachment_data
        except Exception as exc:
            print('Exception: {}'.format(exc))
    return documents


def get_s3_object(s3, s3key):
    att_obj = s3.get_object(
        Bucket=current_app.config.get('AWS_S3_BUCKET_NAME'),
        Key=s3key,
        ResponseContentEncoding='utf-8'
    )
    att_body = att_obj['Body'].read()
    att_data = None

    # Replace with logic based on content-type if that is added to S3
    try:
        att_data = att_body.decode('utf-8')
        # attachment_data.append(att_data)
        return att_data
    except Exception as exc:
        # TO DO - make this a log statement
        print('exception using utf-8 decoding: {}'.format(exc))
    try:
        att_data = str(base64.b64decode(att_body))
        return att_data
    except Exception as exc:
        # TO DO - make this a log statement
        print('Exception using base 64 decoding: {}'.format(exc))

    # TO DO - make this a log statement
    print('Could not decode attachment for key {}; casting to string'.format(s3key))
    return str(att_body)


def generate_presigned_urls(resource, request, lookup=None):
    # If not configured to use S3 Attachments, don't generate presigned urls for contents of attachments array
    if not current_app.config.get('S3_ATTACHMENTS') == "True":
        return

    current_app.logger.info('Generating S3 presigned urls for attachments.')

    # Get list of doc IDs out of request.data.attachments.documents
    req_data = json.loads(request.data)
    docs = req_data.get('attachments', {}).get('documents')
    if docs is None or len(docs) == 0:
        return

    g.presigned_urls = []

    for doc in docs:
        # assume doc is a string that will be the S3 key
        print('doc (aws key): {}'.format(doc))
        presigned = get_presigned_url(doc)
        g.presigned_urls.append(presigned)


def get_presigned_url(key):
    s3 = boto3.client(
        's3',
        aws_access_key_id=current_app.config.get('AWS_ACCESS_KEY'),
        aws_secret_access_key=current_app.config.get('AWS_SECRET_KEY'),
        config=Config(signature_version='s3v4')
    )

    try:
        post = s3.generate_presigned_url(
            ClientMethod='put_object',
            Params={
                "Bucket": current_app.config.get('AWS_S3_BUCKET_NAME'),
                "Key": key
            }
        )
    except Exception as exc:
        print('exception: {}'.format(exc))
        return None
    print('POST: {}'.format(post))

    return post


def include_presigned_urls(resource, request, payload):
    # If not configured to use S3 Attachments, don't attempt to add presigned urls to response payload
    if not current_app.config.get('S3_ATTACHMENTS') == "True":
        return

    current_app.logger.info('Adding S3 presigned urls to response.')

    data = json.loads(payload.data)
    data['_presigned_urls'] = g.presigned_urls
    payload.data = json.dumps(data)
