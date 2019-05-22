from eve import Eve
import logging
from aggregators import add_ascl_redaction
from auth import check_insert_access, check_insert_data_context, CharonAuth
from s3 import include_s3_data, generate_presigned_urls, include_presigned_urls
from update import check_perms_in_db
from flask_cors import CORS

app = Eve(auth=CharonAuth)
CORS(app)

app.on_pre_POST += check_insert_data_context
app.on_pre_POST += check_insert_access
app.on_pre_POST += generate_presigned_urls

app.on_pre_PATCH += check_insert_data_context
app.on_pre_PATCH += check_insert_access
app.on_pre_PATCH += check_perms_in_db

app.on_post_POST += include_presigned_urls

app.on_pre_DELETE += check_perms_in_db

app.before_aggregation += add_ascl_redaction
app.after_aggregation += include_s3_data

# When not run directly (e.g. through gunicorn), get log level from gunicorn
if __name__ != '__main__':
    # Using try in case something other than gunicorn or __main__ calls this file
    try:
        gunicorn_logger = logging.getLogger('gunicorn.error')
        app.logger.handlers = gunicorn_logger.handlers
        app.logger.setLevel(gunicorn_logger.level)
    except Exception as exc:
        app.logger.error('Could not get gunicorn log level')

if __name__ == '__main__':
    app.run()
