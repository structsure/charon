from eve import Eve
import logging
from aggregators import before_agg
from auth import assign_auth, set_context, check_insert_access, check_insert_data_context, AssignSecAuth
from s3 import include_s3_data, generate_presigned_urls, include_presigned_urls
from update import check_perms_for_patch
from flask_cors import CORS

app = Eve()
CORS(app)

app.on_pre_GET += assign_auth
app.on_pre_GET += set_context
app.on_pre_POST += assign_auth
app.on_pre_POST += set_context
app.on_pre_POST += check_insert_data_context
app.on_pre_POST += check_insert_access
app.on_pre_POST += generate_presigned_urls

app.on_pre_PATCH += assign_auth
app.on_pre_PATCH += set_context
app.on_pre_PATCH += check_insert_data_context
app.on_pre_PATCH += check_insert_access
app.on_pre_PATCH += check_perms_for_patch

app.on_post_POST += include_presigned_urls


app.before_aggregation += before_agg
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
    app.run(auth=AssignSecAuth)
