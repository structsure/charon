About
======
Charon is a security monitor that enforces fine-grained Advanced Security Context Labeling (ASCL) for data stored in MongoDB collections.

Charon uses Eve_ to provide a REST API for database operations. API calls enforce schema rules (for ``insert`` and ``update``) and perform data redaction (for ``find``).

.. _Eve: https://docs.python-eve.org/en/stable/

Setup
=====

If you want to get up and running quickly, see the Quickstart_. 

.. _Quickstart:

Building Charon
---------------
Get the Charon image by running: ::

    docker pull structsure-charon

If using Docker run, create a local bridge network to connect to your container: ::

    docker network create --driver bridge charon-network

Follow the instructions in the next section to set the environment variables in a file called ``env.list``, then continue to the next step to run the container.

Then, run the container: ::

    docker run -p 5000:5000/tcp --env-file env.list --network=charon-network structsure-charon


Environment Variables
---------------------
The Charon instance is configured by passing environment variables to the Docker container. 

If you are using Docker run, you can do this by creating a file to hold the variables (e.g. ``env.list``) and then passing it in the Docker run command by including ``--env-file env.list``. Make sure to keep this file secret - add it to your project's ``.gitignore`` to prevent accidental inclusion in version control.

The following environment variables must be included: ::

    - SCHEMA
        - A json string describing the schema for objects managed by Charon. See the Schema Enforcement section for more info.
        - Required
    - MONGO_DBNAME
        - The name of the Mongo DB used with Charon.
        - Required
    - MONGO_HOST
        - The hostname for the Mongo instance to be used with Charon. For example, if using a Docker container for Mongo, this is the container name.
        - Required
    - MONGO_PORT
        - The port number used by the Mongo instance.
        - Optional, defaults to ``27017``, the default Mongo port.
    - MONGO_USERNAME
        - The username for a service user in Mongo that has full permissions.
        - Optional, defaults to ``""``.
    - MONGO_PASSWORD
        - The password for the user specified in MONGO_USERNAME.
        - Optional, defaults to ``""``.
    - MONGO_AUTH_SOURCE
        - The Mongo database where user credentials are stored. E.g. ``admin``
        - Optional, defaults to ``"admin"``.
    - S3_ATTACHMENTS
        - Set to true to store documents in the ``attachments.documents`` field in S3.
        - Optional, defaults to ``False``.
    - AWS_ACCESS_KEY
        - If using the ``S3_ATTACHMENTS``, the AWS Access Key
        - Required if S3_ATTACHMENTS = True
    - AWS_SECRET_KEY
        - If using the ``S3_ATTACHMENTS``, the AWS Secret Access Key
        - Required if S3_ATTACHMENTS = True
    - AWS_S3_BUCKET_NAME
        - If using the ``S3_ATTACHMENTS``, the name of the S3 bucket. (Do not include ``s3://``.)
        - Required if S3_ATTACHMENTS = True

Docker Network
--------------
Charon is designed to run as a Docker container and runs on port ``5000``. You will need to make port 5000 accessible for the Docker container, and make sure the Mongo instance can be reached from the Charon Docker container.

If you are using Docker run, you can set up a Docker network using the following command: ::

    docker network create --driver bridge charon-network

Then, when running the Charon Docker container, include ``--network=charon-network`` in the run command.


Nginx
-----
Charon requires API calls to include the requester's security context to evaluate the security rules in the data structure (to redact data or disallow writing data the user does not have permission to write). However, Charon does not include a system to authenticate the information in these requests. It should be run in a trusted environment; for example, run Charon behind nginx, and have nginx perform authentication.

Mongo
-----
If you don't already have a MongoDB instance to use with Charon, you can easily set one up using Docker.

Get the Mongo image: ``docker pull mongo``

By default, your Mongo instance will run on port ``27017``. If you change the port, make sure to update the ``MONGO_PORT`` environment variable for Charon. 

If using Docker run, create a Mongo container that runs on the Docker network you created: ``docker run -p 27017:27017 --network=charon-network --name=charon-mongo mongo``

Config
======

Auth System
-----------
Charon operates on a Bring Your Own Auth basis. The ``set_context`` method of ``auth.py`` receives the resource name, the request object, and the lookup string (if any), and assigns the users security context. The user's security context consists of:
    - Security Category - a string set in Flask ``g._cat``
    - Dissemination Rules - a list of strings set in Flask ``g._diss``

The auth system you add to Charon must set these values based on the data received in the Authentication header. The Authentication header has the form: ``Authentication: Basic some_token_here``.

Features
========
REST API
--------
General Request Format
~~~~~~~~~~~~~~~~~~~~~~
Charon takes HTTP requests and returns json responses. Each collection has two endpoints - one for reading data and one for writing data. These are based off the name of the collection. For example, a collection called ``users`` would have the read-only endpoint ``users`` as well as the write-only endpoint ``users_write``.

These endpoints are automatically generated based on the resources in the schema. To add a new endpoint, simply update the schema to include an entry for the new collection.

Requests must include the user's security context in request headers. Because the auth system must be added when you deploy Charon, the exact content depends on what your auth system looks like. Charon expects a header of the format: ``Authentication: Basic some_token_here``. The auth system that you add must use the token value to assign the security rules the user should have based on their identity. See the ``Auth System`` section in ``Config`` for more info.

Resources
~~~~~~~~~
Charon will expose endpoints for each object in the ``SCHEMA`` environment variable. Each resource will get a read-only and a write-only endpoint in the form ``resource_name`` and ``resource_name_write``. 

For example, the ``fees`` object has the read-only endpoint ``fees`` and the write-only endpoint ``fees_write``.

Read
~~~~
To retrieve data for the entire collection, send a GET request to the endpoint ``collectionName``. To retrieve data for a specific object, send a GET request to ``collectionName?aggregate={"$id": "id_goes_here"}``, substituting the ID for the object you wish to read.

At this time, queries are not supported.

Insert
~~~~~~
To insert an object into a collection by sending a POST request to ``collectionName_write``. The data, sent as json in the request body, must be valid based on the schema entry for ``collectionName``. If the data is not valid, or there is no ``collectionName`` entry in the schema dict, the insert will be refused.

Update
~~~~~~
To update an object, send a PATCH request to ``collectionName_write/object_id``. Nested fields can be updated by including the full path to that field. If a field that contains multiple subfields is updated, each subfield must be specified.

Like for inserts, if the data is not valid, or there is no ``collectionName`` entry in the schema dict, the insert will be refused.

At this time, document versioning is not supported.

Schema Enforcement
------------------
The schema defines the structure of objects in the database. Although Mongo does not require a schema, Charon enforces schema rules to ensure data integrity. For more information on valid schema formatting, refer to the json-schema_ documentation.

.. _json-schema: https://json-schema.org/

Charon defines schemas for structures applying security rules (``_sec``) and for storing documents in Amazon S3 (``attachments``). Both structures can be used at the top level of a document or at the field level.

Advanced Security Context Labeling (ASCL)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
ASCL rules control access to objects and specific fields in those objects. To apply ASCL rules, add the ``_sec`` schema as an attribute of a field. The security context of a request is checked against each ASCL - the request must be assigned the security category (``cat``) and all of the dissemination controls (``diss``) present in the ASCL to pass the check.

For read requests, the field marked with the ASCL is redacted (along with all sub-fields) if the user context is not valid for that ASCL. 

For inserts, the user context must be valid for all ASCLs contained in the data in the request.

For updates, the user context must be valid for all ASCLs in the data in the request, and any field that would be overwritten by the data in the request.

ASCL Schema
+++++++++++
The ASCL schema is as follows: ::

    "_sec": {
        "type": "dict",
        "schema": {
            "cat": {"type": "string"},
            "diss": {
                "type": "list",
                "schema": {"type": "string"}
            }
        }
    }


Example
+++++++
Here is a schema for an ``employee`` object that has an ASCL at the object level and at the field level for the ``status`` field.

If the request context fails the ASCL check at the top level, no data will be returned.

If the request passes to top-level ASCL but fails the ``status`` ASCL check, the object will be returned without the ``status`` field - only the ``name`` field is returned. ::

    "employee": {
        "name": {"type": "string"},
        "status": {
            "type": "dict",
            "schema": {
                "value": {"type": "string"},
                "_sec": {
                    "type": "dict",
                    "schema": {
                        "cat": {"type": "string"},
                        "diss": {
                            "type": "list",
                            "schema": {"type": "string"}
                        }
                    }
                }
            }
        },
        "_sec": {
            "type": "dict",
            "schema": {
                "cat": {"type": "string"},
                "diss": {
                    "type": "list",
                    "schema": {"type": "string"}
                }
            }
        }
    }

Here is an example ``employee`` object: ::

    {
        "name": "Jane Doe",
        "status": {
            "value": "employed",
            "_sec": {
                "cat": "admin",
                "diss": ["human_resources", "dc_office"]
            }
        },
        "_sec": {
            "cat": "employee",
            "diss": ["dc_office"]
        }
    }


Any requester who has the category ``employee`` and the dissemination control ``dc_office`` assigned to their profile can see this employee's name. Only users whose profile contains those attributes and the ``admin`` security category and ``human_resources`` dissemination control can see the employee's status.

S3 Attachments
--------------
To add a field that stores IDs for objects stored in S3, you can add the ``attachments`` schema to an object or field.

When this object is inserted, the response will contain a ``_presigned_urls`` field with urls that include encoded one-time AWS credentials. The client is responsible for using the presigned urls to upload the contents of each document to the S3 bucket.

When a read is performed, the ``attachments.documents`` list will contain the data stored in each S3 ID, but only the ID is stored in Mongo.

Pros and Cons of S3 Attachments
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
This feature reduces the storage requirements for the MongoDB instance. Mongo recommends_ using GridFS for storing files larger than 16 MB. If you do not have GridFS enabled, you can use set ``S3_ATTACHMENTS = True`` to store only the ID in Mongo.

.. _recommends: https://docs.mongodb.com/manual/core/gridfs/

The downside of using the ``S3_ATTACHMENTS`` feature is losing the ability to easily update the list. Because the list of IDs is not returned to the client, there is not a way to add or remove a single element. If the ``attachments.documents`` list needs to be changed, the client must supply the IDs for each element in the updated list.

There is an item on the roadmap to add support for attachment updates.

Attachments Schema
~~~~~~~~~~~~~~~~~~
The attachments schema is as follows: ::

    "attachments": {
        "type": "dict",
        "schema": {
            "_sec": {
                "type": "dict",
                "schema": {
                    "cat": {"type": "string"},
                    "diss": {
                        "type": "list",
                        "schema": {"type": "string"}
                    }
                }
            },
            "documents": {"type": "list"}
        }
    }

Example Case
++++++++++++
Here is a schema for a ``case`` object with attachments stored in S3: ::

    "case": {
        "case_number": {"type": "string"},
        "notes": {"type": "string"},
        "attachments": {
            "type": "dict",
            "schema": {
                "_sec": ascl,
                "documents": {"type": "list"}
            }
        }
    }

And an example of a ``case`` object to be uploaded: ::

    {
        "case_number": "A1SD2F",
        "notes": "This was a particularly interesting case.",
        "attachments": {
            "_sec": {
                "cat": "employee",
                "diss": []
            }
            "documents": ["1234", "5678"]
        }
    }


Sample Schema with Tagged Rules and Attachments
-----------------------------------------------
The following is an example of a schema entry that includes document level security, field level security (in the signature field), and an attachments field to use the S3 attachments feature. ::

    "signature": {
        "date": {"type": "string"},
        "name": {"type": "string"},
        "signature": {
            "type": "dict",
            "schema": {
                "value": {"type": "string"},
                "_sec": {
                    "type": "dict",
                    "schema": {
                        "cat": {"type": "string"},
                        "diss": {
                            "type": "list",
                            "schema": {"type": "string"}
                        }
                    }
                }
            }
        },
        "attachments": {
            "type": "dict",
            "schema": {
                "_sec": ascl,
                "documents": {"type": "list"}
            }
        },
        "_sec": {
            "type": "dict",
            "schema": {
                "cat": {"type": "string"},
                "diss": {
                    "type": "list",
                    "schema": {"type": "string"}
                }
            }
        }
    }


Known Issues & Future Development
=================================
Bring Your Own Auth
-------------------
Charon does not include an authentication system. It uses a request header to assign the security context, but does not verify that the user is who they claim to be. Further, Charon does not currently support a method for assigning security context based on the token passed in the auth header.

While there are improvements to this on the roadmap, the current state of auth is not secure. We suggest running Charon behind nginx and handling auth in nginx.

Deletes not allowed
-------------------
Delete operations are not permitted by Charon. 

There is an item on the roadmap to support soft deleting and hard deleting items.

S3 attachment updates are all-or-nothing
----------------------------------------
The ``attachments`` field cannot be partially modified, it must be completely overwritten. Because the S3 ID is not sent back to the client on a read operation (the data for the document is returned instead) the client cannot simply send a modified list.

There is an item on the roadmap to improve attachment management.

S3 attachment uploads carry risk of data integrity errors
---------------------------------------------------------
Because the client is responsible for uploading the document to S3, there is a risk of data integrity issues. For example, if the client fails to upload the document, there will be an ID in Mongo that does not have a corresponding document in S3.

There is an item on the roadmap to improve data integrity for S3 attachments.
