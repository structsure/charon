Quickstart
============

This guide will walk through setting up a demo instance of Charon. 

Set up Charon
----------------

Create Docker Image
~~~~~~~~~~~~~~~~~~~
Pull the Docker image: ::

    docker pull structsure/charon:latest


Create config file
~~~~~~~~~~~~~~~~~~
Charon uses a schema to define the available endpoints and to enforce the data format they will accept. You can read more about creating a schema in the Config section. For now, we've included a sample schema that defines a single object, `fees`.

Create a file called `env.list` and add the following to it: ::

    MONGO_DBNAME=charon-demo-db
    MONGO_HOST=charon-mongo
    S3_ATTACHMENTS=False
    SCHEMA={"fees": {"Notes": {"type": "string"},"FeeAmount" : {"type": "string"},"FeeID" : {"type": "string"},"FeeIssuedDate" : {"type": "string"},"FeeType": {"type": "string"},"attachments": {"type": "dict","schema": {"_sec": {"type": "dict","schema": {"cat": {"type": "string"},"diss": {"type": "list","schema": {"type": "string"}}}},"documents": {"type": "list"}}},"_sec" : {"type": "dict","schema": {"cat": {"type": "string"},"diss": {"type": "list","schema": {"type": "string"}}}}}}


Create Docker network
~~~~~~~~~~~~~~~~~~~~~
Create a Docker bridge network for your local containers to communicate: ::

    docker network create --driver bridge charon-network

Create mongo instance
~~~~~~~~~~~~~~~~~~~~~~~~~

If you have an instance of MongoDB that you want to use for the demo, you can skip this step.

Pull down the Docker image for Mongo: ::

    docker pull mongo


Run a container using this image on your bridge network: ::

    docker run -p 27017:27017 --network=charon-network --name=charon-mongo mongo


Run your Charon instance
~~~~~~~~~~~~~~~~~~~~~~~~
Execute the following to run your Charon instance: ::

    docker run -p 5000:5000/tcp --env-file env.list --network=charon-network charon

Use the Charon API
------------------
Charon exposes a REST API for all resources defined in the schema. Each resource will get two endpoints - one for reading (the resource name) and one for writing (the resource name with ``_write`` appended). For a resource named ``fees``, the read endpoint will be ``/fees`` and the write endpoint will be ``/fees_write``.

Insert Data
~~~~~~~~~~~
Here is a sample of a fees object, followed by an example API call to insert it into the database.

Notice that the insert call uses an HTTP ``POST``, and assigns the a header for authorization: ``Authorization: Basic username``.

You can change the values of each field, but changing the object format (by removing or adding a field, for example) will cause the insert to fail schema validation. Try it out!

Changing the values in the ``_sec`` attachment could cause the insert to fail due to insufficient permissions - stay tuned for the `Assign Security` section for more information.

Sample Fees object
++++++++++++++++++
We will be using a ``fees`` object, which has the following form: ::

    {
        "Notes": "",
        "FeeAmount" : "2000.00",
        "FeeID" : "441",
        "FeeIssuedDate" : "2008-05-23T00:00:00",
        "FeeType": "Parking",
        "attachments": {
            "_sec": {
                "cat" : "usg_unclassified",
                "diss" : [ ]
            },
            "documents": ["02867bec-d8a2-48fc-a6f7-859888f6883b", "8375b2c8-b461-4568-b4a3-6d37e05dc750"]
        },
        "_sec" : {
            "cat" : "usg_unclassified",
            "diss" : [ ]
        }
    }

Sample API call
+++++++++++++++
Execute the following curl command to insert the object above. If you would like to modify the data, replace the json object after the `-d` flag with your modified json.::


    curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' -d '{"Notes": "Sample Fee","FeeAmount" : "2000.00","FeeID" : "441","FeeIssuedDate" : "2008-05-23T00:00:00","FeeType": "Parking","attachments": {"_sec": {"cat" : "usg_unclassified","diss" : [ ]},"documents": ["02867bec-d8a2-48fc-a6f7-859888f6883b", "8375b2c8-b461-4568-b4a3-6d37e05dc750"]},"_sec" : {"cat" : "usg_unclassified","diss" : [ ]}}' localhost:5000/fees_write


Read Data
~~~~~~~~~
Now that you have inserted some data into the database, make a call to read it. You can fetch all data for the collection, or look up by an object ID.

Get all data for the `fees` collection
++++++++++++++++++++++++++++++++++++++
Execute the following command to read all the data from the ``fees`` collection: ::

    curl -X GET -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' localhost:5000/fees


Get data for specific ``fees`` object
+++++++++++++++++++++++++++++++++++++
Individual items can be read by including an aggregation command at the end of the url: ``?aggregate={"$id":"id-goes-here"}``.



Get the ID for a ``fees`` object (look in the ``_id`` field of the response for the whole ``fees`` collection). Replace ``id-goes-here`` at the end of the url in the following command, and execute the API call. You will receive data for the object you specified. If you are using curl, make sure to escape your quotation marks. ::

    curl -X GET -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' http://localhost:5000/fees?aggregate={%22$id%22:%22id-goes-here%22}


Update Data
~~~~~~~~~~~
You can update an object by passing its ID and specifying the new values of the fields you want to update. Fields that aren't specified won't be modified.

Modify the ``FeeAmount`` for a ``fees`` object
++++++++++++++++++++++++++++++++++++++++++++++
Suppose we want to change the Fee Amount to 1000.00. We will execute an HTTP ``PATCH`` request, specifying the ID of the object to modify, and the changes to make.

This request requires three pieces of information:
 - The ID of the object to be updated, which goes at the end of the url (e.g. for ``localhost:5000/fees_write/12345``, ``12345`` is the ID)
 - The ETag, which you will receive as metadata from a `GET` request. This is sent in a request header: ``"If-Match: etag-goes-here"``
 - The data to be modified. This should be in the request body, and should be a json string in the form ``{"path.to.field": "new_value"}``

Call the ``fees`` read API described above. Then, replace ``id-goes-here`` and ``etag-goes-here`` in the following command with the ID and ETag from the response, and execute the curl command. ::


    curl -X PATCH -d '{"FeeAmount": "1000.00"}' -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' -H "If-Match: etag-goes-here" localhost:5000/fees_write/id-goes-here


Now, perform another ``GET`` request for that object to confirm the Fee Amount was updated to ``1000.00``.

Use Charon Security Rules
-------------------------
Charon implements Advanced Security Context Labels at the object and field level. So far we have authenticated as a user that is granted permissions for all Security Categories up to Top Secret. The data we have entered has a required Security Category of Unclassified, so our user has been able to fully manipulate it.

To demonstrate how security rules work, we will be authenticate as a user that is only allowed to view items with a Security Category of Unclassified. We will apply the ``usg_topsecret`` Security Category Label to items to set their required Security Category to Top Secret.

Insert Records with Top Secret Security Category Label
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
To insert a record with a security label, the user must have permissions for that security label. For example, a user who does not have access to read objects labelled Top Secret will not be permitted to write objects labelled Top Secret.

The following two commands authenticate as the ``usg_topsecret_cumul`` user, who has Top Secret permission. The first command inserts an object labelled as Top Secret at the object level. The second command inserts an object labelled Unclassified at the object level, but with the ``attachments`` field labelled Top Secret.

Labelled Top Secret at the object level
+++++++++++++++++++++++++++++++++++++++
::

    curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' -d '{"Notes": "Object-level Top Secret","FeeAmount" : "2000.00","FeeID" : "441","FeeIssuedDate" : "2008-05-23T00:00:00","FeeType": "Parking","attachments": {"_sec": {"cat" : "usg_unclassified","diss" : [ ]},"documents": ["02867bec-d8a2-48fc-a6f7-859888f6883b", "8375b2c8-b461-4568-b4a3-6d37e05dc750"]},"_sec" : {"cat" : "usg_topsecret","diss" : [ ]}}' localhost:5000/fees_write

Labelled Unclassified at the object level and Top Secret for the attachments field
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
::

    curl -X POST -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' -d '{"Notes": "Attachment field Top Secret","FeeAmount" : "2000.00","FeeID" : "441","FeeIssuedDate" : "2008-05-23T00:00:00","FeeType": "Parking","attachments": {"_sec": {"cat" : "usg_topsecret","diss" : [ ]},"documents": ["02867bec-d8a2-48fc-a6f7-859888f6883b", "8375b2c8-b461-4568-b4a3-6d37e05dc750"]},"_sec" : {"cat" : "usg_unclassified","diss" : [ ]}}' localhost:5000/fees_write

Attempt to read data
~~~~~~~~~~~~~~~~~~~~
Charon enforces security rules on reads - responses will only contain data that is allowed for the user in the request.

To demonstrate, we will attempt to read the data that we just inserted using a requesting user without permission to view items labelled Top Secret.

Do a read for the entire ``fees`` collection with the ``us_unclassified_only`` user, then look at the output.::


    curl -X GET -H 'Content-Type: application/json' -H 'Authorization: Basic us_unclassified_only' localhost:5000/fees


Notice that the first Top Secret object we inserted, with "Object-level Top Secret" in the notes field, does not appear. The second object, with "Attachment field Top Secret" in the notes field, is included in the results but the ``attachments`` field has been redacted.

Perform the same read with a user who has Top Secret permissions, and notice that those two objects have been included in their entirety. ::


    curl -X GET -H 'Content-Type: application/json' -H 'Authorization: Basic us_topsecret_cumul' localhost:5000/fees

