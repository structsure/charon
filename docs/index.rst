Structsure Charon: MongoDB Security Monitor
===========================================

About
-----
Charon is a security monitor that enforces fine-grained Advanced Security Context Labeling (ASCL) for data stored in MongoDB collections.

Charon uses Eve to provide a REST API for database operations. API calls enforce schema rules (for insert and update) and perform data redaction (for find).

.. _Eve: https://docs.python-eve.org/en/stable/

.. toctree::
   :maxdepth: 1
   
   about
   quickstart
   license
