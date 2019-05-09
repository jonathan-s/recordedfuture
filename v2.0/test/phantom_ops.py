"""Helper functions to create Phantom data structures."""


def ph_artifact(**kwargs):
    """Return a Phantom artifact with the supplied CEF fields."""
    artifact = {
        # "asset_id":10,
        # "cef_types": {
        #     "my_custom_cef_field": [ "ip" ]
        # },
        # "container_id": 100,
        # "data":{},
        # "end_time":"2014-10-19T14:45:51.100Z",
        "label":"event",
        "run_automation": True,
        # "severity":"high",
        # "source_data_identifier":"4",
        # "start_time":"2014-10-19T14:41:33.384Z",
        # "tags": ["tag1", "tag2"],
        # "type":"network"
    }
    artifact['cef'] = kwargs

    return artifact


def ph_container(artifacts=[]):
    """Return a Phantom container with the supplied fields."""
    return {
        # "asset_id": 12,
        "artifacts": artifacts,
        "custom_fields": {},
        # "data": { },
        "description": "Test container.",
        # "due_time": "2015-03-21T19:29:23.759Z",
        "label": "events",
        "name": "Test event",
        # "owner_id": "phantom@recordedfuture.com",
        # "run_automation": True,
        # "sensitivity": "red",
        # "severity": "high",
        # "source_data_identifier": "4",
        # "status": "new",
        # "start_time": "2015-03-21T19:28:13.759Z",
        # "open_time": "2015-03-21T19:29:00.141Z",
        # "tags": ["tag1", "tag2"]
    }