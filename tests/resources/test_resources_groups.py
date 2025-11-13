# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 CERN.
# Copyright (C) 2025 KTH Royal Institute of Technology.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Groups resource tests."""


def test_group_create_api(app, client, user_moderator):
    user_moderator.login(client)

    payload = {
        "name": "api-role",
        "description": "Created via API",
        "is_managed": False,
    }

    res = client.post("/groups", json=payload)
    assert 201 == res.status_code
    data = res.get_json()
    assert payload["name"] == data["name"]
    assert payload["description"] == data["description"]

    res = client.delete(f"/groups/{data['id']}")
    assert 204 == res.status_code


def test_group_avatar(app, client, group, not_managed_group, user_pub):
    res = client.get(f"/groups/{not_managed_group.id}/avatar.svg")
    assert res.status_code == 403

    user_pub.login(client)

    # unmanaged group can be retrieved
    res = client.get(f"/groups/{not_managed_group.id}/avatar.svg")
    assert res.status_code == 200
    assert res.mimetype == "image/svg+xml"

    # managed group can *not* be retrieved
    res = client.get(f"/groups/{group.id}/avatar.svg")
    assert res.status_code == 403


# TODO: test conditional requests
# TODO: test caching headers
# TODO: test invalid identifiers
