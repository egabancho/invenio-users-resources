# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 KTH Royal Institute of Technology
# Copyright (C) 2022 TU Wien.
# Copyright (C) 2022 CERN.
# Copyright (C) 2022 European Union.
# Copyright (C) 2025 KTH Royal Institute of Technology.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Groups service."""

from flask import current_app
from invenio_accounts.models import Role
from invenio_db import db
from invenio_i18n import lazy_gettext as _
from invenio_records_resources.resources.errors import PermissionDeniedError
from invenio_records_resources.services import RecordService
from invenio_records_resources.services.uow import (
    RecordCommitOp,
    RecordIndexDeleteOp,
    unit_of_work,
)
from marshmallow import ValidationError
from sqlalchemy.exc import IntegrityError

from ...records.api import GroupAggregate
from ..results import AvatarResult


class GroupsService(RecordService):
    """User groups service."""

    @staticmethod
    def _datastore():
        """Reuse Flask-Security datastore helpers (same as CLI)."""
        return current_app.extensions["security"].datastore

    @unit_of_work()
    def create(self, identity, data, raise_errors=True, uow=None):
        """Create a new group/role."""
        self.require_permission(identity, "create")
        data, errors = self.schema.load(
            data or {},
            context={"identity": identity},
            raise_errors=raise_errors,
        )

        name = data.get("name")

        datastore = self._datastore()
        role_kwargs = {
            "id": name,
            "name": name,
        }
        if "description" in data:
            role_kwargs["description"] = data["description"]
        if "is_managed" in data:
            role_kwargs["is_managed"] = data["is_managed"]

        try:
            role = datastore.create_role(**role_kwargs)
        except IntegrityError as exc:
            raise ValidationError(
                {"name": [_("A role with this name already exists.")]}
            ) from exc

        group = GroupAggregate.from_model(role)

        self.run_components(
            "create",
            identity,
            data=data,
            group=group,
            errors=errors,
            uow=uow,
        )

        uow.register(RecordCommitOp(group, indexer=self.indexer, index_refresh=True))
        return self.result_item(
            self, identity, group, errors=errors, links_tpl=self.links_item_tpl
        )

    def read(self, identity, id_):
        """Retrieve a user group."""
        group = GroupAggregate.get_record_by_name(id_)
        if group is None:
            raise PermissionDeniedError()
        self.require_permission(identity, "read", record=group)
        for component in self.components:
            if hasattr(component, "read"):
                component.read(identity, group=group)
        return self.result_item(self, identity, group, links_tpl=self.links_item_tpl)

    @unit_of_work()
    def update(self, identity, id_, data, raise_errors=True, uow=None):
        """Update an existing group."""
        group = GroupAggregate.get_record_by_name(id_)
        if group is None:
            raise PermissionDeniedError()
        self.require_permission(identity, "update", record=group)

        data, errors = self.schema.load(
            data or {},
            schema_args={"partial": True},
            context={"identity": identity, "record": group},
            raise_errors=raise_errors,
        )

        if "name" in data and data["name"] != group.name:
            raise ValidationError({"name": [_("Renaming roles is not supported.")]})

        datastore = self._datastore()
        role = datastore.find_role(group.name)
        if role is None:
            raise ValidationError({"id": [_("Role could not be loaded.")]})

        if "description" in data:
            role.description = data["description"]
        if "is_managed" in data:
            role.is_managed = data["is_managed"]

        updated_group = GroupAggregate.from_model(role)

        self.run_components(
            "update",
            identity,
            data=data,
            group=updated_group,
            errors=errors,
            uow=uow,
        )

        uow.register(
            RecordCommitOp(updated_group, indexer=self.indexer, index_refresh=True)
        )
        return self.result_item(
            self,
            identity,
            updated_group,
            errors=errors,
            links_tpl=self.links_item_tpl,
        )

    @unit_of_work()
    def delete(self, identity, id_, uow=None):
        """Delete a group."""
        group = GroupAggregate.get_record_by_name(id_)
        if group is None:
            raise PermissionDeniedError()
        self.require_permission(identity, "delete", record=group)

        datastore = self._datastore()
        role = datastore.find_role(group.name)
        if role is None:
            raise ValidationError({"id": [_("Role could not be loaded.")]})

        datastore.delete(role)

        self.run_components(
            "delete",
            identity,
            group=group,
            uow=uow,
        )

        uow.register(
            RecordIndexDeleteOp(group, indexer=self.indexer, index_refresh=True)
        )

        return True

    def read_avatar(self, identity, name_):
        """Get a groups's avatar."""
        group = GroupAggregate.get_record_by_name(name_)
        if group is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self.require_permission(identity, "read", record=group)
        return AvatarResult(group)

    def rebuild_index(self, identity, uow=None):
        """Reindex all user groups managed by this service."""
        role_ids = db.session.query(Role.id).yield_per(1000)
        self.indexer.bulk_index([role_id for (role_id,) in role_ids])
        return True
