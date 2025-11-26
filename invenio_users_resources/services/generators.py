# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 TU Wien.
# Copyright (C) 2022 CERN.
# Copyright (C) 2023 Graz University of Technology.
# Copyright (C) 2024 KTH Royal Institute of Technology.
# Copyright (C) 2025 Ubiquity Press.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Permission generators for users and groups."""

from abc import abstractmethod

from flask import current_app
from flask_principal import UserNeed
from invenio_access import (
    ActionRoles,
    ActionUsers,
    Permission,
    any_user,
    superuser_access,
)
from invenio_access.models import Role
from invenio_access.utils import get_identity
from invenio_db import db
from invenio_records.dictutils import dict_lookup
from invenio_records_permissions.generators import (
    ConditionalGenerator,
    Generator,
)
from invenio_search.engine import dsl
from sqlalchemy import exists


class DenyAll(Generator):
    """Generator that denies all access by excluding any_user."""

    def excludes(self, **kwargs):
        """Exclude all users."""
        return [any_user]


class IfPublic(ConditionalGenerator):
    """Generator for different permissions based on the visibility settings."""

    def __init__(self, field_name, then_, else_, **kwargs):
        """Constructor."""
        super().__init__(then_=then_, else_=else_, **kwargs)
        self._field_name = field_name

    def _condition(self, record=None, **kwargs):
        """Condition to choose generators set."""
        if record is None:
            return False

        visibility = record.preferences.get(self._field_name, "restricted")
        is_public = visibility == "public"

        return is_public

    def query_filter(self, **kwargs):
        """Filters for queries."""
        field = f"preferences.{self._field_name}"
        q_public = dsl.Q("match", **{field: "public"})
        q_restricted = dsl.Q("match", **{field: "restricted"})
        then_query = self._make_query(self.then_, **kwargs)
        else_query = self._make_query(self.else_, **kwargs)

        if then_query and else_query:
            return (q_public & then_query) | (q_restricted & else_query)
        elif then_query:
            return q_public & then_query
        elif else_query:
            return q_public | (q_restricted & else_query)
        else:
            return q_public


class IfPublicEmail(IfPublic):
    """Generator checking the 'email_visibility' setting."""

    def __init__(self, then_, else_):
        """Constructor."""
        super().__init__("email_visibility", then_, else_)


class IfPublicUser(IfPublic):
    """Generator checking the 'visibility' setting."""

    def __init__(self, then_, else_):
        """Constructor."""
        super().__init__("visibility", then_, else_)


class Self(Generator):
    """Requires the users themselves."""

    def needs(self, record=None, **kwargs):
        """Set of Needs granting permission."""
        if record is not None:
            return [UserNeed(record.id)]

        return []

    def query_filter(self, identity=None, **kwargs):
        """Filters for the current identity."""
        if identity is not None:
            for need in identity.provides:
                if need.method == "id":
                    return dsl.Q("term", id=need.value)

        return []


class PreventSelf(Generator):
    """Prevents users from performing actions on themselves."""

    def excludes(self, record=None, actor_id=None, **kwargs):
        """Exclude needs to prevent self-actions."""
        if record is None or actor_id is None:
            return []
        if actor_id == record.id:
            return [UserNeed(record.id)]
        return []


class IfGroupNotManaged(ConditionalGenerator):
    """Generator for managed group access."""

    def __init__(self, then_, else_, **kwargs):
        """Constructor."""
        super().__init__(then_=then_, else_=else_, **kwargs)
        self._field_name = "is_managed"

    def _condition(self, record, **kwargs):
        """Condition to choose generators set."""
        if record is None:
            return False

        is_managed = dict_lookup(record, self._field_name)
        return not is_managed

    def query_filter(self, **kwargs):
        """Filters for queries."""
        q_not_managed = dsl.Q("match", **{self._field_name: False})
        then_query = self._make_query(self.then_, **kwargs)
        else_query = self._make_query(self.else_, **kwargs)
        identity = kwargs.get("identity", None)
        if identity:
            permission = Permission(*self.needs(**kwargs))
            if permission.allows(identity):
                return else_query

        return q_not_managed & then_query


class GroupsEnabled(Generator):
    """Generator to restrict if the groups are not enabled.

    If the groups are not enabled, exclude any user for adding members of the
    param member type.

    A system process is allowed to do anything.
    """

    def __init__(self, *need_groups_enabled_types):
        """Types that need the groups enabled."""
        self.need_groups_enabled_types = need_groups_enabled_types

    def excludes(self, member_types=None, **kwargs):
        """Preventing needs."""
        member_types = member_types or {"group"}
        for m in member_types:
            if (
                m in self.need_groups_enabled_types
                and not current_app.config["USERS_RESOURCES_GROUPS_ENABLED"]
            ):
                return [any_user]
        return []


class AdministrationAction(Generator):
    def __init__(self, action):
        self.action = action

    @abstractmethod
    def _records_to_exclude(self): ...

    def needs(self, **kwargs):
        """Enabling Needs."""
        return [self.action]

    def query_filter(self, identity=None, **kwargs):
        """Not implemented at this level."""
        permission = Permission(self.action)
        if identity and permission.allows(identity):
            exclude_ids = self._records_to_exclude()
            return dsl.Q("match_all") & ~dsl.Q("terms", **{"id": exclude_ids})
        return []


class AdministrationUserAction(AdministrationAction):
    def _records_to_exclude(self):
        """."""
        return list(
            # Get users that belong to a super admin role
            {
                user.id
                for ac in ActionRoles.query_by_action(superuser_access).all()
                for user in ac.role.users
            }
            # Get users that have the super admin action atached to them
            | {au.user_id for au in ActionUsers.query_by_action(superuser_access).all()}
        )


class AdministrationGroupAction(AdministrationAction):
    def _records_to_exclude(self):
        """."""
        return list(
            {ac.role_id for ac in ActionRoles.query_by_action(superuser_access).all()}
        )


class IfSuperAdmin(ConditionalGenerator):
    """."""

    def _is_user_superadmin(self, identity):
        """Check if the current identity "provides" super admin "needs"."""
        if not identity:
            return False
        permission = Permission(superuser_access)
        return permission.allows(identity)

    def _is_role_superadmin(self, record):
        """Check if a role has superadmin access."""
        return db.session.query(
            exists(
                ActionRoles.query_by_action(superuser_access)
                .filter_by(role_id=record.id)
                .statement
            )
        ).scalar()

    def _is_record_superadmin(self, record):
        """Check if a record represents a superadmin role or user."""
        if isinstance(record.model.model_obj, Role):
            return self._is_role_superadmin(record)
        else:
            record_identity = get_identity(record.model.model_obj)
            return self._is_user_superadmin(record_identity)

    def _condition(self, record=None, identity=None, **kwargs):
        """Check if user or record has superadmin access."""
        if identity and self._is_user_superadmin(identity):
            return True

        if record is None:
            return False

        # Check if the record represents a superadmin user or role
        return self._is_record_superadmin(record)

    def query_filter(self, identity=None, **kwargs):
        """."""
        is_user_super = self._is_user_superadmin(identity)
        if is_user_super:
            return self._make_query(self.then_, idenity=identity, **kwargs)

        return self._make_query(self.else_, identity=identity, **kwargs)
