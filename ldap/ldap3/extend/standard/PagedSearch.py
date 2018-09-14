"""
"""

# Created on 2014.07.08
#
# Author: Giovanni Cannata
#
# Copyright 2014 - 2018 Giovanni Cannata
#
# This file is part of ldap3.
#
# ldap3 is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ldap3 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ldap3 in the COPYING and COPYING.LESSER files.
# If not, see <http://www.gnu.org/licenses/>.

from ... import SUBTREE, DEREF_ALWAYS
from ...utils.dn import safe_dn
from ...core.results import DO_NOT_RAISE_EXCEPTIONS, RESULT_SIZE_LIMIT_EXCEEDED
from ...core.exceptions import LDAPOperationResult
from ...utils.log import log, log_enabled, ERROR, BASIC, PROTOCOL, NETWORK, EXTENDED


def paged_search_generator(connection,
                           search_base,
                           search_filter,
                           search_scope=SUBTREE,
                           dereference_aliases=DEREF_ALWAYS,
                           attributes=None,
                           size_limit=0,
                           time_limit=0,
                           types_only=False,
                           get_operational_attributes=False,
                           controls=None,
                           paged_size=100,
                           paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    responses = []
    cookie = True  # performs search at least one time
    while cookie:
        result = connection.search(search_base,
                                   search_filter,
                                   search_scope,
                                   dereference_aliases,
                                   attributes,
                                   size_limit,
                                   time_limit,
                                   types_only,
                                   get_operational_attributes,
                                   controls,
                                   paged_size,
                                   paged_criticality,
                                   None if cookie is True else cookie)

        if not isinstance(result, bool):
            response, result = connection.get_response(result)
        else:
            response = connection.response
            result = connection.result

        responses.extend(response)
        try:
            cookie = result['controls']['1.2.840.113556.1.4.319']['value']['cookie']
        except KeyError:
            cookie = None

        if result and result['result'] not in DO_NOT_RAISE_EXCEPTIONS:
            if log_enabled(PROTOCOL):
                log(PROTOCOL, 'paged search operation result <%s> for <%s>', result, connection)
            if result['result'] == RESULT_SIZE_LIMIT_EXCEEDED:
                while responses:
                    yield responses.pop()
            raise LDAPOperationResult(result=result['result'], description=result['description'], dn=result['dn'], message=result['message'], response_type=result['type'])

        while responses:
            yield responses.pop()

    connection.response = None


def paged_search_accumulator(connection,
                             search_base,
                             search_filter,
                             search_scope=SUBTREE,
                             dereference_aliases=DEREF_ALWAYS,
                             attributes=None,
                             size_limit=0,
                             time_limit=0,
                             types_only=False,
                             get_operational_attributes=False,
                             controls=None,
                             paged_size=100,
                             paged_criticality=False):
    if connection.check_names and search_base:
        search_base = safe_dn(search_base)

    responses = []
    for response in paged_search_generator(connection,
                                           search_base,
                                           search_filter,
                                           search_scope,
                                           dereference_aliases,
                                           attributes,
                                           size_limit,
                                           time_limit,
                                           types_only,
                                           get_operational_attributes,
                                           controls,
                                           paged_size,
                                           paged_criticality):
        responses.append(response)

    connection.response = responses
    return responses
