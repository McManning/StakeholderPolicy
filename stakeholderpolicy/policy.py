#!/usr/bin/env python
# -*- coding: utf-8 -*-
#

#
# Copyright (C) 2015 Chase McManning <cmcmanning@gmail.com>
#
# Some code adapted from tracopt.perm.authz_policy.py 
# Copyright (C) 2007 Alec Thomas <alec@swapoff.org>
#
# Licensed under the same license as Trac
# http://trac.edgewall.org/wiki/TracLicense
#

import os

from fnmatch import fnmatchcase # Unix shell-style wildcard (*, ?, [seq], [!seq]) matching

from trac.core import *
from trac.config import Option, ConfigurationError
from trac.perm import IPermissionPolicy, IPermissionGroupProvider, PermissionSystem

from trac.ticket.model import Ticket

from trac.util import lazy
from trac.util.text import to_unicode

from configobj import ConfigObj, ConfigObjError

class StakeholderPolicy(Component):
    """Trac permission policy to give limited fine-grained access to non-developer project stakeholders.

    Designed for a specific workflow, this policy allows access to reports, tickets, wiki pages,
    and milestones based on pattern matching the requested resources. This is to limit the scope
    of access for stakeholder users to specific areas of the Trac environment (i.e., tickets
    and wiki documentation that only affect the projects they are stakeholders on). Specifying 
    discrete access permissions within each available realm (i.e., TICKET_CREATE permissions) 
    is still done with an external policy (such as AuthzPolicy or DefaultPermissionPolicy) but 
    this will automatically deny privilege to anything outside of specified patterns. 

    === Installation ===
    Add to trac.ini:

        [components]
        stakeholderpolicy.* = enabled

        [stakeholder_policy]
        stakeholder_file = /path/to/configs/stakeholderpolicy.conf

        [trac]
        permission_policies = StakeholderPolicy, DefaultPermissionPolicy

    === Configuration ===
    The stakeholderpolicy.conf is a .ini style configuration file.

    - Each section of the config file is a permission group, to be matched with the current user.
        The FIRST group found is the one that will be used for access checking. So take care of
        order if a user is within multiple permission groups. Groups not specified by this file 
        will default to relying on other policies to determine access.
    - Keys in each section specify Trac realms, with each behaving slightly differently.
        milestone - Comma separated list of glob patterns for milestone titles. Additionally, 
            ticket access will be restricted to those that fall under an allowed milestone. 
            e.g., `milestone = Buck-IRB *, Common *` will provide access to both the milestone 
            and tickets for Buck-IRB 1.8, Buck-IRB 1.9, Buck-IRB Backlog, Common 1.0, etc. 
        wiki - Comma separated list of glob patterns for wiki paths. 
            e.g., `wiki = Projects/Buck-IRB*, Public/*` will match Projects/Buck-IRB, 
            Projects/Buck-IRB/Issues, as well as the Public/Contact and Public/AboutUs pages.
        attachment - NOT YET SUPPORTED (only if attached to a milestone/wiki page with the appropriate ruleset?)
        changeset, source, repository - NOT YET SUPPORTED

    Example configuration (where buckirb_stakeholders and coi_stakeholders were defined 
    via another policy or via trac-admin):
        
        [buckirb_stakeholders]
        milestone = Buck-IRB*
        wiki = Projects/Buck-IRB*, Public*

        [coi_stakeholders]
        milestone = COI*, Trustees COI*
        wiki = Projects/COI*, Projects/Trustees COI*, Public*

    """
    implements(IPermissionPolicy)

    group_providers = ExtensionPoint(IPermissionGroupProvider)

    config_file = Option('stakeholder_policy', 'stakeholder_file', '',
                            "Location of the stakeholder policy configuration file. "
                            "Non-absolute paths are relative to the "
                            "Environment `conf` directory.")

    config = None
    config_mtime = None # Track and determine whether we should reload the policy config

    def __init__(self):
        if not self.config_file:
            raise ConfigurationError(message="The `[stakeholder_policy] stakeholder_file` configuration "
                                    "option in trac.ini is empty or not defined.")

        try:
            os.stat(self.config_file)
        except OSError as e:
            raise ConfigurationError(message="Error parsing stakeholder permission policy file: %s" % to_unicode(e))

    # IPermissionPolicy methods

    def check_permission(self, action, username, resource, perm):
        """
            username being a string of whomever
            action being a WIKI_CREATE, TICKET_VIEW, etc. 
            permission being a string: view, create, ...
        """
        # Refresh config, if it changed on disk
        if not self.config_mtime or os.path.getmtime(self._get_config_file) != self.config_mtime:
            self._parse_config()

        if resource and resource.id:
            if resource.realm == 'wiki':
                return self._check_wiki_permission(username, resource, perm)
            elif resource.realm == 'milestone':
                return self._check_milestone_permission(username, resource, perm)
            else:
                # Dig for a ticket
                # Common plugin behavior, what about the other resource types? Same thing?
                while resource:
                    if resource.realm == 'ticket':
                        break
                    resource = resource.parent

                if resource and resource.realm == 'ticket' and resource.id:
                    return self._check_ticket_permission(username, resource, perm)

        # I don't know what this resource is, or don't care. 
        # Delegate to another policy
        return None


    # Internal methods

    @lazy
    def _get_config_file(self):
        if not self.config_file:
            self.log.error('The `[stakeholder_policy] stakeholder_file` configuration '
                           'option in trac.ini is empty or not defined.')
            raise ConfigurationError()

        config_file = self.config_file if os.path.isabs(self.config_file) \
                                     else os.path.join(self.env.path,
                                                       self.config_file)
        try:
            os.stat(config_file)
        except OSError, e:
            self.log.error("Error parsing stakeholder policy file: %s" % to_unicode(e))
            raise ConfigurationError()

        return config_file

    def _parse_config(self):
        if ConfigObj is None:
            self.log.error("ConfigObj package not found.")
            raise ConfigurationError()

        #f = '/var/trac/projects/orissandbox/conf/stakeholderpolicy.conf'
        self.log.debug("Parsing stakeholder security policy %s" % self.config_file)

        try:
            self.config = ConfigObj(self._get_config_file, encoding='utf8',
                                   raise_errors=True)
        except ConfigObjError, e:
            self.log.error("Error parsing stakeholder policy file: %s" % to_unicode(e))
            raise ConfigurationError()

        #f = self.config_file
        #self.config = ConfigObj(f)
        self.config_mtime = os.path.getmtime(self._get_config_file)


    def _check_wiki_permission(self, username, resource, perm):
        """
        Resource.id being the wiki path (eg: /Projects/Buck-IRB)
        """
        glob_patterns = self._get_glob_patterns(username, 'wiki')
        if resource and resource.id and glob_patterns:

            found = False
            for glob_pattern in glob_patterns:
                if fnmatchcase(resource.id, glob_pattern):
                    found = True
                    break

            if not found: # We don't have access at all
                return False

        # Invalid resource, or we have access. Either way, delegate
        # further permission checking to other policies
        return None
        

    def _check_ticket_permission(self, username, resource, perm):
        """
        Resource.id being the ticket ID (eg: 1234)
        """
        try:
            ticket = Ticket(self.env, resource.id)
        except TracError:
            return None # Ticket does not exist, let Trac figure that out for itself

        glob_patterns = self._get_glob_patterns(username, 'milestone')
        if ticket and glob_patterns:

            found = False
            for glob_pattern in glob_patterns:
                if fnmatchcase(ticket['milestone'], glob_pattern):
                    found = True
                    break

            if not found: # We don't have access at all
                return False

        # Bad ticket, or we have access. Either way, delegate
        # further permission checking to other policies
        return None


    def _check_milestone_permission(self, username, resource, perm):
        """
        Resource.id being the milestone title (eg: Buck-IRB 1.8)
        """
        glob_patterns = self._get_glob_patterns(username, 'milestone')
        if resource and resource.id and glob_patterns:

            found = False
            for glob_pattern in glob_patterns:
                if fnmatchcase(resource.id, glob_pattern):
                    found = True
                    break

            if not found: # We don't have access at all
                return False

        # Invalid resource, or we have access. Either way, delegate
        # further permission checking to other policies
        return None


    def _get_groups(self, username):
        """Return set of all groups the user is in across providers. """

        groups = set([username])
        for provider in self.group_providers:
            for group in provider.get_permission_groups(username):
                groups.add(group)
        
        # TODO: Necessary? What is this for?
        perms = PermissionSystem(self.env).get_all_permissions()
        repeat = True
        while repeat:
            repeat = False
            for subject, action in perms:
                if subject in groups and action.islower() and action not in groups:
                    groups.add(action)
                    repeat = True 
       
        return groups


    def _get_glob_patterns(self, username, realm):
        """Return a list of patterns matching the users group for a specific realm.

        This will scan through our config groups. Once we find a group that the 
        user is a member of, it will pull the realm, split (comma delimited) and 
        return a list of items. If the user isn't in any group from the config, 
        or it's an invalid realm, we'll just kick back an empty list.
        """

        for group in [a for a in self.config.sections]:
            groups = self._get_groups(username)
            if group in groups: # User is in a group listed, pull up realm
                for group_realm, glob_patterns in self.config[group].iteritems():
                    if group_realm == realm:
                        #glob_patterns = to_list(glob_patterns) # Split comma-delimited list 

                        if isinstance(glob_patterns, basestring):
                            return [glob_patterns]
                        else:
                            return glob_patterns

        return [] # Nada found


