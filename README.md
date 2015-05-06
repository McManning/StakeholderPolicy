# StakeholderPolicy
Trac permission policy to give limited fine-grained access to non-developer project stakeholders.

Designed for a specific workflow, this policy allows access to reports, tickets, wiki pages,
and milestones based on pattern matching the requested resources. This is to limit the scope
of access for stakeholder users to specific areas of the Trac environment (i.e., tickets
and wiki documentation that only affect the projects they are stakeholders on). Specifying 
discrete access permissions within each available realm (i.e., TICKET_CREATE permissions) 
is still done with an external policy (such as AuthzPolicy or DefaultPermissionPolicy) but 
this will automatically deny privilege to anything outside of specified patterns. 

## Installation
Add to trac.ini:

    [components]
    stakeholderpolicy.* = enabled

    [stakeholder_policy]
    stakeholder_file = /path/to/configs/stakeholderpolicy.conf

    [trac]
    permission_policies = StakeholderPolicy, DefaultPermissionPolicy

## Configuration
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
