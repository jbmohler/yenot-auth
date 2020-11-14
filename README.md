# Introduction

This builds on the yenot server framework with an authentication framework and
a basic declarative data structure for describing an end-point to the client.

# Authentication

Provides a user add/remove and authentication end-point.

# Permissions & Roles

Provides role add/remove and end-points to assign users to roles and end-points
to roles.  In this way, users can be assigned to 1 or more roles and gain
access to related groups of end-points.

# Declarative structure for Reports (aka end-points)

Yenot end-points can be annotated with `report_prompts` and `report_sidebars`
which describe to a client what kind of input widgets to use in a generic
reporting client.  The sidebars describe to the client what related data a user
may want to see when looking at a report.

Idealistic dreams aside, this basically provides a language on which a client
application and Yenot extension server can use to agree on inputs and
structured views of output.
