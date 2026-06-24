# About the MCP API boundary

There is a rule in Enceladus that looks, at first, like a small implementation detail: MCP tool handlers may not touch the database. A tool that needs business data must call a service API — the same `/api/v1/...` endpoints that humans and other services use — and let that API own the read or write. Reaching directly into DynamoDB or S3 from inside a tool handler is forbidden, and a CI guard fails the build if anyone tries.

This document explains why that boundary is load-bearing rather than fussy.

## Two data paths will always diverge

The MCP server is one of several ways into the system, and tools are the most tempting place to cut a corner. A handler already has AWS credentials in scope; a direct `get_item` is right there; it is faster and it works. The problem is what it quietly creates: a *second* data path.

Once a tool can read or write the database directly, the system has two ways to do the same thing — through the service API, and around it. And the two ways are never quite the same. The API path carries authorization checks, field validation, write-source attribution, and audit logging. The direct path carries whatever the handler author remembered to reimplement, which is to say: less, and drifting further apart with every change. The day someone tightens a validation rule in the API, the direct path keeps accepting the old shape. The day someone adds an audit field, the direct path stops recording it. Nobody decides this; it is the default outcome of having two paths.

The boundary exists to keep the number of data paths at one.

## A tool is just another caller

The deeper idea is that an MCP tool should hold no privilege of its own. It is not a special insider with database keys; it is a governed *caller* of the same APIs everything else uses. That framing is what makes the tool surface trustworthy: when a tool writes a task, the write is subject to exactly the permissioning, validation, and attribution that any other write is. It does not matter whether the actor on the other end is a terminal agent, a desktop session, or a browser connector — they all reach the data through one front door, and that front door behaves identically for all of them.

This is the same principle the platform applies everywhere else, expressed at the tool layer. The system has [one write path](governance-as-architecture.md), and the API boundary is what stops the MCP server from becoming a second one.

## The cost, and why it is worth it

The boundary costs a network hop. A tool that could read DynamoDB in a millisecond instead makes an authenticated API call, and that latency is real. The trade accepted here is the same one accepted throughout Enceladus: a little overhead in exchange for the guarantee that there is exactly one place where correctness lives, and it is enforced the same way for everyone. A consistent system that is slightly slower beats a fast system whose behavior depends on which door you came in through.

The mechanics — which CI workflow enforces this and which script implements the check — are described in [repository operations](../reference/repository-operations.md).
