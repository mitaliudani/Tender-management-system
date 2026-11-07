# Public reference backend: limited defensive source review

**Date:** 8 November 2026  
**Method:** Read-only inspection of publicly visible Java source. No requests were sent to an application, database, account, or deployment.

## Provenance and scope

The JSP and SQL files in this repository's original upload have identical Git blob hashes to files in [shashirajraja/Tender-Management-System](https://github.com/shashirajraja/Tender-Management-System). Other GitHub repositories contain duplicate JSP files, so the precise source of the manual upload cannot be proven from Git metadata. This is an **external reference**, not Java backend code committed to this repository, and does not establish a license to redistribute it.

References below are pinned to the publicly inspected [reference revision](https://github.com/shashirajraja/Tender-Management-System/tree/815592dd53fe97562fa6f6887efc9c0244f083b0). The reference project may have changed since that revision.

## Confirmed observations

| Observation | Reference | Defensive implication |
| --- | --- | --- |
| Admin login accepts hard-coded default credentials; vendor login compares the submitted password directly against a database `password` column. | [LoginSrv.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/srv/LoginSrv.java) | Replace default login, implement salted password hashing and secure verification, and require deployment-specific secrets. |
| Successful logins store the submitted password in the HTTP session and vendor data model. | [LoginSrv.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/srv/LoginSrv.java) | Never retain raw passwords in session state; regenerate the session identifier after authentication. |
| Bid acceptance, rejection, and notice removal modify state in `doGet`; their `doPost` methods delegate to `doGet`. Their authorization redirects do not return before continuing. | [AcceptBidSrv.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/srv/AcceptBidSrv.java), [RejectBidSrv.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/srv/RejectBidSrv.java), [RemoveNoticeSrv.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/srv/RemoveNoticeSrv.java) | The new JSP POST forms are method-compatible with the reference. The proposed filter must be deployed with real handlers, and handlers should independently reject unauthorized requests and stop after denial. |
| Bid acceptance checks whether a tender is assigned before updating a bid; updates and assignment occur through separate DAO calls. | [BidderDaoImpl.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/dao/BidderDaoImpl.java) | Review transactional consistency and concurrent bid acceptance. Use database constraints and atomic transactions if the rule requires one accepted bid per tender. |
| The inspected bid/notice DAO methods use parameterized SQL statements. | [BidderDaoImpl.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/dao/BidderDaoImpl.java), [NoticeDaoImpl.java](https://github.com/shashirajraja/Tender-Management-System/blob/815592dd53fe97562fa6f6887efc9c0244f083b0/tendermanagement/src/com/hit/dao/NoticeDaoImpl.java) | Preserve prepared statements. This inspection makes no claim about other DAO methods or SQL injection across the full application. |

## Recommended sequence before any deployment

1. Establish a lawful source license or obtain permission to reuse the missing backend classes, with appropriate attribution.
2. Recover the Java classes into a **separate review branch**, without overwriting local security helpers.
3. Replace hard-coded and plaintext password handling with safe authentication, session regeneration, and authorization checks in every servlet. Review object-level ownership for vendor operations.
4. Refactor state-changing handlers so POST is enforced by both handler and filter, and apply CSRF defense to all other state changes.
5. Verify bid acceptance is transactionally safe. Escape untrusted output in the correct HTML/JavaScript contexts.
6. Add database-backed integration tests with **synthetic accounts/data**, then complete a local staging deployment review before merging into `main`.

**Status:** These backend fixes are proposed, not implemented. The security filter and JSP changes in this repository do not prove a complete or secure deployed application. This document is source-review evidence, not a vulnerability disclosure against any live third-party deployment.
