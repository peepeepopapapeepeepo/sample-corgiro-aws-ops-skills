# Event Catalog — credential-exposure-triage

The authoritative mapping from a CloudTrail `(eventSource, eventName)` tuple to **exactly one** tactic bucket, used by Step 6a. **Classification is by exact tuple only — no prefix matching, no wildcards.** The exact event-catalog tuple takes precedence over `readOnly`; an event matched to no tuple but carrying `readOnly=true` is generic `Discovery`.

**Table contract (enforced).** Every classifier row below has: one full `*.amazonaws.com` `eventSource`, one exact `eventName`, one deterministic `bucket`, and an explicit `predicate` that is either `always` or a concrete condition on request/response fields. When one API can land in two buckets depending on its fields, it appears as **two rows with mutually-exclusive predicates** — never one row with two buckets. `findings.json` carries one bucket per finding (`state-contract.md`), so the classifier must resolve to one.

**Citations.** The cited source is the service's CloudTrail-logging page or API reference. CloudTrail `eventName` equals the public API action **except** where a service records a versioned name; every versioned name in this table is verified against the service's CloudTrail page and written in full (e.g. Lambda). Names that could not be verified to an exact CloudTrail string are **not** in the classifier — they are listed separately under "Unverified candidates (not used by the classifier)".

`predicate` column resolves `succeeded`/`attempted` on top of the bucket: an event is **succeeded** when its parsed `CloudTrailEvent` JSON has no `errorCode`, else **attempted** (`outcome` in `findings.json`). The field predicates below select the *bucket*, not the outcome.

## IAM (`iam.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); action names per [IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateUser | Persistence | always |
| CreateRole | Persistence | always |
| CreateInstanceProfile | Persistence | always |
| AddRoleToInstanceProfile | PrivilegeEscalation | always |
| CreateAccessKey | Persistence | always (derived subject, Step 5) |
| CreateLoginProfile | Persistence | always |
| UpdateLoginProfile | Persistence | always |
| DeleteLoginProfile | DefenseEvasion | always |
| DeleteUser | DefenseEvasion | always |
| DeleteRole | DefenseEvasion | always |
| CreateVirtualMFADevice | Persistence | always |
| EnableMFADevice | Persistence | always |
| DeactivateMFADevice | DefenseEvasion | always |
| AttachUserPolicy | PrivilegeEscalation | always |
| AttachRolePolicy | PrivilegeEscalation | always |
| AttachGroupPolicy | PrivilegeEscalation | always |
| PutUserPolicy | PrivilegeEscalation | always |
| PutRolePolicy | PrivilegeEscalation | always |
| PutGroupPolicy | PrivilegeEscalation | always |
| AddUserToGroup | PrivilegeEscalation | always |
| DetachUserPolicy | DefenseEvasion | always (target `AWSCompromisedKeyQuarantine*` ⇒ containment-defeating, 6g) |
| DetachRolePolicy | DefenseEvasion | always (target `AWSCompromisedKeyQuarantine*` ⇒ containment-defeating, 6g) |
| DeleteUserPolicy | DefenseEvasion | always |
| CreatePolicy | PrivilegeEscalation | always |
| CreatePolicyVersion | PrivilegeEscalation | always |
| SetDefaultPolicyVersion | PrivilegeEscalation | always |
| UpdateAssumeRolePolicy | PrivilegeEscalation | always |
| CreateSAMLProvider | Persistence | always |
| CreateOpenIDConnectProvider | Persistence | always |
| UploadSSHPublicKey | Persistence | always |
| CreateServiceSpecificCredential | Persistence | always |
| UpdateAccessKey | DefenseEvasion | always (`requestParameters.status=Active` ⇒ reactivation, containment-defeating, 6g) |
| DeleteAccessKey | DefenseEvasion | always |
| UpdateAccountPasswordPolicy | DefenseEvasion | always (containment-defeating, 6g) |
| DeleteAccountPasswordPolicy | DefenseEvasion | always (containment-defeating, 6g) |
| GenerateCredentialReport | Discovery | always |

## STS (`sts.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); [STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| AssumeRole | InitialAccess | always (hop; `responseElements.credentials.accessKeyId` = ASIA) |
| GetFederationToken | InitialAccess | always (Step 0 branch C) |
| GetSessionToken | InitialAccess | always (Step 0 branch C) |
| GetCallerIdentity | Discovery | always |

## Sign-in (`signin.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) (`signin.amazonaws.com/ConsoleLogin`).

| eventName | bucket | predicate |
|---|---|---|
| ConsoleLogin | InitialAccess | always (`additionalEventData.MFAUsed=No` raises confidence; `userIdentity.type=Root` ⇒ root runbook, 6e/6f) |

## EC2 (`ec2.amazonaws.com`)
Source: [Amazon EC2 API reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-api.html).

| eventName | bucket | predicate |
|---|---|---|
| RunInstances | PrivilegeEscalation | `requestParameters.iamInstanceProfile` present |
| RunInstances | ResourceAbuse | `requestParameters.iamInstanceProfile` absent |
| RequestSpotInstances | ResourceAbuse | always |
| CreateFleet | ResourceAbuse | always |
| StopInstances | Impact | always |
| TerminateInstances | Impact | always |
| CreateVolume | Impact | always |
| AttachVolume | Impact | always |
| DetachVolume | Impact | always |
| DeleteVolume | Impact | always |
| CreateSnapshot | Persistence | always (lifecycle-paired in 6b; sharing is a later ModifySnapshotAttribute) |
| DeleteSnapshot | Impact | always |
| ModifySnapshotAttribute | Exfiltration | `requestParameters.createVolumePermission.add` present |
| ModifySnapshotAttribute | DefenseEvasion | `requestParameters.createVolumePermission.add` absent |
| ModifyImageAttribute | Exfiltration | `requestParameters.launchPermission.add` present |
| DeregisterImage | Impact | always |
| CreateKeyPair | Persistence | always |
| ImportKeyPair | Persistence | always |
| DeleteKeyPair | Impact | always |
| CreateSecurityGroup | DefenseEvasion | always |
| DeleteSecurityGroup | DefenseEvasion | always |
| AuthorizeSecurityGroupIngress | InitialAccess | always |
| ModifyInstanceAttribute | DefenseEvasion | always |
| AssociateIamInstanceProfile | PrivilegeEscalation | always |
| GetPasswordData | CredentialAccess | always |
| GetConsoleOutput | CredentialAccess | always (member role denies) |
| GetConsoleScreenshot | CredentialAccess | always (member role denies) |
| DeleteFlowLogs | DefenseEvasion | always |

> `CreateAutoScalingGroup` is `autoscaling.amazonaws.com`, not `ec2.amazonaws.com` — see Auto Scaling below.

## Auto Scaling (`autoscaling.amazonaws.com`)
Source: [Amazon EC2 Auto Scaling API reference](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateAutoScalingGroup | ResourceAbuse | always |

## EC2 Instance Connect (`ec2-instance-connect.amazonaws.com`)
Source: [EC2 Instance Connect API reference](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| SendSSHPublicKey | InitialAccess | always (triggers instance-session review, Step 5) |
| SendSerialConsoleSSHPublicKey | InitialAccess | always |
| OpenTunnel | InitialAccess | always |

## SSM (`ssm.amazonaws.com`)
Source: [AWS Systems Manager API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| SendCommand | Impact | always (parameters redacted in CloudTrail; content via handoff) |
| StartSession | InitialAccess | always |
| GetParameter | CredentialAccess | always (member role denies) |
| GetParameters | CredentialAccess | always (member role denies) |
| GetParametersByPath | CredentialAccess | always (member role denies) |

## Secrets Manager (`secretsmanager.amazonaws.com`)
Source: [Secrets Manager API reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| GetSecretValue | CredentialAccess | always (member role denies; attempts still log) |
| BatchGetSecretValue | CredentialAccess | always (member role denies; attempts still log) |
| PutSecretValue | Impact | always |
| DeleteSecret | Impact | always |

## KMS (`kms.amazonaws.com`)
Source: [AWS KMS API reference](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| Decrypt | CredentialAccess | always (member role denies; attempts log) |
| ScheduleKeyDeletion | Impact | always |
| DeleteImportedKeyMaterial | Impact | always |
| CancelKeyDeletion | DefenseEvasion | always |
| DisableKey | Impact | always |
| CreateKey | Persistence | always |
| CreateAlias | Persistence | always |
| DeleteAlias | DefenseEvasion | always |
| PutKeyPolicy | PrivilegeEscalation | always (can grant external principals) |

## S3 (`s3.amazonaws.com`)
Source: [Logging S3 API calls with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html) (management events only; object reads are **data events** — see NOT-events).

| eventName | bucket | predicate |
|---|---|---|
| CreateBucket | ResourceAbuse | always |
| DeleteBucket | Impact | always |
| PutBucketPolicy | Exfiltration | always (can expose data to external principals) |
| PutBucketAcl | Exfiltration | always |
| PutAccountPublicAccessBlock | DefenseEvasion | always |
| PutBucketReplication | Exfiltration | always |
| PutBucketLifecycle | Impact | always (expiry = destruction) |
| PutBucketEncryption | Impact | always |
| PutBucketVersioning | DefenseEvasion | always (`requestParameters.VersioningConfiguration.Status=Suspended` ⇒ disabling recovery) |

## RDS (`rds.amazonaws.com`)
Source: [Amazon RDS API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateDBSnapshot | Persistence | always (lifecycle-paired; sharing is a later ModifyDBSnapshotAttribute) |
| ModifyDBSnapshotAttribute | Exfiltration | `requestParameters.valuesToAdd` contains `all` or an external account |
| ModifyDBClusterSnapshotAttribute | Exfiltration | `requestParameters.valuesToAdd` contains `all` or an external account |
| DeleteDBSnapshot | Impact | always |
| RestoreDBInstanceFromDBSnapshot | Exfiltration | always |
| StartExportTask | Exfiltration | always |
| DeleteDBInstance | Impact | always |
| DeleteDBCluster | Impact | always |
| DeleteDBSubnetGroup | Impact | always |
| ModifyDBInstance | DefenseEvasion | `requestParameters.publiclyAccessible=true` |

## DynamoDB (`dynamodb.amazonaws.com`)
Source: [DynamoDB API reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| DeleteTable | Impact | always (item ops are data events — NOT-events) |

## Backup (`backup.amazonaws.com`)
Source: [AWS Backup API reference](https://docs.aws.amazon.com/aws-backup/latest/devguide/api-reference.html).

| eventName | bucket | predicate |
|---|---|---|
| DeleteRecoveryPoint | Impact | always |

## Lambda (`lambda.amazonaws.com`)
Source: [Logging Lambda API calls using CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html). CloudTrail records **versioned** event names; every name below is the exact CloudTrail `eventName` from that page (verified).

| eventName | bucket | predicate |
|---|---|---|
| CreateFunction20150331 | Persistence | always |
| UpdateFunctionCode20150331v2 | Persistence | always (code swap) |
| AddPermission20150331v2 | PrivilegeEscalation | always (resource-policy grant) |
| GetFunction20150331v2 | CredentialAccess | always (returns env vars; member role denies GetFunction) |
| CreateEventSourceMapping20150331 | Persistence | always (trigger wiring) |

## EventBridge (`events.amazonaws.com`)
Source: [EventBridge API reference](https://docs.aws.amazon.com/eventbridge/latest/APIReference/Welcome.html). **eventSource trap:** `events.amazonaws.com` is EventBridge.

| eventName | bucket | predicate |
|---|---|---|
| PutRule | Persistence | always |
| PutTargets | Persistence | always |
| DisableRule | DefenseEvasion | always |
| RemoveTargets | DefenseEvasion | always |

## CloudTrail (`cloudtrail.amazonaws.com`)
Source: [CloudTrail API reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html). Disabling logging does **not** erase Event history itself.

| eventName | bucket | predicate |
|---|---|---|
| StopLogging | DefenseEvasion | always |
| DeleteTrail | DefenseEvasion | always |
| UpdateTrail | DefenseEvasion | always |
| PutEventSelectors | DefenseEvasion | always |
| DeleteEventDataStore | DefenseEvasion | always |

## GuardDuty (`guardduty.amazonaws.com`)
Source: [GuardDuty API reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| DeleteDetector | DefenseEvasion | always |
| UpdateDetector | DefenseEvasion | always |
| ArchiveFindings | DefenseEvasion | always |
| DisassociateFromAdministratorAccount | DefenseEvasion | always |
| CreateIPSet | DefenseEvasion | always (allowlisting attacker IPs) |

## Config (`config.amazonaws.com`)
Source: [AWS Config API reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| StopConfigurationRecorder | DefenseEvasion | always |
| DeleteConfigurationRecorder | DefenseEvasion | always |
| DeleteDeliveryChannel | DefenseEvasion | always |

## Security Hub (`securityhub.amazonaws.com`)
Source: [Security Hub API reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| DisableSecurityHub | DefenseEvasion | always |

## CloudWatch (`monitoring.amazonaws.com`)
Source: [CloudWatch API reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/Welcome.html). **eventSource trap:** CloudWatch alarms are `monitoring.amazonaws.com`.

| eventName | bucket | predicate |
|---|---|---|
| DisableAlarmActions | DefenseEvasion | always |
| DeleteAlarms | DefenseEvasion | always |

## CloudWatch Logs (`logs.amazonaws.com`)
Source: [CloudWatch Logs API reference](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/Welcome.html). **eventSource trap:** Logs are `logs.amazonaws.com`.

| eventName | bucket | predicate |
|---|---|---|
| DeleteLogGroup | DefenseEvasion | always |

## Bedrock (`bedrock.amazonaws.com`)
Source: [Logging Bedrock API calls with CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html).

| eventName | bucket | predicate |
|---|---|---|
| InvokeModel | ResourceAbuse | always (LLMjacking) |
| InvokeModelWithResponseStream | ResourceAbuse | always |
| Converse | ResourceAbuse | always |
| ConverseStream | ResourceAbuse | always |
| PutFoundationModelEntitlement | ResourceAbuse | always |
| CreateFoundationModelAgreement | ResourceAbuse | always |
| DeleteModelInvocationLoggingConfiguration | DefenseEvasion | always |

## SQS (`sqs.amazonaws.com`)
Source: [SQS API reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| PurgeQueue | Impact | always |
| DeleteQueue | Impact | always |

## SNS (`sns.amazonaws.com`)
Source: [SNS API reference](https://docs.aws.amazon.com/sns/latest/api/welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| DeleteTopic | Impact | always |
| GetSMSAttributes | Discovery | always (SMS-pumping recon) |

## SES v2 (`ses.amazonaws.com`)
Source: [SES v2 API reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| VerifyEmailIdentity | Persistence | always (phishing-sender setup) |
| GetSendQuota | Discovery | always (spam-capacity recon) |

## ECR (`ecr.amazonaws.com`)
Source: [ECR API reference](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| GetAuthorizationToken | CredentialAccess | always (registry creds) |

## ECS (`ecs.amazonaws.com`)
Source: [ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| RunTask | ResourceAbuse | always |
| CreateService | ResourceAbuse | always |
| RegisterTaskDefinition | PrivilegeEscalation | `requestParameters.taskRoleArn` present |
| RegisterTaskDefinition | ResourceAbuse | `requestParameters.taskRoleArn` absent |

## EKS (`eks.amazonaws.com`)
Source: [EKS API reference](https://docs.aws.amazon.com/eks/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateCluster | ResourceAbuse | always |

## Batch (`batch.amazonaws.com`)
Source: [AWS Batch API reference](https://docs.aws.amazon.com/batch/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| SubmitJob | ResourceAbuse | always |

## CodeBuild (`codebuild.amazonaws.com`)
Source: [CodeBuild API reference](https://docs.aws.amazon.com/codebuild/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateProject | PrivilegeEscalation | always (build role abuse) |
| StartBuild | ResourceAbuse | always |

## Glue (`glue.amazonaws.com`)
Source: [AWS Glue API reference](https://docs.aws.amazon.com/glue/latest/webapi/API_Operations.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateJob | PrivilegeEscalation | always (job role abuse) |

## CloudFormation (`cloudformation.amazonaws.com`)
Source: [CloudFormation API reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateStack | PrivilegeEscalation | `requestParameters.roleARN` present |
| CreateStack | ResourceAbuse | `requestParameters.roleARN` absent |
| DeleteStack | Impact | always |

## Route 53 (`route53.amazonaws.com`)
Source: [Route 53 API reference](https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| ChangeResourceRecordSets | Impact | always (DNS hijack / redirect) |

## RAM (`ram.amazonaws.com`)
Source: [RAM API reference](https://docs.aws.amazon.com/ram/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| CreateResourceShare | Exfiltration | always (share resources to attacker account) |

## Organizations (`organizations.amazonaws.com`)
Source: [Organizations API reference](https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html).

| eventName | bucket | predicate |
|---|---|---|
| LeaveOrganization | Impact | always |
| CreateAccount | ResourceAbuse | always |
| InviteAccountToOrganization | Persistence | always |
| AcceptHandshake | Persistence | always |
| DetachPolicy | DefenseEvasion | always (SCP removal) |

## Account Management (`account.amazonaws.com`)
Source: [Account Management API reference](https://docs.aws.amazon.com/accounts/latest/reference/welcome.html). **eventSource trap:** the Account service is `account.amazonaws.com`.

| eventName | bucket | predicate |
|---|---|---|
| EnableRegion | ResourceAbuse | always (opt-in region for mining) |

## NOT-events (never list these as management activity)
- `PassRole` — a **permission**, not an API event; classify escalation via the role fields on `RunInstances` / `ecs:RegisterTaskDefinition` / `CreateStack` (predicates above), not by looking for a `PassRole` event.
- `GenerateDbAuthToken` — client-side RDS IAM-auth token generation; **no CloudTrail event** is emitted.
- S3 `GetObject` / Lambda `Invoke` / DynamoDB item operations (`GetItem` / `Query` / `Scan` / …) — **data events**, absent from Event history. Record as `not-observable`, never "none" ([logging data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)).

## eventSource traps (do not key off the service short name)
| eventSource | is actually |
|---|---|
| monitoring.amazonaws.com | CloudWatch (alarms) |
| events.amazonaws.com | EventBridge |
| signin.amazonaws.com | console sign-in |
| account.amazonaws.com | Account Management |
| logs.amazonaws.com | CloudWatch Logs |
| autoscaling.amazonaws.com | EC2 Auto Scaling |

## Unverified candidates (NOT used by the classifier)
These were considered but their exact CloudTrail `(eventSource, eventName)` strings could not be verified against an authoritative CloudTrail page at authoring time. The classifier MUST NOT match on them. A maintainer may promote a row into the tables above only after verifying the exact recorded `eventName` on the service's CloudTrail-logging page and adding a citation. If such an event appears at run time and carries `readOnly=true`, it falls through to generic `Discovery`; otherwise it is reported as an unclassified mutation for operator review (never silently bucketed).

- API Gateway v2 (`apigateway.amazonaws.com`): `CreateApi`, `CreateRoute`, `CreateIntegration`, `CreateStage` — the exact v2 CloudTrail `eventName` strings are not confirmed (the API Gateway CloudTrail doc covers REST-API logging). Candidate bucket: Persistence (backdoor HTTP API).
- SageMaker / Lightsail / Amplify create calls — exact CloudTrail names unverified. Candidate bucket: ResourceAbuse (compute for mining).
- Account Management `PutContactInformation` / `PutAlternateContact` — exact CloudTrail names unverified. Candidate bucket: Impact (contact hijack).

## Static lifecycle follow-up table (Step 6b / 6c; read-only; ID-only substitution)
Each row has **all** mandatory fields (per Step 6b's contract): exact `(source, create eventName)`; the `delete pair eventName` whose matching resource ID closes the lifecycle; the success predicate; the resource-ID JSON path; the **pair key** (the field whose equality pairs create/delete); the account/Region source; the read-only follow-up argv template (ID-only substitution); and the ID regex validated before substitution. A row missing any field prohibits pairing and follow-up.

| source | create eventName | delete pair eventName | success predicate | resource-ID JSON path | pair key | account/Region source | read-only follow-up (argv) | ID regex |
|---|---|---|---|---|---|---|---|---|
| iam.amazonaws.com | CreateAccessKey | DeleteAccessKey | no `errorCode` | `responseElements.accessKey.accessKeyId` | accessKeyId (matched by sha256) | event `recipientAccountId`; IAM global (no Region) | `iam list-access-keys --user-name <userName>` then match the row by `sha256` (never pass a masked key to `--access-key-id`) | user name `^[\w+=,.@-]{1,64}$` |
| iam.amazonaws.com | CreateUser | DeleteUser | no `errorCode` | `responseElements.user.userName` | userName | event `recipientAccountId`; IAM global | `iam get-user --user-name <ID>` | `^[\w+=,.@-]{1,64}$` |
| iam.amazonaws.com | CreateRole | DeleteRole | no `errorCode` | `responseElements.role.roleName` | roleName | event `recipientAccountId`; IAM global | `iam get-role --role-name <ID>` | `^[\w+=,.@-]{1,64}$` |
| iam.amazonaws.com | CreatePolicy | DeletePolicy | no `errorCode` | `responseElements.policy.arn` | policyArn | event `recipientAccountId`; IAM global | `iam get-policy --policy-arn <ID>` | `^arn:aws[\w-]*:iam::[0-9]{12}:policy/[\w+=,.@/-]{1,128}$` |
| kms.amazonaws.com | CreateKey | ScheduleKeyDeletion | no `errorCode` | `responseElements.keyMetadata.keyId` | keyId | event `recipientAccountId` + `awsRegion` | `kms describe-key --key-id <ID>` (DeletionDate, cancel-before) | `^[0-9a-f-]{36}$` |
| ec2.amazonaws.com | CreateSnapshot | DeleteSnapshot | no `errorCode` | `responseElements.snapshotId` | snapshotId | event `recipientAccountId` + `awsRegion` | `ec2 describe-snapshots --owner-ids self --snapshot-ids <ID>` then `describe-snapshot-attribute --attribute createVolumePermission --snapshot-id <ID>` | `^snap-[0-9a-f]{8,17}$` |
| ec2.amazonaws.com | AssociateIamInstanceProfile | DisassociateIamInstanceProfile | no `errorCode` | `requestParameters.associateIamInstanceProfileRequest.instanceId` | instanceId | event `recipientAccountId` + `awsRegion` | `ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values=<ID>` | `^i-[0-9a-f]{8,17}$` |
| rds.amazonaws.com | StartExportTask | (no delete pair; one-shot export) | no `errorCode` | `responseElements.exportTaskIdentifier` | exportTaskIdentifier | event `recipientAccountId` + `awsRegion` | `rds describe-export-tasks --export-task-identifier <ID>` | `^[\w-]{1,255}$` |
| ssm.amazonaws.com | SendCommand | (no delete pair; command lifecycle) | no `errorCode` | `responseElements.command.commandId` | commandId | event `recipientAccountId` + `awsRegion` | `ssm list-commands --command-id <ID>` (metadata only; never get-command-invocation) | `^[0-9a-f-]{36}$` |
| lambda.amazonaws.com | CreateFunction20150331 | DeleteFunction20150331 | no `errorCode` | `requestParameters.functionName` | functionName | event `recipientAccountId` + `awsRegion` | `lambda list-functions` then `lambda get-policy --function-name <ID>` (GetFunction denied) | `^[\w-]{1,140}$` |
| logs.amazonaws.com | CreateLogGroup | DeleteLogGroup | no `errorCode` | `requestParameters.logGroupName` | logGroupName | event `recipientAccountId` + `awsRegion` | `logs describe-log-streams --log-group-name <ID>` (timestamps only; FilterLogEvents/GetLogEvents denied) | `^[\w./#-]{1,512}$` |
| cloudformation.amazonaws.com | CreateStack | DeleteStack | no `errorCode` | `requestParameters.stackName` | stackName | event `recipientAccountId` + `awsRegion` | `cloudformation describe-stacks --stack-name <ID>` (StackSet enumeration needs delegated-admin authority; else not observable) | `^[\w-]{1,128}$` |
| cloudtrail.amazonaws.com | PutEventSelectors | (config change; no delete pair) | no `errorCode` | `requestParameters.trailName` | trailName | event `recipientAccountId` + `awsRegion` | `cloudtrail get-event-selectors --trail-name <ID>` (does any trail log S3 data events?) | `^[\w._-]{3,128}$` |

## Signal-3 high-signal EventNames (~20; discovery path only)
Rare, high-signal mutations to sample one page each per named account/region pair (Step 1b Signal 3). All are exact classifier tuples above:

`CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, `AttachUserPolicy`, `PutUserPolicy`, `CreateUser`, `DeactivateMFADevice`, `UpdateAccountPasswordPolicy`, `CreateSAMLProvider`, `CreateOpenIDConnectProvider`, `GetFederationToken`, `ModifySnapshotAttribute`, `ModifyImageAttribute`, `PutBucketPolicy`, `CreateKeyPair`, `RunInstances`, `StopLogging`, `DeleteTrail`, `CreateIPSet`, `DeleteModelInvocationLoggingConfiguration`.

(Handoff argv templates with per-type regexes are defined in [`step-7-report-handoff.md`](step-7-report-handoff.md) → "Handoff command templates".)
