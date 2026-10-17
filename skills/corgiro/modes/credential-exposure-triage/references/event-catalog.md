# Event Catalog — credential-exposure-triage

The authoritative mapping from a CloudTrail `(eventSource, eventName)` tuple to a tactic bucket, used by Step 6a. **Classification is by exact tuple only — no prefix matching.** The exact event-catalog tuple takes precedence over `readOnly`; an event matched to no tuple but carrying `readOnly=true` is generic `Discovery`.

**How to read the citations.** For most AWS services the CloudTrail `eventName` equals the public API action, so the cited source is that service's API reference or its "Logging … with CloudTrail" page. Where an event name is **versioned or non-obvious** (Lambda, API Gateway v2), the exact string is flagged "confirm exact eventName at run time" — do not assert it from memory (MODE.md / CONTRIBUTING: every API fact is cited or labelled unverified). A coder/tester verifying this catalog should spot-check tuples against the cited page.

`success predicate`: an event counts as **succeeded** when its parsed `CloudTrailEvent` JSON has no `errorCode`; otherwise it is **attempted** (`outcome` in `findings.json`).

## IAM (`iam.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); action names per [IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html).

| eventName | bucket | notes |
|---|---|---|
| CreateUser, CreateRole, CreateInstanceProfile, AddRoleToInstanceProfile | Persistence | new principal/compute identity; watchlist (6c) |
| CreateAccessKey | Persistence | derived subject (Step 5); attacker key |
| CreateLoginProfile, UpdateLoginProfile | Persistence | console password added/changed |
| DeleteLoginProfile, DeleteUser, DeleteRole | DefenseEvasion | may be cleanup or lockout (6c) |
| CreateVirtualMFADevice, EnableMFADevice, DeactivateMFADevice | Persistence | MFA tampering; Deactivate also DefenseEvasion |
| AttachUserPolicy, AttachRolePolicy, AttachGroupPolicy, PutUserPolicy, PutRolePolicy, PutGroupPolicy, AddUserToGroup | PrivilegeEscalation | grants; parse policyDocument for Deny in 6c |
| DetachUserPolicy, DetachRolePolicy, DeleteUserPolicy | DefenseEvasion | detaching quarantine ⇒ containment-defeating (6g) |
| CreatePolicy, CreatePolicyVersion, SetDefaultPolicyVersion | PrivilegeEscalation | policy body/version swap |
| UpdateAssumeRolePolicy | PrivilegeEscalation | trust-policy change (backdoor) |
| CreateSAMLProvider, CreateOpenIDConnectProvider | Persistence | federation backdoor |
| UploadSSHPublicKey, CreateServiceSpecificCredential | Persistence | alternate credential channel |
| UpdateAccessKey | DefenseEvasion | reactivation ⇒ containment-defeating (6g) |
| DeleteAccessKey | DefenseEvasion | key cleanup |
| UpdateAccountPasswordPolicy, DeleteAccountPasswordPolicy | DefenseEvasion | containment-defeating (6g) |
| GenerateCredentialReport | Discovery | attacker reconnaissance |

## STS (`sts.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); [STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html).

| eventName | bucket | notes |
|---|---|---|
| AssumeRole | InitialAccess | hop (Step 5); `responseElements.credentials.accessKeyId` = ASIA |
| GetFederationToken, GetSessionToken | InitialAccess | hop; underlying user minted the token (Step 0 branch C) |
| GetCallerIdentity | Discovery | "who am I" recon |

## Sign-in (`signin.amazonaws.com`)
Source: [CloudTrail record contents](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).

| eventName | bucket | notes |
|---|---|---|
| ConsoleLogin | InitialAccess | check `additionalEventData.MFAUsed`; `userIdentity.type=Root` ⇒ root runbook (6e/6f) |

## EC2 (`ec2.amazonaws.com`)
Source: [Amazon EC2 API reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-api.html).

| eventName | bucket | notes |
|---|---|---|
| RunInstances | PrivilegeEscalation / ResourceAbuse | `iamInstanceProfile` set ⇒ escalation; else cost abuse |
| RequestSpotInstances, CreateFleet, CreateAutoScalingGroup (source `autoscaling.amazonaws.com`) | ResourceAbuse | cryptomining pattern |
| StopInstances, TerminateInstances | Impact | destruction/disruption |
| CreateVolume, AttachVolume, DetachVolume, DeleteVolume | Impact | volume tampering |
| CreateSnapshot, DeleteSnapshot, ModifySnapshotAttribute | Exfiltration / Impact | ModifySnapshotAttribute sharing externally ⇒ Exfiltration (6b) |
| ModifyImageAttribute, DeregisterImage | Exfiltration / Impact | AMI shared externally / destroyed |
| CreateKeyPair, ImportKeyPair, DeleteKeyPair | Persistence | access key pairs |
| CreateSecurityGroup, DeleteSecurityGroup, AuthorizeSecurityGroupIngress | DefenseEvasion / InitialAccess | opening ingress |
| ModifyInstanceAttribute, AssociateIamInstanceProfile | PrivilegeEscalation | attaching a role to an instance |
| GetPasswordData, GetConsoleOutput, GetConsoleScreenshot | CredentialAccess | may expose secrets (member role denies console output/screenshot) |
| DeleteFlowLogs | DefenseEvasion | log tampering |

## EC2 Instance Connect (`ec2-instance-connect.amazonaws.com`)
Source: [EC2 Instance Connect API reference](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/Welcome.html).

| eventName | bucket | notes |
|---|---|---|
| SendSSHPublicKey, SendSerialConsoleSSHPublicKey | InitialAccess | triggers instance-session review (Step 5) |
| OpenTunnel | InitialAccess | EIC Endpoint tunnel |

## SSM (`ssm.amazonaws.com`)
Source: [AWS Systems Manager API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html).

| eventName | bucket | notes |
|---|---|---|
| SendCommand, StartSession | Impact / InitialAccess | remote exec; SendCommand parameters are redacted in CloudTrail (handoff for content) |
| GetParameter, GetParameters, GetParametersByPath | CredentialAccess | SecureString values (member role denies these) |

## Secrets Manager (`secretsmanager.amazonaws.com`)
Source: [Secrets Manager API reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Operations.html).

| eventName | bucket | notes |
|---|---|---|
| GetSecretValue, BatchGetSecretValue | CredentialAccess | member role denies these; attempts still log |
| PutSecretValue | Impact | secret overwrite |
| DeleteSecret | Impact | destruction |

## KMS (`kms.amazonaws.com`)
Source: [AWS KMS API reference](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html).

| eventName | bucket | notes |
|---|---|---|
| Decrypt | CredentialAccess / Exfiltration | member role denies Decrypt; attempts log |
| ScheduleKeyDeletion, DeleteImportedKeyMaterial | Impact | data-destruction (ransom) |
| CancelKeyDeletion | DefenseEvasion | — |
| DisableKey | Impact | — |
| CreateKey, CreateAlias, DeleteAlias, PutKeyPolicy | Persistence / PrivilegeEscalation | PutKeyPolicy can grant external access |

## S3 (`s3.amazonaws.com`)
Source: [Logging S3 API calls with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging.html) (management events only; object reads are **data events** — see NOT-events).

| eventName | bucket | notes |
|---|---|---|
| CreateBucket | ResourceAbuse | staging bucket |
| DeleteBucket | Impact | — |
| PutBucketPolicy, PutBucketAcl, PutAccountPublicAccessBlock | Exfiltration / DefenseEvasion | making data public |
| PutBucketReplication | Exfiltration | replicate to attacker account |
| PutBucketLifecycle, PutBucketEncryption, PutBucketVersioning | Impact / DefenseEvasion | versioning off / lifecycle expiry = destruction |

## RDS (`rds.amazonaws.com`)
Source: [Amazon RDS API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html).

| eventName | bucket | notes |
|---|---|---|
| CreateDBSnapshot, ModifyDBSnapshotAttribute, ModifyDBClusterSnapshotAttribute | Exfiltration | snapshot shared externally (6b) |
| DeleteDBSnapshot | Impact | — |
| RestoreDBInstanceFromDBSnapshot, StartExportTask | Exfiltration | export to attacker-controlled target |
| DeleteDBInstance, DeleteDBCluster, DeleteDBSubnetGroup | Impact | destruction |
| ModifyDBInstance | DefenseEvasion / Impact | publicly-accessible flip |

## DynamoDB / Backup
Sources: [DynamoDB API reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Operations.html), [AWS Backup API reference](https://docs.aws.amazon.com/aws-backup/latest/devguide/api-reference.html).

| source | eventName | bucket | notes |
|---|---|---|---|
| dynamodb | DeleteTable | Impact | item ops are data events (NOT-events) |
| backup | DeleteRecoveryPoint | Impact | recovery destruction |

## Lambda (`lambda.amazonaws.com`)
Source: [Logging Lambda API calls using CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/with-cloudtrail.html). **Event names are versioned** (e.g. `UpdateFunctionCode20150331v2`); confirm the exact string at run time against that page.

| eventName (confirm exact string) | bucket | notes |
|---|---|---|
| CreateFunction20150331 | Persistence | — |
| UpdateFunctionCode20150331v2 | Persistence / Impact | code swap |
| AddPermission20150331v2 | PrivilegeEscalation | resource-policy grant |
| GetFunction20150331v2 | CredentialAccess | returns env vars (member role denies GetFunction) |
| CreateEventSourceMapping | Persistence | trigger wiring |

## API Gateway (`apigateway.amazonaws.com`)
Source: [API Gateway v2 API reference](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/api-reference.html). **Confirm exact v2 eventName strings at run time** — not asserted here.

| eventName (confirm exact string) | bucket | notes |
|---|---|---|
| CreateApi, CreateRoute, CreateIntegration, CreateStage | Persistence | backdoor HTTP API |

## EventBridge (`events.amazonaws.com`)
Source: [EventBridge API reference](https://docs.aws.amazon.com/eventbridge/latest/APIReference/Welcome.html). **eventSource trap:** `events.amazonaws.com` is EventBridge, not a generic "events" service.

| eventName | bucket | notes |
|---|---|---|
| PutRule, PutTargets | Persistence | scheduled attacker job |
| DisableRule, RemoveTargets | DefenseEvasion | disabling detections/automation |

## CloudTrail (`cloudtrail.amazonaws.com`)
Source: [CloudTrail API reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html). Note: disabling logging does **not** erase Event history itself.

| eventName | bucket | notes |
|---|---|---|
| StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors, DeleteEventDataStore | DefenseEvasion | log tampering |

## GuardDuty (`guardduty.amazonaws.com`)
Source: [GuardDuty API reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/Welcome.html).

| eventName | bucket | notes |
|---|---|---|
| DeleteDetector, UpdateDetector, ArchiveFindings, DisassociateFromAdministratorAccount | DefenseEvasion | disabling detection |
| CreateIPSet | DefenseEvasion | allowlisting attacker IPs |

## Config / Security Hub / CloudWatch / Logs
Sources: [Config API reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html), [Security Hub API reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html), [CloudWatch API reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/Welcome.html), [CloudWatch Logs API reference](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/Welcome.html). **eventSource traps:** CloudWatch alarms are `monitoring.amazonaws.com`; CloudWatch Logs are `logs.amazonaws.com`.

| source | eventName | bucket | notes |
|---|---|---|---|
| config | StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel | DefenseEvasion | — |
| securityhub | DisableSecurityHub | DefenseEvasion | — |
| monitoring | DisableAlarmActions, DeleteAlarms | DefenseEvasion | — |
| logs | DeleteLogGroup | DefenseEvasion | — |

## Bedrock (`bedrock.amazonaws.com`)
Source: [Logging Bedrock API calls with CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html).

| eventName | bucket | notes |
|---|---|---|
| InvokeModel, InvokeModelWithResponseStream, Converse, ConverseStream | ResourceAbuse | LLMjacking (cost abuse) |
| PutFoundationModelEntitlement, CreateFoundationModelAgreement | ResourceAbuse | enabling paid models |
| DeleteModelInvocationLoggingConfiguration | DefenseEvasion | hiding usage |

## Messaging / notification cost abuse
Sources: [SQS API reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html), [SNS API reference](https://docs.aws.amazon.com/sns/latest/api/welcome.html), [SES v2 API reference](https://docs.aws.amazon.com/ses/latest/APIReference-V2/Welcome.html).

| source | eventName | bucket | notes |
|---|---|---|---|
| sqs | PurgeQueue, DeleteQueue | Impact | — |
| sns | DeleteTopic | Impact | — |
| sns | GetSMSAttributes | Discovery | SMS-pumping recon |
| ses | VerifyEmailIdentity | Persistence | phishing-sender setup |
| ses | GetSendQuota | Discovery | spam-capacity recon |

## Compute / container / build (ResourceAbuse + PrivEsc via PassRole-equivalent fields)
Sources: [ECR](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html), [ECS](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html), [EKS](https://docs.aws.amazon.com/eks/latest/APIReference/Welcome.html), [Batch](https://docs.aws.amazon.com/batch/latest/APIReference/Welcome.html), [CodeBuild](https://docs.aws.amazon.com/codebuild/latest/APIReference/Welcome.html), [Glue](https://docs.aws.amazon.com/glue/latest/webapi/API_Operations.html).

| source | eventName | bucket | notes |
|---|---|---|---|
| ecr | GetAuthorizationToken | CredentialAccess | registry creds |
| ecs | RunTask, CreateService, RegisterTaskDefinition | PrivilegeEscalation / ResourceAbuse | `taskRoleArn` set ⇒ escalation |
| eks | CreateCluster | ResourceAbuse | — |
| batch | SubmitJob | ResourceAbuse | — |
| codebuild | CreateProject, StartBuild | PrivilegeEscalation / ResourceAbuse | build role abuse |
| glue | CreateJob | PrivilegeEscalation / ResourceAbuse | job role abuse |
| sagemaker / lightsail / amplify | Create* (confirm exact names at run time) | ResourceAbuse | compute for mining |

## CloudFormation / Route 53 / RAM / Organizations / Account
Sources: [CloudFormation](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/Welcome.html), [Route 53](https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html), [RAM](https://docs.aws.amazon.com/ram/latest/APIReference/Welcome.html), [Organizations](https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html), [Account Management](https://docs.aws.amazon.com/accounts/latest/reference/welcome.html). **eventSource trap:** the Account service is `account.amazonaws.com`.

| source | eventName | bucket | notes |
|---|---|---|---|
| cloudformation | CreateStack | PrivilegeEscalation | `roleARN` ⇒ escalation |
| cloudformation | DeleteStack | Impact | — |
| route53 | ChangeResourceRecordSets | Impact / Exfiltration | DNS hijack / data redirect |
| ram | CreateResourceShare | Exfiltration | share resources to attacker account |
| organizations | LeaveOrganization, CreateAccount, InviteAccountToOrganization, AcceptHandshake, DetachPolicy | Impact / DefenseEvasion | org-level tampering / SCP removal |
| account | EnableRegion | ResourceAbuse | opt-in region for mining |
| account | PutContactInformation, PutAlternateContact (confirm exact names at run time) | Impact | contact hijack |

## NOT-events (never list these as management activity)
- `PassRole` — a **permission**, not an API event; classify escalation via the role fields on `RunInstances`/`ecs:RegisterTaskDefinition`/`CreateStack`, not by looking for a `PassRole` event.
- `GenerateDbAuthToken` — client-side RDS IAM-auth token generation; **no CloudTrail event** is emitted.
- S3 `GetObject` / Lambda `Invoke` / DynamoDB item operations (`GetItem`/`Query`/`Scan`/…) — **data events**, absent from Event history. Record as `not-observable`, never "none" ([logging data events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html)).

## eventSource traps (do not key off the service short name)
| eventSource | is actually |
|---|---|
| monitoring.amazonaws.com | CloudWatch (alarms) |
| events.amazonaws.com | EventBridge |
| signin.amazonaws.com | console sign-in |
| account.amazonaws.com | Account Management |
| logs.amazonaws.com | CloudWatch Logs |

## Static lifecycle follow-up table (Step 6b / 6c; read-only; ID-only substitution)
Each row: the creating `eventName`, the read-only follow-up argv template (only the resource ID is substituted), the JSON path to the resource ID in the event, and the regex the ID must match before substitution. Every field is mandatory — a row missing any field prohibits pairing and follow-up.

| creating eventName | read-only follow-up (argv template) | resource-ID JSON path | ID regex |
|---|---|---|---|
| CreateAccessKey | `iam get-access-key-last-used --access-key-id <ID>` | `responseElements.accessKey.accessKeyId` | `^AKIA[0-9A-Z]{16}$` |
| CreateUser | `iam get-user --user-name <ID>` | `responseElements.user.userName` | `^[\w+=,.@-]{1,64}$` |
| CreateRole | `iam get-role --role-name <ID>` | `responseElements.role.roleName` | `^[\w+=,.@-]{1,64}$` |
| CreatePolicy | `iam get-policy --policy-arn <ID>` | `responseElements.policy.arn` | `^arn:aws[\w-]*:iam::[0-9]{12}:policy/[\w+=,.@/-]{1,128}$` |
| CreateKey | `kms describe-key --key-id <ID>` (DeletionDate, cancel-before line) | `responseElements.keyMetadata.keyId` | `^[0-9a-f-]{36}$` |
| ScheduleKeyDeletion | `kms describe-key --key-id <ID>` | `requestParameters.keyId` | `^[0-9a-f-]{36}$` |
| CreateSnapshot | `ec2 describe-snapshots --owner-ids self --snapshot-ids <ID>` then `describe-snapshot-attribute --attribute createVolumePermission --snapshot-id <ID>` | `responseElements.snapshotId` | `^snap-[0-9a-f]{8,17}$` |
| ModifySnapshotAttribute | `ec2 describe-snapshot-attribute --attribute createVolumePermission --snapshot-id <ID>` | `requestParameters.snapshotId` | `^snap-[0-9a-f]{8,17}$` |
| AssociateIamInstanceProfile | `ec2 describe-iam-instance-profile-associations --filters Name=instance-id,Values=<ID>` | `requestParameters.associateIamInstanceProfileRequest.instanceId` | `^i-[0-9a-f]{8,17}$` |
| StartExportTask | `rds describe-export-tasks --export-task-identifier <ID>` | `responseElements.exportTaskIdentifier` | `^[\w-]{1,255}$` |
| SendCommand | `ssm list-commands --command-id <ID>` (metadata only; never get-command-invocation) | `responseElements.command.commandId` | `^[0-9a-f-]{36}$` |
| CreateFunction20150331 / UpdateFunctionCode20150331v2 | `lambda list-functions` then `lambda get-policy --function-name <ID>` (GetFunction denied) | `requestParameters.functionName` | `^[\w-]{1,140}$` |
| CreateLogGroup | `logs describe-log-streams --log-group-name <ID>` (timestamps only; FilterLogEvents/GetLogEvents denied) | `requestParameters.logGroupName` | `^[\w./#-]{1,512}$` |
| CreateStack | `cloudformation list-stack-instances --stack-set-name <ID>` (needs StackSets authority; else not observable) | `requestParameters.stackName` | `^[\w-]{1,128}$` |
| PutEventSelectors | `cloudtrail get-event-selectors --trail-name <ID>` (does any trail log S3 data events?) | `requestParameters.trailName` | `^[\w._-]{3,128}$` |

## Signal-3 high-signal EventNames (~20; discovery path only)
Rare, high-signal mutations to sample one page each per named account/region pair (Step 1b Signal 3):

`CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, `AttachUserPolicy`, `PutUserPolicy`, `CreateUser`, `DeactivateMFADevice`, `UpdateAccountPasswordPolicy`, `CreateSAMLProvider`, `CreateOpenIDConnectProvider`, `GetFederationToken`, `ModifySnapshotAttribute`, `ModifyImageAttribute`, `PutBucketPolicy`, `CreateKeyPair`, `RunInstances`, `StopLogging`, `DeleteTrail`, `CreateIPSet`, `DeleteModelInvocationLoggingConfiguration`.

(Handoff argv templates with per-type regexes are defined in [`step-7-report-handoff.md`](step-7-report-handoff.md) → "Handoff command templates".)
