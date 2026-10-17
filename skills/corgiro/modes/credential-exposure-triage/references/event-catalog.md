# Event Catalog — credential-exposure-triage

The authoritative mapping from a CloudTrail `(eventSource, eventName)` tuple to **exactly one** tactic bucket, used by Step 6a. **Classification is by exact tuple only — no prefix matching, no wildcards.** The exact event-catalog tuple takes precedence over `readOnly`; an event matched to no tuple but carrying `readOnly=true` is generic `Discovery`.

**Table contract (enforced).** Every classifier row below is **row-local and self-contained**: it carries its own full `source` (`*.amazonaws.com`) column, one exact `eventName`, one deterministic `bucket`, and an explicit `predicate` (either `always` or a concrete condition on request/response fields). A parser matches `(source, eventName)` from the row alone — it never has to read a section heading. When one API can land in two buckets depending on its fields, it appears as **two rows with mutually-exclusive predicates** — never one row with two buckets. `findings.json` carries one bucket per finding (`state-contract.md`), so the classifier must resolve to one. The per-section heading repeats the source for readers; the authority is the row's `source` cell.

**Citations.** The cited source is the service's CloudTrail-logging page or API reference. CloudTrail `eventName` equals the public API action **except** where a service records a versioned name; every versioned name in this table is verified against the service's CloudTrail page and written in full (e.g. Lambda). Names that could not be verified to an exact CloudTrail string are **not** in the classifier — they are listed separately under "Unverified candidates (not used by the classifier)".

`predicate` column resolves `succeeded`/`attempted` on top of the bucket: an event is **succeeded** when its parsed `CloudTrailEvent` JSON has no `errorCode`, else **attempted** (`outcome` in `findings.json`). The field predicates below select the *bucket*, not the outcome.

**Predicate and resource-ID field paths — confirm casing at first use.** Each predicate/ID field path below (e.g. `requestParameters.iamInstanceProfile`, `requestParameters.VersioningConfiguration.Status`, `requestParameters.createVolumePermission.add`, `requestParameters.associateIamInstanceProfileRequest.instanceId`, `requestParameters.taskRoleArn`, `requestParameters.roleARN`) is written as the **API parameter name**; the exact CloudTrail casing and nesting (EC2 in particular wraps newer APIs in PascalCase request objects) are not asserted from memory. **Confirm each path against a real sample `CloudTrailEvent` record at first use in a run.** If the documented path is absent from a sample that clearly contains the field under a different casing/nesting, **hard stop** that row's classification for that event and record it as an unclassified mutation for operator review — never silently flip a two-row predicate on an absent path. The same caveat covers the `ssm.amazonaws.com / SendCommand` paths used by Step 4's secret-dropping rule (`requestParameters.parameters`, `requestParameters.documentName`, `requestParameters.instanceIds`, `responseElements.command.commandId`): they are API parameter names with no published CloudTrail sample. That rule is **fail-safe by construction** — it is an allowlist (keep only `documentName`, `instanceIds`, `command.commandId`; drop everything else in `requestParameters`/`responseElements`), so a `parameters` field that appears under a different casing is dropped along with every other non-allowlisted member, and a `documentName`/`commandId` under a different casing is simply lost (recorded as `partial`), never leaked.

## IAM (`iam.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); action names per [IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| iam.amazonaws.com | CreateUser | Persistence | always |
| iam.amazonaws.com | CreateRole | Persistence | always |
| iam.amazonaws.com | CreateInstanceProfile | Persistence | always |
| iam.amazonaws.com | AddRoleToInstanceProfile | PrivilegeEscalation | always |
| iam.amazonaws.com | CreateAccessKey | Persistence | always (derived subject, Step 5) |
| iam.amazonaws.com | CreateLoginProfile | Persistence | always |
| iam.amazonaws.com | UpdateLoginProfile | Persistence | always |
| iam.amazonaws.com | DeleteLoginProfile | DefenseEvasion | always |
| iam.amazonaws.com | DeleteUser | DefenseEvasion | always |
| iam.amazonaws.com | DeleteRole | DefenseEvasion | always |
| iam.amazonaws.com | CreateVirtualMFADevice | Persistence | always |
| iam.amazonaws.com | EnableMFADevice | Persistence | always |
| iam.amazonaws.com | DeactivateMFADevice | DefenseEvasion | always |
| iam.amazonaws.com | AttachUserPolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | AttachRolePolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | AttachGroupPolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | PutUserPolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | PutRolePolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | PutGroupPolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | AddUserToGroup | PrivilegeEscalation | always |
| iam.amazonaws.com | DetachUserPolicy | DefenseEvasion | always (target `AWSCompromisedKeyQuarantine*` ⇒ containment-defeating, 6g) |
| iam.amazonaws.com | DetachRolePolicy | DefenseEvasion | always (target `AWSCompromisedKeyQuarantine*` ⇒ containment-defeating, 6g) |
| iam.amazonaws.com | DeleteUserPolicy | DefenseEvasion | always |
| iam.amazonaws.com | CreatePolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | CreatePolicyVersion | PrivilegeEscalation | always |
| iam.amazonaws.com | SetDefaultPolicyVersion | PrivilegeEscalation | always |
| iam.amazonaws.com | UpdateAssumeRolePolicy | PrivilegeEscalation | always |
| iam.amazonaws.com | CreateSAMLProvider | Persistence | always |
| iam.amazonaws.com | CreateOpenIDConnectProvider | Persistence | always |
| iam.amazonaws.com | UploadSSHPublicKey | Persistence | always |
| iam.amazonaws.com | CreateServiceSpecificCredential | Persistence | always |
| iam.amazonaws.com | UpdateAccessKey | DefenseEvasion | always (`requestParameters.status=Active` ⇒ reactivation, containment-defeating, 6g) |
| iam.amazonaws.com | DeleteAccessKey | DefenseEvasion | always |
| iam.amazonaws.com | UpdateAccountPasswordPolicy | DefenseEvasion | always (containment-defeating, 6g) |
| iam.amazonaws.com | DeleteAccountPasswordPolicy | DefenseEvasion | always (containment-defeating, 6g) |
| iam.amazonaws.com | GenerateCredentialReport | Discovery | always |

## STS (`sts.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html); [STS API reference](https://docs.aws.amazon.com/STS/latest/APIReference/welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| sts.amazonaws.com | AssumeRole | InitialAccess | always (hop; `responseElements.credentials.accessKeyId` = ASIA) |
| sts.amazonaws.com | GetFederationToken | InitialAccess | always (Step 0 branch C) |
| sts.amazonaws.com | GetSessionToken | InitialAccess | always (Step 0 branch C) |
| sts.amazonaws.com | GetCallerIdentity | Discovery | always |

## Sign-in (`signin.amazonaws.com`)
Source: [Logging IAM and AWS STS API calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html) (`signin.amazonaws.com/ConsoleLogin`).

| source | eventName | bucket | predicate |
|---|---|---|---|
| signin.amazonaws.com | ConsoleLogin | InitialAccess | always (`additionalEventData.MFAUsed=No` raises confidence; `userIdentity.type=Root` ⇒ root runbook, 6e/6f) |

## EC2 (`ec2.amazonaws.com`)
Source: [Amazon EC2 API reference](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/OperationList-query-api.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ec2.amazonaws.com | RunInstances | PrivilegeEscalation | `requestParameters.iamInstanceProfile` present |
| ec2.amazonaws.com | RunInstances | ResourceAbuse | `requestParameters.iamInstanceProfile` absent |
| ec2.amazonaws.com | RequestSpotInstances | ResourceAbuse | always |
| ec2.amazonaws.com | CreateFleet | ResourceAbuse | always |
| ec2.amazonaws.com | StopInstances | Impact | always |
| ec2.amazonaws.com | TerminateInstances | Impact | always |
| ec2.amazonaws.com | CreateVolume | Impact | always |
| ec2.amazonaws.com | AttachVolume | Impact | always |
| ec2.amazonaws.com | DetachVolume | Impact | always |
| ec2.amazonaws.com | DeleteVolume | Impact | always |
| ec2.amazonaws.com | CreateSnapshot | Persistence | always (lifecycle-paired in 6b; sharing is a later ModifySnapshotAttribute) |
| ec2.amazonaws.com | DeleteSnapshot | Impact | always |
| ec2.amazonaws.com | ModifySnapshotAttribute | Exfiltration | `requestParameters.createVolumePermission.add` present |
| ec2.amazonaws.com | ModifySnapshotAttribute | DefenseEvasion | `requestParameters.createVolumePermission.add` absent |
| ec2.amazonaws.com | ModifyImageAttribute | Exfiltration | `requestParameters.launchPermission.add` present |
| ec2.amazonaws.com | DeregisterImage | Impact | always |
| ec2.amazonaws.com | CreateKeyPair | Persistence | always |
| ec2.amazonaws.com | ImportKeyPair | Persistence | always |
| ec2.amazonaws.com | DeleteKeyPair | Impact | always |
| ec2.amazonaws.com | CreateSecurityGroup | DefenseEvasion | always |
| ec2.amazonaws.com | DeleteSecurityGroup | DefenseEvasion | always |
| ec2.amazonaws.com | AuthorizeSecurityGroupIngress | InitialAccess | always |
| ec2.amazonaws.com | ModifyInstanceAttribute | DefenseEvasion | always |
| ec2.amazonaws.com | AssociateIamInstanceProfile | PrivilegeEscalation | always |
| ec2.amazonaws.com | GetPasswordData | CredentialAccess | always |
| ec2.amazonaws.com | GetConsoleOutput | CredentialAccess | always (member role denies) |
| ec2.amazonaws.com | GetConsoleScreenshot | CredentialAccess | always (member role denies) |
| ec2.amazonaws.com | DeleteFlowLogs | DefenseEvasion | always |

> `CreateAutoScalingGroup` is `autoscaling.amazonaws.com`, not `ec2.amazonaws.com` — see Auto Scaling below.

## Auto Scaling (`autoscaling.amazonaws.com`)
Source: [Amazon EC2 Auto Scaling API reference](https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| autoscaling.amazonaws.com | CreateAutoScalingGroup | ResourceAbuse | always |

## EC2 Instance Connect (`ec2-instance-connect.amazonaws.com`)
Source: [EC2 Instance Connect API reference](https://docs.aws.amazon.com/ec2-instance-connect/latest/APIReference/Welcome.html); `OpenTunnel` (EIC Endpoint) logging per [Log EC2 Instance Connect Endpoint using CloudTrail](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/log-ec2-instance-connect-endpoint-using-cloudtrail.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ec2-instance-connect.amazonaws.com | SendSSHPublicKey | InitialAccess | always (triggers instance-session review, Step 5) |
| ec2-instance-connect.amazonaws.com | SendSerialConsoleSSHPublicKey | InitialAccess | always |
| ec2-instance-connect.amazonaws.com | OpenTunnel | InitialAccess | always |

## SSM (`ssm.amazonaws.com`)
Source: [AWS Systems Manager API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ssm.amazonaws.com | SendCommand | Impact | always (`requestParameters.parameters` may be visible in CloudTrail — AWS warns plaintext command parameters are logged; Corgiro drops them before the first write, Step 4; command content via handoff) |
| ssm.amazonaws.com | StartSession | InitialAccess | always |
| ssm.amazonaws.com | GetParameter | CredentialAccess | always (member role denies) |
| ssm.amazonaws.com | GetParameters | CredentialAccess | always (member role denies) |
| ssm.amazonaws.com | GetParametersByPath | CredentialAccess | always (member role denies) |

## Secrets Manager (`secretsmanager.amazonaws.com`)
Source: [Secrets Manager API reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Operations.html); CloudTrail entries per [Log Secrets Manager events with CloudTrail](https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| secretsmanager.amazonaws.com | GetSecretValue | CredentialAccess | always (member role denies; attempts still log. CloudTrail says this entry is "Generated by the GetSecretValue and BatchGetSecretValue operations") |
| secretsmanager.amazonaws.com | BatchGetSecretValue | CredentialAccess | always (member role denies; a distinct CloudTrail entry — [Secrets Manager CloudTrail log entries](https://docs.aws.amazon.com/secretsmanager/latest/userguide/cloudtrail_log_entries.html)) |
| secretsmanager.amazonaws.com | PutSecretValue | Impact | always |
| secretsmanager.amazonaws.com | DeleteSecret | Impact | always |

## KMS (`kms.amazonaws.com`)
Source: [AWS KMS API reference](https://docs.aws.amazon.com/kms/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| kms.amazonaws.com | Decrypt | CredentialAccess | always (member role denies; attempts log) |
| kms.amazonaws.com | ScheduleKeyDeletion | Impact | always |
| kms.amazonaws.com | DeleteImportedKeyMaterial | Impact | always |
| kms.amazonaws.com | CancelKeyDeletion | DefenseEvasion | always |
| kms.amazonaws.com | DisableKey | Impact | always |
| kms.amazonaws.com | CreateKey | Persistence | always |
| kms.amazonaws.com | CreateAlias | Persistence | always |
| kms.amazonaws.com | DeleteAlias | DefenseEvasion | always |
| kms.amazonaws.com | PutKeyPolicy | PrivilegeEscalation | always (can grant external principals) |

## S3 (`s3.amazonaws.com`)
Source: [Logging S3 API calls with CloudTrail](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html) (management events only; object reads are **data events** — see NOT-events).

| source | eventName | bucket | predicate |
|---|---|---|---|
| s3.amazonaws.com | CreateBucket | ResourceAbuse | always |
| s3.amazonaws.com | DeleteBucket | Impact | always |
| s3.amazonaws.com | PutBucketPolicy | Exfiltration | always (can expose data to external principals) |
| s3.amazonaws.com | PutBucketAcl | Exfiltration | always |
| s3.amazonaws.com | PutAccountPublicAccessBlock | DefenseEvasion | always |
| s3.amazonaws.com | PutBucketReplication | Exfiltration | always |
| s3.amazonaws.com | PutBucketLifecycle | Impact | always (expiry = destruction) |
| s3.amazonaws.com | PutBucketEncryption | Impact | always |
| s3.amazonaws.com | PutBucketVersioning | DefenseEvasion | `requestParameters.VersioningConfiguration.Status=Suspended` (disables recovery) |

## Audit records (NOT classifier rows — neutral entries, never findings)
These `(source, eventName, predicate)` triples match events that are **not** attacks. Step 6a writes a match here to `completeness.json.audit_records[]` as a neutral entry; it is **never** assigned a tactic bucket, never becomes a finding, and never produces a Risk Tier. They live outside the classifier so the "every matched row yields exactly one bucket" contract stays intact.

| source | eventName | predicate | why it is not a finding |
|---|---|---|---|
| s3.amazonaws.com | PutBucketVersioning | `requestParameters.VersioningConfiguration.Status=Enabled` | enabling versioning strengthens recovery; it is defensive, not an attack |

## RDS (`rds.amazonaws.com`)
Source: [Amazon RDS API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| rds.amazonaws.com | CreateDBSnapshot | Persistence | always (lifecycle-paired; sharing is a later ModifyDBSnapshotAttribute) |
| rds.amazonaws.com | ModifyDBSnapshotAttribute | Exfiltration | `requestParameters.valuesToAdd` contains `all` or an external account |
| rds.amazonaws.com | ModifyDBClusterSnapshotAttribute | Exfiltration | `requestParameters.valuesToAdd` contains `all` or an external account |
| rds.amazonaws.com | DeleteDBSnapshot | Impact | always |
| rds.amazonaws.com | RestoreDBInstanceFromDBSnapshot | Exfiltration | always |
| rds.amazonaws.com | StartExportTask | Exfiltration | always |
| rds.amazonaws.com | DeleteDBInstance | Impact | always |
| rds.amazonaws.com | DeleteDBCluster | Impact | always |
| rds.amazonaws.com | DeleteDBSubnetGroup | Impact | always |
| rds.amazonaws.com | ModifyDBInstance | DefenseEvasion | `requestParameters.publiclyAccessible=true` |

## DynamoDB (`dynamodb.amazonaws.com`)
Source: [DynamoDB API reference](https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| dynamodb.amazonaws.com | DeleteTable | Impact | always (item ops are data events — NOT-events) |

## Backup (`backup.amazonaws.com`)
Source: [AWS Backup API reference](https://docs.aws.amazon.com/aws-backup/latest/devguide/api-reference.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| backup.amazonaws.com | DeleteRecoveryPoint | Impact | always |

## Lambda (`lambda.amazonaws.com`)
Source: [Logging Lambda API calls using CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html). CloudTrail records **versioned** event names for most actions; the GetFunction read appears in two forms (`GetFunction` in the sample record, `GetFunction20150331v2` in the note), so both are classified.

| source | eventName | bucket | predicate |
|---|---|---|---|
| lambda.amazonaws.com | CreateFunction20150331 | Persistence | always |
| lambda.amazonaws.com | UpdateFunctionCode20150331v2 | Persistence | always (code swap) |
| lambda.amazonaws.com | AddPermission20150331v2 | PrivilegeEscalation | always (resource-policy grant) |
| lambda.amazonaws.com | GetFunction | CredentialAccess | always (returns env vars; member role denies GetFunction) |
| lambda.amazonaws.com | GetFunction20150331v2 | CredentialAccess | always (returns env vars; versioned form of GetFunction) |
| lambda.amazonaws.com | CreateEventSourceMapping20150331 | Persistence | always (trigger wiring) |

## EventBridge (`events.amazonaws.com`)
Source: [EventBridge API reference](https://docs.aws.amazon.com/eventbridge/latest/APIReference/Welcome.html). **eventSource trap:** `events.amazonaws.com` is EventBridge.

| source | eventName | bucket | predicate |
|---|---|---|---|
| events.amazonaws.com | PutRule | Persistence | always |
| events.amazonaws.com | PutTargets | Persistence | always |
| events.amazonaws.com | DisableRule | DefenseEvasion | always |
| events.amazonaws.com | RemoveTargets | DefenseEvasion | always |

## CloudTrail (`cloudtrail.amazonaws.com`)
Source: [CloudTrail API reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/Welcome.html). Disabling logging does **not** erase Event history itself.

| source | eventName | bucket | predicate |
|---|---|---|---|
| cloudtrail.amazonaws.com | StopLogging | DefenseEvasion | always |
| cloudtrail.amazonaws.com | DeleteTrail | DefenseEvasion | always |
| cloudtrail.amazonaws.com | UpdateTrail | DefenseEvasion | always |
| cloudtrail.amazonaws.com | PutEventSelectors | DefenseEvasion | always |
| cloudtrail.amazonaws.com | DeleteEventDataStore | DefenseEvasion | always |

## GuardDuty (`guardduty.amazonaws.com`)
Source: [GuardDuty API reference](https://docs.aws.amazon.com/guardduty/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| guardduty.amazonaws.com | DeleteDetector | DefenseEvasion | always |
| guardduty.amazonaws.com | UpdateDetector | DefenseEvasion | always |
| guardduty.amazonaws.com | ArchiveFindings | DefenseEvasion | always |
| guardduty.amazonaws.com | DisassociateFromAdministratorAccount | DefenseEvasion | always |
| guardduty.amazonaws.com | CreateIPSet | DefenseEvasion | always (allowlisting attacker IPs) |

## Config (`config.amazonaws.com`)
Source: [AWS Config API reference](https://docs.aws.amazon.com/config/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| config.amazonaws.com | StopConfigurationRecorder | DefenseEvasion | always |
| config.amazonaws.com | DeleteConfigurationRecorder | DefenseEvasion | always |
| config.amazonaws.com | DeleteDeliveryChannel | DefenseEvasion | always |

## Security Hub (`securityhub.amazonaws.com`)
Source: [Security Hub API reference](https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| securityhub.amazonaws.com | DisableSecurityHub | DefenseEvasion | always |

## CloudWatch (`monitoring.amazonaws.com`)
Source: [CloudWatch API reference](https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/Welcome.html). **eventSource trap:** CloudWatch alarms are `monitoring.amazonaws.com`.

| source | eventName | bucket | predicate |
|---|---|---|---|
| monitoring.amazonaws.com | DisableAlarmActions | DefenseEvasion | always |
| monitoring.amazonaws.com | DeleteAlarms | DefenseEvasion | always |

## CloudWatch Logs (`logs.amazonaws.com`)
Source: [CloudWatch Logs API reference](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/Welcome.html). **eventSource trap:** Logs are `logs.amazonaws.com`.

| source | eventName | bucket | predicate |
|---|---|---|---|
| logs.amazonaws.com | DeleteLogGroup | DefenseEvasion | always |

## Bedrock (`bedrock.amazonaws.com`)
Source: [Logging Bedrock API calls with CloudTrail](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| bedrock.amazonaws.com | InvokeModel | ResourceAbuse | always (LLMjacking) |
| bedrock.amazonaws.com | InvokeModelWithResponseStream | ResourceAbuse | always |
| bedrock.amazonaws.com | Converse | ResourceAbuse | always |
| bedrock.amazonaws.com | ConverseStream | ResourceAbuse | always |
| bedrock.amazonaws.com | CreateFoundationModelAgreement | ResourceAbuse | always |
| bedrock.amazonaws.com | DeleteModelInvocationLoggingConfiguration | DefenseEvasion | always |

> **Streaming double-count.** A Bedrock streaming call (`InvokeModelWithResponseStream`, `ConverseStream`) produces a second "stream-completion" record with the same `eventName`. Count only records whose `eventType == AwsApiCall` for Bedrock invocation volume, or counts are overstated ([Bedrock CloudTrail logging](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html)).

## SQS (`sqs.amazonaws.com`)
Source: [SQS API reference](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| sqs.amazonaws.com | PurgeQueue | Impact | always |
| sqs.amazonaws.com | DeleteQueue | Impact | always |

## SNS (`sns.amazonaws.com`)
Source: [SNS API reference](https://docs.aws.amazon.com/sns/latest/api/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| sns.amazonaws.com | DeleteTopic | Impact | always |
| sns.amazonaws.com | GetSMSAttributes | Discovery | always (SMS-pumping recon) |

## SES v1 (`ses.amazonaws.com`)
Source: [SES API reference](https://docs.aws.amazon.com/ses/latest/APIReference/API_Operations.html); CloudTrail logging per [Logging SES API calls with CloudTrail](https://docs.aws.amazon.com/ses/latest/dg/logging-using-cloudtrail.html). `VerifyEmailIdentity` and `GetSendQuota` are **SES v1** actions (the SES v2 equivalents are `CreateEmailIdentity` and `GetAccount`, which this catalog does not classify).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ses.amazonaws.com | VerifyEmailIdentity | Persistence | always (phishing-sender setup) |
| ses.amazonaws.com | GetSendQuota | Discovery | always (spam-capacity recon) |

## ECR (`ecr.amazonaws.com`)
Source: [ECR API reference](https://docs.aws.amazon.com/AmazonECR/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ecr.amazonaws.com | GetAuthorizationToken | CredentialAccess | always (registry creds) |

## ECS (`ecs.amazonaws.com`)
Source: [ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ecs.amazonaws.com | RunTask | ResourceAbuse | always |
| ecs.amazonaws.com | CreateService | ResourceAbuse | always |
| ecs.amazonaws.com | RegisterTaskDefinition | PrivilegeEscalation | `requestParameters.taskRoleArn` present |
| ecs.amazonaws.com | RegisterTaskDefinition | ResourceAbuse | `requestParameters.taskRoleArn` absent |

## EKS (`eks.amazonaws.com`)
Source: [EKS API reference](https://docs.aws.amazon.com/eks/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| eks.amazonaws.com | CreateCluster | ResourceAbuse | always |

## Batch (`batch.amazonaws.com`)
Source: [AWS Batch API reference](https://docs.aws.amazon.com/batch/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| batch.amazonaws.com | SubmitJob | ResourceAbuse | always |

## CodeBuild (`codebuild.amazonaws.com`)
Source: [CodeBuild API reference](https://docs.aws.amazon.com/codebuild/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| codebuild.amazonaws.com | CreateProject | PrivilegeEscalation | always (build role abuse) |
| codebuild.amazonaws.com | StartBuild | ResourceAbuse | always |

## Glue (`glue.amazonaws.com`)
Source: [AWS Glue API reference](https://docs.aws.amazon.com/glue/latest/webapi/API_Operations.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| glue.amazonaws.com | CreateJob | PrivilegeEscalation | always (job role abuse) |

## CloudFormation (`cloudformation.amazonaws.com`)
Source: [CloudFormation API reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| cloudformation.amazonaws.com | CreateStack | PrivilegeEscalation | `requestParameters.roleARN` present |
| cloudformation.amazonaws.com | CreateStack | ResourceAbuse | `requestParameters.roleARN` absent |
| cloudformation.amazonaws.com | DeleteStack | Impact | always |

## Route 53 (`route53.amazonaws.com`)
Source: [Route 53 API reference](https://docs.aws.amazon.com/Route53/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| route53.amazonaws.com | ChangeResourceRecordSets | Impact | always (DNS hijack / redirect) |

## RAM (`ram.amazonaws.com`)
Source: [RAM API reference](https://docs.aws.amazon.com/ram/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| ram.amazonaws.com | CreateResourceShare | Exfiltration | always (share resources to attacker account) |

## Organizations (`organizations.amazonaws.com`)
Source: [Organizations API reference](https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html).

| source | eventName | bucket | predicate |
|---|---|---|---|
| organizations.amazonaws.com | LeaveOrganization | Impact | always |
| organizations.amazonaws.com | CreateAccount | ResourceAbuse | always |
| organizations.amazonaws.com | InviteAccountToOrganization | Persistence | always |
| organizations.amazonaws.com | AcceptHandshake | Persistence | always |
| organizations.amazonaws.com | DetachPolicy | DefenseEvasion | always (SCP removal) |

## Account Management (`account.amazonaws.com`)
Source: [Account Management API reference](https://docs.aws.amazon.com/accounts/latest/reference/welcome.html); CloudTrail logging per [Logging Account Management API calls with CloudTrail](https://docs.aws.amazon.com/accounts/latest/reference/monitoring-cloudtrail.html) (all Account Management API operations are logged, with `eventSource: account.amazonaws.com`). **eventSource trap:** the Account service is `account.amazonaws.com`.

| source | eventName | bucket | predicate |
|---|---|---|---|
| account.amazonaws.com | EnableRegion | ResourceAbuse | always (opt-in region for mining) |
| account.amazonaws.com | PutAlternateContact | Impact | always (contact hijack) |
| account.amazonaws.com | PutContactInformation | Impact | always (contact hijack) |

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
- Bedrock `PutFoundationModelEntitlement` — appears only as an IAM action (e.g. in `AWSCompromisedKeyQuarantineV3`); it is not in the Bedrock API operations list and no AWS doc shows a CloudTrail record with this name. Candidate bucket: ResourceAbuse (model entitlement).

## Static lifecycle follow-up table (Step 6b / 6c; read-only; ID-only substitution)
Each row has **all** mandatory fields (per Step 6b's contract): exact `(source, create eventName)`; the `delete pair eventName` whose matching resource ID closes the lifecycle; the success predicate; the resource-ID JSON path; the **pair key** (the field whose equality pairs create/delete); the account/Region source; the read-only follow-up argv (ID-only substitution, **equals-joined options** so a validated value can never be read as a flag); and the ID regex validated before substitution. Every ID regex is a **`re.fullmatch` body** (regex-dialect note in MODE.md; PCRE/Ruby/Java users wrap in `\A…\z`), first char alphanumeric, and excludes commas and newlines. A row missing any field prohibits pairing and follow-up. **Each argv in the follow-up column is one AWS request and one counted call.** Most rows hold a single argv, but some hold **two** (snapshot `describe-snapshots` + `describe-snapshot-attribute`; Lambda `list-functions` + `get-policy`): in a multi-command row **decrement both budget counters (`call_budget` for the account and `global_call_budget`) before each argv**, and stop at the per-account cap or before a request that would exceed `global_call_budget` even partway through a row. **Every follow-up argv is issued with `--no-paginate` and never loops on a token** — the `--no-paginate` is shown explicitly on every list/describe call the CLI would otherwise auto-paginate (`iam list-access-keys`, `ListFunctions`, `ListCommands`, the `describe-*` calls), so one argv is exactly one service request; a truncated first page is recorded as `partial`, not paged.

| source | create eventName | delete pair eventName | success predicate | resource-ID JSON path | pair key | account/Region source | read-only follow-up (argv, equals-joined) | ID regex |
|---|---|---|---|---|---|---|---|---|
| iam.amazonaws.com | CreateAccessKey | DeleteAccessKey | no `errorCode` | `responseElements.accessKey.accessKeyId` | accessKeyId (matched by sha256) | event `recipientAccountId`; IAM global (no Region) | `iam list-access-keys --user-name=<userName> --no-paginate` then match the row by `sha256` (never pass a masked key to `--access-key-id`) | user name `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}` |
| iam.amazonaws.com | CreateUser | DeleteUser | no `errorCode` | `responseElements.user.userName` | userName | event `recipientAccountId`; IAM global | `iam get-user --user-name=<ID>` | `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}` |
| iam.amazonaws.com | CreateRole | DeleteRole | no `errorCode` | `responseElements.role.roleName` | roleName | event `recipientAccountId`; IAM global | `iam get-role --role-name=<ID>` | `[A-Za-z0-9][A-Za-z0-9_+=.@-]{0,63}` |
| iam.amazonaws.com | CreatePolicy | DeletePolicy | no `errorCode` | `responseElements.policy.arn` | policyArn | event `recipientAccountId`; IAM global | `iam get-policy --policy-arn=<ID>` | `arn:aws[a-z-]*:iam::[0-9]{12}:policy/[A-Za-z0-9][A-Za-z0-9_+=,.@/-]{0,127}` |
| kms.amazonaws.com | CreateKey | ScheduleKeyDeletion | no `errorCode` | `responseElements.keyMetadata.keyId` | keyId | event `recipientAccountId` + `awsRegion` | `kms describe-key --key-id=<ID>` (DeletionDate, cancel-before) | `KMS_KEY_ID` (named body defined directly below this table; multi-Region keys use the `mrk-` prefix) |
| ec2.amazonaws.com | CreateSnapshot | DeleteSnapshot | no `errorCode` | `responseElements.snapshotId` | snapshotId | event `recipientAccountId` + `awsRegion` | `ec2 describe-snapshots --owner-ids=self --snapshot-ids=<ID> --no-paginate` then `ec2 describe-snapshot-attribute --attribute=createVolumePermission --snapshot-id=<ID>` | `snap-[0-9a-f]{8,17}` |
| ec2.amazonaws.com | AssociateIamInstanceProfile | DisassociateIamInstanceProfile | no `errorCode` | `requestParameters.associateIamInstanceProfileRequest.instanceId` | instanceId | event `recipientAccountId` + `awsRegion` | `ec2 describe-iam-instance-profile-associations --filters=Name=instance-id,Values=<ID> --no-paginate` | `i-[0-9a-f]{8,17}` |
| rds.amazonaws.com | StartExportTask | (no delete pair; one-shot export) | no `errorCode` | `responseElements.exportTaskIdentifier` | exportTaskIdentifier | event `recipientAccountId` + `awsRegion` | `rds describe-export-tasks --export-task-identifier=<ID> --no-paginate` | `[A-Za-z0-9][A-Za-z0-9_-]{0,254}` |
| ssm.amazonaws.com | SendCommand | (no delete pair; command lifecycle) | no `errorCode` | `responseElements.command.commandId` | commandId | event `recipientAccountId` + `awsRegion` | `ssm list-commands --command-id=<ID> --no-paginate --query='Commands[].{CommandId:CommandId,DocumentName:DocumentName,Status:Status,RequestedDateTime:RequestedDateTime,InstanceIds:InstanceIds}'` (projects metadata only — **never** `Parameters`; never get-command-invocation) | `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| lambda.amazonaws.com | CreateFunction20150331 | DeleteFunction20150331 | no `errorCode` | `requestParameters.functionName` | functionName | event `recipientAccountId` + `awsRegion` | `lambda list-functions --no-paginate --query='Functions[].[FunctionName,FunctionArn]'` (one page; projects names/ARNs only — **never** env vars; `ListFunctions` returns `Environment.Variables` otherwise) then `lambda get-policy --function-name=<ID>` (GetFunction denied) | `[A-Za-z0-9][A-Za-z0-9_-]{0,139}` |
| logs.amazonaws.com | CreateLogGroup | DeleteLogGroup | no `errorCode` | `requestParameters.logGroupName` | logGroupName | event `recipientAccountId` + `awsRegion` | `logs describe-log-streams --log-group-name=<ID> --no-paginate` (timestamps only; FilterLogEvents/GetLogEvents denied) | `[A-Za-z0-9][A-Za-z0-9_./#-]{0,511}` |
| cloudformation.amazonaws.com | CreateStack | DeleteStack | no `errorCode` | `requestParameters.stackName` | stackName | event `recipientAccountId` + `awsRegion` | `cloudformation describe-stacks --stack-name=<ID> --no-paginate` (single stack; org-wide StackSet health not observable from a member/tooling session) | `[A-Za-z0-9][A-Za-z0-9_-]{0,127}` |
| cloudtrail.amazonaws.com | PutEventSelectors | (config change; no delete pair) | no `errorCode` | `requestParameters.trailName` | trailName | event `recipientAccountId` + `awsRegion` | `cloudtrail get-event-selectors --trail-name=<ID>` (does any trail log S3 data events?) | `[A-Za-z0-9][A-Za-z0-9_._-]{2,127}` |

`KMS_KEY_ID` (a `re.fullmatch` body; defined outside the table because a `|` inside a table cell splits the cell under GFM): `(mrk-[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` — either a multi-Region key ID (`mrk-` + 32 hex) or a single-Region key ID (UUID form) ([KMS key identifiers](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html)).

## Signal-3 high-signal EventNames (~20; discovery path only)
Rare, high-signal mutations to sample one page each per named account/region pair (Step 1b Signal 3). All are exact classifier tuples above:

`CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`, `AttachUserPolicy`, `PutUserPolicy`, `CreateUser`, `DeactivateMFADevice`, `UpdateAccountPasswordPolicy`, `CreateSAMLProvider`, `CreateOpenIDConnectProvider`, `GetFederationToken`, `ModifySnapshotAttribute`, `ModifyImageAttribute`, `PutBucketPolicy`, `CreateKeyPair`, `RunInstances`, `StopLogging`, `DeleteTrail`, `CreateIPSet`, `DeleteModelInvocationLoggingConfiguration`.

(Handoff argv templates with per-type regexes are defined in [`step-7-report-handoff.md`](step-7-report-handoff.md) → "Handoff command templates".)
