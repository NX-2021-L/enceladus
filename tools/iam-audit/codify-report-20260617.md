# ENC-TSK-G95 — bulk-role codification report (2026-06-17)

Parameterization proven against prod-live (suffix='') AND gamma-live (suffix='-gamma').

## devops-coordination-api-lambda-role
  - missing actions: ['bedrock:associateagentknowledgebase', 'bedrock:createagent', 'bedrock:createagentactiongroup', 'bedrock:createagentalias', 'bedrock:deleteagent', 'bedrock:deleteagentactiongroup', 'bedrock:deleteagentalias', 'bedrock:disassociateagentknowledgebase', 'bedrock:getagent', 'bedrock:getagentactiongroup', 'bedrock:getagentalias', 'bedrock:invokeagent', 'bedrock:prepareagent', 'cognito-idp:createuserpoolclient', 'cognito-idp:deleteuserpoolclient', 'cognito-idp:describeuserpoolclient', 'cognito-idp:initiateauth', 'cognito-idp:updateuserpoolclient', 'dynamodb:deleteitem', 'dynamodb:describetable', 'dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'ec2:createtags', 'ec2:describeinstances', 'ec2:describelaunchtemplates', 'ec2:describelaunchtemplateversions', 'ec2:runinstances', 'ec2:terminateinstances', 'iam:passrole', 'lambda:invokefunction', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getbucketlocation', 's3:getobject', 's3:headbucket', 's3:listbucket', 's3:putobject', 'secretsmanager:describesecret', 'secretsmanager:getsecretvalue', 'sns:publish', 'ssm:describeinstanceinformation', 'ssm:getcommandinvocation', 'ssm:listcommandinvocations', 'ssm:listcommands', 'ssm:sendcommand']
  - PROVEN statements (auto-codify): ['InvokeBedrockAgentAlias', 'CloudWatchLogs', 'CoordinationTableAccess', 'TrackerTableAccess', 'ProjectsTableRead', 'GovernancePoliciesReadWrite', 'DocumentsTableRead', 'ComponentRegistryTableAccess', 'GovernanceAndReferenceS3Read', 'GovernanceAndReferenceS3Get', 'GovernanceS3Write', 'S3HeadBucket', 'SSMDispatch', 'EC2FleetDispatch', 'ProviderSecretsRead', 'ComponentEventsTopicPublish', 'CognitoTerminalAuth', 'CognitoOAuthClientManagement', 'BedrockAgentLifecycle', 'BedrockAgentInvoke', 'BedrockPassAgentRole', 'FleetHostPassRole']
  - NEEDS REVIEW (not auto-emitted): [('InvokeBedrockActionLambda', ['arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:enceladus-bedrock-agent-actions', 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:enceladus-bedrock-agent-actions:*'])]

## devops-tracker-mutation-lambda-role
  - missing actions: ['events:putevents']
  - PROVEN statements (auto-codify): [['events:PutEvents']]

## devops-document-api-lambda-role
  - missing actions: ['dynamodb:deleteitem', 'dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:deleteobject', 's3:getobject', 's3:listbucket', 's3:putobject']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'DynamoDBDocuments', 'DynamoDBProjectsRead', 'DynamoDBTrackerRead', 'S3DocumentsObjectAccess', 'S3ReferenceRead', 'S3ListPrefixes']

## devops-project-service-lambda-role
  - missing actions: ['dynamodb:deleteitem', 'dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:deleteobject', 's3:putobject']
  - PROVEN statements (auto-codify): ['ProjectsTableFullAccess', 'TrackerTableLimitedWrite', 'CloudWatchLogs']
  - NEEDS REVIEW (not auto-emitted): [('S3ReferenceWrite', ['arn:aws:s3:::jreese-net/gamma/mobile/v1/reference/*'])]

## devops-feed-query-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:query', 'dynamodb:scan']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker/index/*', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/projects', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/projects/index/*'])]

## devops-coordination-monitor-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:scan', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'CoordinationTableRead']

## devops-deploy-intake-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'lambda:invokefunction', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject', 's3:putobject', 'sqs:getqueueurl', 'sqs:sendmessage']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'DeployTableAccess', 'ProjectsTableRead', 'S3ConfigAccess', 'SQSSendMessage', 'InvokeDocPrepLambda']

## devops-deploy-orchestrator-lambda-role
  - missing actions: ['codebuild:startbuild', 'dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 's3:getobject', 's3:listbucket', 's3:putobject']
  - PROVEN statements (auto-codify): ['DeployTableAccess', 'ProjectsTableRead', 'TrackerTableWorklog', 'S3ConfigAccess', 'S3SourceRead', 'CodeBuildStart']

## devops-deploy-finalize-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:putobject']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('CloudWatchLogs', ['arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/devops-deploy-finalize*']), ('DeployTableAccess', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-deployment-manager', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-deployment-manager/index/*']), ('TrackerTableAccess', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker']), ('ProjectsTableRead', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/projects']), ('VersionFileWrite', ['arn:aws:s3:::jreese-net/deploy-config/*/current-version.json'])]

## devops-reference-search-lambda-role
  - missing actions: ['logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'S3ReferenceRead']

## devops-feed-publisher-lambda-role
  - missing actions: ['cloudfront:createinvalidation', 'dynamodb:getitem', 'dynamodb:query', 'dynamodb:scan', 'events:putevents', 's3:getobject', 's3:putobject', 'sns:publish']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('DynamoDBRead', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker/index/*', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/documents', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/documents/index/*']), ('S3MobileFeedsWrite', ['arn:aws:s3:::jreese-net/mobile/v1/*']), ('S3AnalyticsSyncStageWrite', ['arn:aws:s3:::devops-agentcli-compute/projects/sync-stage/*']), ('CloudFrontInvalidation', ['arn:aws:cloudfront::${AWS::AccountId}:distribution/E2BOQXCW1TA6Y4']), ('SNSPublish', ['arn:aws:sns:${AWS::Region}:${AWS::AccountId}:devops-project-json-sync']), ('EventBridgePut', ['*'])]

## enceladus-governance-audit-role
  - missing actions: ['sns:publish']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('', ['arn:aws:sns:${AWS::Region}:${AWS::AccountId}:devops-project-json-sync'])]

## devops-doc-prep-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:query', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('CloudWatchLogs', ['arn:aws:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/devops-doc-prep*']), ('DynamoDBProjects', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/projects']), ('DynamoDBTracker', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/devops-project-tracker/index/*']), ('DynamoDBDocuments', ['arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/documents', 'arn:aws:dynamodb:${AWS::Region}:${AWS::AccountId}:table/documents/index/*']), ('S3ReadDocs', ['arn:aws:s3:::jreese-net/mobile/v1/reference/*', 'arn:aws:s3:::jreese-net/agent-documents/*'])]

## enceladus-bedrock-actions-lambda-role
  - missing actions: ['dynamodb:getitem', 'dynamodb:putitem', 'dynamodb:query', 'dynamodb:scan', 'dynamodb:updateitem', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject', 's3:listbucket']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'TrackerTableAccess', 'ProjectsTableRead', 'DocumentsTableRead', 'CoordinationTableRead', 'DeploymentTableRead', 'GovernancePoliciesRead', 'ComplianceTableWrite', 'S3ReadAccess']

## devops-changelog-api-lambda-role
  - missing actions: ['dynamodb:query', 'logs:createloggroup', 'logs:createlogstream', 'logs:putlogevents', 's3:getobject']
  - PROVEN statements (auto-codify): ['CloudWatchLogs', 'DeployTableRead', 'S3VersionRead']

## auth-refresh-lambda-role
  - missing actions: ['cognito-idp:initiateauth']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('', ['arn:aws:cognito-idp:us-east-1:${AWS::AccountId}:userpool/us-east-1_b2D0V3E1k'])]

## devops-feed-pipe-role
  - missing actions: ['sqs:getqueueattributes']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('SQSSend', ['arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:devops-feed-publish-queue.fifo'])]

## devops-graph-pipe-role
  - missing actions: ['sqs:getqueueattributes']
  - PROVEN statements (auto-codify): []
  - NEEDS REVIEW (not auto-emitted): [('SQSSend', ['arn:aws:sqs:${AWS::Region}:${AWS::AccountId}:devops-graph-sync-queue.fifo'])]
