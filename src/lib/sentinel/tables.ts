/**
 * Log Analytics table schemas of the simulated Sentinel workspace.
 *
 * Generated from the published references, column for column (never written from memory):
 *  - Azure Monitor table reference: learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/<table>
 *  - Defender XDR advanced hunting schema: learn.microsoft.com/en-us/defender-xdr/advanced-hunting-<table>-table
 *    (the streamed tables also carry Timestamp, which the Azure Monitor pages omit)
 *  - learn.microsoft.com/en-us/azure/sentinel/security-alert-schema (TenantId, SourceSystem on SecurityAlert)
 *  - Connector table definitions in github.com/Azure/Azure-Sentinel/Solutions, which is where the *_CL
 *    tables are defined. The misspelled SrcGeoLongtitude on OktaV2_CL is the real column name.
 * Hidden columns (_BilledSize, _IsBillable, _ResourceId, _SubscriptionId) are left out.
 */
import type { KqlColumn, KqlTable, KqlType } from "@/lib/kql/types";

type Compact = Partial<Record<KqlType, string>>;

const SCHEMAS: Record<string, Compact> = {
  // Sentinel analytics rules and Microsoft security products
  SecurityAlert: {
    string: "AlertLink AlertName AlertSeverity AlertType CompromisedEntity ConfidenceLevel Description DisplayName Entities ExtendedLinks ExtendedProperties ProductComponentName ProductName ProviderName RemediationSteps ResourceId SourceComputerId Status SubTechniques SystemAlertId Tactics Techniques Type VendorName VendorOriginalId WorkspaceResourceGroup WorkspaceSubscriptionId TenantId SourceSystem",
    real: "ConfidenceScore",
    datetime: "EndTime ProcessingEndTime StartTime TimeGenerated",
    bool: "IsIncident",
  },
  // Sentinel incidents
  SecurityIncident: {
    dynamic: "AdditionalData AlertIds BookmarkIds Comments Labels Owner RelatedAnalyticRuleIds Tasks",
    string: "Classification ClassificationComment ClassificationReason Description IncidentName IncidentUrl ModifiedBy ProviderIncidentId ProviderName Severity SourceSystem Status TenantId Title Type",
    datetime: "ClosedTime CreatedTime FirstActivityTime FirstModifiedTime LastActivityTime LastModifiedTime TimeGenerated",
    int: "IncidentNumber",
  },
  // Entra ID sign-ins
  SigninLogs: {
    string: "AADTenantId AlternateSignInName AppDisplayName AppId AppliedConditionalAccessPolicies AppOwnerTenantId AuthenticationAppDeviceDetails AuthenticationAppPolicyEvaluationDetails AuthenticationContextClassReferences AuthenticationDetails AuthenticationMethodsUsed AuthenticationProcessingDetails AuthenticationProtocol AuthenticationRequirement AuthenticationRequirementPolicies AuthenticatorAppLocation AutonomousSystemNumber Category ClientAppUsed ClientCredentialType ClientSessionId ConditionalAccessAudiences ConditionalAccessStatus CorrelationId CrossTenantAccessType FederatedCredentialId GlobalSecureAccessIpAddress HomeTenantId HomeTenantName Id Identity IncomingTokenType IPAddress IPAddressFromResourceProvider Level Location NetworkLocationDetails OperationName OperationVersion OriginalRequestId OriginalTransferMethod ProcessingTimeInMilliseconds Resource ResourceDisplayName ResourceGroup ResourceId ResourceIdentity ResourceOwnerTenantId ResourceProvider ResourceServicePrincipalId ResourceTenantId ResultDescription ResultSignature ResultType RiskDetail RiskEventTypes RiskEventTypes_V2 RiskLevel RiskLevelAggregated RiskLevelDuringSignIn RiskState RootActorID ServicePrincipalId ServicePrincipalName SessionId SessionLifetimePolicies SignInIdentifier SignInIdentifierType SourceAppClientId SourceSystem TokenIssuerName TokenIssuerType Type UniqueTokenIdentifier UserAgent UserDisplayName UserId UserPrincipalName UserType",
    dynamic: "Agent AppliedEventListeners ConditionalAccessPolicies DeviceDetail LocationDetails MfaDetail Status TokenProtectionStatusDetails",
    datetime: "CreatedDateTime TimeGenerated",
    long: "DurationMs",
    bool: "FlaggedForReview IsInteractive IsRisky IsTenantRestricted IsThroughGlobalSecureAccess",
  },
  // Entra ID directory audit
  AuditLogs: {
    string: "AADOperationType AADTenantId ActivityDisplayName Category CorrelationId Id Identity Level Location LoggedByService OperationName OperationVersion Resource ResourceGroup ResourceId ResourceProvider Result ResultDescription ResultReason ResultSignature ResultType SourceSystem Type",
    datetime: "ActivityDateTime TimeGenerated",
    dynamic: "AdditionalDetails InitiatedBy TargetResources",
    long: "DurationMs",
  },
  // Windows Security log
  SecurityEvent: {
    string: "AccessMask Account AccountDomain AccountExpires AccountName AccountSessionIdentifier AccountType Activity AdditionalInfo AdditionalInfo2 AllowedToDelegateTo Attributes AuditPolicyChanges AuthenticationPackageName AuthenticationProvider AuthenticationServer AuthenticationType AzureDeploymentID CACertificateHash CalledStationID CallerProcessId CallerProcessName CallingStationID CAPublicKeyHash CategoryId CertificateDatabaseHash Channel ClassId ClassName ClientAddress ClientIPAddress ClientName CommandLine CompatibleIds Computer Correlation DCDNSName DeviceDescription DeviceId DisplayName Disposition DomainBehaviorVersion DomainName DomainPolicyChanged DomainSid EAPType ElevatedToken EventData EventLevelName EventRecordId EventSourceName ExtendedQuarantineState FailureReason FileHash FilePath FilePathNoUser Filter ForceLogoff Fqbn FullyQualifiedSubjectMachineName FullyQualifiedSubjectUserName GroupMembership HandleId HardwareIds HomeDirectory HomePath InterfaceUuid IpAddress IpPort Keywords Level LmPackageName LocationInformation LockoutDuration LockoutObservationWindow LockoutThreshold LoggingResult LogonGuid LogonHours LogonID LogonProcessName LogonTypeName MachineAccountQuota MachineInventory MachineLogon ManagementGroupName MandatoryLabel MaxPasswordAge MemberName MemberSid MinPasswordAge MinPasswordLength MixedDomainMode NASIdentifier NASIPv4Address NASIPv6Address NASPort NASPortType NetworkPolicyName NewDate NewMaxUsers NewProcessId NewProcessName NewRemark NewShareFlags NewTime NewUacValue NewValue NewValueType ObjectName ObjectServer ObjectType ObjectValueName OemInformation OldMaxUsers OldRemark OldShareFlags OldUacValue OldValue OldValueType Opcode OperationType PackageName ParentProcessName PasswordHistoryLength PasswordLastSet PasswordProperties PreviousDate PreviousTime PrimaryGroupId PrivateKeyUsageCount PrivilegeList Process ProcessId ProcessName ProfilePath Properties ProtocolSequence ProxyPolicyName QuarantineHelpURL QuarantineSessionID QuarantineSessionIdentifier QuarantineState QuarantineSystemHealthResult RelativeTargetName RemoteIpAddress RemotePort Requester RequestId RestrictedAdminMode RowsDeleted SamAccountName ScriptPath SecurityDescriptor ServiceAccount ServiceFileName ServiceName ServiceType SessionName ShareLocalPath ShareName SidHistory SourceComputerId SourceSystem Status StorageAccount SubcategoryGuid SubcategoryId Subject SubjectAccount SubjectDomainName SubjectKeyIdentifier SubjectLogonId SubjectMachineName SubjectMachineSID SubjectUserName SubjectUserSid SubStatus SystemUserId TableId TargetAccount TargetDomainName TargetInfo TargetLinkedLogonId TargetLogonGuid TargetLogonId TargetOutboundDomainName TargetOutboundUserName TargetServerName TargetSid TargetUser TargetUserName TargetUserSid TemplateContent TemplateDSObjectFQDN TemplateInternalName TemplateOID TemplateSchemaVersion TemplateVersion TenantId TokenElevationType TransmittedServices Type UserAccountControl UserParameters UserPrincipalName UserWorkstations VendorIds VirtualAccount Workstation WorkstationName",
    int: "AuditsDiscarded AuthenticationLevel AuthenticationService ErrorCode EventID KeyLength LogonType ServiceStartType SystemProcessId SystemThreadId Task Version",
    datetime: "TimeGenerated",
  },
  // Windows event channels, where Sysmon lands
  Event: {
    string: "AzureDeploymentID Computer EventData EventLevelName EventLog ManagementGroupName Message ParameterXml RenderedDescription Role Source SourceSystem Type UserName TenantId",
    int: "EventCategory EventID EventLevel",
    datetime: "TimeGenerated",
  },
  // Defender for Endpoint
  DeviceProcessEvents: {
    string: "AccountDomain AccountName AccountObjectId AccountSid AccountUpn ActionType AppGuardContainerId DeviceId DeviceName FileName FolderPath InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessSignatureStatus InitiatingProcessSignerType InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion MachineGroup MD5 ProcessCommandLine ProcessIntegrityLevel ProcessRemoteSessionDeviceName ProcessRemoteSessionIP ProcessTokenElevation ProcessUniqueId ProcessVersionInfoCompanyName ProcessVersionInfoFileDescription ProcessVersionInfoInternalFileName ProcessVersionInfoOriginalFileName ProcessVersionInfoProductName ProcessVersionInfoProductVersion SHA1 SHA256 SourceSystem TenantId Type",
    dynamic: "AdditionalFields",
    long: "CreatedProcessSessionId FileSize InitiatingProcessFileSize InitiatingProcessId InitiatingProcessLogonId InitiatingProcessParentId InitiatingProcessSessionId LogonId ProcessId ReportId",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime ProcessCreationTime TimeGenerated Timestamp",
    bool: "IsInitiatingProcessRemoteSession IsProcessRemoteSession",
  },
  // Defender for Endpoint
  DeviceNetworkEvents: {
    string: "ActionType AppGuardContainerId DeviceId DeviceName InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion LocalIP LocalIPType MachineGroup Protocol RemoteIP RemoteIPType RemoteUrl SourceSystem TenantId Type",
    dynamic: "AdditionalFields",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime TimeGenerated Timestamp",
    long: "InitiatingProcessFileSize InitiatingProcessId InitiatingProcessParentId InitiatingProcessSessionId ReportId",
    bool: "IsInitiatingProcessRemoteSession",
    int: "LocalPort RemotePort",
  },
  // Defender for Endpoint
  DeviceFileEvents: {
    string: "ActionType AppGuardContainerId DeviceId DeviceName FileName FileOriginIP FileOriginReferrerUrl FileOriginUrl FolderPath InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion MachineGroup MD5 PreviousFileName PreviousFolderPath RequestAccountDomain RequestAccountName RequestAccountSid RequestProtocol RequestSourceIP SensitivityLabel SensitivitySubLabel SHA1 SHA256 ShareName SourceSystem TenantId Type",
    dynamic: "AdditionalFields",
    long: "FileSize InitiatingProcessFileSize InitiatingProcessId InitiatingProcessParentId InitiatingProcessSessionId ReportId",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime TimeGenerated Timestamp",
    bool: "IsAzureInfoProtectionApplied IsInitiatingProcessRemoteSession",
    int: "RequestSourcePort",
  },
  // Defender for Endpoint
  DeviceRegistryEvents: {
    string: "ActionType AppGuardContainerId DeviceId DeviceName InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion MachineGroup PreviousRegistryKey PreviousRegistryValueData PreviousRegistryValueName RegistryKey RegistryValueData RegistryValueName RegistryValueType SourceSystem TenantId Type",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime TimeGenerated Timestamp",
    long: "InitiatingProcessFileSize InitiatingProcessId InitiatingProcessParentId InitiatingProcessSessionId ReportId",
    bool: "IsInitiatingProcessRemoteSession",
  },
  // Defender for Endpoint
  DeviceLogonEvents: {
    string: "AccountDomain AccountName AccountSid ActionType AppGuardContainerId DeviceId DeviceName FailureReason InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion LogonType MachineGroup Protocol RemoteDeviceName RemoteIP RemoteIPType SourceSystem TenantId Type",
    dynamic: "AdditionalFields",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime TimeGenerated Timestamp",
    long: "InitiatingProcessFileSize InitiatingProcessId InitiatingProcessParentId InitiatingProcessSessionId LogonId ReportId",
    bool: "IsInitiatingProcessRemoteSession IsLocalAdmin",
    int: "RemotePort",
  },
  // Defender for Endpoint
  DeviceEvents: {
    string: "AccountDomain AccountName AccountSid ActionType AppGuardContainerId DeviceId DeviceName FileName FileOriginIP FileOriginUrl FolderPath InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion LocalIP MachineGroup MD5 ProcessCommandLine ProcessRemoteSessionDeviceName ProcessRemoteSessionIP ProcessTokenElevation RegistryKey RegistryValueData RegistryValueName RemoteDeviceName RemoteIP RemoteUrl SHA1 SHA256 SourceSystem TenantId Type",
    dynamic: "AdditionalFields",
    long: "CreatedProcessSessionId FileSize InitiatingProcessFileSize InitiatingProcessId InitiatingProcessLogonId InitiatingProcessParentId InitiatingProcessSessionId LogonId ProcessId ReportId",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime ProcessCreationTime TimeGenerated Timestamp",
    bool: "IsInitiatingProcessRemoteSession IsProcessRemoteSession",
    int: "LocalPort RemotePort",
  },
  // Defender for Endpoint
  DeviceImageLoadEvents: {
    string: "ActionType AppGuardContainerId DeviceId DeviceName FileName FolderPath InitiatingProcessAccountDomain InitiatingProcessAccountName InitiatingProcessAccountObjectId InitiatingProcessAccountSid InitiatingProcessAccountUpn InitiatingProcessCommandLine InitiatingProcessFileName InitiatingProcessFolderPath InitiatingProcessIntegrityLevel InitiatingProcessMD5 InitiatingProcessParentFileName InitiatingProcessRemoteSessionDeviceName InitiatingProcessRemoteSessionIP InitiatingProcessSHA1 InitiatingProcessSHA256 InitiatingProcessTokenElevation InitiatingProcessUniqueId InitiatingProcessVersionInfoCompanyName InitiatingProcessVersionInfoFileDescription InitiatingProcessVersionInfoInternalFileName InitiatingProcessVersionInfoOriginalFileName InitiatingProcessVersionInfoProductName InitiatingProcessVersionInfoProductVersion MachineGroup MD5 SHA1 SHA256 SourceSystem TenantId Type",
    long: "FileSize InitiatingProcessFileSize InitiatingProcessId InitiatingProcessParentId InitiatingProcessSessionId ReportId",
    datetime: "InitiatingProcessCreationTime InitiatingProcessParentCreationTime TimeGenerated Timestamp",
    bool: "IsInitiatingProcessRemoteSession",
  },
  // Defender XDR
  AlertInfo: {
    string: "AlertId AttackTechniques Category DetectionSource ServiceSource Severity SourceSystem TenantId Title Type",
    datetime: "TimeGenerated Timestamp",
  },
  // Defender XDR
  AlertEvidence: {
    string: "AccountDomain AccountName AccountObjectId AccountSid AccountUpn AlertId Application AttackTechniques AzureResourceId AzureResourceType AzureSubscriptionId Categories CloudPlatform CloudResource DetectionSource DeviceId DeviceName EmailSubject EntityType EvidenceDirection EvidenceRole FileName FolderPath LocalIP NetworkMessageId OAuthApplicationId ProcessCommandLine RegistryKey RegistryValueData RegistryValueName RemoteIP RemoteUrl ServiceSource Severity SHA1 SHA256 SourceSystem TenantId ThreatFamily Title Type",
    dynamic: "AdditionalFields",
    int: "ApplicationId",
    long: "FileSize",
    datetime: "TimeGenerated Timestamp",
  },
  // Office 365 connector
  OfficeActivity: {
    string: "AADGroupId AADTarget Activity Actor ActorContextId ActorIpAddress AddOnGuid AddonName AddOnType AffectedItems AppDistributionMode AppId Application ApplicationId AppPoolName AzureActiveDirectory_EventType AzureADAppId ChannelGuid ChannelName ChannelType ChatName ChatThreadId Client Client_IPAddress ClientAppId ClientInfoString ClientIP ClientMachineName ClientProcessName ClientVersion CommunicationType CustomEvent DestFolder DestinationFileExtension DestinationFileName DestinationRelativeUrl DestMailboxId DestMailboxOwnerMasterAccountSid DestMailboxOwnerSid DestMailboxOwnerUPN DeviceInformation EffectiveOrganization ElevationApprover ElevationRequestId ElevationRole Event_Data EventSource ExtendedProperties ExternalAccess Folder Folders GenericInfo InterSystemsId IntraSystemId Item ItemName ItemType ListItemUniqueId Logon_Type LogonUserDisplayName LogonUserSid MachineDomainInfo MachineId MailboxGuid MailboxOwnerMasterAccountSid MailboxOwnerSid MailboxOwnerUPN MeetingDetailId MessageId ModifiedObjectResolvedName ModifiedProperties Name NewValue OfficeId OfficeObjectId OfficeTenantId OfficeWorkload OldValue Operation OperationScope OrganizationId OrganizationName OriginatingServer Parameters RecordType ResultReasonType ResultStatus SendAsUserMailboxGuid SendAsUserSmtp SendonBehalfOfUserMailboxGuid SendOnBehalfOfUserSmtp SensitivityLabelId SharingType Site_ Site_Url Source_Name SourceFileExtension SourceFileName SourceRecordId SourceRelativeUrl SourceSystem SRPolicyId SRPolicyName SupportTicketId TabType TargetContextId TargetUserId TargetUserOrGroupName TargetUserOrGroupType TeamGuid TeamName TenantId Type UniqueSharingId UserAgent UserDomain UserId UserKey UserSharedWith UserType",
    dynamic: "AppAccessContext ArtifactsShared Attendees ExtraProperties Members OperationProperties SRRuleMatchDetails",
    bool: "CrossMailboxOperations IsJoinedFromLobby IsManagedDevice",
    int: "DataCenterSecurityEventType ElevationDuration InternalLogonType LoginStatus",
    datetime: "ElevationApprovedTime ElevationTime JoinTime LeaveTime Start_Time TimeGenerated",
  },
  // Defender for Office 365
  EmailEvents: {
    dynamic: "AdditionalFields Cc To",
    int: "AttachmentCount BulkComplaintLevel EmailSize UrlCount",
    string: "AuthenticationDetails ConfidenceLevel Connectors Context DeliveryAction DeliveryLocation DetectionMethods DistributionList EmailAction EmailActionPolicy EmailActionPolicyGuid EmailDirection EmailLanguage ExchangeTransportRule ForwardingInformation InternetMessageId LatestDeliveryAction LatestDeliveryLocation NetworkMessageId OrgLevelAction OrgLevelPolicy RecipientDomain RecipientEmailAddress RecipientObjectId ReportId SenderDisplayName SenderFromAddress SenderFromDomain SenderIPv4 SenderIPv6 SenderMailFromAddress SenderMailFromDomain SenderObjectId SourceSystem Subject TenantId ThreatClassification ThreatNames ThreatTypes Type UserLevelAction UserLevelPolicy",
    long: "EmailClusterId",
    bool: "IsFirstContact",
    datetime: "LastEventExecutionTime TimeGenerated Timestamp",
  },
  // Defender for Office 365
  EmailAttachmentInfo: {
    string: "DetectionMethods FileExtension FileName FileType NetworkMessageId RecipientEmailAddress RecipientObjectId ReportId SenderDisplayName SenderFromAddress SenderObjectId SHA256 SourceSystem TenantId ThreatNames ThreatTypes Type",
    long: "FileSize",
    datetime: "TimeGenerated Timestamp",
  },
  // Defender for Office 365
  EmailUrlInfo: {
    string: "NetworkMessageId ReportId SourceSystem TenantId Type Url UrlChainId UrlDomain UrlLocation",
    datetime: "TimeGenerated Timestamp",
    int: "UrlChainPosition",
  },
  // Defender for Office 365
  EmailPostDeliveryEvents: {
    string: "Action ActionResult ActionTrigger ActionType DeliveryLocation DetectionMethods EmailDirection InternetMessageId NetworkMessageId RecipientEmailAddress ReportId SenderFromAddress SourceSystem TenantId ThreatTypes Type",
    datetime: "TimeGenerated Timestamp",
  },
  // Defender for Office 365
  UrlClickEvents: {
    string: "AccountUpn ActionType AppName AppVersion DetectionMethods IPAddress NetworkMessageId ReportId SourceId SourceSystem TenantId ThreatTypes Type Url UrlChain Workload",
    bool: "IsClickedThrough",
    datetime: "TimeGenerated Timestamp",
  },
  // CEF: firewalls, VPN, proxy, PAM, Falcon detections
  CommonSecurityLog: {
    string: "Activity AdditionalExtensions ApplicationProtocol CollectorHostName CommunicationDirection Computer DestinationDnsDomain DestinationHostName DestinationIP DestinationMACAddress DestinationNTDomain DestinationProcessName DestinationServiceName DestinationTranslatedAddress DestinationUserID DestinationUserName DestinationUserPrivileges DeviceAction DeviceAddress DeviceCustomDate1 DeviceCustomDate1Label DeviceCustomDate2 DeviceCustomDate2Label DeviceCustomFloatingPoint1Label DeviceCustomFloatingPoint2Label DeviceCustomFloatingPoint3Label DeviceCustomFloatingPoint4Label DeviceCustomIPv6Address1 DeviceCustomIPv6Address1Label DeviceCustomIPv6Address2 DeviceCustomIPv6Address2Label DeviceCustomIPv6Address3 DeviceCustomIPv6Address3Label DeviceCustomIPv6Address4 DeviceCustomIPv6Address4Label DeviceCustomNumber1Label DeviceCustomNumber2Label DeviceCustomNumber3Label DeviceCustomString1 DeviceCustomString1Label DeviceCustomString2 DeviceCustomString2Label DeviceCustomString3 DeviceCustomString3Label DeviceCustomString4 DeviceCustomString4Label DeviceCustomString5 DeviceCustomString5Label DeviceCustomString6 DeviceCustomString6Label DeviceDnsDomain DeviceEventCategory DeviceEventClassID DeviceExternalID DeviceFacility DeviceInboundInterface DeviceMacAddress DeviceName DeviceNtDomain DeviceOutboundInterface DevicePayloadId DeviceProduct DeviceTimeZone DeviceTranslatedAddress DeviceVendor DeviceVersion EventOutcome ExtID FileCreateTime FileHash FileID FileModificationTime FileName FilePath FilePermission FileType FlexDate1 FlexDate1Label FlexNumber1Label FlexNumber2Label FlexString1 FlexString1Label FlexString2 FlexString2Label IndicatorThreatType LogSeverity MaliciousIP MaliciousIPCountry Message OldFileCreateTime OldFileHash OldFileID OldFileModificationTime OldFileName OldFilePath OldFilePermission OldFileType OriginalLogSeverity ProcessName Protocol Reason ReceiptTime RemoteIP RemotePort ReportReferenceLink RequestClientApplication RequestContext RequestCookies RequestMethod RequestURL SimplifiedDeviceAction SourceDnsDomain SourceHostName SourceIP SourceMACAddress SourceNTDomain SourceProcessName SourceServiceName SourceSystem SourceTranslatedAddress SourceUserID SourceUserName SourceUserPrivileges TenantId ThreatConfidence ThreatDescription Type",
    int: "DestinationPort DestinationProcessId DestinationTranslatedPort DeviceCustomNumber1 DeviceCustomNumber2 DeviceCustomNumber3 EventCount EventType ExternalID FileSize FlexNumber1 FlexNumber2 OldFileSize ProcessID SourcePort SourceProcessId SourceTranslatedPort ThreatSeverity",
    real: "DeviceCustomFloatingPoint1 DeviceCustomFloatingPoint2 DeviceCustomFloatingPoint3 DeviceCustomFloatingPoint4 MaliciousIPLatitude MaliciousIPLongitude",
    datetime: "EndTime StartTime TimeGenerated",
    long: "FieldDeviceCustomNumber1 FieldDeviceCustomNumber2 FieldDeviceCustomNumber3 ReceivedBytes SentBytes",
  },
  // Linux hosts, Infoblox NIOS
  Syslog: {
    string: "CollectorHostName Computer Facility HostIP HostName ProcessName SeverityLevel SourceSystem SyslogMessage Type TenantId",
    datetime: "EventTime TimeGenerated",
    int: "ProcessID",
  },
  // Windows DNS server
  DnsEvents: {
    string: "ClientIP Computer Confidence Description IndicatorThreatType IPAddresses MaliciousIP Message Name QueryType RemoteIPCountry Result SourceSystem SubType TaskCategory Type TenantId",
    int: "EventId ResultCode Severity",
    real: "RemoteIPLatitude RemoteIPLongitude",
    datetime: "TimeGenerated",
  },
  // Azure subscription activity
  AzureActivity: {
    string: "ActivityStatus ActivityStatusValue ActivitySubstatus ActivitySubstatusValue Authorization Caller CallerIpAddress Category CategoryValue Claims CorrelationId EventDataId Hierarchy HTTPRequest Level OperationId OperationName OperationNameValue Properties Resource ResourceGroup ResourceId ResourceProvider ResourceProviderValue SourceSystem SubscriptionId TenantId Type",
    dynamic: "Authorization_d Claims_d Properties_d",
    datetime: "EventSubmissionTimestamp TimeGenerated",
  },
  // AWS S3 connector
  AWSCloudTrail: {
    string: "AdditionalEventData APIVersion AwsEventId AWSRegion AwsRequestId AwsRequestId_ Category CidrIp CipherSuite ClientProvidedHostHeader DestinationPort EC2RoleDelivery ErrorCode ErrorMessage EventName EventSource EventTypeName EventVersion IpProtocol OperationName RecipientAccountId RequestParameters Resources ResponseElements ServiceEventDetails SessionIssuerAccountId SessionIssuerArn SessionIssuerPrincipalId SessionIssuerType SessionIssuerUserName SharedEventId SourceIpAddress SourcePort SourceSystem TenantId TlsVersion Type UserAgent UserIdentityAccessKeyId UserIdentityAccountId UserIdentityArn UserIdentityInvokedBy UserIdentityPrincipalid UserIdentityStoreArn UserIdentityType UserIdentityUserId UserIdentityUserName VpcEndpointId",
    bool: "ManagementEvent ReadOnly SessionMfaAuthenticated",
    datetime: "SessionCreationDate TimeGenerated",
  },
  // AWS S3 connector
  AWSGuardDuty: {
    string: "AccountId ActivityType Arn Description Id Partition Region SchemaVersion SourceSystem TenantId Title Type",
    dynamic: "ResourceDetails ServiceDetails",
    int: "Severity",
    datetime: "TimeCreated TimeGenerated",
  },
  // AWS S3 connector
  AWSVPCFlow: {
    string: "AccountId Action AzId DstAddr EcsClusterArn EcsClusterName EcsContainerId EcsContainerInstanceArn EcsContainerInstanceId EcsSecondContainerId EcsServiceName EcsTaskArn EcsTaskDefinitionArn EcsTaskId FlowDirection InstanceId InterfaceId LogStatus PktDstAddr PktDstAwsService PktSrcAddr PktSrcAwsService Region SourceSystem SrcAddr SublocationId SublocationType SubnetId TenantId TrafficPath TrafficType Type VpcId",
    long: "Bytes",
    int: "DstPort Packets Protocol SrcPort TcpFlags Version",
    datetime: "End Start TimeGenerated",
  },
  // GCP Pub/Sub connector
  GCPAuditLogs: {
    dynamic: "AuthenticationInfo AuthorizationInfo Metadata Request RequestMetadata ResourceLocation ResourceOriginalState Response ServiceData Status",
    string: "GCPResourceName GCPResourceType InsertId LogName MethodName NumResponseItems PrincipalEmail ProjectId ServiceName Severity SourceSystem StatusMessage Subscription TenantId Type",
    datetime: "TimeGenerated Timestamp",
  },
  // AKS diagnostic settings
  AKSAudit: {
    dynamic: "Annotations ObjectRef RequestObject ResponseObject ResponseStatus SourceIps User",
    string: "AuditId Level PodName RequestUri SourceSystem Stage TenantId Type UserAgent Verb",
    datetime: "RequestReceivedTime StageReceivedTime TimeGenerated",
  },
  // Google Workspace Activities connector
  GoogleWorkspaceReports: {
    string: "AccountState ActorApplicationInfoApplicationName ActorApplicationInfoOauthClientId ActorCallerType ActorEmail ActorKey ActorProfileId ApiKind ApplicationEdition ApplicationName AppName BrowserVersion CalendarId ChromeOrgUnitId ClientId ClientType ContentHash ContentName ContentRiskLevel ContentSize ContentTransferMethod ContentType DestinationFolderId DestinationFolderTitle DestUserUpn DeviceId DeviceName DevicePlatform DeviceType DeviceUser DocId DocTitle DocType DstUserUpn DvcGuid DvcInterfaceGuid DvcModelName DvcModelNumber DvcType Etag EventEndTime EventGuest EventId EventMessage EventName EventOriginalMessage EventProduct EventResourceId EventResourceName EventResponseStatus EventResult EventStartTime EventTitle EventType EventUid EventVendor GroupDomain GroupEmail IdApplicationName IdCustomerId IdTime IdUniqueQualifier IosVendorId IosVendorUID Kind LastSyncAuditDate LoginChallengeMethod LoginChallengeStatus LoginType ModuleName NetworkInfoRegionCode NetworkInfoSubdivisionCode NewValue NotificationMessageId NotificationMethod NotificationType OldEventTitle OldValue OldVisibility OrganizerCalendarId OrgUnitName OriginatingAppId OsProperty Owner OwnerDomain OwnerEmail ProcessName ProfileUserName RegisterPrivelege Resource_Id RoleName RuleName ScanId Scope ScopeData SerialNumber SharedDriveId SourceFolderId SourceFolderTitle SourceSystem SrcIpAddr TargetCalendarId TargetDomain TargetUserDomain TargetUserName TeamDriveId TenantId Timestamp TriggerDestination TriggerSource TriggerType Type Url UserAadid UserAgent UserAgentOriginal UserEmail Value VirtualDeviceId Visibility VisibilityChange",
    bool: "ActorApplicationInfoImpersonation ActorIsCollaboratorAccount Billable IsSecondFactor IsSuspicious OwnerIsSharedDrive OwnerIsTeamDrive PrimaryEvent",
    dynamic: "EventParameters NetworkIpAsn ResourceDetails",
    datetime: "TimeGenerated",
  },
  // CrowdStrike Falcon Data Replicator connector
  ASimProcessEventLogs: {
    string: "ActingProcessCommandLine ActingProcessEntityKey ActingProcessFileCompany ActingProcessFileDescription ActingProcessFileInternalName ActingProcessFilename ActingProcessFileOriginalName ActingProcessFileProduct ActingProcessFileVersion ActingProcessGuid ActingProcessId ActingProcessIMPHASH ActingProcessInjectedAddress ActingProcessIntegrityLevel ActingProcessMD5 ActingProcessName ActingProcessSHA1 ActingProcessSHA256 ActingProcessSHA512 ActingProcessTokenElevation ActorOriginalUserType ActorScope ActorScopeId ActorSessionId ActorUserEntityKey ActorUserId ActorUserIdType ActorUsername ActorUsernameType ActorUserType DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcScope DvcScopeId DvcZone EventMessage EventOriginalResultDetails EventOriginalSeverity EventOriginalSubType EventOriginalType EventOriginalUid EventOwner EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchemaVersion EventSeverity EventSubType EventType EventVendor ParentProcessEntityKey ParentProcessFileCompany ParentProcessFileDescription ParentProcessFileProduct ParentProcessFileVersion ParentProcessGuid ParentProcessId ParentProcessIMPHASH ParentProcessInjectedAddress ParentProcessIntegrityLevel ParentProcessMD5 ParentProcessName ParentProcessSHA1 ParentProcessSHA256 ParentProcessSHA512 ParentProcessTokenElevation RuleName SourceSystem TargetOriginalUserType TargetProcessCommandLine TargetProcessCurrentDirectory TargetProcessEntityKey TargetProcessFileCompany TargetProcessFileDescription TargetProcessFileInternalName TargetProcessFilename TargetProcessFileOriginalName TargetProcessFileProduct TargetProcessFileVersion TargetProcessGuid TargetProcessId TargetProcessIMPHASH TargetProcessInjectedAddress TargetProcessIntegrityLevel TargetProcessMD5 TargetProcessName TargetProcessSHA1 TargetProcessSHA256 TargetProcessSHA512 TargetProcessStatusCode TargetProcessTokenElevation TargetScope TargetScopeId TargetUserEntityKey TargetUserId TargetUserIdType TargetUsername TargetUsernameType TargetUserSessionGuid TargetUserSessionId TargetUserType TenantId ThreatCategory ThreatField ThreatId ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel Type",
    datetime: "ActingProcessCreationTime EventEndTime EventStartTime ParentProcessCreationTime TargetProcessCreationTime ThreatFirstReportedTime ThreatLastReportedTime TimeGenerated",
    long: "ActingProcessFileSize TargetProcessFileSize",
    bool: "ActingProcessIsHidden ParentProcessIsHidden TargetProcessIsHidden ThreatIsActive",
    dynamic: "ActorUserAdditionalIds AdditionalEntities AdditionalFields TargetUserAdditionalIds",
    int: "EventCount RuleNumber ThreatConfidence ThreatRiskLevel",
  },
  // CrowdStrike Falcon Data Replicator connector
  ASimNetworkSessionLogs: {
    dynamic: "AdditionalEntities AdditionalFields DstUserAdditionalIds SrcUserAdditionalIds",
    string: "DstAppId DstApplicationEntityKey DstAppName DstAppType DstDescription DstDeviceType DstDomain DstDomainType DstDvcId DstDvcIdType DstFQDN DstGeoCity DstGeoCountry DstGeoRegion DstHostname DstInterfaceGuid DstInterfaceName DstIpAddr DstMacAddr DstNatIpAddr DstOriginalUserType DstSubscriptionId DstSystemEntityKey DstUserEntityKey DstUserId DstUserIdType DstUsername DstUsernameType DstUserType DstVlanId DstZone Dvc DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInboundInterface DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcOutboundInterface DvcSubscriptionId DvcZone EventMessage EventOriginalResultDetails EventOriginalSeverity EventOriginalSubType EventOriginalType EventOriginalUid EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchemaVersion EventSeverity EventSubType EventType EventVendor NetworkApplicationProtocol NetworkConnectionHistory NetworkDirection NetworkIcmpType NetworkProtocol NetworkProtocolVersion NetworkRuleName NetworkSessionId SourceSystem SrcAppId SrcApplicationEntityKey SrcAppName SrcAppType SrcDescription SrcDeviceType SrcDomain SrcDomainType SrcDvcId SrcDvcIdType SrcFQDN SrcGeoCity SrcGeoCountry SrcGeoRegion SrcHostname SrcInterfaceGuid SrcInterfaceName SrcIpAddr SrcMacAddr SrcNatIpAddr SrcOriginalUserType SrcSubscriptionId SrcSystemEntityKey SrcUserEntityKey SrcUserId SrcUserIdType SrcUsername SrcUsernameType SrcUserType SrcVlanId SrcZone TenantId ThreatCategory ThreatField ThreatId ThreatIpAddr ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel Type",
    long: "DstBytes DstPackets NetworkBytes NetworkPackets SrcBytes SrcPackets",
    real: "DstGeoLatitude DstGeoLongitude SrcGeoLatitude SrcGeoLongitude",
    int: "DstNatPortNumber DstPortNumber EventCount NetworkDuration NetworkIcmpCode NetworkRuleNumber SrcNatPortNumber SrcPortNumber ThreatConfidence ThreatRiskLevel",
    datetime: "EventEndTime EventStartTime ThreatFirstReportedTime ThreatLastReportedTime TimeGenerated",
    bool: "TcpFlagsAck TcpFlagsFin TcpFlagsPsh TcpFlagsRst TcpFlagsSyn TcpFlagsUrg ThreatIsActive",
  },
  // CrowdStrike Falcon Data Replicator connector
  ASimFileEventLogs: {
    string: "ActingApplicationEntityKey ActingProcessCommandLine ActingProcessGuid ActingProcessId ActingProcessName ActorOriginalUserType ActorScope ActorScopeId ActorSessionId ActorUserAadId ActorUserEntityKey ActorUserId ActorUserIdType ActorUsername ActorUsernameType ActorUserSid ActorUserType DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcScope DvcScopeId DvcZone EventMessage EventOriginalResultDetails EventOriginalSeverity EventOriginalSubType EventOriginalType EventOriginalUid EventOwner EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchema EventSchemaVersion EventSeverity EventSubType EventType EventVendor HashType HttpUserAgent NetworkApplicationProtocol RuleName SourceSystem SrcDescription SrcDeviceType SrcDomain SrcDomainType SrcDvcId SrcDvcIdType SrcDvcScope SrcDvcScopeId SrcFileDirectory SrcFileEntityKey SrcFileExtension SrcFileMD5 SrcFileMimeType SrcFileName SrcFilePath SrcFilePathType SrcFileSHA1 SrcFileSHA256 SrcFileSHA512 SrcFQDN SrcGeoCity SrcGeoCountry SrcGeoRegion SrcHostname SrcIpAddr SrcMacAddr SrcOriginalRiskLevel SrcProcessEntityKey SrcSystemEntityKey TargetAppId TargetApplicationEntityKey TargetAppName TargetAppType TargetFileDirectory TargetFileEntityKey TargetFileExtension TargetFileMD5 TargetFileMimeType TargetFileName TargetFilePath TargetFilePathType TargetFileSHA1 TargetFileSHA256 TargetFileSHA512 TargetOriginalAppType TargetUrl TenantId ThreatCategory ThreatField ThreatFilePath ThreatId ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel Type",
    dynamic: "ActorUserAdditionalIds AdditionalEntities AdditionalFields",
    int: "EventCount RuleNumber SrcPortNumber SrcRiskLevel ThreatConfidence ThreatRiskLevel",
    datetime: "EventEndTime EventStartTime SrcFileCreationTime TargetFileCreationTime ThreatFirstReportedTime ThreatLastReportedTime TimeGenerated",
    long: "SrcFileSize TargetFileSize",
    real: "SrcGeoLatitude SrcGeoLongitude",
    bool: "ThreatIsActive",
  },
  // CrowdStrike Falcon Data Replicator connector
  ASimRegistryEventLogs: {
    string: "ActingProcessCommandLine ActingProcessEntityKey ActingProcessGuid ActingProcessId ActingProcessName ActorOriginalUserType ActorScope ActorScopeId ActorSessionId ActorUserAadId ActorUserEntityKey ActorUserId ActorUserIdType ActorUsername ActorUsernameType ActorUserSid ActorUserType DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcScope DvcScopeId DvcZone EventMessage EventOriginalResultDetails EventOriginalSeverity EventOriginalSubType EventOriginalType EventOriginalUid EventOwner EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchema EventSchemaVersion EventSeverity EventSubType EventType EventVendor ParentProcessCommandLine ParentProcessEntityKey ParentProcessGuid ParentProcessId ParentProcessName RegistryKey RegistryPreviousKey RegistryPreviousValue RegistryPreviousValueData RegistryPreviousValueType RegistryValue RegistryValueData RegistryValueType RuleName SourceSystem TenantId ThreatCategory ThreatField ThreatId ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel Type",
    dynamic: "ActorUserAdditionalIds AdditionalEntities AdditionalFields",
    int: "EventCount RuleNumber ThreatConfidence ThreatRiskLevel",
    datetime: "EventEndTime EventStartTime ThreatFirstReportedTime ThreatLastReportedTime TimeGenerated",
    bool: "ThreatIsActive",
  },
  // CrowdStrike Falcon Data Replicator connector
  ASimDnsActivityLogs: {
    dynamic: "AdditionalEntities AdditionalFields SrcUserAdditionalIds",
    string: "DnsFlags DnsQuery DnsQueryClassName DnsQueryTypeName DnsResponseIpCity DnsResponseIpCountry DnsResponseIpRegion DnsResponseName DnsSessionId Dst DstDescription DstDeviceType DstDomain DstDomainType DstDvcId DstDvcIdType DstDvcScope DstDvcScopeId DstFQDN DstGeoCity DstGeoCountry DstGeoRegion DstHostname DstIpAddr DstOriginalRiskLevel DstSystemEntityKey Dvc DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcScope DvcScopeId DvcZone EventMessage EventOriginalSeverity EventOriginalType EventOriginalUid EventOwner EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchemaVersion EventSeverity EventSubType EventType EventVendor NetworkProtocol NetworkProtocolVersion RuleName SourceSystem Src SrcDescription SrcDeviceType SrcDomain SrcDomainType SrcDvcId SrcDvcIdType SrcDvcScope SrcDvcScopeId SrcFQDN SrcGeoCity SrcGeoCountry SrcGeoRegion SrcHostname SrcIpAddr SrcOriginalRiskLevel SrcOriginalUserType SrcProcessEntityKey SrcProcessGuid SrcProcessId SrcProcessName SrcSystemEntityKey SrcUserEntityKey SrcUserId SrcUserIdType SrcUsername SrcUsernameType SrcUserScope SrcUserScopeId SrcUserSessionId SrcUserType TenantId ThreatCategory ThreatField ThreatFirstReportedTime ThreatId ThreatIpAddr ThreatLastReportedTime ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel_s TransactionIdHex Type UrlCategory",
    bool: "DnsFlagsAuthenticated DnsFlagsAuthoritative DnsFlagsCheckingDisabled DnsFlagsRecursionAvailable DnsFlagsRecursionDesired DnsFlagsTruncated DnsFlagsZ ThreatIsActive",
    int: "DnsNetworkDuration DnsQueryClass DnsQueryType DnsResponseCode DstPortNumber DstRiskLevel EventCount RuleNumber SrcPortNumber SrcRiskLevel ThreatConfidence ThreatOriginalRiskLevel ThreatRiskLevel",
    real: "DnsResponseIpLatitude DnsResponseIpLongitude DstGeoLatitude DstGeoLongitude SrcGeoLatitude SrcGeoLongitude",
    datetime: "EventEndTime EventStartTime ThreatFirstReportedTime_d ThreatLastReportedTime_d TimeGenerated",
  },
  // Okta SSO codeless connector
  OktaV2_CL: {
    string: "ActingAppName ActingAppType ActorDisplayName ActorSessionId ActorUserId ActorUserIdType ActorUsername ActorUsernameType ActorUserType AuthenticationContextAuthenticationProvider AuthenticationContextCredentialProvider AuthenticationContextInterface AuthenticationContextIssuerId AuthenticationContextIssuerType DomainName DvcAction EventMessage EventOriginalResultDetails EventOriginalType EventOriginalUid EventResult EventSeverity HttpUserAgent LegacyEventType LogonMethod OriginalActorAlternateId OriginalClientDevice OriginalOutcomeResult OriginalSeverity OriginalUserId OriginalUserType SecurityContextAsOrg SecurityContextDomain SrcDeviceType SrcDvcId SrcDvcOs SrcGeoCity SrcGeoCountry SrcGeoPostalCode SrcGeoRegion SrcIpAddr SrcIsp SrcZone TransactionId TransactionType Version SrcDvcIdType Type TenantId",
    dynamic: "ActorDetailEntry DebugData OriginalTarget Request TransactionDetail",
    int: "AuthenticationContextAuthenticationStep SecurityContextAsNumber",
    bool: "SecurityContextIsProxy",
    real: "SrcGeoLatitude SrcGeoLongtitude",
    datetime: "TimeGenerated",
  },
  // SentinelOne codeless connector
  SentinelOneThreats_CL: {
    datetime: "TimeGenerated CreatedAt UpdatedAt",
    string: "FilePath CloudVerdict MitigationMode AgentOsType InitiatingUserId Engines Id FileExtensionType MitigationStatus AgentDomain FileDisplayName AgentIp AccountName AgentMachineType FileVerificationType Indicators InitiatedByDescription AgentId ProcessArguments MitigationReport ThreatName ClassificationSource InitiatedBy AgentNetworkStatus AgentComputerName Classification CertId SiteId AgentVersion FileContentHash WhiteningOptions Username FileSha256 CollectionId SiteName AccountId Type TenantId",
    bool: "AgentInfected IsCertValid AutomaticallyResolved AgentIsActive AgentIsDecommissioned",
    dynamic: "ThreatInfo AgentDetectionInfo AgentRealtimeInfo",
  },
  // Sophos Endpoint Protection codeless connector
  SophosEPAlerts_CL: {
    datetime: "TimeGenerated EventEndTime",
    string: "CustomerId EventSeverity EventVendor EventType EventProduct event_service_event_id DvcAction description DvcHostname EventOriginalUid Source ThreatName Type TenantId",
    dynamic: "data info",
    bool: "threat_cleanable",
  },
  // Sophos Endpoint Protection codeless connector
  SophosEPEvents_CL: {
    datetime: "TimeGenerated Created EventEndTime",
    string: "EventVendor EventProduct EventType AppSha256 CoreRemedyItems CustomerId EndpointId SrcDvcType ThreatCategory EventOriginalUid DvcHostname EventMessage EventSubType EventSeverity Source SrcIpAddr ThreatName DvcAction DstUserSid Type TenantId",
    dynamic: "amsi_threat_data appCerts details ips_threat_data source_info whitelist_properties",
    int: "CoreRemedyTotalItems",
  },
  // Proofpoint TAP codeless connector
  ProofPointTAPClicksPermittedV2_CL: {
    string: "campaignId classification clickIP GUID id messageID recipient sender senderIP threatID threatStatus threatURL url userAgent Type TenantId",
    datetime: "clickTime threatTime TimeGenerated",
  },
  // Proofpoint TAP codeless connector
  ProofPointTAPClicksBlockedV2_CL: {
    string: "campaignId classification clickIP GUID id messageID recipient sender senderIP threatID threatStatus threatURL url userAgent Type TenantId",
    datetime: "clickTime threatTime TimeGenerated",
  },
  // Proofpoint TAP codeless connector
  ProofPointTAPMessagesDeliveredV2_CL: {
    dynamic: "ccAddresses fromAddress messageParts modulesRun policyRoutes recipient replyToAddress threatsInfoMap toAddresses xmailer",
    string: "cluster GUID headerFrom headerReplyTo id messageID QID quarantineFolder quarantineRule sender senderIP subject Type TenantId",
    bool: "completelyRewritten",
    int: "impostorScore malwareScore messageSize phishScore spamScore",
    datetime: "messageTime TimeGenerated",
  },
  // Proofpoint TAP codeless connector
  ProofPointTAPMessagesBlockedV2_CL: {
    dynamic: "ccAddresses fromAddress messageParts modulesRun policyRoutes recipient replyToAddress threatsInfoMap toAddresses xmailer",
    string: "cluster GUID headerFrom headerReplyTo id messageID QID quarantineFolder quarantineRule sender senderIP subject Type TenantId",
    bool: "completelyRewritten",
    int: "impostorScore malwareScore messageSize phishScore spamScore",
    datetime: "messageTime TimeGenerated",
  },
  // Microsoft Graph Security alerts_v2, as a Logic App or connector ingestion lands them: no built-in table holds them
  GraphSecurityAlerts_CL: {
    datetime: "TimeGenerated createdDateTime lastUpdateDateTime firstActivityDateTime lastActivityDateTime",
    string: "Type TenantId id providerAlertId incidentId title description severity status classification determination serviceSource detectionSource productName detectorId category threatDisplayName alertWebUrl incidentWebUrl",
    dynamic: "mitreTechniques evidence",
  },
  // AWS S3 connector
  AWSCloudWatch: {
    datetime: "ExtractedTime TimeGenerated",
    string: "Message SourceSystem TenantId Type",
  },
  // Custom log, table named by the Zscaler Private Access connector. Columns are this workspace's (a text-log table has no published schema)
  ZPA_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log, table named by the Thinkst Canary connector. Columns are this workspace's
  ThinkstCanaryIncidents_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log, table named by the F5 BIG-IP connector. Columns are this workspace's
  F5Telemetry_ASM_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log, table named by the GitHub connector. Columns are this workspace's
  GitHubAdvancedSecurityAlerts_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log, table named by the ClaudeCompliance connector. Columns are this workspace's
  BV_ClaudeCompliance_ComplianceActivities_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log for a Logic App ingestion: no connector carries tickets. Name and columns are this workspace's
  ServiceNow_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log: no connector. Name and columns are this workspace's
  EpiqEMRAudit_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log for the Windows DHCP server log. Name and columns are this workspace's
  DHCP_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log: no connector. Name and columns are this workspace's
  Exabeam_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log: no connector. Name and columns are this workspace's
  Securonix_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Custom log for any other product a Logic App forwards. Name and columns are this workspace's
  ThirdPartyLogs_CL: {
    datetime: "TimeGenerated",
    string: "Type TenantId SourceSystem EventVendor EventProduct EventType EventMessage EventSeverity DvcHostname ActorUsername SrcIpAddr DstIpAddr Url",
    int: "SrcPortNumber DstPortNumber",
    dynamic: "RawData",
  },
  // Sentinel UEBA identity inventory
  IdentityInfo: {
    string: "AccountCloudSID AccountDisplayName AccountDomain AccountName AccountObjectId AccountSID AccountTenantId AccountUPN Applications BlastRadius ChangeSource City CompanyName Country Department EmployeeId GivenName JobTitle MailAddress Manager OnPremisesDistinguishedName OnPremisesExtensionAttributes Phone RiskLevel RiskLevelDetails RiskState SAMAccountName SourceSystem State StreetAddress Surname Tags TenantId Type UACFlags UserState UserType",
    datetime: "AccountCreationTime DeletedDateTime LastSeenDate TimeGenerated UserStateChangedOn",
    dynamic: "AdditionalMailAddresses AssignedRoles EntityRiskScore ExtensionProperty GroupMembership RelatedAccounts ServicePrincipals UserAccountControl",
    int: "InvestigationPriority InvestigationPriorityPercentile",
    bool: "IsAccountEnabled IsMFARegistered IsServiceAccount",
  },
  // Defender for Endpoint inventory
  DeviceInfo: {
    string: "AadDeviceId AssetValue AwsResourceName AzureResourceId AzureVmId AzureVmSubscriptionId ClientVersion CloudPlatforms ConnectivityType DeviceCategory DeviceDynamicTags DeviceId DeviceManualTags DeviceName DeviceObjectId DeviceSubtype DeviceType ExclusionReason ExposureLevel GcpFullResourceName HardwareUuid HostDeviceId JoinType MachineGroup MergedDeviceIds MergedToDeviceId MitigationStatus Model OnboardingStatus OSArchitecture OsBuildRevision OSDistribution OSPlatform OSVersion OSVersionInfo PublicIP RegistryDeviceTag RestrictedDeviceSecurityOperations SensorHealthState SourceSystem TenantId Type Vendor",
    dynamic: "AdditionalFields LoggedOnUsers",
    bool: "IsAzureADJoined IsExcluded IsInternetFacing IsTransient",
    long: "OSBuild ReportId",
    datetime: "TimeGenerated Timestamp",
  },
  // Defender for Endpoint inventory
  DeviceNetworkInfo: {
    dynamic: "ConnectedNetworks DefaultGateways DnsAddresses IPAddresses",
    string: "DeviceId DeviceName IPv4Dhcp IPv6Dhcp MacAddress MachineGroup NetworkAdapterName NetworkAdapterStatus NetworkAdapterType NetworkAdapterVendor SourceSystem TenantId TunnelType Type",
    long: "ReportId",
    datetime: "TimeGenerated Timestamp",
  },
  // Sentinel UEBA
  BehaviorAnalytics: {
    string: "ActionType ActivityType ActorName ActorPrincipalName DestinationDevice DestinationIPAddress DestinationIPLocation Device EventProductVersion EventSource EventVendor NativeTableName SourceDevice SourceIPAddress SourceIPLocation SourceRecordId SourceSystem TargetName TargetPrincipalName TenantId Type UserName UserPrincipalName",
    dynamic: "ActivityInsights DevicesInsights UsersInsights",
    int: "InvestigationPriority",
    datetime: "TimeGenerated TimeProcessed",
  },
  // Workday connector
  ASimAuditEventLogs: {
    string: "ActingAppId ActingApplicationEntityKey ActingAppName ActingAppType ActingOriginalAppType ActorOriginalUserType ActorScope ActorScopeId ActorSessionId ActorUserAadId ActorUserEntityKey ActorUserId ActorUserIdType ActorUsername ActorUsernameType ActorUserSid ActorUserType DvcAction DvcDescription DvcDomain DvcDomainType DvcEntityKey DvcFQDN DvcHostname DvcId DvcIdType DvcInterface DvcIpAddr DvcMacAddr DvcOriginalAction DvcOs DvcOsVersion DvcScope DvcScopeId DvcZone EventMessage EventOriginalResultDetails EventOriginalSeverity EventOriginalSubType EventOriginalType EventOriginalUid EventOwner EventProduct EventProductVersion EventReportUrl EventResult EventResultDetails EventSchemaVersion EventSeverity EventSubType EventType EventVendor HttpUserAgent NewValue Object ObjectId ObjectType OldValue Operation OriginalObjectType RuleName SourceSystem SrcDescription SrcDeviceType SrcDomain SrcDomainType SrcDvcId SrcDvcIdType SrcDvcScope SrcDvcScopeId SrcFQDN SrcGeoCity SrcGeoCountry SrcGeoRegion SrcHostname SrcIpAddr SrcOriginalRiskLevel SrcSystemEntityKey TargetAppId TargetApplicationEntityKey TargetAppName TargetAppType TargetDescription TargetDeviceType TargetDomain TargetDomainType TargetDvcId TargetDvcIdType TargetDvcOs TargetDvcScope TargetDvcScopeId TargetFQDN TargetGeoCity TargetGeoCountry TargetGeoRegion TargetHostname TargetIpAddr TargetOriginalAppType TargetOriginalRiskLevel TargetSystemEntityKey TargetUrl TenantId ThreatCategory ThreatField ThreatId ThreatIpAddr ThreatName ThreatOriginalConfidence ThreatOriginalRiskLevel Type ValueType",
    dynamic: "ActorUserAdditionalIds AdditionalEntities AdditionalFields",
    int: "EventCount RuleNumber SrcPortNumber SrcRiskLevel TargetPortNumber TargetRiskLevel ThreatConfidence ThreatRiskLevel",
    datetime: "EventEndTime EventStartTime ThreatFirstReportedTime ThreatLastReportedTime TimeGenerated",
    real: "SrcGeoLatitude SrcGeoLongitude TargetGeoLatitude TargetGeoLongitude",
    bool: "ThreatIsActive",
  },
  // Defender for Cloud Apps
  CloudAppEvents: {
    string: "AccountDisplayName AccountId AccountObjectId AccountType ActionType ActivityType Application AuditSource City CountryCode DeviceType IPAddress IPCategory ISP OAuthAppId ObjectId ObjectName ObjectType OSPlatform ReportId SourceSystem TenantId Type UserAgent",
    dynamic: "ActivityObjects AdditionalFields IPTags LastSeenForUser RawEventData SessionData UncommonForUser UserAgentTags",
    int: "AppInstanceId ApplicationId",
    bool: "IsAdminOperation IsAnonymousProxy IsExternalUser IsImpersonated",
    datetime: "TimeGenerated Timestamp",
  },
  // Azure resource diagnostics (Azure SQL audit, Azure OpenAI, Front Door)
  AzureDiagnostics: {
    string: "action_id_s action_name_s action_s AdditionalFields AdHocOrScheduledJob_s application_name_s avg_cpu_percent_s avg_mean_time_s backendHostname_s Caller_s callerId_s CallerIPAddress calls_s Category client_ip_s clientInfo_s clientIP_s clientIp_s clientIpAddress_s code_s collectionName_s conditions_destinationIP_s conditions_destinationPortRange_s conditions_None_s conditions_protocols_s conditions_sourceIP_s conditions_sourcePortRange_s CorrelationId database_name_s database_principal_name_s DatabaseName_s db_id_s direction_s ElasticPoolName_s Environment_s error_code_s error_message_s errorLevel_s event_class_s event_s event_subclass_s EventName_s host_s httpMethod_s httpStatusCode_s httpVersion_s id_s identity_claim_ipaddr_s instanceId_s ip_s is_column_permission_s JobDurationInSecs_s JobFailureCode_s jobId_s JobOperation_s JobOperationSubType_s JobStartDateTime_s JobStatus_s Level LogicalServerName_s macAddress_s max_time_s mean_time_s Message min_time_s msg_s object_name_s OperationName OperationVersion partitionKey_s policy_s policyMode_s primaryIPv4Address_s properties_s properties_sku_Family_s properties_sku_Name_s query_hash_s query_plan_hash_s querytext_s Region_s requestCharge_s requestQuery_s requestResourceId_s requestResourceType_s requestUri_s reserved_storage_mb_s Resource resource_actionName_s resource_location_s resource_originRunId_s resource_resourceGroupName_s resource_runId_s resource_triggerName_s resource_workflowName_s ResourceGroup ResourceProvider ResourceType resultCode_s ResultDescription resultDescription_ChildJobs_s resultDescription_ErrorJobs_s resultMessage_s ResultSignature ResultType rootCauseAnalysis_s routingRuleName_s ruleName_s RunbookName_s RunOn_s schema_name_s server_principal_sid_s Type TenantId SourceSystem",
    guid: "ActivityId_g identity_claim_appid_g JobId_g JobUniqueId_g properties_tenantId_g resource_subscriptionId_g resource_workflowId_g sequence_group_id_g",
    real: "audit_schema_version_d clientPort_d count_executions_d cpu_time_d dop_d duration_d duration_milliseconds_d execution_type_d executionInfo_exitCode_d httpStatus_d httpStatusCode_d interval_end_time_d interval_start_time_d log_bytes_used_d logical_io_reads_d logical_io_writes_d matchedConnections_d max_cpu_time_d max_dop_d max_duration_d max_log_bytes_used_d max_logical_io_reads_d max_logical_io_writes_d max_num_physical_io_reads_d max_physical_io_reads_d max_query_max_used_memory_d max_rowcount_d num_physical_io_reads_d object_id_d physical_io_reads_d plan_id_d priority_d query_id_d query_max_used_memory_d query_time_d receivedBytes_d response_rows_d rowcount_d sentBytes_d sequence_number_d session_id_d",
    long: "DurationMs",
    datetime: "endTime_t event_time_t executionInfo_endTime_t executionInfo_startTime_t TimeGenerated",
    bool: "isAccessPolicyMatch_b properties_enabledForDeployment_b properties_enabledForDiskEncryption_b properties_enabledForTemplateDeployment_b",
  },
  // Application Gateway WAF
  AGWFirewallLogs: {
    string: "Action ClientIp DetailedData DetailedMessage FileDetails Hostname InstanceId LineDetails Message OperationName ParanoiaLevel PolicyId PolicyScope PolicyScopeName RequestUri RuleId RuleSetType RuleSetVersion Site SourceSystem TenantId TransactionId Type",
    int: "ClientPort",
    datetime: "TimeGenerated",
  },
  // Azure Storage
  StorageBlobLogs: {
    string: "AccessTier AccountName AuthenticationHash AuthenticationType CallerIpAddress Category ClientRequestId ConditionsUsed CopyDestinationArmId CorrelationId DestinationUri EncryptionKeyTypeOfBlob Etag Location MetricResponseType ObjectKey OperationName OperationVersion Protocol ReferrerHeader RehydratePriority RequesterAppId RequesterAudience RequesterObjectId RequesterTenantId RequesterTokenIssuer RequesterUpn RequestMd5 RequestRegion ResponseMd5 SasExpiryStatus SchemaVersion ServiceType SourceAccessTier SourceSystem SourceUri StatusCode StatusText TenantId TlsVersion TrafficClassification Type Uri UserAgentHeader",
    dynamic: "AuthorizationDetails",
    long: "ContentLengthHeader RequestBodySize RequestHeaderSize ResponseBodySize ResponseHeaderSize",
    real: "DurationMs ServerLatencyMs",
    datetime: "LastModifiedTime TimeGenerated",
    int: "OperationCount",
  },
  // Microsoft Graph activity
  MicrosoftGraphActivityLogs: {
    string: "AadTenantId ApiVersion AppId ATContent ATContentH ATContentP ClientRequestId ConditionalAccessStatus DeviceId IdentityProvider IPAddress Location OperationId RequestId RequestMethod RequestUri Roles Scopes ServicePrincipalId SessionId SignInActivityId SourceSystem TenantId Type UniqueTokenId UserAgent UserId Wids",
    int: "ClientAuthMethod DurationMs ResponseSizeBytes ResponseStatusCode",
    datetime: "TimeGenerated TokenIssuedAt",
  },
  // IIS logs
  W3CIISLog: {
    string: "AzureDeploymentID cIP Computer Confidence csCookie csHost csMethod csReferer csUriQuery csUriStem csUserAgent csUserName csVersion Description FirstReportedDateTime IndicatorThreatType IsActive LastReportedDateTime MaliciousIP ManagementGroupName RemoteIPCountry Role RoleInstance scStatus scSubStatus scWin32Status sIP SourceSystem sSiteName StorageAccount TLPLevel Type TenantId",
    long: "csBytes scBytes TimeTaken",
    real: "RemoteIPLatitude RemoteIPLongitude",
    int: "Severity sPort",
    datetime: "TimeGenerated",
  },
  // AWS S3 connector
  AWSWAF: {
    string: "Action Args ClientIp Country FormatVersion HttpMethod HttpSourceId HttpSourceName HttpVersion Ja3Fingerprint RequestId RuleGroupId SourceSystem TenantId TerminatingRuleId TerminatingRuleType Type Uri WebAclId",
    dynamic: "CaptchaResponse ChallengeResponse ExcludedRules Headers HttpRequest Labels NonTerminatingMatchingRules OversizeFields RateBasedRuleList RequestHeadersInserted RuleGroupList TerminatingRule TerminatingRuleMatchDetails",
    int: "ResponseCodeSent",
    datetime: "TimeGenerated",
  },
  // Google Security Command Center connector
  GoogleCloudSCC: {
    dynamic: "Findings FindingsResource SourceProperties",
    string: "SourceSystem TenantId Type",
    datetime: "TimeGenerated",
  },
  // EKS codeless connector
  AWSEKSLogs_CL: {
    datetime: "TimeGenerated",
    string: "AwsAccountId Region ClusterName Verb User UserAgent ObjectRef Stage AuthDecision Type TenantId",
    dynamic: "SourceIPs RawEvent",
    int: "ResponseCode",
  },
  // Cloudflare codeless connector (the columns this workspace fills, of 495)
  CloudflareV2_CL: {
    datetime: "TimeGenerated",
    string: "Email RuleID Action RayID ClientCountry ClientIP ClientRequestHost ClientRequestMethod ClientRequestUserAgent Source ClientRequestURI ZoneName Type TenantId",
    int: "EdgeResponseStatus",
  },
  // GitHub codeless connector (the columns this workspace fills, of 481)
  GitHubAuditLogsV2_CL: {
    datetime: "TimeGenerated",
    string: "Org Action Repo Actor User OperationType ActorIp UserAgent Email CountryCode Type TenantId",
  },
};

function expand(c: Compact): KqlColumn[] {
  const out: KqlColumn[] = [];
  for (const [type, names] of Object.entries(c)) {
    for (const name of (names as string).split(" ")) out.push({ name, type: type as KqlType });
  }
  return out.sort((a, b) => a.name.localeCompare(b.name));
}

/** Column lists by table name. Case-sensitive, as in Log Analytics. */
export const TABLE_SCHEMAS: Record<string, KqlColumn[]> = Object.fromEntries(Object.entries(SCHEMAS).map(([n, c]) => [n, expand(c)]));

export const TABLE_NAMES: string[] = Object.keys(SCHEMAS);

/** Custom-log tables of this workspace: the ones with no published column list. */
export const CUSTOM_LOG_TABLES = new Set<string>(["ZPA_CL","ThinkstCanaryIncidents_CL","F5Telemetry_ASM_CL","GitHubAdvancedSecurityAlerts_CL","BV_ClaudeCompliance_ComplianceActivities_CL","ServiceNow_CL","EpiqEMRAudit_CL","DHCP_CL","Exabeam_CL","Securonix_CL","ThirdPartyLogs_CL"]);

const COLUMN_TYPES = new Map(Object.entries(TABLE_SCHEMAS).map(([n, cols]) => [n, new Map(cols.map(c => [c.name, c.type]))]));

/** The real type of a column, or undefined when the table has no such column. */
export function columnType(table: string, column: string): KqlType | undefined {
  return COLUMN_TYPES.get(table)?.get(column);
}

/** An empty KqlTable with the table's real schema. */
export function emptyTable(name: string): KqlTable {
  return { name, columns: TABLE_SCHEMAS[name], rows: [] };
}
