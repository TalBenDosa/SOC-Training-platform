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

const COLUMN_TYPES = new Map(Object.entries(TABLE_SCHEMAS).map(([n, cols]) => [n, new Map(cols.map(c => [c.name, c.type]))]));

/** The real type of a column, or undefined when the table has no such column. */
export function columnType(table: string, column: string): KqlType | undefined {
  return COLUMN_TYPES.get(table)?.get(column);
}

/** An empty KqlTable with the table's real schema. */
export function emptyTable(name: string): KqlTable {
  return { name, columns: TABLE_SCHEMAS[name], rows: [] };
}
