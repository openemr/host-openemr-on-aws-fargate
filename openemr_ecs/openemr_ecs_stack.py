from aws_cdk import (
    Stack,
    aws_sagemaker as sagemaker,
    aws_emrserverless as emrserverless,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_efs as efs,
    aws_backup as backup,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticache as elasticache,
    aws_cloudtrail as cloudtrail,
    aws_logs as logs,
    aws_kms as kms,
    aws_ecs_patterns as ecs_patterns,
    aws_rds as rds,
    aws_s3 as s3,
    aws_ssm as ssm,
    aws_wafv2 as wafv2,
    aws_lambda as _lambda,
    aws_ses as ses,
    aws_ses_actions as ses_actions,
    aws_secretsmanager as secretsmanager,
    aws_certificatemanager as acm,
    aws_events as events,
    aws_events_targets as event_targets,
    aws_globalaccelerator as ga,
    aws_globalaccelerator_endpoints as ga_endpoints,
    aws_route53 as route53,
    aws_route53_targets as targets,
    CfnOutput,
    triggers,
    Duration,
    RemovalPolicy,
    ArnFormat
)
from constructs import Construct
import hashlib

class OpenemrEcsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # initialize variables
        self.cidr = "10.0.0.0/16"
        self.mysql_port = 3306
        self.valkey_port = 6379
        self.container_port = 443
        self.number_of_days_to_regenerate_ssl_materials = 2
        self.emr_serverless_release_label = "emr-7.8.0"
        self.aurora_mysql_engine_version = rds.AuroraMysqlEngineVersion.VER_3_08_1
        self.openemr_version = "7.0.3"
        self.lambda_python_runtime = _lambda.Runtime.PYTHON_3_13

        # build infrastructure
        self._create_vpc()
        self._create_security_groups()
        self._create_elb_log_bucket()
        self._create_cloudtrail_logging_bucket()
        self._create_alb()
        self._create_and_configure_dns_and_certificates()
        self._configure_ses()
        self._create_waf()
        self._create_environment_variables()
        self._create_password()
        self._create_db_instance()
        self._create_valkey_cluster()
        self._create_efs_volume()
        self._create_backup()
        self._create_ecs_cluster()
        self._create_and_maintain_tls_materials()
        self._create_openemr_service()
        self._create_serverless_analytics_environment()

    def _create_vpc(self):
        vpc_flow_role = iam.Role(
            self, 'Flow-Log-Role',
            assumed_by=iam.ServicePrincipal('vpc-flow-logs.amazonaws.com')
        )

        vpc_log_group = logs.LogGroup(
            self,
            'VPC-Log-Group',
        )

        self.vpc = ec2.Vpc(
            self,
            "OpenEmr-Vpc",
            ip_addresses=ec2.IpAddresses.cidr(self.cidr),
            max_azs=2,
            subnet_configuration=[
                ec2.SubnetConfiguration(
                    name="private-subnet",
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                ec2.SubnetConfiguration(
                    name="public-subnet",
                    subnet_type=ec2.SubnetType.PUBLIC,
                    map_public_ip_on_launch=False
                )
            ]
        )

        ec2.CfnFlowLog(
            self, 'FlowLogs',
            resource_id=self.vpc.vpc_id,
            resource_type='VPC',
            traffic_type='ALL',
            deliver_logs_permission_arn=vpc_flow_role.role_arn,
            log_destination_type='cloud-watch-logs',
            log_group_name=vpc_log_group.log_group_name
        )

    def _create_elb_log_bucket(self):
        self.elb_log_bucket = s3.Bucket(
            self,
            "elb-logs-bucket",
            auto_delete_objects=True,
            removal_policy=RemovalPolicy.DESTROY,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            enforce_ssl=True,
            versioned=True
        )

        policy_statement = iam.PolicyStatement(
            actions=["s3:PutObject"],
            resources=[f"{self.elb_log_bucket.bucket_arn}/*"],
            principals=[iam.ArnPrincipal(f"arn:aws:iam::{self.account}:root")]
        )

        self.elb_log_bucket.add_to_resource_policy(policy_statement)

    def _create_cloudtrail_logging_bucket(self):

        if self.node.try_get_context("enable_long_term_cloudtrail_monitoring") == "true":

            # Create a key and give cloudwatch logs, cloudtrail and s3 permissions to use it
            self.cloudtrail_kms_key = kms.Key(self, "CloudtrailKmsKey", enable_key_rotation=True)
            self.cloudtrail_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("logs." + self.region + ".amazonaws.com"))
            self.cloudtrail_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("s3.amazonaws.com"))
            self.cloudtrail_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("cloudtrail.amazonaws.com"))

            # Create an S3 bucket for CloudTrail logs
            self.cloudtrail_log_bucket = s3.Bucket(
                self,
                "CloudTrailLogBucket",
                versioned=True,
                encryption_key=self.cloudtrail_kms_key,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL
            )

            # Add lifecycle policy to retain logs for 7 years
            self.cloudtrail_log_bucket.add_lifecycle_rule(
                id="Retain7Years",
                enabled=True,
                expiration=Duration.days(7 * 365),  # Expire objects after 7 years
                transitions=[
                    s3.Transition(
                        storage_class=s3.StorageClass.GLACIER,
                        transition_after=Duration.days(90),  # Move to Glacier after 90 days
                    )
                ]
            )

            # Create a CloudTrail trail
            self.trail = cloudtrail.Trail(
                self,
                "OpenEMRCloudTrail",
                bucket=self.cloudtrail_log_bucket,
                encryption_key=self.cloudtrail_kms_key,
                include_global_service_events=True,
                cloud_watch_logs_retention=logs.RetentionDays.NINE_YEARS,
                management_events=cloudtrail.ReadWriteType.ALL,
            )

            # Grant CloudTrail permissions to write to the bucket
            self.cloudtrail_log_bucket.add_to_resource_policy(
                iam.PolicyStatement(
                    actions=["s3:PutObject", "s3:GetBucketAcl"],
                    resources=[
                        self.cloudtrail_log_bucket.arn_for_objects("*"),
                        self.cloudtrail_log_bucket.bucket_arn,
                    ],
                    principals=[iam.ServicePrincipal("cloudtrail.amazonaws.com")],
                )
            )

    def _create_backup(self):
        plan = backup.BackupPlan.daily_weekly_monthly7_year_retention(self, "Plan")
        plan.apply_removal_policy(RemovalPolicy.DESTROY)
        plan.add_selection(
            "Resources",
            resources=[
                backup.BackupResource.from_rds_database_instance(self.db_instance),
                backup.BackupResource.from_efs_file_system(self.file_system_for_ssl_folder),
                backup.BackupResource.from_efs_file_system(self.file_system_for_sites_folder)
            ]
        )

    def _create_environment_variables(self):
        self.swarm_mode = ssm.StringParameter(
            self,
            "swarm-mode",
            parameter_name="swarm_mode",
            string_value="yes"
        )
        self.mysql_port_var = ssm.StringParameter(
            self,
            "mysql-port",
            parameter_name="mysql_port",
            string_value=str(self.mysql_port)
        )

    def _create_password(self):
        self.password = secretsmanager.Secret(
            self,
            "Password",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                include_space=False,
                secret_string_template='{"username": "admin"}',
                generate_string_key="password"
            )
        )

    def _create_security_groups(self):
        self.db_sec_group = ec2.SecurityGroup(
            self,
            "db-sec-group",
            vpc=self.vpc,
            allow_all_outbound=False
        )
        self.valkey_sec_group = ec2.SecurityGroup(
            self,
            "valkey-sec-group",
            vpc=self.vpc,
            allow_all_outbound=False
        )
        self.lb_sec_group = ec2.SecurityGroup(
            self,
            "lb-sec-group",
            vpc=self.vpc,
            allow_all_outbound=False
        )
        if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
            cidr_ipv4 = self.node.try_get_context("security_group_ip_range_ipv4")
            if cidr_ipv4:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv4(cidr_ipv4),
                    ec2.Port.tcp(443),
                )
                self.lb_sec_group.add_egress_rule(
                    ec2.Peer.ipv4(cidr_ipv4),
                    ec2.Port.tcp(443),
                )
        else:
            cidr_ipv4 = self.node.try_get_context("security_group_ip_range_ipv4")
            if cidr_ipv4:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv4(cidr_ipv4),
                    ec2.Port.tcp(80),
                )
                self.lb_sec_group.add_egress_rule(
                    ec2.Peer.ipv4(cidr_ipv4),
                    ec2.Port.tcp(80),
                )
        if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
            cidr_ipv6 = self.node.try_get_context("security_group_ip_range_ipv6")
            if cidr_ipv6:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv6(cidr_ipv6),
                    ec2.Port.tcp(443),
                )
                self.lb_sec_group.add_egress_rule(
                    ec2.Peer.ipv6(cidr_ipv6),
                    ec2.Port.tcp(443),
                )
        else:
            cidr_ipv6 = self.node.try_get_context("security_group_ip_range_ipv6")
            if cidr_ipv6:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv6(cidr_ipv6),
                    ec2.Port.tcp(80),
                )
                self.lb_sec_group.add_egress_rule(
                    ec2.Peer.ipv6(cidr_ipv6),
                    ec2.Port.tcp(80),
                )

    def _create_alb(self):
        self.alb = elb.ApplicationLoadBalancer(
            self,
            "Load-Balancer",
            security_group=self.lb_sec_group,
            vpc=self.vpc,
            internet_facing=True,
            drop_invalid_header_fields=True
        )
        self.alb.log_access_logs(self.elb_log_bucket)

        if self.node.try_get_context("enable_global_accelerator") == "true":

            # Create global accelerator
            self.accelerator = ga.Accelerator(self, "GlobalAccelerator")

            # Add ALB endpoint to global accelerator
            if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):

                # Use HTTPS if certificate is provided
                ga_listener = self.accelerator.add_listener("GAListener",
                                                            port_ranges=[ga.PortRange(from_port=443, to_port=443)])

            else:
                # Use HTTP if no certificate is provided
                ga_listener = self.accelerator.add_listener("GAListener",
                                                            port_ranges=[ga.PortRange(from_port=80, to_port=80)])

            ga_listener.add_endpoint_group(
                "EndpointGroup",
                endpoints=[ga_endpoints.ApplicationLoadBalancerEndpoint(self.alb)]
            )

            # Output the Global Accelerator URL
            if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                CfnOutput(
                    self, "GlobalAcceleratorUrl",
                    value=f"https://{self.accelerator.dns_name}",
                    description="The URL for the Global Accelerator"
                )
            else:
                CfnOutput(
                    self, "GlobalAcceleratorUrl",
                    value=f"http://{self.accelerator.dns_name}",
                    description="The URL for the Global Accelerator"
                )

        if self.node.try_get_context("activate_openemr_apis") == "true":
            self.activate_fhir_service = ssm.StringParameter(
                scope=self,
                id="activate-fhir-service",
                parameter_name="activate_fhir_service",
                string_value="1"
            )
            self.activate_rest_api = ssm.StringParameter(
                scope=self,
                id="activate-rest-api",
                parameter_name="activate_rest_api",
                string_value="1"
            )

        if self.node.try_get_context("enable_patient_portal") == "true":

            # Construct Patient Portal Address Parameter

            if self.node.try_get_context("route53_domain"):
                if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                    self.portal_onsite_two_address = ssm.StringParameter(
                        scope=self,
                        id="portal-onsite-two-address",
                        parameter_name="portal_onsite_two_address",
                        string_value='https://openemr.' + self.node.try_get_context("route53_domain") + '/portal/'
                    )
                else:
                    self.portal_onsite_two_address = ssm.StringParameter(
                        scope=self,
                        id="portal-onsite-two-address",
                        parameter_name="portal_onsite_two_address",
                        string_value='http://openemr.' + self.node.try_get_context("route53_domain") + '/portal/'
                    )
            else:
                # Value of DNS name will change based on whether it's using a global accelerator endpoint
                if self.node.try_get_context("enable_global_accelerator") == "true":
                    if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                        self.portal_onsite_two_address = ssm.StringParameter(
                            scope=self,
                            id="portal-onsite-two-address",
                            parameter_name="portal_onsite_two_address",
                            string_value='https://' + self.accelerator.dns_name + '/portal/',
                        )
                    else:
                        self.portal_onsite_two_address = ssm.StringParameter(
                            scope=self,
                            id="portal-onsite-two-address",
                            parameter_name="portal_onsite_two_address",
                            string_value='http://' + self.accelerator.dns_name + '/portal/'
                        )
                else:
                    if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                        self.portal_onsite_two_address = ssm.StringParameter(
                            scope=self,
                            id="portal-onsite-two-address",
                            parameter_name="portal_onsite_two_address",
                            string_value='https://' + self.alb.dns_name + '/portal/'
                        )
                    else:
                        self.portal_onsite_two_address = ssm.StringParameter(
                            scope=self,
                            id="portal-onsite-two-address",
                            parameter_name="portal_onsite_two_address",
                            string_value='https://' + self.alb.dns_name + '/portal/'
                        )

            # Other parameters
            self.portal_onsite_two_enable = ssm.StringParameter(
                scope=self,
                id="portal-onsite-two-enable",
                parameter_name="portal_onsite_two_enable",
                string_value="1"
            )
            self.ccda_alt_service_enable = ssm.StringParameter(
                scope=self,
                id="ccda-alt-service-enable",
                parameter_name="ccda_alt_service_enable",
                string_value="3"
            )
            self.rest_portal_api = ssm.StringParameter(
                scope=self,
                id="rest-portal-api",
                parameter_name="rest_portal_api",
                string_value="1"
            )

        # must set site-addr-oath if using the OpenEMR APIs or enabling the patient portal.
        if self.node.try_get_context("activate_openemr_apis") == "true" or self.node.try_get_context(
                "enable_patient_portal") == "true":
            if self.node.try_get_context("route53_domain"):
                if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                    self.site_addr_oath = ssm.StringParameter(
                        scope=self,
                        id="site-addr-oath",
                        parameter_name="site_addr_oath",
                        string_value='https://openemr.' + self.node.try_get_context("route53_domain")
                    )
                else:
                    self.site_addr_oath = ssm.StringParameter(
                        scope=self,
                        id="site-addr-oath",
                        parameter_name="site_addr_oath",
                        string_value='http://openemr.' + self.node.try_get_context("route53_domain")
                    )
            else:
                # Value of DNS name will change based on whether it's using a global accelerator endpoint
                if self.node.try_get_context("enable_global_accelerator") == "true":
                    if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                        self.site_addr_oath = ssm.StringParameter(
                            scope=self,
                            id="site-addr-oath",
                            parameter_name="site_addr_oath",
                            string_value='https://' + self.accelerator.dns_name
                        )
                    else:
                        self.site_addr_oath = ssm.StringParameter(
                            scope=self,
                            id="site-addr-oath",
                            parameter_name="site_addr_oath",
                            string_value='http://' + self.accelerator.dns_name
                        )
                else:
                    if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
                        self.site_addr_oath = ssm.StringParameter(
                            scope=self,
                            id="site-addr-oath",
                            parameter_name="site_addr_oath",
                            string_value='https://' + self.alb.load_balancer_dns_name
                        )
                    else:
                        self.site_addr_oath = ssm.StringParameter(
                            scope=self,
                            id="site-addr-oath",
                            parameter_name="site_addr_oath",
                            string_value='http://' + self.alb.load_balancer_dns_name
                        )

    def _create_and_configure_dns_and_certificates(self):

        if self.node.try_get_context("route53_domain"):

            # Define the hosted zone in Route 53
            hosted_zone = route53.HostedZone.from_lookup(
                self, "HostedZoneForRoute53",
                domain_name=self.node.try_get_context("route53_domain")
            )

            self.certificate = acm.Certificate(
                self, "Certificate",
                domain_name="*." + self.node.try_get_context("route53_domain"),
                validation=acm.CertificateValidation.from_dns(hosted_zone)
            )

            if self.node.try_get_context("enable_global_accelerator") == "true":
                # Create a Route 53 alias record pointing to the ALB
                route53.ARecord(
                    self, "AliasRecordOpenEMR",
                    zone=hosted_zone,
                    target=route53.RecordTarget.from_alias(
                        targets.GlobalAcceleratorDomainTarget(self.accelerator.dns_name)),
                    record_name="openemr"
                )
            else:
                # Create a Route 53 alias record pointing to the Global Accelerator
                route53.ARecord(
                    self, "AliasRecordOpenEMR",
                    zone=hosted_zone,
                    target=route53.RecordTarget.from_alias(targets.LoadBalancerTarget(self.alb)),
                    record_name="openemr"
                )

    def _configure_ses(self):

        if self.node.try_get_context("route53_domain") and self.node.try_get_context("configure_ses") == 'true':
            # Define the hosted zone in Route 53
            hosted_zone = route53.HostedZone.from_lookup(
                self, "HostedZoneForSES",
                domain_name=self.node.try_get_context("route53_domain")
            )

            # Create an SES domain identity for email verification
            ses_domain_identity = ses.EmailIdentity(self,
                                                    "SESIdentity",
                                                    identity=ses.Identity.public_hosted_zone(hosted_zone),
                                                    mail_from_domain="services." + self.node.try_get_context(
                                                        "route53_domain")
                                                    )

            # Create 3 CNAME Records Necessary to Verify Domain Identity
            dkim_cname_record_1 = route53.CnameRecord(
                self,
                "DkimCnameRecord1",
                zone=hosted_zone,
                record_name=ses_domain_identity.dkim_dns_token_name1,
                domain_name=ses_domain_identity.dkim_dns_token_value1
            )
            dkim_cname_record_2 = route53.CnameRecord(
                self,
                "DkimCnameRecord2",
                zone=hosted_zone,
                record_name=ses_domain_identity.dkim_dns_token_name2,
                domain_name=ses_domain_identity.dkim_dns_token_value2
            )
            dkim_cname_record_3 = route53.CnameRecord(
                self,
                "DkimCnameRecord3",
                zone=hosted_zone,
                record_name=ses_domain_identity.dkim_dns_token_name3,
                domain_name=ses_domain_identity.dkim_dns_token_value3
            )

            # Set up DMARC; for documentation see here
            # (https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dmarc.html).
            dmarc_record = route53.TxtRecord(
                self,
                "DmarcRecord",
                zone=hosted_zone,
                record_name="_dmarc",
                values=["v=DMARC1;p=quarantine;rua=mailto:help@"+self.node.try_get_context("route53_domain")]
            )

            # Create IAM user for SES SMTP access
            ses_smtp_user = iam.User(self, "SmtpUser", user_name="ses-smtp-user")

            # Attach the required SES SMTP policy to the IAM user
            ses_domain_identity.grant_send_email(ses_smtp_user)

            # Generate SMTP credentials for the SES SMTP user
            access_key = iam.AccessKey(self, "SmtpAccessKey", user=ses_smtp_user)

            # Create secret to store SMTP password and store secret access key in another secret for processing.
            self.smtp_password = secretsmanager.Secret(
                self,
                "smtp-secret"
            )
            self.secret_access_key = secretsmanager.Secret(
                self,
                "secret-access-key",
                secret_object_value={
                    "password":  access_key.secret_access_key
                }
            )
            # Create a function and run it once so our SMTP parameter is properly set
            self.one_time_generate_smtp_credential_lambda = triggers.TriggerFunction(self, "SMTPSetup",
                                                                                 runtime=self.lambda_python_runtime,
                                                                                 code=_lambda.Code.from_asset('lambda'),
                                                                                 architecture=_lambda.Architecture.ARM_64,
                                                                                 handler='lambda_functions.generate_smtp_credential',
                                                                                 timeout=Duration.minutes(10)
                                                                                 )

            # Grant appropriate IAM permissions
            self.secret_access_key.grant_read(self.one_time_generate_smtp_credential_lambda.role)
            self.smtp_password.grant_write(self.one_time_generate_smtp_credential_lambda.role)

            # Add environment variable
            self.one_time_generate_smtp_credential_lambda.add_environment('SECRET_ACCESS_KEY', self.secret_access_key.secret_arn)
            self.one_time_generate_smtp_credential_lambda.add_environment('SMTP_PASSWORD', self.smtp_password.secret_arn)

            # Store SMTP User, Host, Port, and other values SSM Parameters
            self.smtp_user = ssm.StringParameter(
                scope=self,
                id="smtp-user",
                parameter_name="smtp_user",
                string_value=access_key.access_key_id
            )
            self.smtp_host = ssm.StringParameter(
                scope=self,
                id="smtp-host",
                parameter_name="smtp_host",
                string_value="email-smtp." + self.region + ".amazonaws.com"
            )
            self.smtp_port = ssm.StringParameter(
                scope=self,
                id="smtp-port",
                parameter_name="smtp_port",
                string_value="587"
            )
            self.smtp_secure = ssm.StringParameter(
                scope=self,
                id="smtp-secure",
                parameter_name="smtp_secure",
                string_value="tls"
            )
            self.patient_reminder_sender_email = ssm.StringParameter(
                scope=self,
                id="patient-reminder-sender-email",
                parameter_name="patient_reminder_sender_email",
                string_value="notifications@" + "services." + self.node.try_get_context("route53_domain")
            )
            self.patient_reminder_sender_name = ssm.StringParameter(
                scope=self,
                id="patient-reminder-sender-name",
                parameter_name="patient_reminder_sender_name",
                string_value="OpenEMR"
            )

            # Create VPC endpoint for sending SMTP email with SES
            self.smtp_interface_endpoint = self.vpc.add_interface_endpoint(
                "smtp_vpc_interface_endpoint",
                private_dns_enabled=True,
                service=ec2.InterfaceVpcEndpointAwsService.EMAIL_SMTP,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )


            # Validate Email Receiving Domain
            record_set = route53.MxRecord(self,
                                          "MxReceivingRecord",
                                          values=[route53.MxRecordValue(
                                              host_name="inbound-smtp."+self.region+".amazonaws.com",
                                              priority=10
                                          )],
                                          zone=hosted_zone,
                                          record_name=self.node.try_get_context("route53_domain"),
                                          )

            # Pass the KMS key in the `encryptionKey` field to associate the key to the S3 bucket
            self.email_storage_bucket = s3.Bucket(self, "EmailStorageBucket",
                                         auto_delete_objects=True,
                                         removal_policy=RemovalPolicy.DESTROY,
                                         block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                         enforce_ssl=True,
                                         versioned=True
                                         )

            # Create the policy statement allowing access for SES to the S3 bucket.
            ses_write_policy = iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                principals=[iam.ServicePrincipal("ses.amazonaws.com")],
                actions=[
                    "s3:PutObject",
                    "s3:PutObjectAcl"
                ],
                resources=[
                    f"{self.email_storage_bucket.bucket_arn}/*"  # Allow access to all objects in bucket
                ]
            )

            # Add the policy to the bucket
            self.email_storage_bucket.add_to_resource_policy(ses_write_policy)

            # Create an IAM policy that grants SES permissions to write to S3
            ses_policy = iam.PolicyStatement(
                actions=["s3:PutObject","s3:PutObjectAcl"],
                resources=[f"{self.email_storage_bucket.bucket_arn}/*"],
                effect=iam.Effect.ALLOW
            )

            # Create a role for SES to assume when accessing the S3 bucket
            ses_role = iam.Role(self, "SesRole", assumed_by=iam.ServicePrincipal("ses.amazonaws.com"))

            # Add the SES policy to the SES role
            ses_role.add_to_policy(ses_policy)

            # Grant SES the permissions to write to the S3 bucket
            self.email_storage_bucket.grant_write(ses_role)

            # Set up an SES Rule Set
            rule_set = ses.ReceiptRuleSet(self, "RuleSet")

            if self.node.try_get_context("email_forwarding_address"):

                # Create a Lambda function to process and forward emails
                self.email_forwarding_lambda = _lambda.Function(
                    self,
                    "EmailForwardingLambda",
                    runtime=self.lambda_python_runtime,
                    code=_lambda.Code.from_asset('lambda'),
                    architecture=_lambda.Architecture.ARM_64,
                    handler='lambda_functions.send_email',
                    environment={
                        "FORWARD_TO": self.node.try_get_context("email_forwarding_address"),
                        "SOURCE_ARN": ses_domain_identity.email_identity_arn,
                        "SOURCE_NAME": "help@" + self.node.try_get_context("route53_domain"),
                        "BUCKET_NAME": self.email_storage_bucket.bucket_name
                    }
                )

                # Grant the Lambda function permissions to read from the S3 bucket
                self.email_storage_bucket.grant_read(self.email_forwarding_lambda)

                # Grant the Lambda function SES email sending permissions
                ses_domain_identity.grant_send_email(self.email_forwarding_lambda)

                # Add a rule to the rule set
                rule_set.add_rule(
                    "ForwardingRule",
                    recipients=["help@" + self.node.try_get_context("route53_domain")],
                    enabled=True,
                    scan_enabled=True,
                    tls_policy=ses.TlsPolicy.REQUIRE,
                    actions=[
                        ses_actions.S3(
                            bucket=self.email_storage_bucket
                        ),
                        ses_actions.Lambda(
                            function=self.email_forwarding_lambda
                        ),
                    ]
                )
            else:
                # Add a rule to the rule set
                rule_set.add_rule(
                    "ForwardingRule",
                    recipients=["help@" + self.node.try_get_context("route53_domain")],
                    enabled=True,
                    scan_enabled=True,
                    tls_policy=ses.TlsPolicy.REQUIRE,
                    actions=[
                        ses_actions.S3(
                            bucket=self.email_storage_bucket
                        )
                    ]
                )

            # Create a function and run it once so our rule set for receiving is active
            self.set_rule_set_to_active = triggers.TriggerFunction(
                self,
                "MakeRuleSetActive",
                 runtime=self.lambda_python_runtime,
                 code=_lambda.Code.from_asset('lambda'),
                 architecture=_lambda.Architecture.ARM_64,
                 handler='lambda_functions.make_ruleset_active',
                 timeout=Duration.minutes(10),
                environment={
                    "RULE_SET_NAME": rule_set.receipt_rule_set_name
                }
             )

            # Create IAM policy statement to allow lambda to make ruleset active and add it to the function
            policy_statement = iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ses:SetActiveReceiptRuleSet"],
                resources=["*"]
            )
            self.set_rule_set_to_active.add_to_role_policy(policy_statement)

            # Set up practice return email parameter
            self.practice_return_email_path = ssm.StringParameter(
                scope=self,
                id="practice-return-email-path",
                parameter_name="practice_return_email_path",
                string_value="help@" + self.node.try_get_context("route53_domain")
            )

    def _create_db_instance(self):
        db_secret = secretsmanager.Secret(
            self,
            "db-secret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                include_space=False,
                secret_string_template='{"username": "dbadmin"}',
                generate_string_key="password"
            )
        )

        db_credentials = rds.Credentials.from_secret(db_secret)

        parameters = {
            "server_audit_logs_upload": "1",
            "log_queries_not_using_indexes": "1",
            "general_log": "1",
            "slow_query_log": "1",
            "server_audit_logging": "1",
            "require_secure_transport": "ON",
            "server_audit_events": "CONNECT,QUERY,QUERY_DCL,QUERY_DDL,QUERY_DML,TABLE"
        }

        parameters["net_read_timeout"] = self.node.try_get_context("net_read_timeout")
        parameters["net_write_timeout"] = self.node.try_get_context("net_write_timeout")
        parameters["wait_timeout"] = self.node.try_get_context("wait_timeout")
        parameters["connect_timeout"] = self.node.try_get_context("connect_timeout")
        parameters["max_execution_time"] = self.node.try_get_context("max_execution_time")

        if self.node.try_get_context("enable_bedrock_integration") == "true":
            database_ml_role = iam.Role(
                self,
                "AuroraMLRole",
                assumed_by=iam.ServicePrincipal("rds.amazonaws.com"),
            )
            database_ml_role.add_to_policy(
                iam.PolicyStatement(
                    actions=['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
                    resources=['arn:aws:bedrock:*::foundation-model/*']
                )
            )
            parameters["aws_default_bedrock_role"] = database_ml_role.role_arn
            parameters["aurora_ml_inference_timeout"] = self.node.try_get_context("aurora_ml_inference_timeout")

        parameter_group = rds.ParameterGroup(
            self,
            "ParameterGroup",
            engine=rds.DatabaseClusterEngine.aurora_mysql(version=self.aurora_mysql_engine_version),
            parameters=parameters
        )

        if self.node.try_get_context("enable_data_api") == "true":
            self.db_instance = rds.DatabaseCluster(self, "DatabaseCluster",
                                                   engine=rds.DatabaseClusterEngine.aurora_mysql(
                                                       version=self.aurora_mysql_engine_version),
                                                   cloudwatch_logs_exports=["audit", "error", "general", "slowquery"],
                                                   writer=rds.ClusterInstance.serverless_v2("writer"),
                                                   enable_data_api=True,
                                                   enable_performance_insights=True,
                                                   performance_insight_retention=rds.PerformanceInsightRetention.LONG_TERM,
                                                   serverless_v2_min_capacity=0,
                                                   serverless_v2_max_capacity=256,
                                                   storage_encrypted=True,
                                                   parameter_group=parameter_group,
                                                   credentials=db_credentials,
                                                   readers=[rds.ClusterInstance.serverless_v2("reader",
                                                                                              scale_with_writer=True)],
                                                   security_groups=[self.db_sec_group],
                                                   vpc_subnets=ec2.SubnetSelection(
                                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                                   ),
                                                   vpc=self.vpc
                                                   )
        else:
            self.db_instance = rds.DatabaseCluster(self, "DatabaseCluster",
                                                   engine=rds.DatabaseClusterEngine.aurora_mysql(
                                                       version=self.aurora_mysql_engine_version),
                                                   cloudwatch_logs_exports=["audit", "error", "general", "slowquery"],
                                                   writer=rds.ClusterInstance.serverless_v2("writer"),
                                                   enable_performance_insights=True,
                                                   performance_insight_retention=rds.PerformanceInsightRetention.LONG_TERM,
                                                   serverless_v2_min_capacity=0,
                                                   serverless_v2_max_capacity=256,
                                                   storage_encrypted=True,
                                                   parameter_group=parameter_group,
                                                   credentials=db_credentials,
                                                   readers=[rds.ClusterInstance.serverless_v2("reader",
                                                                                              scale_with_writer=True)],
                                                   security_groups=[self.db_sec_group],
                                                   vpc_subnets=ec2.SubnetSelection(
                                                       subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                                                   ),
                                                   vpc=self.vpc
                                                   )

        if self.node.try_get_context("enable_bedrock_integration") == "true":
            # Associate role with database cluster
            cfn_db_instance = self.db_instance.node.default_child
            cfn_db_instance.associated_roles = [
                {
                    "featureName": 'Bedrock',
                    "roleArn": database_ml_role.role_arn,
                },
            ]

            # Create VPC endpoints for bedrock so we can use it from a private subnet
            bedrock_runtime_interface_endpoint = self.vpc.add_interface_endpoint(
                "BedrockRuntimeEndpoint",
                private_dns_enabled=True,
                service=ec2.InterfaceVpcEndpointAwsService.BEDROCK_RUNTIME,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )

            # Allow connections to and from the bedrock endpoints to the database
            bedrock_runtime_interface_endpoint.connections.allow_default_port_from(self.db_sec_group)
            bedrock_runtime_interface_endpoint.connections.allow_default_port_to(self.db_sec_group)

            # Allow connections to and from the database to the bedrock endpoints
            self.db_instance.connections.allow_default_port_from(bedrock_runtime_interface_endpoint)
            self.db_instance.connections.allow_default_port_to(bedrock_runtime_interface_endpoint)

            # Add policy that allows RDS to access Bedrock VPC endpoint.
            bedrock_runtime_interface_endpoint.add_to_policy(
                iam.PolicyStatement(
                    principals=[database_ml_role],
                    actions=['bedrock:InvokeModel', 'bedrock:InvokeModelWithResponseStream'],
                    resources=['arn:aws:bedrock:*::foundation-model/*'],
                    effect=iam.Effect.ALLOW,
                )
            )

    def _create_valkey_cluster(self):
        private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]

        self.valkey_cluster = elasticache.CfnServerlessCache(
            scope=self,
            id="ValkeyCluster",
            engine="valkey",
            serverless_cache_name="openemrvalkey",
            subnet_ids=private_subnets_ids,
            security_group_ids=[self.valkey_sec_group.security_group_id]
        )

        self.valkey_endpoint = ssm.StringParameter(
            self,
            "valkey-endpoint",
            parameter_name="valkey_endpoint",
            string_value=self.valkey_cluster.attr_endpoint_address
        )

        self.php_valkey_tls_variable = ssm.StringParameter(
            scope=self,
            id="php-valkey-tls-variable",
            parameter_name="php_valkey_tls_variable",
            string_value="yes"
        )

    def _create_ecs_cluster(self):
        if self.node.try_get_context("enable_ecs_exec") == "true":

            # Create a key and give cloudwatch logs and s3 permissions to use it
            self.kms_key = kms.Key(self, "KmsKey", enable_key_rotation=True)
            self.kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("logs." + self.region + ".amazonaws.com"))
            self.kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("s3.amazonaws.com"))

            # Pass the KMS key in the `encryptionKey` field to associate the key to the log group
            self.ecs_exec_group = logs.LogGroup(self, "LogGroup",
                                                encryption_key=self.kms_key
                                                )

            # Pass the KMS key in the `encryptionKey` field to associate the key to the S3 bucket
            self.exec_bucket = s3.Bucket(self, "EcsExecBucket",
                                         auto_delete_objects=True,
                                         removal_policy=RemovalPolicy.DESTROY,
                                         block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                                         encryption_key=self.kms_key,
                                         enforce_ssl=True,
                                         versioned=True
                                         )

            # Create cluster
            self.ecs_cluster = ecs.Cluster(self, "ecs-cluster",
                                           vpc=self.vpc,
                                           container_insights=True,
                                           enable_fargate_capacity_providers=True,
                                           execute_command_configuration=ecs.ExecuteCommandConfiguration(
                                               kms_key=self.kms_key,
                                               log_configuration=ecs.ExecuteCommandLogConfiguration(
                                                   cloud_watch_log_group=self.ecs_exec_group,
                                                   cloud_watch_encryption_enabled=True,
                                                   s3_bucket=self.exec_bucket,
                                                   s3_encryption_enabled=True,
                                                   s3_key_prefix="exec-command-output"
                                               ),
                                               logging=ecs.ExecuteCommandLogging.OVERRIDE,
                                           )
                                           )

        else:

            # Create cluster
            self.ecs_cluster = ecs.Cluster(self, "ecs-cluster",
                                           vpc=self.vpc,
                                           container_insights=True,
                                           enable_fargate_capacity_providers=True
                                           )

        # Add dependency so cluster is not created before the database
        self.ecs_cluster.node.add_dependency(self.db_instance)

        # Create log group for container logging
        self.log_group = logs.LogGroup(
            self,
            "log-group",
            retention=logs.RetentionDays.ONE_WEEK,
        )

    def _create_efs_volume(self):
        # Create EFS for sites folder
        self.file_system_for_sites_folder = efs.FileSystem(
            self,
            "EfsFileSystemForSitesFolder",
            vpc=self.vpc,
            encrypted=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create EFS volume configuration for sites folder
        self.efs_volume_configuration_for_sites_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_sites_folder.file_system_id,
            transit_encryption="ENABLED"
        )

        # Create EFS for ssl folder
        self.file_system_for_ssl_folder = efs.FileSystem(
            self,
            "EfsFileSystemForSslFolder",
            vpc=self.vpc,
            encrypted=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Create EFS volume configuration for ssl folder
        self.efs_volume_configuration_for_ssl_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_ssl_folder.file_system_id,
            transit_encryption="ENABLED"
        )

    def _create_and_maintain_tls_materials(self):

        # Create generate SSL materials task definition
        create_ssl_materials_task = ecs.FargateTaskDefinition(
            self,
            "CreateSSLMaterialsTaskDefinition",
            cpu=256,
            memory_limit_mib=512,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64
            )
        )
        create_ssl_materials_task.add_volume(
            name='SslFolderVolume',
            efs_volume_configuration=self.efs_volume_configuration_for_ssl_folder
        )

        # This script generates self-signed SSL materials using OpenSSL.
        command_array = [
            "mkdir -p /etc/ssl/certs/ && \
            mkdir -p /etc/ssl/private/ && \
            openssl genrsa 2048 > /etc/ssl/private/selfsigned.key.pem && \
            openssl req -new -x509 -nodes -sha256 -days 365 -key /etc/ssl/private/selfsigned.key.pem \
            -outform PEM -out /etc/ssl/certs/selfsigned.cert.pem -config /swarm-pieces/ssl/openssl.cnf \
            -subj '/CN=localhost' && \
            cp /etc/ssl/private/selfsigned.key.pem /etc/ssl/private/webserver.key.pem && \
            cp /etc/ssl/certs/selfsigned.cert.pem /etc/ssl/certs/webserver.cert.pem && \
            touch /etc/ssl/docker-selfsigned-configured"
        ]

        # Add container definition for a container with OpenSSL to the original task
        ssl_maintenance_container = create_ssl_materials_task.add_container("AmazonLinuxContainer",
                                                                            logging=ecs.LogDriver.aws_logs(
                                                                                stream_prefix="ecs/sslmaintenance",
                                                                                log_group=self.log_group, ),
                                                                            port_mappings=[ecs.PortMapping(
                                                                                container_port=self.container_port)],
                                                                            essential=True,
                                                                            container_name="openemr",
                                                                            entry_point=["/bin/sh", "-c"],
                                                                            command=command_array,
                                                                            image=ecs.ContainerImage.from_registry(
                                                                            f"openemr/openemr:{self.openemr_version}")
                                                                            )

        # Create mount point for EFS for ssl folder
        efs_mount_point_for_ssl_folder = ecs.MountPoint(
            container_path="/etc/ssl/",
            read_only=False,
            source_volume='SslFolderVolume'
        )

        # Add mount points to container definition
        ssl_maintenance_container.add_mount_points(
            efs_mount_point_for_ssl_folder
        )

        # Get private subnet ID string
        private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]
        private_subnet_id_string = ','.join(private_subnets_ids)

        # # Create EFS only security group and get ID
        self.efs_only_security_group = ec2.SecurityGroup(self,
                                                         "EFSOnlySecurityGroup",
                                                         vpc=self.vpc
                                                         )
        security_group_id = self.efs_only_security_group.security_group_id

        # Add ability for the security group to access the EFS with the SSL materials
        self.file_system_for_ssl_folder.connections.allow_default_port_from(self.efs_only_security_group)

        # Create generate SSL materials Lambda
        create_ssl_materials_lambda = _lambda.Function(
            self, 'MaintainSSLMaterialsLambda',
            runtime=self.lambda_python_runtime,
            code=_lambda.Code.from_asset('lambda'),
            architecture=_lambda.Architecture.ARM_64,
            handler='lambda_functions.generate_ssl_materials',
            timeout=Duration.minutes(10)
        )

        # Create IAM policy statement to add to task role
        policy_statement = iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=["ecs:RunTask", "ecs:DescribeTasks"],
            resources=["*"]
        )
        policy_statement.add_condition("ArnEquals", {"ecs:cluster": self.ecs_cluster.cluster_arn})

        # Add permissions to task role
        create_ssl_materials_task.grant_run(create_ssl_materials_lambda.grant_principal)
        create_ssl_materials_lambda.add_to_role_policy(policy_statement)

        # Add environment variables
        create_ssl_materials_lambda.add_environment('ECS_CLUSTER', self.ecs_cluster.cluster_arn)
        create_ssl_materials_lambda.add_environment('TASK_DEFINITION', create_ssl_materials_task.task_definition_arn)
        create_ssl_materials_lambda.add_environment('SUBNETS', private_subnet_id_string)
        create_ssl_materials_lambda.add_environment('SECURITY_GROUPS', security_group_id)

        # Add schedule so function runs on regular interval
        rule_to_run_on_regular_interval = events.Rule(
            self,
            "RegularScheduleforSSLMaintenance",
            schedule=events.Schedule.rate(Duration.days(self.number_of_days_to_regenerate_ssl_materials)),
            targets=[event_targets.LambdaFunction(create_ssl_materials_lambda)]
        )

        # Create a function and run it once so that SSL is set up before the OpenEMR containers start
        self.one_time_create_ssl_materials_lambda = triggers.TriggerFunction(self, "OneTimeSSLSetup",
                                                                             runtime=self.lambda_python_runtime,
                                                                             code=_lambda.Code.from_asset('lambda'),
                                                                             architecture=_lambda.Architecture.ARM_64,
                                                                             handler='lambda_functions.generate_ssl_materials',
                                                                             timeout=Duration.minutes(10)
                                                                             )

        # Add permissions to task role
        create_ssl_materials_task.grant_run(self.one_time_create_ssl_materials_lambda.grant_principal)
        self.one_time_create_ssl_materials_lambda.add_to_role_policy(policy_statement)

        # Add environment variables
        self.one_time_create_ssl_materials_lambda.add_environment('ECS_CLUSTER', self.ecs_cluster.cluster_arn)
        self.one_time_create_ssl_materials_lambda.add_environment('TASK_DEFINITION',create_ssl_materials_task.task_definition_arn)
        self.one_time_create_ssl_materials_lambda.add_environment('SUBNETS', private_subnet_id_string)
        self.one_time_create_ssl_materials_lambda.add_environment('SECURITY_GROUPS', security_group_id)

    def _create_openemr_service(self):

        # Test for user supplied certificate
        if self.node.try_get_context("certificate_arn"):
            self.certificate = acm.Certificate.from_certificate_arn(
                self,
                "domainCert",
                self.node.try_get_context("certificate_arn")
            )

        # Create OpenEMR task definition
        openemr_fargate_task_definition = ecs.FargateTaskDefinition(
            self,
            "OpenEMRFargateTaskDefinition",
            cpu=1024,
            memory_limit_mib=2048,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64
            )
        )

        # Add volumes to task definition
        openemr_fargate_task_definition.add_volume(
            name='SitesFolderVolume',
            efs_volume_configuration=self.efs_volume_configuration_for_sites_folder
        )
        openemr_fargate_task_definition.add_volume(
            name='SslFolderVolume',
            efs_volume_configuration=self.efs_volume_configuration_for_ssl_folder
        )

        # This script sets up certificates to allow for the usage of ElastiCache and RDS with SSL/TLS.
        command_array = [
            'curl --cacert /swarm-pieces/ssl/certs/ca-certificates.crt -o /root/certs/redis/redis-ca \
            --create-dirs https://www.amazontrust.com/repository/AmazonRootCA1.pem && \
            chown apache /root/certs/redis/redis-ca && \
            curl --cacert /swarm-pieces/ssl/certs/ca-certificates.crt -o /root/certs/mysql/server/mysql-ca \
            --create-dirs https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem && \
            chown apache /root/certs/mysql/server/mysql-ca && \
            chmod +x ./openemr.sh && \
            echo "1 23  *   *   *   httpd -k graceful" >> /etc/crontabs/root && \
            ./openemr.sh'
        ]

        # Define secrets
        secrets = {
            "MYSQL_ROOT_USER": ecs.Secret.from_secrets_manager(self.db_instance.secret, "username"),
            "MYSQL_ROOT_PASS": ecs.Secret.from_secrets_manager(self.db_instance.secret, "password"),
            "MYSQL_USER": ecs.Secret.from_secrets_manager(self.db_instance.secret, "username"),
            "MYSQL_PASS": ecs.Secret.from_secrets_manager(self.db_instance.secret, "password"),
            "MYSQL_HOST": ecs.Secret.from_secrets_manager(self.db_instance.secret, "host"),
            "MYSQL_PORT": ecs.Secret.from_ssm_parameter(self.mysql_port_var),
            "OE_USER": ecs.Secret.from_secrets_manager(self.password, "username"),
            "OE_PASS": ecs.Secret.from_secrets_manager(self.password, "password"),
            "REDIS_SERVER": ecs.Secret.from_ssm_parameter(self.valkey_endpoint),
            "REDIS_TLS": ecs.Secret.from_ssm_parameter(self.php_valkey_tls_variable),
            "SWARM_MODE": ecs.Secret.from_ssm_parameter(self.swarm_mode),
        }

        if self.node.try_get_context("activate_openemr_apis") == "true" or self.node.try_get_context(
                "enable_patient_portal") == "true":
            secrets["OPENEMR_SETTING_site_addr_oath"] = ecs.Secret.from_ssm_parameter(self.site_addr_oath)

        if self.node.try_get_context("activate_openemr_apis") == "true":
            secrets["OPENEMR_SETTING_rest_api"] = ecs.Secret.from_ssm_parameter(self.activate_rest_api)
            secrets["OPENEMR_SETTING_rest_fhir_api"] = ecs.Secret.from_ssm_parameter(self.activate_fhir_service)

        if self.node.try_get_context("enable_patient_portal") == "true":
            secrets["OPENEMR_SETTING_portal_onsite_two_address"] = ecs.Secret.from_ssm_parameter(
                self.portal_onsite_two_address)
            secrets["OPENEMR_SETTING_portal_onsite_two_enable"] = ecs.Secret.from_ssm_parameter(
                self.portal_onsite_two_enable)
            secrets["OPENEMR_SETTING_ccda_alt_service_enable"] = ecs.Secret.from_ssm_parameter(
                self.ccda_alt_service_enable)
            secrets["OPENEMR_SETTING_rest_portal_api"] = ecs.Secret.from_ssm_parameter(self.rest_portal_api)

        if self.node.try_get_context("configure_ses") == "true":
            secrets["OPENEMR_SETTING_SMTP_PASS"] = ecs.Secret.from_secrets_manager(self.smtp_password, "password")
            secrets["OPENEMR_SETTING_SMTP_USER"] = ecs.Secret.from_ssm_parameter(self.smtp_user)
            secrets["OPENEMR_SETTING_SMTP_HOST"] = ecs.Secret.from_ssm_parameter(self.smtp_host)
            secrets["OPENEMR_SETTING_SMTP_PORT"] = ecs.Secret.from_ssm_parameter(self.smtp_port)
            secrets["OPENEMR_SETTING_SMTP_SECURE"] = ecs.Secret.from_ssm_parameter(self.smtp_secure)
            secrets["OPENEMR_SETTING_patient_reminder_sender_email"] = ecs.Secret.from_ssm_parameter(
                self.patient_reminder_sender_email)
            secrets["OPENEMR_SETTING_patient_reminder_sender_name"] = ecs.Secret.from_ssm_parameter(
                self.patient_reminder_sender_name)

            if self.node.try_get_context("email_forwarding_address"):
                secrets["OPENEMR_SETTING_practice_return_email_path"] = ecs.Secret.from_ssm_parameter(
                    self.practice_return_email_path)

        # Add OpenEMR container definition to original task
        openemr_container = openemr_fargate_task_definition.add_container("OpenEMRContainer",
                                                                          logging=ecs.LogDriver.aws_logs(
                                                                              stream_prefix="ecs/openemr",
                                                                              log_group=self.log_group),
                                                                          port_mappings=[ecs.PortMapping(
                                                                              container_port=self.container_port)],
                                                                          essential=True,
                                                                          container_name="openemr",
                                                                          working_directory='/var/www/localhost/htdocs/openemr',
                                                                          entry_point=["/bin/sh", "-c"],
                                                                          command=command_array,
                                                                          health_check=ecs.HealthCheck(
                                                                              command=["CMD-SHELL",
                                                                                       "curl -f http://localhost:80/swagger || exit 1"],
                                                                              start_period=Duration.seconds(300),
                                                                              interval=Duration.seconds(120)
                                                                          ),
                                                                          image=ecs.ContainerImage.from_registry(
                                                                              f"openemr/openemr:{self.openemr_version}"),
                                                                          secrets=secrets
                                                                          )

        # Create mount point for EFS for sites folder
        efs_mount_point_for_sites_folder = ecs.MountPoint(
            container_path="/var/www/localhost/htdocs/openemr/sites/",
            read_only=False,
            source_volume='SitesFolderVolume'
        )

        # Create mount point for EFS for ssl folder
        efs_mount_point_for_ssl_folder = ecs.MountPoint(
            container_path="/etc/ssl/",
            read_only=False,
            source_volume='SslFolderVolume'
        )

        # Add mount points to container definition
        openemr_container.add_mount_points(
            efs_mount_point_for_sites_folder,
            efs_mount_point_for_ssl_folder
        )

        # Create proxy service with load balancer
        if self.node.try_get_context("certificate_arn") or self.node.try_get_context("route53_domain"):
            openemr_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self, "OpenEMRFargateLBService",
                certificate=self.certificate,
                min_healthy_percent=100,
                cluster=self.ecs_cluster,
                desired_count=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                load_balancer=self.alb,
                open_listener=False,
                target_protocol=elb.ApplicationProtocol.HTTPS,
                task_definition=openemr_fargate_task_definition
            )
        else:
            openemr_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self, "OpenEMRFargateLBService",
                min_healthy_percent=100,
                cluster=self.ecs_cluster,
                desired_count=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                load_balancer=self.alb,
                open_listener=False,
                target_protocol=elb.ApplicationProtocol.HTTPS,
                task_definition=openemr_fargate_task_definition
            )
        openemr_application_load_balanced_fargate_service.node.add_dependency(self.one_time_create_ssl_materials_lambda)
        openemr_service = openemr_application_load_balanced_fargate_service.service

        # Add availability zone rebalancing.
        # This will allow us to recover better in the event an avalability zone goes down.
        # Documentation here: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/service-rebalancing.html
        cfn_openemr_service = openemr_service.node.default_child
        cfn_openemr_service.add_property_override("AvailabilityZoneRebalancing","ENABLED")

        # Configure health check
        openemr_application_load_balanced_fargate_service.target_group.configure_health_check(
            protocol=elb.Protocol.HTTPS,
            path="/",
            port='443',
            healthy_http_codes="302",
            healthy_threshold_count=2,
            unhealthy_threshold_count=3,
            interval=Duration.seconds(300)
        )

        # Set up ECS Exec for Debuggging
        if self.node.try_get_context("enable_ecs_exec") == "true":
            cfn_openemr_service.add_property_override("EnableExecuteCommand", "True")
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["ssmmessages:CreateControlChannel",
                             "ssmmessages:CreateDataChannel",
                             "ssmmessages:OpenControlChannel",
                             "ssmmessages:OpenDataChannel", ],
                    resources=["*"])
            )
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["s3:PutObject",
                             "s3:GetEncryptionConfiguration"],
                    resources=[self.exec_bucket.bucket_arn,
                               self.exec_bucket.bucket_arn + '/*'])
            )
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["logs:DescribeLogGroups"],
                    resources=["*"])
            )
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["logs:CreateLogStream",
                             "logs:DescribeLogStreams",
                             "logs:PutLogEvents"],
                    resources=[self.ecs_exec_group.log_group_arn])
            )
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["kms:Decrypt",
                             "kms:GenerateDataKey"],
                    resources=[self.kms_key.key_arn])
            )

        # Add permission to describe subnets
        openemr_fargate_task_definition.execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=['ec2:DescribeSubnets'],
                resources=['*']
            )
        )

        # Add managed policies for AWS App Mesh and Xray
        openemr_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly")
        )
        openemr_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess")
        )
        openemr_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess")
        )

        # Allow conenctions to and from both of our EFSs for our Fargate service
        openemr_service.connections.allow_from(self.file_system_for_ssl_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_from(self.file_system_for_sites_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_ssl_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_sites_folder, ec2.Port.tcp(2049))

        # Allow connections to and from our database and web caching for our fargate service
        openemr_service.connections.allow_from(self.db_instance, ec2.Port.tcp(self.mysql_port))
        openemr_service.connections.allow_to(self.db_instance, ec2.Port.tcp(self.mysql_port))

        openemr_service.connections.allow_from(self.valkey_sec_group, ec2.Port.tcp(self.valkey_port))
        openemr_service.connections.allow_to(self.valkey_sec_group, ec2.Port.tcp(self.valkey_port))

        # Allow outbound traffic to SMTP servers operating on port 587
        if self.node.try_get_context("open_smtp_port") == "true":
            openemr_service.connections.allow_to_any_ipv4(ec2.Port.tcp(587))

        # Allow communication to the SES interface endpoint if SES is configured
        if self.node.try_get_context("configure_ses") == "true":
            openemr_service.connections.allow_to_any_ipv4(ec2.Port.tcp(587))
            self.smtp_interface_endpoint.connections.allow_from(openemr_service, ec2.Port.tcp(587))
            self.smtp_interface_endpoint.connections.allow_to(openemr_service, ec2.Port.tcp(587))
            openemr_service.connections.allow_from(self.smtp_interface_endpoint, ec2.Port.tcp(587))
            openemr_service.connections.allow_to(self.smtp_interface_endpoint, ec2.Port.tcp(587))

        # Add CPU and memory utilization based autoscaling
        openemr_scalable_target = (
            openemr_service.auto_scale_task_count(
                min_capacity=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                max_capacity=self.node.try_get_context("openemr_service_fargate_maximum_capacity")
            )
        )

        openemr_scalable_target.scale_on_cpu_utilization(
            "OpenEMRCPUScaling",
            target_utilization_percent=self.node.try_get_context("openemr_service_fargate_cpu_autoscaling_percentage")
        )

        openemr_scalable_target.scale_on_memory_utilization(
            "OpenEMRMemoryScaling",
            target_utilization_percent=self.node.try_get_context(
                "openemr_service_fargate_memory_autoscaling_percentage")
        )

    def _create_waf(self):
        web_acl = wafv2.CfnWebACL(
            self,
            "web-acl",
            default_action=wafv2.CfnWebACL.DefaultActionProperty(
                allow=wafv2.CfnWebACL.AllowActionProperty()
            ),
            scope="REGIONAL",
            visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                cloud_watch_metrics_enabled=True,
                metric_name="MetricForWebACLCDK",
                sampled_requests_enabled=True
            ),
            name="cdk-web-acl",
            rules=[
                wafv2.CfnWebACL.RuleProperty(
                    name="CRSRule",
                    priority=0,
                    statement=wafv2.CfnWebACL.StatementProperty(
                        managed_rule_group_statement=wafv2.CfnWebACL.ManagedRuleGroupStatementProperty(
                            name="AWSManagedRulesCommonRuleSet",
                            vendor_name="AWS"
                        )
                    ),
                    visibility_config=wafv2.CfnWebACL.VisibilityConfigProperty(
                        cloud_watch_metrics_enabled=True,
                        metric_name="MetricForWebACLCDK-CRS",
                        sampled_requests_enabled=True
                    ),
                    override_action=wafv2.CfnWebACL.OverrideActionProperty(
                        none={}
                    )
                )
            ]
        )

        waf_log_group = logs.LogGroup(
            self,
            'WAF-Log-Group',
            log_group_name="aws-waf-logs-openemr"
        )
        waf_log_group.apply_removal_policy(RemovalPolicy.DESTROY)

        wafv2.CfnWebACLAssociation(
            self,
            "WebACLAssociation",
            resource_arn=self.alb.load_balancer_arn,
            web_acl_arn=web_acl.attr_arn
        )

        wafv2.CfnLoggingConfiguration(
            self,
            "waf-logging-configuration",
            resource_arn=web_acl.attr_arn,
            log_destination_configs=[
                Stack.of(self).format_arn(
                    arn_format=ArnFormat.COLON_RESOURCE_NAME,
                    service="logs",
                    resource="log-group",
                    resource_name=waf_log_group.log_group_name,
                )
            ]
        )

        web_acl.node.add_dependency(self.alb)

    def _create_serverless_analytics_environment(self):

        if self.node.try_get_context("create_serverless_analytics_environment") == "true":

            # Make an 18 character deterministic unique id
            # Sagemaker only integrates with certain infrastructure if "SageMaker" is in the name.
            # This unique ID allows us to create names that contain "SageMaker" while being safe from naming collisions.
            # This is especially important because S3 names must be globally unique.
            unique_id = hashlib.md5(bytes(f"{self.node.addr}", 'utf-8')).hexdigest().lower()[:18]

            # Create a key and give cloudwatch logs, rds, rds export, sagemaker, EFS and s3 permissions to use it
            # This key will be used to encrypt everything in the serverless analytics environment
            self.analytics_kms_key = kms.Key(self,
                                             "AnalyticsKmsKey",
                                             alias=f"AmazonSageMakerSMKMS{unique_id}{self.account}{self.region}",
                                             enable_key_rotation=True
                                             )
            self.analytics_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("logs." + self.region + ".amazonaws.com"))
            self.analytics_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("export.rds.amazonaws.com"))
            self.analytics_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("rds.amazonaws.com"))
            self.analytics_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("sagemaker.amazonaws.com"))
            self.analytics_kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("elasticfilesystem.amazonaws.com"))

            # Create policy statement that grants permissions needed for apps to integrate with our KMS key.
            kms_policy_statement = iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=[
                    "kms:CreateGrant",
                    "kms:ListGrants",
                    "kms:RevokeGrant",
                    "kms:GenerateDataKeyWithoutPlaintext",
                    "kms:DescribeKey",
                    "kms:RetireGrant"
                ],
                resources=[self.analytics_kms_key.key_arn]
            )

            # Create an S3 bucket for RDS export
            # Exports of data in the MySQL database in RDS will end up here.
            self.export_bucket_rds = s3.Bucket(self, "S3ExportBucket",
                auto_delete_objects=True,
                removal_policy=RemovalPolicy.DESTROY,
                bucket_name=f"sagemaker-rds-export-{unique_id}-{self.account}-{self.region}",
                encryption_key=self.analytics_kms_key,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                enforce_ssl=True,
                versioned=True
            )

            # Create an S3 bucket for EFS export
            # Exports of data in the EFS that hosts the "sites" folder will end up here.
            self.export_bucket_efs = s3.Bucket(self, "EFSExportBucket",
                auto_delete_objects=True,
                removal_policy=RemovalPolicy.DESTROY,
                bucket_name=f"sagemaker-efs-export-{unique_id}-{self.account}-{self.region}",
                encryption_key=self.analytics_kms_key,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                enforce_ssl=True,
                versioned=True
            )

            # Get private subnet ids
            private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]

            # Create an IAM role for the Aurora database to export to S3
            aurora_s3_export_role = iam.Role(
                self,
                "AuroraExportRole",
                assumed_by=iam.ServicePrincipal("export.rds.amazonaws.com"),
            )

            # Grant read/write permissions to the aurora role to the S3 bucket
            self.export_bucket_rds.grant_read_write(aurora_s3_export_role)

            # Attach the required AmazonRDSDataFullAccess policy for RDS export
            aurora_s3_export_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonRDSDataFullAccess")
            )

            # Create an IAM role for SageMaker
            # Must start role name with "AmazonSageMaker" for all permissions to work.
            # For documentation see here:
            # https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol.html#security-iam-awsmanpol-AmazonSageMakerFullAccess
            sagemaker_role = iam.Role(
                self,
                "SageMakerExecutionRole",
                role_name=f"AmazonSageMakerSMRole{unique_id}{self.account}{self.region}",
                assumed_by=iam.ServicePrincipal("sagemaker.amazonaws.com")
            )

            # Add S3 read/write permissions to the sagemaker role
            self.export_bucket_rds.grant_read_write(sagemaker_role)
            self.export_bucket_efs.grant_read_write(sagemaker_role)

            # Create an EMR Serverless application
            # We'll be able to submit Apache Spark jobs to this EMR cluster and run data analytics against our EMR data
            emr_app = emrserverless.CfnApplication(
                self,
                "EMRServerlessApp",
                release_label=self.emr_serverless_release_label,
                type="SPARK",
                name="MyEMRServerlessApp",
            )

            # Create SageMaker Domain
            # Use our KMS key to encrypt the domain.
            # Only IAM users logged into the console with sufficient IAM permissions will be able to access anything.
            # Enable RStudio in case anyone wants to use it for data analysis.
            # Enable the option to share notebooks with an S3 bucket encrypted with our KMS key.
            # Route all traffic through the VPC we've provisioned.
            # Provide access to the EFS encrypted with our KMS key for our users to use for shared file storage.
            sagemaker_domain = sagemaker.CfnDomain(
                self,
                "OpenEMRSagemakerDomain",
                auth_mode="IAM",
                kms_key_id=self.analytics_kms_key.key_id,
                default_user_settings=sagemaker.CfnDomain.UserSettingsProperty(
                    execution_role=sagemaker_role.role_arn,
                    r_studio_server_pro_app_settings=sagemaker.CfnDomain.RStudioServerProAppSettingsProperty(
                        access_status="ENABLED",
                        user_group="R_STUDIO_ADMIN"
                    ),
                    sharing_settings=sagemaker.CfnDomain.SharingSettingsProperty(
                        notebook_output_option="Allowed",
                        s3_kms_key_id=self.analytics_kms_key.key_id
                    )
                ),
                app_network_access_type="VpcOnly",
                default_space_settings=sagemaker.CfnDomain.DefaultSpaceSettingsProperty(
                    execution_role=sagemaker_role.role_arn
                ),
                domain_name="OpenEMRSageMakerDomain",
                vpc_id=self.vpc.vpc_id,
                subnet_ids=private_subnets_ids,
            )

            # Create task to sync EFS to S3
            sync_efs_to_s3_task = ecs.FargateTaskDefinition(
                self,
                "SyncEFStoS3Task",
                cpu=256,
                memory_limit_mib=512,
                runtime_platform=ecs.RuntimePlatform(
                    cpu_architecture=ecs.CpuArchitecture.ARM64
                )
            )

            # Add EFS volume
            # This volume configuration also enforces transit encryption.
            sync_efs_to_s3_task.add_volume(
                name='SitesFolderVolume',
                efs_volume_configuration=self.efs_volume_configuration_for_sites_folder
            )

            # This script syncs our EFS to the target s3 bucket
            command_array = [
            f"apk add --no-cache aws-cli \
            && aws s3 sync /var/www/localhost/htdocs/openemr/sites/ s3://{self.export_bucket_efs.bucket_name}"
            ]

            # Add container definition for OpenEMR to the task that will be used to sync EFS to s3
            sync_efs_to_s3_container = sync_efs_to_s3_task.add_container("AmazonLinuxContainer",
                                                                        logging=ecs.LogDriver.aws_logs(
                                                                            stream_prefix="ecs/efstos3",
                                                                            log_group=self.log_group, ),
                                                                        port_mappings=[ecs.PortMapping(
                                                                            container_port=self.container_port)],
                                                                        essential=True,
                                                                        container_name="openemr",
                                                                        entry_point=["/bin/sh", "-c"],
                                                                        command=command_array,
                                                                        image=ecs.ContainerImage.from_registry(
                                                                            f"openemr/openemr:{self.openemr_version}")
                                                                    )

            # Create mount point for EFS for sites folder.
            # Make read_only because we should not be writing here now; all we're doing is copying from EFS to S3.
            efs_mount_point_for_sites_folder = ecs.MountPoint(
                container_path="/var/www/localhost/htdocs/openemr/sites/",
                read_only=True,
                source_volume='SitesFolderVolume'
            )

            # Add mount points to container definition
            sync_efs_to_s3_container.add_mount_points(
                efs_mount_point_for_sites_folder
            )

            # Create an EFS to S3 export Lambda
            export_efs_to_s3_lambda = _lambda.Function(
                self, 'EFStoS3ExportLambda',
                runtime=self.lambda_python_runtime,
                code=_lambda.Code.from_asset('lambda'),
                architecture=_lambda.Architecture.ARM_64,
                handler='lambda_functions.sync_efs_to_s3',
                timeout=Duration.minutes(10)
            )

            # Get private subnet ID string
            private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]
            private_subnet_id_string = ','.join(private_subnets_ids)

            # Add environment variables
            export_efs_to_s3_lambda.add_environment('ECS_CLUSTER', self.ecs_cluster.cluster_arn)
            export_efs_to_s3_lambda.add_environment('TASK_DEFINITION', sync_efs_to_s3_task.task_definition_arn)
            export_efs_to_s3_lambda.add_environment('SUBNETS', private_subnet_id_string)
            export_efs_to_s3_lambda.add_environment('SECURITY_GROUPS', self.efs_only_security_group.security_group_id)

            # Allow connections to and from both of our EFSs for our Fargate task
            self.efs_only_security_group.connections.allow_to(self.file_system_for_sites_folder, ec2.Port.tcp(2049))
            self.efs_only_security_group.connections.allow_from(self.file_system_for_sites_folder, ec2.Port.tcp(2049))

            # Grant read write for the export s3 bucket for EFS to the task role
            self.export_bucket_efs.grant_read_write(sync_efs_to_s3_task.task_role)

            # Grant additional KMS permissions to task role
            sync_efs_to_s3_task.task_role.add_to_principal_policy(kms_policy_statement)

            # Allow lambda to run the ECS task
            sync_efs_to_s3_task.grant_run(export_efs_to_s3_lambda.grant_principal)

            # Add permissions for RDS export to access the rds export s3 bucket
            rds_export_access_to_s3_bucket_policy_statement_service_principal = iam.PolicyStatement(
                actions=["s3:*"],
                resources=[self.export_bucket_rds.bucket_arn, f"{self.export_bucket_rds.bucket_arn}/*"],
                principals=[iam.ServicePrincipal("export.rds.amazonaws.com")]
            )
            self.export_bucket_rds.add_to_resource_policy(
                rds_export_access_to_s3_bucket_policy_statement_service_principal
            )
            rds_export_access_to_s3_bucket_policy_statement_iam_arn_principal = iam.PolicyStatement(
                actions=["s3:*"],
                resources=[self.export_bucket_rds.bucket_arn, f"{self.export_bucket_rds.bucket_arn}/*"],
                principals=[iam.ArnPrincipal(aurora_s3_export_role.role_arn)]
            )
            self.export_bucket_rds.add_to_resource_policy(
                rds_export_access_to_s3_bucket_policy_statement_iam_arn_principal
            )

            # Create an RDS to S3 export Lambda
            export_rds_to_s3_lambda = _lambda.Function(
                self, 'RDStoS3ExportLambda',
                runtime=self.lambda_python_runtime,
                code=_lambda.Code.from_asset('lambda'),
                architecture=_lambda.Architecture.ARM_64,
                handler='lambda_functions.export_from_rds_to_s3',
                timeout=Duration.minutes(10)
            )

            # Grant permissions to decrypt and encrypt with the encryption key
            self.analytics_kms_key.grant_encrypt_decrypt(export_rds_to_s3_lambda.grant_principal)
            self.analytics_kms_key.grant_encrypt_decrypt(aurora_s3_export_role)
            self.analytics_kms_key.grant_encrypt_decrypt(sagemaker_role)
            self.analytics_kms_key.grant_encrypt_decrypt(sync_efs_to_s3_task.task_role)

            # Add environment variables
            export_rds_to_s3_lambda.add_environment('DB_CLUSTER_ARN', self.db_instance.cluster_arn)
            export_rds_to_s3_lambda.add_environment('KMS_KEY_ID', self.analytics_kms_key.key_id)
            export_rds_to_s3_lambda.add_environment('S3_BUCKET_NAME', self.export_bucket_rds.bucket_name)
            export_rds_to_s3_lambda.add_environment('EXPORT_ROLE_ARN', aurora_s3_export_role.role_arn)

            # Create policy statements to allow lambda to run rds export task and add them to the function
            rds_policy_statement = iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["rds:StartExportTask", "rds:DescribeDBSnapshots", "rds:DescribeExportTasks"],
                resources=[self.db_instance.cluster_arn]
            )
            export_rds_to_s3_lambda.add_to_role_policy(rds_policy_statement)
            iam_policy_statement = iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["iam:PassRole"],
                resources=[aurora_s3_export_role.role_arn]
            )
            export_rds_to_s3_lambda.add_to_role_policy(iam_policy_statement)

            # Add KMS policy statement
            export_rds_to_s3_lambda.add_to_role_policy(kms_policy_statement)

            # Grant permission for users to invoke the Lambdas
            export_efs_to_s3_lambda.grant_invoke(sagemaker_role)
            export_rds_to_s3_lambda.grant_invoke(sagemaker_role)

            # Create a SageMaker user profile
            sagemaker_user = sagemaker.CfnUserProfile(
                self,
                "SagemakerUserProfile",
                domain_id=sagemaker_domain.attr_domain_id,
                user_profile_name="ServerlessAnalyticsUser",
                user_settings=sagemaker.CfnUserProfile.UserSettingsProperty(
                    security_groups=[self.efs_only_security_group.security_group_id],
                    execution_role=sagemaker_role.role_arn,
                    sharing_settings=sagemaker.CfnUserProfile.SharingSettingsProperty(
                        notebook_output_option="Allowed",
                        s3_kms_key_id=self.analytics_kms_key.key_id
                    ),
                    r_studio_server_pro_app_settings=sagemaker.CfnUserProfile.RStudioServerProAppSettingsProperty(
                        access_status="ENABLED",
                        user_group="R_STUDIO_ADMIN"
                    )
                )
            )

            # Create an IAM role with Glue permissions and permissions for EMR-serverless to assume
            # Must start role name with "AmazonSageMaker" for all permissions to work.
            # For documentation see here:
            # https://docs.aws.amazon.com/sagemaker/latest/dg/security-iam-awsmanpol.html#security-iam-awsmanpol-AmazonSageMakerFullAccess
            glue_role = iam.Role(
                self,
                "GlueRoleForEMRServerless",
                role_name=f"AmazonSageMakerGlueRole{unique_id}{self.account}{self.region}",
                assumed_by=iam.ServicePrincipal("emr-serverless.amazonaws.com"),  # EMR Serverless trust relationship
                description="IAM Role with Glue permissions for EMR Serverless",
            )

            # Attach Glue permissions to the role
            glue_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("service-role/AWSGlueServiceRole")
            )

            # Add custom permissions for Glue operations
            glue_role.add_to_policy(
                iam.PolicyStatement(
                    actions=[
                        "glue:GetDatabase",
                        "glue:CreateDatabase",
                        "glue:GetDataBases",
                        "glue:CreateTable",
                        "glue:GetTable",
                        "glue:UpdateTable",
                        "glue:DeleteTable",
                        "glue:GetTables",
                        "glue:GetPartition",
                        "glue:GetPartitions",
                        "glue:CreatePartition",
                        "glue:BatchCreatePartition",
                        "glue:GetUserDefinedFunctions"
                    ],
                    resources=["*"],  # Restrict resources as needed
                )
            )

            # Grant read/write permissions to the glue role to the S3 bucket
            self.export_bucket_rds.grant_read_write(glue_role)
            self.export_bucket_efs.grant_read_write(glue_role)

            # The following policies enable functionality within Sagemaker Studio and Canvas.
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFullAccess")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerClusterInstanceRolePolicy")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerFeatureStoreAccess")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerModelGovernanceUseAccess")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerModelRegistryFullAccess")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerGroundTruthExecution")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerPipelinesIntegrations")
            )
            sagemaker_role.add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSageMakerCanvasFullAccess")
            )

            # Define the policy statements to allow sagemaker to ...
            # 1. Integrate with emr serverless.
            # 2. Access custom container images published in the same account to ECR.
            # 3. Use the KMS key created for the environment
            # 4. Monitor exports from EFS to S3 (via ECS)
            # 5. Monitor exports from RDS to S3 (via RDS export)
            policy_statements = [

                # This allows us to access EMR serverless functions from the Sagemaker console
                iam.PolicyStatement(
                    actions=[
                        "emr-serverless:StartApplication",
                        "emr-serverless:StopApplication",
                        "emr-serverless:UpdateApplication",
                        "emr-serverless:RunJob",
                        "emr-serverless:CancelJobRun",
                        "emr-serverless:GetJobRun",
                        "emr-serverless:GetApplication",
                        "emr-serverless:AccessLivyEndpoints",
                        "emr-serverless:GetDashboardForJobRun"
                    ],
                    effect=iam.Effect.ALLOW,
                    resources=[f"arn:aws:emr-serverless:{self.region}:{self.account}:applications/{emr_app.ref}"],
                ),

                # This allows the listing of applications
                iam.PolicyStatement(
                    sid="EMRServerlessUnTaggedActions",
                    effect=iam.Effect.ALLOW,
                    actions=["emr-serverless:ListApplications"],
                    resources=[f"arn:aws:emr-serverless:{self.region}:{self.account}:/*"],
                ),

                # This allows sagemaker to pass role to EMR serverless
                iam.PolicyStatement(
                    sid="EMRServerlessPassRole",
                    effect=iam.Effect.ALLOW,
                    actions=["iam:PassRole"],
                    resources=[glue_role.role_arn],
                    conditions={
                        "StringLike": {
                            "iam:PassedToService": "emr-serverless.amazonaws.com",
                        }
                    },
                ),

                # This allows the creation and tagging of EMR serverless applications
                iam.PolicyStatement(
                    sid="EMRServerlessCreateApplicationAction",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "emr-serverless:CreateApplication",
                        "emr-serverless:TagResource",
                    ],
                    resources=[f"arn:aws:emr-serverless:{self.region}:{self.account}:/*"],
                    conditions={
                        "ForAllValues:StringEquals": {
                            "aws:TagKeys": [
                                "sagemaker:domain-arn",
                                "sagemaker:user-profile-arn",
                                "sagemaker:space-arn",
                            ]
                        },
                        "Null": {
                            "aws:RequestTag/sagemaker:domain-arn": "false",
                            "aws:RequestTag/sagemaker:user-profile-arn": "false",
                            "aws:RequestTag/sagemaker:space-arn": "false",
                        },
                    },
                ),

                # This makes the EMR serverless permissions more restrictive
                iam.PolicyStatement(
                    sid="EMRServerlessDenyPermissiveTaggingAction",
                    effect=iam.Effect.DENY,
                    actions=[
                        "emr-serverless:TagResource",
                        "emr-serverless:UntagResource",
                    ],
                    resources=[f"arn:aws:emr-serverless:{self.region}:{self.account}:/*"],
                    conditions={
                        "Null": {
                            "aws:ResourceTag/sagemaker:domain-arn": "true",
                            "aws:ResourceTag/sagemaker:user-profile-arn": "true",
                            "aws:ResourceTag/sagemaker:space-arn": "true",
                        },
                    },
                ),

                # This allows some emr serverless actions that Sagemaker will need to enable the integration.
                iam.PolicyStatement(
                    sid="EMRServerlessActions",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "emr-serverless:StartApplication",
                        "emr-serverless:StopApplication",
                        "emr-serverless:GetApplication",
                        "emr-serverless:DeleteApplication",
                        "emr-serverless:AccessLivyEndpoints",
                        "emr-serverless:GetDashboardForJobRun",
                    ],
                    resources=[f"arn:aws:emr-serverless:{self.region}:{self.account}:/applications/*"],
                    conditions={
                        "Null": {
                            "aws:ResourceTag/sagemaker:domain-arn": "false",
                            "aws:ResourceTag/sagemaker:user-profile-arn": "false",
                            "aws:ResourceTag/sagemaker:space-arn": "false",
                        },
                    },
                ),

                # This allows the pulling of custom container images in the into sagemaker for use with analysis
                # This policy allows the pulling of images in the same account so deploy any images you want to ECR
                iam.PolicyStatement(
                    sid="ECRRepositoryListGetPolicy",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "ecr:GetDownloadUrlForLayer",
                        "ecr:BatchGetImage",
                        "ecr:DescribeImages"
                    ],
                    resources=[f"arn:aws:ecr:*:{self.account}:*/*"]
                ),

                # Grant the ability to monitor RDS export tasks for our specific database
                iam.PolicyStatement(
                    sid="RDSMonitorExportTasks",
                    effect=iam.Effect.ALLOW,
                    actions=[
                        "rds:DescribeExportTasks"
                    ],
                    resources=[self.db_instance.cluster_arn]
                ),

                # Grant the ability to describe running ECS tasks for our EFS to S3 export job
                iam.PolicyStatement(
                    effect=iam.Effect.ALLOW,
                    actions=["ecs:DescribeTasks"],
                    resources=["*"],
                    conditions={
                        "ArnEquals": {
                            "ecs:TaskArn": sync_efs_to_s3_task.task_definition_arn
                        }
                    }
                ),

                # Grant additional KMS permissions
                kms_policy_statement
            ]

            # Create a policy with the statements
            policy = iam.Policy(
                self,
                "EMRServerlessPolicy",
                policy_name="EMRServerlessPolicy",
                statements=policy_statements,
            )

            # Attach the policy to the existing role
            policy.attach_to_role(sagemaker_role)

            # Create SageMaker VPC Endpoints
            self.sagemaker_api_interface_endpoint = self.vpc.add_interface_endpoint(
                "sagemaker_api_interface_endpoint",
                private_dns_enabled=True,
                service=ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_API,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )
            self.sagemaker_runtime_interface_endpoint = self.vpc.add_interface_endpoint(
                "sagemaker_runtime_interface_endpoint",
                private_dns_enabled=True,
                service=ec2.InterfaceVpcEndpointAwsService.SAGEMAKER_RUNTIME,
                subnets=ec2.SubnetSelection(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
            )