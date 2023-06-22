from aws_cdk import (
    Stack,
    aws_ec2 as ec2,
    aws_ecs as ecs,
    aws_efs as efs,
    aws_backup as backup,
    aws_iam as iam,
    aws_elasticloadbalancingv2 as elb,
    aws_elasticache as elasticache,
    aws_logs as logs,
    aws_kms as kms,
    aws_ecs_patterns as ecs_patterns,
    aws_rds as rds,
    aws_s3 as s3,
    aws_ssm as ssm,
    aws_wafv2 as wafv2,
    aws_secretsmanager as secretsmanager,
    aws_appmesh as appmesh,
    aws_acmpca as acmpca,
    aws_servicediscovery as servicediscovery,
    aws_certificatemanager as acm,
    Duration,
    RemovalPolicy,
    ArnFormat
)
from constructs import Construct

class OpenemrEcsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.cidr = "10.0.0.0/16"
        self.private_dns_namespace_name = "openemr.local"
        self.mysql_port = 3306
        self.redis_port = 6379
        self.container_port = 80
        self._create_vpc()
        self._create_security_groups()
        self._create_elb_log_bucket()
        self._create_alb()
        self._create_waf()
        self._create_environment_variables()
        self._create_password()
        self._create_db_instance()
        self._create_redis_cluster()
        self._create_efs_volume()
        self._create_backup()
        self._create_ecs_cluster()
        self._create_tls_certificates()
        self._create_app_mesh_and_log_group()
        self._create_proxy_service()
        self._create_openemr_service()

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
            max_azs=3,
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
                exclude_punctuation=True,
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
        self.redis_sec_group = ec2.SecurityGroup(
            self,
            "redis-sec-group",
            vpc=self.vpc,
            allow_all_outbound=False
        )
        self.lb_sec_group = ec2.SecurityGroup(
            self,
            "lb-sec-group",
            vpc=self.vpc,
            allow_all_outbound=False
        )
        if self.node.try_get_context("certificate_arn"):
            cidr = self.node.try_get_context("security_group_ip_range")
            if cidr:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv4(cidr),
                    ec2.Port.tcp(443),
                )
        else:
            cidr = self.node.try_get_context("security_group_ip_range")
            if cidr:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv4(cidr),
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

        self.db_instance = rds.ServerlessCluster(
            self,
            "DatabaseCluster",
            vpc=self.vpc,
            engine=rds.DatabaseClusterEngine.AURORA_MYSQL,
            security_groups=[self.db_sec_group],
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            credentials=db_credentials,
            scaling=rds.ServerlessScalingOptions(
                auto_pause=Duration.minutes(0),
                min_capacity=rds.AuroraCapacityUnit.ACU_1,
                max_capacity=rds.AuroraCapacityUnit.ACU_256
            )
        )

    def _create_redis_cluster(self):
        private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]

        redis_subnet_group = elasticache.CfnSubnetGroup(
            scope=self,
            id="redis_subnet_group",
            subnet_ids=private_subnets_ids,
            description="subnet group for redis"
        )

        self.redis_secret = secretsmanager.Secret(
            scope=self,
            id="redis_secret",
            generate_secret_string=secretsmanager.SecretStringGenerator(
                exclude_punctuation=True,
                include_space=False,
                secret_string_template='{"username": "dbadmin"}',
                generate_string_key="password"
            )
        )

        self.redis_cluster = elasticache.CfnReplicationGroup(
            scope=self,
            id="RedisCluster",
            replication_group_description='Elasticache Redis Replication Group',
            auth_token=self.redis_secret.secret_value_from_json('password').unsafe_unwrap(),
            num_cache_clusters=2,
            at_rest_encryption_enabled=True,
            automatic_failover_enabled=True,
            transit_encryption_enabled=True,
            multi_az_enabled=True,
            engine="redis",
            cache_node_type=self.node.try_get_context("elasticache_cache_node_type"),
            cache_subnet_group_name=redis_subnet_group.ref,
            security_group_ids=[self.redis_sec_group.security_group_id]
        )
        self.redis_cluster.add_override("Properties.ClusterMode", "Disabled")

        self.redis_endpoint = ssm.StringParameter(
            self,
            "redis-endpoint",
            parameter_name="redis_endpoint",
            string_value=self.redis_cluster.attr_primary_end_point_address
        )

        self.php_redis_build_variable = ssm.StringParameter(
            scope=self,
            id="php-redis-build-variable",
            parameter_name="php_redis_build_variable",
            string_value="develop"
        )

        self.php_redis_tls_variable = ssm.StringParameter(
            scope=self,
            id="php-redis-tls-variable",
            parameter_name="php_redis_tls_variable",
            string_value="yes"
        )

    def _create_ecs_cluster(self):
        if self.node.try_get_context("enable_ecs_exec") == "true":

            # Create a key and give cloudwatch logs and s3 permissions to use it
            self.kms_key = kms.Key(self, "KmsKey",enable_key_rotation=True)
            self.kms_key.grant_encrypt_decrypt(iam.ServicePrincipal("logs."+self.region+".amazonaws.com"))
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

            # Create private_dns_namespace
            self.private_dns_namespace = servicediscovery.PrivateDnsNamespace(self, "OpenEMRPrivateDNSNamespace",
                                                     vpc=self.vpc,
                                                     name=self.private_dns_namespace_name
                                                     )

            # Create cluster
            self.ecs_cluster = ecs.Cluster(self, "ecs-cluster",
                                  vpc=self.vpc,
                                  container_insights=True,
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
            # Create private_dns_namespace
            self.private_dns_namespace = servicediscovery.PrivateDnsNamespace(self, "OpenEMRPrivateDNSNamespace",
                                                     vpc=self.vpc,
                                                     name=self.private_dns_namespace_name
                                                     )

            # Create cluster
            self.ecs_cluster = ecs.Cluster(self, "ecs-cluster",
                                  vpc=self.vpc,
                                  container_insights=True
                                  )

        # Add dependency so cluster is not created before the database
        self.ecs_cluster.node.add_dependency(self.db_instance)

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

    def _create_tls_certificates(self):
        # Create private certificate authority
        self.private_certificate_authority = acmpca.CfnCertificateAuthority(self, "CA",
                                                                       type="ROOT",
                                                                       key_algorithm="RSA_2048",
                                                                       signing_algorithm="SHA256WITHRSA",
                                                                       subject=acmpca.CfnCertificateAuthority.SubjectProperty(
                                                                           common_name="OpenEMRPrivateCA"
                                                                       )
                                                                       )

        # Create activation certificate for private certificate authority
        activation_certificate = acmpca.CfnCertificate(self, "MyCfnCertificate",
                                                       certificate_authority_arn=self.private_certificate_authority.attr_arn,
                                                       certificate_signing_request=self.private_certificate_authority.attr_certificate_signing_request,
                                                       signing_algorithm="SHA256WITHRSA",
                                                       template_arn='arn:aws:acm-pca:::template/RootCACertificate/V1',
                                                       validity=acmpca.CfnCertificate.ValidityProperty(
                                                           type="YEARS",
                                                           value=10
                                                       )
                                                       )
        activation_certificate.apply_removal_policy(RemovalPolicy.DESTROY)

        #Give permissions for ACM to issue certificates from private certificate authority and activate the authority
        cfn_permission = acmpca.CfnPermission(self, "MyCfnPermission",
                                              actions=["IssueCertificate", "GetCertificate", "ListPermissions"],
                                              certificate_authority_arn=self.private_certificate_authority.attr_arn,
                                              principal="acm.amazonaws.com",
                                              )
        self.certificate_authority_activation = acmpca.CfnCertificateAuthorityActivation(self,
                                                                                    "MyCfnCertificateAuthorityActivation",
                                                                                    certificate=activation_certificate.attr_certificate,
                                                                                    certificate_authority_arn=self.private_certificate_authority.attr_arn,
                                                                                    status='ACTIVE'
                                                                                    )
        self.certificate_authority_activation.apply_removal_policy(RemovalPolicy.DESTROY)
        self.certificate_authority_activation.node.add_dependency(cfn_permission)


        # Create private certificates using private certificate authority; wait for activation to complete first.
        self.private_certificate_gateway = acm.CfnCertificate(self, "PrivateCertificateGateway",
                                                 domain_name="*."+self.private_dns_namespace.namespace_name,
                                                 certificate_authority_arn=self.private_certificate_authority.attr_arn
                                                 )
        self.private_certificate_gateway.node.add_dependency(self.certificate_authority_activation)
        self.tls_certificate_gateway = acm.Certificate.from_certificate_arn(
            self, "tlsCertGateway", self.private_certificate_gateway.ref)

        self.private_certificate_backend = acm.CfnCertificate(self, "PrivateCertificateBackend",
                                                 domain_name="*."+self.private_dns_namespace.namespace_name,
                                                 certificate_authority_arn=self.private_certificate_authority.attr_arn
                                                 )
        self.private_certificate_backend.node.add_dependency(self.certificate_authority_activation)
        self.tls_certificate_backend = acm.Certificate.from_certificate_arn(
            self, "tlsCertBackend", self.private_certificate_backend.ref)

        # Create private certificate authority ACMPA object
        self.private_certificate_authority_acmpa_object = acmpca.CertificateAuthority.from_certificate_authority_arn(self,
                                                                                                "CertificateAuthority",
                                                                                                 self.private_certificate_authority.attr_arn)
    def _create_app_mesh_and_log_group(self):
        # Create AppMesh mesh
        self.mesh = appmesh.Mesh(self, "AppMesh",
                            mesh_name="OpenEMRAppMesh"
                            )

        # Create log group for container logging
        self.log_group = logs.LogGroup(
            self,
            "log-group",
            retention=logs.RetentionDays.ONE_WEEK,
        )

    def _create_proxy_service(self):
        # Test for user supplied certificate
        if self.node.try_get_context("certificate_arn"):
            self.user_provided_certificate = acm.Certificate.from_certificate_arn(
                                                        self,
                                                        "domainCert",
                                                        self.node.try_get_context("certificate_arn")
            )
        else:
            self.user_provided_certificate = None

        # Create proxy Fargate task definition
        proxy_fargate_task_definition = ecs.FargateTaskDefinition(
            self,
            "ProxyFargateTaskDefinition",
            cpu=256,
            memory_limit_mib=512,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64
            )
        )

        # Create envoy proxy container definition
        envoy_container = proxy_fargate_task_definition.add_container(
        "ProxyEnvoyContainer",
            logging=ecs.LogDriver.aws_logs(
               stream_prefix="ecs/mesh-gateway",
               log_group=self.log_group,
            ),
            environment={
               'ENVOY_LOG_LEVEL': "info",
               'AWS_REGION': self.region,
               'REGION': self.region,
               'ENABLE_ENVOY_XRAY_TRACING': '1',
               'ENABLE_ENVOY_STATS_TAGS': '1',
            },
            essential=True,
            container_name="envoy",
            port_mappings=[
               ecs.PortMapping(container_port=self.container_port),
               ecs.PortMapping(container_port=9901)
            ],
            health_check=ecs.HealthCheck(
               command=["CMD-SHELL", "curl -s http://localhost:9901/server_info | grep state | grep -q LIVE"],
               start_period=Duration.seconds(
                   10),
               interval=Duration.seconds(5),
               timeout=Duration.seconds(2),
               retries=3
            ),
            image=ecs.ContainerImage.from_registry(
               "public.ecr.aws/appmesh/aws-appmesh-envoy:v1.25.4.0-prod"),
        )

        # Create Xray container definition
        xray_container = proxy_fargate_task_definition.add_container(
        "ProxyXrayContainer",
            logging=ecs.LogDriver.aws_logs(
              stream_prefix="ecs/mesh-gateway-xray",
              log_group=self.log_group,
            ),
            environment={
                'AWS_REGION': self.region,
                'REGION': self.region
            },
            essential=True,
            container_name="xray",
            user='1337',
            image=ecs.ContainerImage.from_registry(
              "public.ecr.aws/xray/aws-xray-daemon:3.3.7"),
        )

        # Create container dependency
        envoy_container.add_container_dependencies(ecs.ContainerDependency(
              container=xray_container,
              condition=ecs.ContainerDependencyCondition.START
          )
        )

        #Create proxy service with load balancer
        if self.user_provided_certificate:
            proxy_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self, "appmesh-openemr-gateway",
                certificate=self.user_provided_certificate,
                cluster=self.ecs_cluster,
                desired_count=self.node.try_get_context("proxy_service_fargate_minimum_capacity"),
                load_balancer=self.alb,
                open_listener=False,
                target_protocol=elb.ApplicationProtocol.HTTPS,
                task_definition=proxy_fargate_task_definition,
                cloud_map_options=ecs.CloudMapOptions(
                    cloud_map_namespace=self.private_dns_namespace,
                )
            )
        else:
            proxy_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self, "OpenEMRFargateLBService",
                cluster=self.ecs_cluster,
                desired_count=self.node.try_get_context("proxy_service_fargate_minimum_capacity"),
                load_balancer=self.alb,
                open_listener=False,
                target_protocol=elb.ApplicationProtocol.HTTPS,
                task_definition=proxy_fargate_task_definition,
                cloud_map_options=ecs.CloudMapOptions(
                    cloud_map_namespace=self.private_dns_namespace,
                )
            )
        proxy_service = proxy_application_load_balanced_fargate_service.service

        # Create virtual gateway
        self.virtual_gateway = appmesh.VirtualGateway(self, "VirtualGatewayProxy",
                                                 mesh=self.mesh,
                                                 virtual_gateway_name=proxy_service.cloud_map_service.service_name,
                                                 listeners=[appmesh.VirtualGatewayListener.http(
                                                     port=self.container_port,
                                                     tls=appmesh.ListenerTlsOptions(
                                                         mode=appmesh.TlsMode.STRICT,
                                                         certificate=appmesh.TlsCertificate.acm(
                                                             self.tls_certificate_gateway
                                                         )
                                                     )
                                                 )],
                                                 backend_defaults=appmesh.BackendDefaults(
                                                 tls_client_policy=appmesh.TlsClientPolicy(
                                                      ports=[self.container_port],
                                                      validation=appmesh.TlsValidation(
                                                          trust=appmesh.TlsValidationTrust.acm(
                                                              certificate_authorities=[
                                                                  self.private_certificate_authority_acmpa_object
                                                            ])
                                                      )
                                                  )
                                                 )
                                             )

        # Only make virtual gateway after private certificate authority is active
        self.virtual_gateway.node.add_dependency(self.certificate_authority_activation)

        # Add environment variable for virtual gateway ARN to envoy proxy container
        envoy_container.add_environment('APPMESH_RESOURCE_ARN', self.virtual_gateway.virtual_gateway_arn)

        # Configure health check
        proxy_application_load_balanced_fargate_service.target_group.configure_health_check(
            protocol=elb.Protocol.HTTP,
            interval=Duration.seconds(10),
            port='9901',
            path='/server_info'
        )

        # Set up ECS Exec for Debuggging
        if self.node.try_get_context("enable_ecs_exec") == "true":
            cfn_proxy_service = proxy_service.node.default_child
            cfn_proxy_service.add_property_override("EnableExecuteCommand", "True")
            proxy_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["ssmmessages:CreateControlChannel",
                             "ssmmessages:CreateDataChannel",
                             "ssmmessages:OpenControlChannel",
                             "ssmmessages:OpenDataChannel",],
                    resources=["*"])
            )
            proxy_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["s3:PutObject",
                             "s3:GetEncryptionConfiguration"],
                    resources=[self.exec_bucket.bucket_arn,
                               self.exec_bucket.bucket_arn+'/*'])
            )
            proxy_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["logs:DescribeLogGroups"],
                    resources=["*"])
            )
            proxy_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["logs:CreateLogStream",
                             "logs:DescribeLogStreams",
                             "logs:PutLogEvents"],
                    resources=[self.ecs_exec_group.log_group_arn])
            )
            proxy_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["kms:Decrypt",
                             "kms:GenerateDataKey"],
                    resources=[self.kms_key.key_arn])
            )

        # Add permission to import certificates to ACM
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ImportCertificate"],
                resources=["arn:aws:acm:"+self.region+":"+self.account+":certificate/*"])
        )

        # Add permissions to export certificates from ACM
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ExportCertificate"],
                resources=[self.private_certificate_gateway.ref])
        )
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ExportCertificate"],
                resources=[self.private_certificate_backend.ref])
        )

        # Add permissions to describe certificates from ACM
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:DescribeCertificate"],
                resources=[self.private_certificate_gateway.ref])
        )
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:DescribeCertificate"],
                resources=[self.private_certificate_backend.ref])
        )

        # Add permission to describe subnets
        proxy_fargate_task_definition.execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=['ec2:DescribeSubnets'],
                resources=['*']
            )
        )

        # Add permission to export certificates from private certificate authority and to describe it
        proxy_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm-pca:GetCertificateAuthorityCertificate",
                         "acm-pca:DescribeCertificateAuthority"],
                resources=[self.private_certificate_authority.attr_arn])
        )

        # Add managed policies for AWS App Mesh and Xray
        proxy_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly")
        )
        proxy_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess")
        )
        proxy_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSAppMeshEnvoyAccess")
        )
        proxy_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess")
        )
        proxy_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSXRayDaemonWriteAccess")
        )

        # Allow connections to and from load balancer security group on the container port and health check port
        proxy_service.connections.allow_from(self.lb_sec_group, ec2.Port.tcp(self.container_port))
        proxy_service.connections.allow_to(self.lb_sec_group, ec2.Port.tcp(self.container_port))
        proxy_service.connections.allow_from(self.lb_sec_group, ec2.Port.tcp(9901))
        proxy_service.connections.allow_to(self.lb_sec_group, ec2.Port.tcp(9901))

        # Create object for service so that we can connect it to the backend service
        self.proxy_service = proxy_service

        # Add CPU and memory utilization based autoscaling
        proxy_scalable_target = (
            proxy_service.auto_scale_task_count(
                min_capacity=self.node.try_get_context("proxy_service_fargate_minimum_capacity"),
                max_capacity=self.node.try_get_context("proxy_service_fargate_maximum_capacity")
            )
        )

        proxy_scalable_target.scale_on_cpu_utilization(
            "ProxyCPUScaling",
            target_utilization_percent=self.node.try_get_context("proxy_service_fargate_cpu_autoscaling_percentage")
        )

        proxy_scalable_target.scale_on_memory_utilization(
            "ProxyMemoryScaling",
            target_utilization_percent=self.node.try_get_context("proxy_service_fargate_memory_autoscaling_percentage")
        )

    def _create_openemr_service(self):
        # Create OpenEMR task definition
        openemr_fargate_task_definition = ecs.FargateTaskDefinition(
            self,
            "OpenEMRFargateTaskDefinition",
            cpu=2048,
            memory_limit_mib=4096,
            runtime_platform=ecs.RuntimePlatform(
                cpu_architecture=ecs.CpuArchitecture.ARM64
            )
        )

        # Set egress ports to ignore connections to EFS port (2049), HTTPS for curl (443), MySQL port, and Redis port.
        proxy_configuration_properties = [
            {"Name": "IgnoredUID", "Value": str(1337)},
            {"Name": "AppPorts", "Value": str(self.container_port)},
            {"Name": "ProxyIngressPort", "Value": str(15000)},
            {"Name": "ProxyEgressPort", "Value": str(15001)},
            {"Name": "EgressIgnoredPorts",
             "Value": "2049,443" + ',' + str(self.redis_port) + ',' + str(self.mysql_port)},
            {"Name": "EgressIgnoredIPs", "Value": "169.254.170.2,169.254.169.254"}
        ]
        cfn_fargate_task_definition = openemr_fargate_task_definition.node.default_child
        cfn_fargate_task_definition.add_property_override("ProxyConfiguration.ContainerName", "envoy")
        cfn_fargate_task_definition.add_property_override("ProxyConfiguration.Type", "APPMESH")
        cfn_fargate_task_definition.add_property_override("ProxyConfiguration.ProxyConfigurationProperties",
                                                          proxy_configuration_properties)

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
            'sed -i "s@phpize@phpize82@g" openemr.sh && \
            sed -i "s@./configure --enable-redis-igbinary@./configure --with-php-config=/usr/bin/php-config82 --enable-redis-igbinary@g" openemr.sh && \
            curl --cacert /swarm-pieces/ssl/certs/ca-certificates.crt -o /root/certs/mysql/server/mysql-ca \
            --create-dirs https://www.amazontrust.com/repository/AmazonRootCA1.pem && \
            chown apache /root/certs/mysql/server/mysql-ca && \
            mkdir -p /root/certs/redis && \
            cp /root/certs/mysql/server/mysql-ca /root/certs/redis/redis-ca && \
            chown apache /root/certs/redis/redis-ca && \
            chmod +x ./openemr.sh && \
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
            "REDIS_PASSWORD": ecs.Secret.from_secrets_manager(self.redis_secret, "password"),
            "REDISCLI_AUTH": ecs.Secret.from_secrets_manager(self.redis_secret, "password"),
            "REDIS_SERVER": ecs.Secret.from_ssm_parameter(self.redis_endpoint),
            "PHPREDIS_BUILD": ecs.Secret.from_ssm_parameter(self.php_redis_build_variable),
            "REDIS_TLS": ecs.Secret.from_ssm_parameter(self.php_redis_tls_variable),
            "SWARM_MODE": ecs.Secret.from_ssm_parameter(self.swarm_mode),
        }

        # Add OpenEMR container definition to original task
        openemr_container = openemr_fargate_task_definition.add_container("OpenEMRContainer",
            logging=ecs.LogDriver.aws_logs(stream_prefix="ecs/openemr", log_group=self.log_group,),
            port_mappings=[ecs.PortMapping(container_port=self.container_port)],
            essential=True,
            container_name="openemr",
            working_directory='/var/www/localhost/htdocs/openemr',
            entry_point=["/bin/sh", "-c"],
            command=command_array,
            health_check=ecs.HealthCheck(
             command=["CMD-SHELL","curl -f http://localhost:80/swagger || exit 1"],
             start_period=Duration.seconds(300),
             interval=Duration.seconds(120)
            ),
            image=ecs.ContainerImage.from_registry("openemr/openemr:7.0.2"),
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

        # Create fargate service for OpenEMR
        if self.node.try_get_context("enable_ecs_exec") == "true":
            openemr_service = ecs.FargateService(
                                self,
                                "BackendService",
                                cluster=self.ecs_cluster,
                                desired_count=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                                enable_execute_command=True,
                                task_definition=openemr_fargate_task_definition,
                                cloud_map_options=ecs.CloudMapOptions(
                                    cloud_map_namespace=self.private_dns_namespace,
                                )
            )
        else:
            openemr_service = ecs.FargateService(
                                self,
                                "BackendService",
                                cluster=self.ecs_cluster,
                                desired_count=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                                enable_execute_command=False,
                                task_definition=openemr_fargate_task_definition,
                                cloud_map_options=ecs.CloudMapOptions(
                                    cloud_map_namespace=self.private_dns_namespace,
                                )
            )

        # Create OpenEMR Virtual Node
        openemr_node = appmesh.VirtualNode(
            self,
            "OpenEMRNode",
            mesh=self.mesh,
            virtual_node_name=openemr_service.cloud_map_service.service_name,
            listeners=[
                appmesh.VirtualNodeListener.http(
                    port=self.container_port,
                    tls=appmesh.ListenerTlsOptions(
                        mode=appmesh.TlsMode.STRICT,
                        certificate=appmesh.TlsCertificate.acm(self.tls_certificate_backend)
                    )
                )
            ],
            service_discovery=appmesh.ServiceDiscovery.cloud_map(openemr_service.cloud_map_service)
        )

        # Create OpenEMR Virtual Service
        virtual_service_name = "{}.{}".format(openemr_service.cloud_map_service.service_name,
                                              openemr_service.cloud_map_service.namespace.namespace_name)
        virtual_service = appmesh.VirtualService(self, "OpenEMRVirtualService",
                                                 virtual_service_provider=appmesh.VirtualServiceProvider.virtual_node(
                                                     openemr_node
                                                 ),
                                                 virtual_service_name=virtual_service_name
                                                 )

        # Add gateway route to virtual service
        self.virtual_gateway.add_gateway_route(
            "MeshGatewayRoute",
            route_spec=appmesh.GatewayRouteSpec.http(
                route_target=virtual_service
            )
        )

        # Create envoy proxy container definition
        envoy_container = openemr_fargate_task_definition.add_container(
            "OpenEMREnvoyContainer",
            logging=ecs.LogDriver.aws_logs(
                stream_prefix="ecs/openemr-envoy-proxy",
                log_group=self.log_group,
            ),
            environment={
                'APPMESH_RESOURCE_ARN': openemr_node.virtual_node_arn,
                'ENVOY_LOG_LEVEL': "info",
                'AWS_REGION': self.region,
                'REGION': self.region,
                'ENABLE_ENVOY_XRAY_TRACING': '1',
                'ENABLE_ENVOY_STATS_TAGS': '1',
            },
            essential=True,
            container_name="envoy",
            health_check=ecs.HealthCheck(
                command=["CMD-SHELL", "curl -s http://localhost:9901/server_info | grep state | grep -q LIVE"],
                start_period=Duration.seconds(10),
                interval=Duration.seconds(5),
                timeout=Duration.seconds(2),
                retries=3
            ),
            user='1337',
            image=ecs.ContainerImage.from_registry(
                "public.ecr.aws/appmesh/aws-appmesh-envoy:v1.25.4.0-prod"),
        )

        # Create Xray container definition
        xray_container = openemr_fargate_task_definition.add_container(
            "OpenEMRXrayContainer",
            logging=ecs.LogDriver.aws_logs(
                stream_prefix="ecs/openemr-xray",
                log_group=self.log_group,
            ),
            environment={
                'AWS_REGION': self.region,
                'REGION': self.region
            },
            essential=True,
            container_name="xray",
            user='1337',
            image=ecs.ContainerImage.from_registry(
                "public.ecr.aws/xray/aws-xray-daemon:3.3.7"),
        )

        # Create container dependency
        envoy_container.add_container_dependencies(ecs.ContainerDependency(
            container=xray_container,
            condition=ecs.ContainerDependencyCondition.START
        )
        )
        openemr_container.add_container_dependencies(ecs.ContainerDependency(
            container=envoy_container,
            condition=ecs.ContainerDependencyCondition.HEALTHY,
        )
        )

        # Set up ECS Exec for Debuggging
        if self.node.try_get_context("enable_ecs_exec") == "true":
            cfn_openemr_service = openemr_service.node.default_child
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

        # Add permissions to export certificates from ACM
        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ExportCertificate"],
                resources=[self.private_certificate_gateway.ref])
        )
        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ExportCertificate"],
                resources=[self.private_certificate_backend.ref])
        )

        # Add permissions to describe certificates from ACM
        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:DescribeCertificate"],
                resources=[self.private_certificate_gateway.ref])
        )
        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:DescribeCertificate"],
                resources=[self.private_certificate_backend.ref])
        )

        # Add permission to describe subnets
        openemr_fargate_task_definition.execution_role.add_to_policy(
            iam.PolicyStatement(
                actions=['ec2:DescribeSubnets'],
                resources=['*']
            )
        )

        # Add permission to export certificates from private certificate authority and to describe it
        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm-pca:GetCertificateAuthorityCertificate",
                         "acm-pca:DescribeCertificateAuthority"],
                resources=[self.private_certificate_authority.attr_arn])
        )

        # Add managed policies for AWS App Mesh and Xray
        openemr_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AmazonEC2ContainerRegistryReadOnly")
        )
        openemr_fargate_task_definition.execution_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchLogsFullAccess")
        )
        openemr_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSAppMeshEnvoyAccess")
        )
        openemr_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("CloudWatchFullAccess")
        )
        openemr_fargate_task_definition.task_role.add_managed_policy(
            iam.ManagedPolicy.from_aws_managed_policy_name("AWSXRayDaemonWriteAccess")
        )

        # Allow conenctions to and from both of our EFSs for our Fargate service
        openemr_service.connections.allow_from(self.file_system_for_ssl_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_from(self.file_system_for_sites_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_ssl_folder, ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_sites_folder, ec2.Port.tcp(2049))

        # Allow inter-service communication
        openemr_service.connections.allow_from(self.proxy_service.connections, ec2.Port.tcp(self.container_port))
        openemr_service.connections.allow_to(self.proxy_service.connections, ec2.Port.tcp(self.container_port))

        # Allow connections to and from our database for our fargate service
        openemr_service.connections.allow_from(self.db_instance, ec2.Port.tcp(self.mysql_port))
        openemr_service.connections.allow_to(self.db_instance, ec2.Port.tcp(self.mysql_port))

        openemr_service.connections.allow_from(self.redis_sec_group, ec2.Port.tcp(self.redis_port))
        openemr_service.connections.allow_to(self.redis_sec_group, ec2.Port.tcp(self.redis_port))

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
         target_utilization_percent=self.node.try_get_context("openemr_service_fargate_memory_autoscaling_percentage")
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
