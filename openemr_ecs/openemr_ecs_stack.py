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
    aws_lambda as _lambda,
    aws_secretsmanager as secretsmanager,
    aws_certificatemanager as acm,
    aws_events as events,
    aws_events_targets as event_targets,
    triggers,
    Duration,
    RemovalPolicy,
    ArnFormat
)
from constructs import Construct

class OpenemrEcsStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.cidr = "10.0.0.0/16"
        self.mysql_port = 3306
        self.valkey_port = 6379
        self.container_port = 443
        self.number_of_days_to_regenerate_ssl_materials = 2
        self._create_vpc()
        self._create_security_groups()
        self._create_elb_log_bucket()
        self._create_alb()
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
        if self.node.try_get_context("certificate_arn"):
            cidr = self.node.try_get_context("security_group_ip_range")
            if cidr:
                self.lb_sec_group.add_ingress_rule(
                    ec2.Peer.ipv4(cidr),
                    ec2.Port.tcp(443),
                )
                self.lb_sec_group.add_egress_rule(
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
                self.lb_sec_group.add_egress_rule(
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
            if self.node.try_get_context("certificate_arn"):
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
            "server_audit_events": "CONNECT,QUERY,QUERY_DCL,QUERY_DDL,QUERY_DML,TABLE"
        }

        if self.node.try_get_context("enable_bedrock_integration") == "true":
            database_ml_role = iam.Role(
                self,
                "AuroraMLRole",
                assumed_by=iam.ServicePrincipal("rds.amazonaws.com"),
            )
            database_ml_role.add_to_policy(
                iam.PolicyStatement(
                    actions=['bedrock:InvokeModel','bedrock:InvokeModelWithResponseStream'],
                    resources=['arn:aws:bedrock:*::foundation-model/*']
                )
            )
            parameters["aws_default_bedrock_role"]=database_ml_role.role_arn
            parameters["net_read_timeout"]="172800"
            parameters["aurora_ml_inference_timeout"]="30000"

        parameter_group = rds.ParameterGroup(
            self,
            "ParameterGroup",
            engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_07_1),
            parameters=parameters
        )

        self.db_instance = rds.DatabaseCluster(self, "DatabaseCluster",
                engine=rds.DatabaseClusterEngine.aurora_mysql(version=rds.AuroraMysqlEngineVersion.VER_3_07_1),
                cloudwatch_logs_exports=["audit", "error", "general", "slowquery"],
                writer=rds.ClusterInstance.serverless_v2("writer"),
                serverless_v2_min_capacity=0.5,
                serverless_v2_max_capacity=128,
                storage_encrypted=True,
                parameter_group=parameter_group,
                credentials=db_credentials,
                readers=[rds.ClusterInstance.serverless_v2("reader", scale_with_writer=True)],
                security_groups=[self.db_sec_group],
                vpc_subnets=ec2.SubnetSelection(
                    subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
                ),
                vpc=self.vpc
                )

        if self.node.try_get_context("enable_bedrock_integration") == "true":
            cfn_db_instance = self.db_instance.node.default_child
            cfn_db_instance.associated_roles = [
                {
                "featureName": 'Bedrock',
                "roleArn": database_ml_role.role_arn,
                },
            ]
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
            logging=ecs.LogDriver.aws_logs(stream_prefix="ecs/sslmaintenance", log_group=self.log_group,),
            port_mappings=[ecs.PortMapping(container_port=self.container_port)],
            essential=True,
            container_name="openemr",
            entry_point=["/bin/sh", "-c"],
            command=command_array,
            image=ecs.ContainerImage.from_registry("openemr/openemr:7.0.2")
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
            runtime=_lambda.Runtime.PYTHON_3_12,
            code=_lambda.Code.from_asset('lambda'),
            architecture=_lambda.Architecture.ARM_64,
            handler='maintain_ssl_materials.handler',
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
        create_ssl_materials_lambda.add_environment('ECS_CLUSTER',self.ecs_cluster.cluster_arn)
        create_ssl_materials_lambda.add_environment('TASK_DEFINITION',create_ssl_materials_task.task_definition_arn)
        create_ssl_materials_lambda.add_environment('SUBNETS',private_subnet_id_string)
        create_ssl_materials_lambda.add_environment('SECURITY_GROUPS',security_group_id)

        # Add schedule so function runs on regular interval
        rule_to_run_on_regular_interval = events.Rule(
            self,
            "RegularScheduleforSSLMaintenance",
            schedule=events.Schedule.rate(Duration.days(self.number_of_days_to_regenerate_ssl_materials)),
            targets=[event_targets.LambdaFunction(create_ssl_materials_lambda)]
        )

        # Create a function and run it once so that SSL is set up before the OpenEMR containers start
        self.one_time_create_ssl_materials_lambda = triggers.TriggerFunction(self, "MyTrigger",
                                 runtime=_lambda.Runtime.PYTHON_3_12,
                                 code=_lambda.Code.from_asset('lambda'),
                                 architecture=_lambda.Architecture.ARM_64,
                                 handler='maintain_ssl_materials.handler',
                                 timeout=Duration.minutes(10)
                                 )

        # Add permissions to task role
        create_ssl_materials_task.grant_run(self.one_time_create_ssl_materials_lambda.grant_principal)
        self.one_time_create_ssl_materials_lambda.add_to_role_policy(policy_statement)

        # Add environment variables
        self.one_time_create_ssl_materials_lambda.add_environment('ECS_CLUSTER',self.ecs_cluster.cluster_arn)
        self.one_time_create_ssl_materials_lambda.add_environment('TASK_DEFINITION',create_ssl_materials_task.task_definition_arn)
        self.one_time_create_ssl_materials_lambda.add_environment('SUBNETS',private_subnet_id_string)
        self.one_time_create_ssl_materials_lambda.add_environment('SECURITY_GROUPS',security_group_id)

    def _create_openemr_service(self):

        # Test for user supplied certificate
        if self.node.try_get_context("certificate_arn"):
            self.user_provided_certificate = acm.Certificate.from_certificate_arn(
                                                        self,
                                                        "domainCert",
                                                        self.node.try_get_context("certificate_arn")
            )
        else:
            self.user_provided_certificate = None

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
        if self.node.try_get_context("activate_openemr_apis") == "true":
            secrets["OPENEMR_SETTING_rest_api"] = ecs.Secret.from_ssm_parameter(self.activate_rest_api)
            secrets["OPENEMR_SETTING_rest_fhir_api"] = ecs.Secret.from_ssm_parameter(self.activate_fhir_service)
            secrets["OPENEMR_SETTING_site_addr_oath"] = ecs.Secret.from_ssm_parameter(self.site_addr_oath)

        # Add OpenEMR container definition to original task
        openemr_container = openemr_fargate_task_definition.add_container("OpenEMRContainer",
            logging=ecs.LogDriver.aws_logs(stream_prefix="ecs/openemr", log_group=self.log_group),
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

        #Create proxy service with load balancer
        if self.user_provided_certificate:
            openemr_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
                self, "OpenEMRFargateLBService",
                certificate=self.user_provided_certificate,
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
                cluster=self.ecs_cluster,
                desired_count=self.node.try_get_context("openemr_service_fargate_minimum_capacity"),
                load_balancer=self.alb,
                open_listener=False,
                target_protocol=elb.ApplicationProtocol.HTTPS,
                task_definition=openemr_fargate_task_definition
            )
        openemr_application_load_balanced_fargate_service.node.add_dependency(self.one_time_create_ssl_materials_lambda)
        openemr_service = openemr_application_load_balanced_fargate_service.service

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

        # Allow connections to and from our database for our fargate service
        openemr_service.connections.allow_from(self.db_instance, ec2.Port.tcp(self.mysql_port))
        openemr_service.connections.allow_to(self.db_instance, ec2.Port.tcp(self.mysql_port))

        openemr_service.connections.allow_from(self.valkey_sec_group, ec2.Port.tcp(self.valkey_port))
        openemr_service.connections.allow_to(self.valkey_sec_group, ec2.Port.tcp(self.valkey_port))

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
