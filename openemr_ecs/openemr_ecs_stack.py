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
        self.redis_port = 6379
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
            #create a key and give cloudwatch logs and s3 permissions to use it
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
            self.ecs_cluster = ecs.Cluster(self, "ecs-cluster",
                                  vpc=self.vpc,
                                  container_insights=True
                                  )
        self.ecs_cluster.node.add_dependency(self.db_instance)

    def _create_efs_volume(self):

        #create EFS for sites folder
        self.file_system_for_sites_folder = efs.FileSystem(
            self,
            "EfsFileSystemForSitesFolder",
            vpc=self.vpc,
            encrypted=True,
            removal_policy=RemovalPolicy.DESTROY,

        )

        #create EFS volume configuration for sites folder
        self.efs_volume_configuration_for_sites_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_sites_folder.file_system_id,
            transit_encryption="ENABLED"
        )

        #create EFS for ssl folder
        self.file_system_for_ssl_folder = efs.FileSystem(
            self,
            "EfsFileSystemForSslFolder",
            vpc=self.vpc,
            encrypted=True,
            removal_policy=RemovalPolicy.DESTROY,
        )

        #create EFS volume configuration for ssl folder
        self.efs_volume_configuration_for_ssl_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_ssl_folder.file_system_id,
            transit_encryption="ENABLED"
        )

    def _create_openemr_service(self):
        log_group = logs.LogGroup(
            self,
            "log-group",
            retention=logs.RetentionDays.ONE_WEEK,
        )

        openemr_fargate_task_definition = ecs.FargateTaskDefinition(
            self,
            "OpenEMRFargateTaskDefinition",
            cpu=2048,
            memory_limit_mib=4096
        )

        # add volumes to task definition
        openemr_fargate_task_definition.add_volume(
            name='SitesFolderVolume',
            efs_volume_configuration=self.efs_volume_configuration_for_sites_folder
        )
        openemr_fargate_task_definition.add_volume(
            name='SslFolderVolume',
            efs_volume_configuration=self.efs_volume_configuration_for_ssl_folder
        )

        #Add OpenEMR container definition
        container_port = 80

        #this script sets up certificates to allow for the usage of ElastiCache and RDS with SSL/TLS.
        command_array = [
            'curl --cacert /swarm-pieces/ssl/certs/ca-certificates.crt -o /root/certs/mysql/server/mysql-ca --create-dirs https://www.amazontrust.com/repository/AmazonRootCA1.pem && \
            chown apache /root/certs/mysql/server/mysql-ca && \
            mkdir -p /root/certs/redis && \
            cp /root/certs/mysql/server/mysql-ca /root/certs/redis/redis-ca && \
            chown apache /root/certs/redis/redis-ca && \
            chmod +x ./openemr.sh && \
            ./openemr.sh'
        ]

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

        openemr_container_definition = openemr_fargate_task_definition.add_container("OpenEMRContainer",
            logging=ecs.LogDriver.aws_logs(
              stream_prefix="ecs/openemr",
              log_group=log_group,
            ),
            port_mappings=[ecs.PortMapping(container_port=container_port)],
            container_name="openemr",
            working_directory='/var/www/localhost/htdocs/openemr',
            entry_point=["/bin/sh", "-c"],
            command=command_array,
            health_check=ecs.HealthCheck(
                command=[ "CMD-SHELL", "curl -f http://localhost:80/swagger || exit 1" ],
                start_period=Duration.seconds(300),
                interval=Duration.seconds(120)
            ),
            image=ecs.ContainerImage.from_registry("openemr/openemr:7.0.2"),
            secrets=secrets
        )

        # create mount point for EFS for sites folder
        efs_mount_point_for_sites_folder = ecs.MountPoint(
            container_path="/var/www/localhost/htdocs/openemr/sites/",
            read_only=False,
            source_volume='SitesFolderVolume'
        )
        #create mount point for EFS for ssl folder
        efs_mount_point_for_ssl_folder = ecs.MountPoint(
            container_path="/etc/ssl/",
            read_only=False,
            source_volume='SslFolderVolume'
        )

        openemr_container_definition.add_mount_points(
            efs_mount_point_for_sites_folder,
            efs_mount_point_for_ssl_folder
        )

        #Create fargate service for OpenEMR
        openemr_application_load_balanced_fargate_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            self, "OpenEMRFargateLBService",
            service_name="openemr-service",
            cluster=self.ecs_cluster,
            desired_count=self.node.try_get_context("fargate_minimum_capacity"),
            load_balancer=self.alb,
            open_listener=False,
            task_definition=openemr_fargate_task_definition,
            health_check_grace_period=Duration.minutes(5)
        )
        openemr_service = openemr_application_load_balanced_fargate_service.service

        #Set up ECS Exec for Debuggging
        if self.node.try_get_context("enable_ecs_exec") == "true":
            cfn_openemr_service = openemr_service.node.default_child
            cfn_openemr_service.add_property_override("EnableExecuteCommand", "True")
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["ssmmessages:CreateControlChannel",
                             "ssmmessages:CreateDataChannel",
                             "ssmmessages:OpenControlChannel",
                             "ssmmessages:OpenDataChannel",],
                    resources=["*"])
            )
            openemr_fargate_task_definition.task_role.add_to_policy(
                iam.PolicyStatement(
                    actions=["s3:PutObject",
                             "s3:GetEncryptionConfiguration"],
                    resources=[self.exec_bucket.bucket_arn,
                               self.exec_bucket.bucket_arn+'/*'])
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

        openemr_fargate_task_definition.task_role.add_to_policy(
            iam.PolicyStatement(
                actions=["acm:ImportCertificate"],
                resources=["arn:aws:acm:"+self.region+":"+self.account+":certificate/*"])
        )

        #Configure health check
        openemr_application_load_balanced_fargate_service.target_group.configure_health_check(
            path="/",
            healthy_http_codes="302",
            interval=Duration.seconds(300),
            healthy_threshold_count=2
        )

        #Allow conenctions to and from both of our EFSs for our Fargate service
        openemr_service.connections.allow_from(self.file_system_for_ssl_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_from(self.file_system_for_sites_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_ssl_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_sites_folder,ec2.Port.tcp(2049))

        #Allow connections to and from our database for our fargate service
        openemr_service.connections.allow_from(self.db_instance,ec2.Port.tcp(self.mysql_port))
        openemr_service.connections.allow_to(self.db_instance,ec2.Port.tcp(self.mysql_port))

        openemr_service.connections.allow_from(self.redis_sec_group, ec2.Port.tcp(self.redis_port))
        openemr_service.connections.allow_to(self.redis_sec_group, ec2.Port.tcp(self.redis_port))

        #Add CPU utilization based autoscaling
        openemr_scalable_target = (
            openemr_service.auto_scale_task_count(
                min_capacity=self.node.try_get_context("fargate_minimum_capacity"),
                max_capacity=self.node.try_get_context("fargate_maximum_capacity")
            )
        )

        openemr_scalable_target.scale_on_cpu_utilization(
            "OpenEMRCPUScaling", target_utilization_percent=self.node.try_get_context("fargate_cpu_autoscaling_percentage")
        )

        openemr_scalable_target.scale_on_memory_utilization(
            "OpenEMRMemoryScaling", target_utilization_percent=self.node.try_get_context("fargate_memory_autoscaling_percentage")
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
