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
        self.mysql_port = 3406
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
        plan = backup.BackupPlan.daily_weekly_monthly5_year_retention(self, "Plan")
        plan.add_selection(
            "Resources",
            resources=[
                backup.BackupResource.from_rds_database_instance(self.db_instance),
                backup.BackupResource.from_efs_file_system(self.file_system_for_ssl_folder),
                backup.BackupResource.from_efs_file_system(self.file_system_for_sites_folder)
            ]
        )

    def _create_environment_variables(self):
        self.oe_user = ssm.StringParameter(
            self,
            "oe-user",
            parameter_name="oe_user",
            string_value="admin"
        )
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
        )
        self.password.add_rotation_schedule(
            "rotation-schedule",
            hosted_rotation=secretsmanager.HostedRotation.mysql_single_user()
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
            deletion_protection=True,
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
        
        db_secret.add_rotation_schedule(
            "db-rotation",
            hosted_rotation=secretsmanager.HostedRotation.maria_db_single_user()
        )

        db_credentials = rds.Credentials.from_secret(db_secret)

        self.db_instance = rds.DatabaseInstance(
            self,
            "DatabaseInstance",
            vpc=self.vpc,
            credentials=db_credentials,
            engine=rds.DatabaseInstanceEngine.maria_db(version=rds.MariaDbEngineVersion.VER_10_6),
            vpc_subnets=ec2.SubnetSelection(
                subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS
            ),
            security_groups=[self.db_sec_group],
            storage_encrypted=True,
            multi_az=True,
            deletion_protection=True,
            port=self.mysql_port,
            monitoring_interval=Duration.seconds(60),
            cloudwatch_logs_exports=["error", "general", "slowquery", "audit"]
        )


    def _create_redis_cluster(self):

        private_subnets_ids = [ps.subnet_id for ps in self.vpc.private_subnets]

        redis_subnet_group = elasticache.CfnSubnetGroup(
            scope=self,
            id="redis_subnet_group",
            subnet_ids=private_subnets_ids,
            description="subnet group for redis"
        )

        self.redis_cluster = elasticache.CfnCacheCluster(
            scope=self,
            id="redis_cluster",
            engine="redis",
            cache_node_type="cache.t3.small",
            num_cache_nodes=1,
            cache_subnet_group_name=redis_subnet_group.ref,
            vpc_security_group_ids=[self.redis_sec_group.security_group_id],
            snapshot_retention_limit=15
        )

        self.redis_endpoint = ssm.StringParameter(
            self,
            "redis-endpoint",
            parameter_name="redis_endpoint",
            string_value=self.redis_cluster.attr_redis_endpoint_address
        )

    def _create_ecs_cluster(self):
        self.ecs_cluster = ecs.Cluster(
            self,
            "ecs-cluster",
            vpc=self.vpc,
            container_insights=True,
        )
        self.ecs_cluster.node.add_dependency(self.db_instance)

    def _create_efs_volume(self):

        #create EFS for sites folder
        self.file_system_for_sites_folder = efs.FileSystem(
            self, 
            "EfsFileSystemForSitesFolder",
            vpc=self.vpc,
            removal_policy=RemovalPolicy.DESTROY,

        )

        #create EFS volume configuration for sites folder
        self.efs_volume_configuration_for_sites_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_sites_folder.file_system_id,
        )

        #create EFS for ssl folder
        self.file_system_for_ssl_folder = efs.FileSystem(
            self, 
            "EfsFileSystemForSslFolder",
            vpc=self.vpc,
            removal_policy=RemovalPolicy.DESTROY,
        )

        #create EFS volume configuration for ssl folder
        self.efs_volume_configuration_for_ssl_folder = ecs.EfsVolumeConfiguration(
            file_system_id=self.file_system_for_ssl_folder.file_system_id,
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
        openemr_container_definition = openemr_fargate_task_definition.add_container("OpenEMRContainer",
            logging=ecs.LogDriver.aws_logs(
              stream_prefix="ecs/openemr",
              log_group=log_group,
            ),
            port_mappings=[ecs.PortMapping(container_port=80)],
            container_name="openemr",
            health_check=ecs.HealthCheck(
                command=[ "CMD-SHELL", "curl -f http://localhost:80/swagger || exit 1" ],
                start_period=Duration.seconds(300),
                interval=Duration.seconds(30)
            ),
            image=ecs.ContainerImage.from_registry("openemr/openemr:7.0.2"),
            secrets={
                "MYSQL_ROOT_USER": ecs.Secret.from_secrets_manager(self.db_instance.secret, "username"),
                "MYSQL_ROOT_PASS": ecs.Secret.from_secrets_manager(self.db_instance.secret, "password"),
                "MYSQL_USER": ecs.Secret.from_secrets_manager(self.db_instance.secret, "username"),
                "MYSQL_PASS": ecs.Secret.from_secrets_manager(self.db_instance.secret, "password"),
                "MYSQL_HOST": ecs.Secret.from_secrets_manager(self.db_instance.secret, "host"),
                "OE_PASS": ecs.Secret.from_secrets_manager(self.password),
                "REDIS_SERVER": ecs.Secret.from_ssm_parameter(
                    self.redis_endpoint
                ),
                "OE_USER": ecs.Secret.from_ssm_parameter(
                    self.oe_user
                ),
                "SWARM_MODE": ecs.Secret.from_ssm_parameter(
                    self.swarm_mode
                ),
                "MYSQL_PORT": ecs.Secret.from_ssm_parameter(
                    self.mysql_port_var
                )
            }
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
            desired_count=3,
            load_balancer=self.alb,
            open_listener=False,
            task_definition=openemr_fargate_task_definition
        )

        openemr_service = openemr_application_load_balanced_fargate_service.service

        #Configure health check
        openemr_application_load_balanced_fargate_service.target_group.configure_health_check(
            path="/",
            healthy_http_codes="302",
            interval=Duration.seconds(300),
        )

        #Allow conenctions to and from both of our EFSs for our Fargate service
        openemr_service.connections.allow_from(self.file_system_for_ssl_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_from(self.file_system_for_sites_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_ssl_folder,ec2.Port.tcp(2049))
        openemr_service.connections.allow_to(self.file_system_for_sites_folder,ec2.Port.tcp(2049))

        #Allow connections to and from our database for our fargate service
        openemr_service.connections.allow_from(self.db_instance,ec2.Port.tcp(self.mysql_port))
        openemr_service.connections.allow_to(self.db_instance,ec2.Port.tcp(self.mysql_port))

        openemr_service.connections.allow_from(self.redis_sec_group, ec2.Port.tcp(6379))
        openemr_service.connections.allow_to(self.redis_sec_group, ec2.Port.tcp(6379))

        #Add CPU utilization based autoscaling
        openemr_scalable_target = (
            openemr_service.auto_scale_task_count(
                min_capacity=1, max_capacity=10
            )
        )

        openemr_scalable_target.scale_on_cpu_utilization(
            "OpenEMRScaling", target_utilization_percent=50
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
